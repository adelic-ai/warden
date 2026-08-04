"""Bridge egress ACL — default-drop, no interception (§1).

**This module used to only *generate* an nftables ruleset that nothing
ever loaded.** The first real-Incus run found the consequence: egress was
entirely unenforced (`example.com` and the LAN gateway both reachable).
See DECISIONS.md "D13 — egress is enforced with Incus network ACLs, not a
host nft table".

The enforcement point is now `incus network acl`, applied to the warden
bridge and to the NIC device in warden's profile. Two reasons this beats
the host-nft-table design it replaces:

1. **A host nft table cannot be scoped to our bridge safely.** nftables
   evaluates every table's chain at a hook, and a `policy drop` forward
   chain in `table inet warden` drops packets for *every* bridge on the
   host — including the unrelated gemini-capsule build sharing this
   machine. Incus ACLs attach to a device, so they can't leak.
2. Incus already owns `table inet incus` for bridge filtering; a second
   table racing it is the kind of thing that works until it doesn't.

Rule shape is carried over from the capsule build, which measured these
behaviours on this same Incus 7.3 host:

- `drop`, never `reject` — a `reject` hands a scanning workload a clean,
  fast signal about what's closed. (The capsule also found `reject` is
  accepted at rule-creation but not actually enforced on bridges.)
- Specific `drop`s **outrank** broad `allow`s on Incus 7.3 bridges
  (capsule T8), so the LAN drops below genuinely bite.
- No drop covering the bridge itself: that would shadow the `/32` allows
  for the proxy and resolver and cut the only permitted path. Everything
  not explicitly allowed is already denied by the network's default-drop
  action, which needs no ordering assumption.

That last point used to be free. The bridge lived in CG-NAT, which is not
one of the private ranges dropped below, so "the bridge's own subnet is
deliberately absent" from the drop list was true by accident. Moving the
bridge out of CG-NAT (it collided with Tailscale — see profiles.py) put it
*inside* `172.16.0.0/12`, and `assert_enforceable` immediately refused the
document: the drop would have shadowed the proxy allow and left the
container with no egress at all. So the carve-out is now explicit — see
`lan_drops`, which subtracts the bridge network from whichever range
contains it. The guard was the only thing standing between a subnet change
and a silently unreachable container.
"""

from __future__ import annotations

from ipaddress import ip_interface, ip_network

ACL_NAME = "warden-egress"

# Private ranges a sandboxed workload has no business reaching.
PRIVATE_RANGES: tuple[str, ...] = (
    "192.168.0.0/16",
    "172.16.0.0/12",
    "10.0.0.0/8",
)


def lan_drops(bridge_subnet: str | None = None) -> tuple[str, ...]:
    """`PRIVATE_RANGES`, with the bridge's own network subtracted out.

    `bridge_subnet=None` means "no carve-out" and returns `PRIVATE_RANGES`
    unchanged — correct whenever the bridge is outside all three, and the
    behaviour every caller had before the bridge moved.

    The subtraction is exact (`address_exclude`), not a "skip the whole /12"
    shortcut: dropping the other ~1M addresses of 172.16/12 is the point of
    the rule, and silently discarding all of them to make one /24 reachable
    would trade a broken container for a quiet hole. Output is sorted so the
    document is byte-stable across runs — `ensure_substrate` only pushes the
    ACL when it differs from what Incus already has.
    """
    if bridge_subnet is None:
        return PRIVATE_RANGES
    bridge = ip_interface(bridge_subnet).network
    out: list = []
    for cidr in PRIVATE_RANGES:
        net = ip_network(cidr)
        if bridge.subnet_of(net):
            out.extend(net.address_exclude(bridge))
        else:
            out.append(net)
    return tuple(str(n) for n in sorted(out, key=lambda n: (n.network_address, n.prefixlen)))


class EgressPolicyError(RuntimeError):
    """A generated ACL document would not actually enforce egress."""


def build_acl_document(gateway: str, proxy_port: int, bridge_subnet: str | None = None) -> dict:
    """The one path out is the host-side allowlist proxy on the bridge
    gateway. DNS and DHCP to the gateway are permitted because the bridge
    is the container's only resolver and lease source; everything else —
    guest-to-guest included — falls through to the network's default drop.

    `bridge_subnet` is carved out of the LAN drops (see `lan_drops`). It is
    optional so that a caller whose bridge is outside all the private ranges
    is unaffected; `assert_enforceable` catches the case where it was needed
    and omitted.
    """
    gw32 = f"{gateway}/32"
    egress: list[dict] = [
        {
            "action": "allow",
            "protocol": "tcp",
            "destination": gw32,
            "destination_port": str(proxy_port),
            "state": "enabled",
        },
        {
            "action": "allow",
            "protocol": "udp",
            "destination": gw32,
            "destination_port": "53",
            "state": "enabled",
        },
        {
            "action": "allow",
            "protocol": "tcp",
            "destination": gw32,
            "destination_port": "53",
            "state": "enabled",
        },
        # DHCP client -> server. Required because the network default is
        # drop in both directions; without it the container never gets a
        # lease and comes up with no address at all.
        {
            "action": "allow",
            "protocol": "udp",
            "destination": gw32,
            "destination_port": "67",
            "state": "enabled",
        },
    ]
    egress += [
        {"action": "drop", "destination": cidr, "state": "enabled"}
        for cidr in lan_drops(bridge_subnet)
    ]
    ingress: list[dict] = [
        {
            "action": "allow",
            "protocol": "udp",
            "source": gw32,
            "destination_port": "68",
            "state": "enabled",
        },
    ]
    return {"config": {}, "description": "warden egress: proxy-only", "egress": egress, "ingress": ingress}


def _ip_to_int(addr: str) -> int:
    parts = [int(p) for p in addr.split(".")]
    if len(parts) != 4 or any(p < 0 or p > 255 for p in parts):
        raise ValueError(f"not an IPv4 address: {addr!r}")
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]


def _cidr_contains(cidr: str, addr: str) -> bool:
    net, _, bits_s = cidr.partition("/")
    bits = int(bits_s) if bits_s else 32
    mask = ((1 << bits) - 1) << (32 - bits) if bits else 0
    return (_ip_to_int(net) & mask) == (_ip_to_int(addr) & mask)


def assert_enforceable(document: dict, gateway: str, proxy_port: int) -> None:
    """Guard a caller runs before pushing the ACL. Not exhaustive Incus
    validation — just the three footguns this build has actually hit."""
    rules = list(document.get("egress", [])) + list(document.get("ingress", []))

    if any(rule.get("action") == "reject" for rule in rules):
        raise EgressPolicyError("ACL uses `reject` — bridge ACLs must use `drop`")

    proxy_allow = [
        rule
        for rule in document.get("egress", [])
        if rule.get("action") == "allow"
        and rule.get("destination") == f"{gateway}/32"
        and rule.get("destination_port") == str(proxy_port)
    ]
    if not proxy_allow:
        raise EgressPolicyError(
            f"ACL has no allow for the proxy at {gateway}:{proxy_port} — "
            "the container would have no permitted path out at all"
        )

    # The shadowing footgun: a drop covering the bridge gateway would cut
    # the proxy/resolver allows above, and (capsule T8) drops outrank
    # allows on this Incus, so it would win.
    for rule in document.get("egress", []):
        dest = rule.get("destination")
        if rule.get("action") == "drop" and dest and _cidr_contains(dest, gateway):
            raise EgressPolicyError(
                f"drop rule {dest} covers the bridge gateway {gateway} — it would shadow "
                "the proxy and resolver allows and leave the container with no egress at all"
            )
