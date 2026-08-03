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
- No `100.64.0.0/10` (or any) drop covering the bridge itself: that would
  shadow the `/32` allows for the proxy and resolver and cut the only
  permitted path. Everything not explicitly allowed is already denied by
  the network's default-drop action, which needs no ordering assumption.
"""

from __future__ import annotations

ACL_NAME = "warden-egress"

# Private ranges a sandboxed workload has no business reaching. The bridge's
# own subnet is deliberately absent — see the module docstring.
LAN_DROPS: tuple[str, ...] = (
    "192.168.0.0/16",
    "172.16.0.0/12",
    "10.0.0.0/8",
)


class EgressPolicyError(RuntimeError):
    """A generated ACL document would not actually enforce egress."""


def build_acl_document(gateway: str, proxy_port: int) -> dict:
    """The one path out is the host-side allowlist proxy on the bridge
    gateway. DNS and DHCP to the gateway are permitted because the bridge
    is the container's only resolver and lease source; everything else —
    guest-to-guest included — falls through to the network's default drop.
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
        {"action": "drop", "destination": cidr, "state": "enabled"} for cidr in LAN_DROPS
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
