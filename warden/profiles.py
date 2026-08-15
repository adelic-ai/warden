"""Restricted project/profile/network config (§1's Incus-config gotchas).

- `restricted=true` on a project only takes effect for profiles if
  `features.profiles=true` is also set — otherwise the project silently
  falls back to the `default` project's (unrestricted) profiles. So the
  project config always sets both, and the profile itself is *defined
  inside* the project, never in `default`.
- `images:debian/12`, not Ubuntu — the `images:` remote dropped Ubuntu
  images (per spec; Debian is the supported unprivileged base here).
- The bridge subnet is pinned (never `auto`) so it can't collide with
  whatever the host LAN happens to be using.
- No host disk devices, ever — `validate_no_host_mounts` is a second,
  independent enforcement layer on top of the project's own
  `restricted.devices.disk`, so a bug in profile construction can't
  silently hand a container a host bind-mount.
- `security.idmap.isolated=true` so two instances never share a host-uid
  range (see DECISIONS.md — this is what makes §4 test 4's "distinct
  idmaps" true by construction).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from ipaddress import ip_interface, ip_network

from warden.egress import ACL_NAME as EGRESS_ACL_NAME

#: Override hook for the container-in-VM shape (VANTAGE-PLAN.md): a vantage VM's own nested
#: wardenbr0 must NOT reuse the outer wardenbr0's exact subnet, or the nested bridge locally
#: shadows the outer gateway's address inside the guest — any connection to it resolves to the
#: guest's own local interface, never reaching the actual outer proxy (real-host incident, phase
#: 5). Unset by default, so every existing bare-host/outer caller is unaffected; set only when
#: driving a nested install (mold.py) or a nested `warden dev` (remote_dev.py).
NESTED_BRIDGE_SUBNET_ENV_VAR = "WARDEN_NESTED_BRIDGE_SUBNET"

IMAGE = "images:debian/12"
BRIDGE_NAME = "wardenbr0"

# RFC 6598 CG-NAT. This used to look like the *safe* choice — "unlikely to be
# on a host's LAN, unlike 10.0.0.0/8 or 192.168.0.0/16" — and that reasoning
# only considered the LAN. It is the range **Tailscale** allocates every node
# out of, and Tailscale installs a route for the whole /10. A managed bridge
# with a /24 inside it is more specific, so it wins: every tailnet peer in
# that /24 becomes unreachable, and if the operator's own path to this host is
# the tailnet, `warden up` can cut the connection it is being driven over.
# Measured on the pop-os validation host: `tailscale0` at 100.120.63.5/32 with
# 100.64.0.0/10 routed, and `wardenbr0` already holding 100.89.0.1/24.
#
# Nothing in warden could notice — the bridge came up correctly, the ACL
# applied, the containers had egress. The damage is entirely off-box.
CGNAT_RANGE = ip_network("100.64.0.0/10")

# Pinned, not `auto`, and now out of both directions of collision: RFC 1918
# 172.16/12 is far less common on consumer LANs than 10/8 or 192.168/16, and
# it is clear of CG-NAT and of Incus's own default `incusbr0` (10.x on this
# host). `assert_subnet_sane` below is the structural guard that keeps the
# next person from "improving" this back into a routed overlay's range.
BRIDGE_SUBNET = os.environ.get(NESTED_BRIDGE_SUBNET_ENV_VAR, "172.29.0.1/24")
BRIDGE_GATEWAY = BRIDGE_SUBNET.split("/")[0]
STORAGE_POOL = "wardenpool"
STORAGE_DRIVER = "btrfs"
# The host-side allowlist proxy binds the bridge gateway on this port. It is
# the container's only permitted destination (see egress.py).
PROXY_PORT = 3128


class ProfileValidationError(RuntimeError):
    """Raised when a generated device set would violate the no-host-mounts
    invariant. This should never fire in practice — it exists as a second,
    independent check on top of the project's own restricted.devices.disk,
    per §1 ("no host mounts... as a second I2 enforcement")."""


def project_config() -> dict[str, str]:
    return {
        "features.profiles": "true",
        "features.images": "true",
        "restricted": "true",
        "restricted.devices.disk": "block",
        "restricted.devices.disk.paths": "",
        "restricted.devices.nic": "managed",
        # `restricted=true` blocks snapshot creation by default, and the
        # design REQUIRES the clean snapshot + restore (I6). Without this
        # the first real run got "Project warden doesn't allow for snapshot
        # creation" — the same finding the capsule build recorded as D9.
        "restricted.snapshots": "allow",
        # Confine the project to the one bridge warden controls. NOTE:
        # `restricted.networks.subnets` is deliberately absent — it takes
        # `<uplink>:<subnet>` pairs, not a network name, and setting it to
        # a bare bridge name is rejected. `restricted.storage.pools` is
        # likewise not set: the pool simply has to exist.
        "restricted.networks.access": f"{BRIDGE_NAME}",
    }


class BridgeSubnetError(RuntimeError):
    """The bridge subnet would hijack a range something else on this host routes."""


def assert_subnet_sane(subnet: str = BRIDGE_SUBNET) -> None:
    """Refuse a bridge subnet inside CG-NAT (100.64.0.0/10).

    Structural, not advisory: the previous value was chosen *because* CG-NAT
    looked unused, and the failure it causes is invisible from inside warden
    (the bridge works perfectly; a routed overlay elsewhere on the host loses
    the addresses). A comment would not have stopped it — a raise does.

    This is deliberately narrow. It does not try to enumerate every overlay a
    host might run; it names the one range that is, by convention, always
    someone else's (Tailscale, and CG-NAT carriers generally).
    """
    network = ip_interface(subnet).network
    if network.subnet_of(CGNAT_RANGE):
        raise BridgeSubnetError(
            f"bridge subnet {subnet} is inside CG-NAT {CGNAT_RANGE} — this is the range "
            "Tailscale (and carrier NAT) allocates from. A more-specific bridge route wins "
            "over the overlay's /10, so every peer in this /24 becomes unreachable and an "
            "operator driving warden over the tailnet can lose the host. Pick an RFC 1918 "
            "subnet outside 100.64.0.0/10."
        )


def network_config(subnet: str = BRIDGE_SUBNET) -> dict[str, str]:
    assert_subnet_sane(subnet)
    return {
        "ipv4.address": subnet,
        "ipv4.nat": "true",
        "ipv6.address": "none",
    }


def validate_no_host_mounts(devices: dict[str, dict]) -> None:
    """A disk device with a `source` key points at a host path — that's a
    bind mount. The only disk device warden ever defines is the
    pool-backed root device (`pool` + in-container `path`, no `source`)."""
    for dev_name, dev in devices.items():
        if dev.get("type") == "disk" and "source" in dev:
            raise ProfileValidationError(
                f"device {dev_name!r} has a host `source` ({dev['source']!r}) — "
                "host mounts are never allowed, even by an operator override"
            )


@dataclass(frozen=True)
class ProfileSpec:
    name: str
    config: dict[str, str]
    devices: dict[str, dict]


def build_profile(
    flavor_name: str,
    *,
    mem: str = "4GiB",
    cpu: str = "2",
    pool: str = STORAGE_POOL,
    bridge: str = BRIDGE_NAME,
    acl: str = EGRESS_ACL_NAME,
) -> ProfileSpec:
    devices = {
        "root": {"type": "disk", "pool": pool, "path": "/"},
        # security.acls is what actually enforces egress — the ACL rides on
        # the NIC device, so it cannot leak onto another bridge the way a
        # host-wide nft table would. Attaching it at the *profile* is the
        # fail-safe direction: anything launched into the project inherits
        # it, rather than failing open if someone forgets a per-instance flag.
        "eth0": {"type": "nic", "network": bridge, "security.acls": acl},
    }
    validate_no_host_mounts(devices)
    config = {
        "security.privileged": "false",
        "security.nesting": "false",
        "security.idmap.isolated": "true",
        "limits.memory": mem,
        "limits.cpu": cpu,
    }
    return ProfileSpec(name=f"warden-{flavor_name}", config=config, devices=devices)
