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

from dataclasses import dataclass, field

IMAGE = "images:debian/12"
BRIDGE_NAME = "wardenbr0"
# Pinned, not `auto` — chosen out of the CG-NAT range (RFC 6598), which is
# unlikely to already be in use on a host's LAN (unlike 10.0.0.0/8 or
# 192.168.0.0/16, both extremely common LAN choices this must not collide
# with).
BRIDGE_SUBNET = "100.89.0.1/24"
STORAGE_POOL = "wardenpool"


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
        "restricted.networks.subnets": f"{BRIDGE_NAME}",
        # default-drop is the baseline; egress.py adds the explicit allows.
        "restricted.networks.access": f"{BRIDGE_NAME}",
    }


def network_config(subnet: str = BRIDGE_SUBNET) -> dict[str, str]:
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
) -> ProfileSpec:
    devices = {
        "root": {"type": "disk", "pool": pool, "path": "/"},
        "eth0": {"type": "nic", "network": bridge},
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
