"""Persistent vantage-VM lifecycle (VANTAGE-PLAN.md phase 1) — the base of the container-in-VM
shape (decision B, `REFACTOR.md`). This is the thing that makes a nested container's eBPF probe
run on a kernel above it instead of on the base host's own kernel.

Distinct from `build_vm.BuildVmRunner`: that spins a VM up and tears it down per build, one atomic
`submit_build` dispatch, no persistence between calls. A vantage VM is the opposite — created once,
reused across every `dev` invocation after, the way the `dev` home it goes on to host already is.
So this module reuses `build_vm.py`'s substrate/profile/wait-ready pieces (`ensure_build_vm_substrate`,
`build_vm_profile`, the wait-ready poll shape) and adds the one thing that path deliberately has
none of: create-if-absent instead of create-and-destroy.

`_wait_ready` is intentionally NOT `warden/recover.py`'s wedge diagnosis. Applying `recover.py`'s L2
tier (exec fails to answer within 15s -> force-restart) to a VM's first boot would misdiagnose normal
boot time as a wedge and force-restart a VM that was never stuck — a VM doesn't answer `exec` until
its guest agent comes up, which VANTAGE-PLAN.md's reference build observed taking up to ~120s cold.
`recover.py` applies, unmodified, only *after* a vantage VM has come up once.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from warden.build_vm import IMAGE, build_vm_profile
from warden.incus import IncusCommandError

if TYPE_CHECKING:
    from warden.app import WardenApp

DEFAULT_NAME = "warden-vantage"
DEFAULT_PROJECT = "default"
PROFILE_NAME = "warden-vantage-vm"

#: Bounding the per-attempt liveness exec while waiting for the guest agent.
PROBE_TIMEOUT = 15.0
#: Matches build_vm.BuildVmRunner.WAIT_READY_TIMEOUT and VANTAGE-PLAN.md's observed cold-boot time
#: (Shape A's reference build: up to ~120s for the guest agent to answer after `incus launch`).
WAIT_READY_TIMEOUT = 120.0


class VantageError(RuntimeError):
    """A step of `ensure_vantage_vm` failed — substrate, launch, or the first-boot wait. Never
    raised for the VM already existing; that's the success path this module exists for."""


@dataclass(frozen=True)
class VantageInfo:
    name: str
    project: str
    #: False when `ensure_vantage_vm` found it already running and did nothing — the common case
    #: after the first call, and the whole point of create-if-absent over create-and-destroy.
    created: bool


def _wait_ready(client, instance: str, project: str, timeout: float = WAIT_READY_TIMEOUT) -> None:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        try:
            if client.exec(instance, ["/bin/true"], project=project, timeout=PROBE_TIMEOUT).ok:
                return
        except IncusCommandError as exc:  # pragma: no cover - timing dependent
            last = str(exc)
        time.sleep(1.0)
    raise VantageError(f"{instance}: guest agent not ready within {timeout}s {last}")


def ensure_vantage_vm(
    app: "WardenApp",
    *,
    name: str = DEFAULT_NAME,
    project: str = DEFAULT_PROJECT,
    mem: str = "3GiB",
    cpu: str = "2",
) -> VantageInfo:
    """Create-if-absent: return the existing vantage VM if one is already running, otherwise stand
    one up. Reuses `ensure_build_vm_substrate` (pool/project/network/ACL — identical to the
    container path's, per that method's own docstring) and `build_vm_profile` (the same VM profile
    shape `build_vm.py` already validates) unmodified; the only new logic here is the existence
    check. No golden-image launch yet (VANTAGE-PLAN.md phase 2/3) — always the stock image today.
    """
    client = app.client
    if client.instance_exists(name, project):
        return VantageInfo(name=name, project=project, created=False)

    profile_spec = build_vm_profile(name=PROFILE_NAME, mem=mem, cpu=cpu, pool=app.pool)
    app.ensure_build_vm_substrate(project, profile_spec)
    client.launch(IMAGE, name, project, profile_spec.name, instance_type="virtual-machine")
    _wait_ready(client, name, project)
    return VantageInfo(name=name, project=project, created=True)
