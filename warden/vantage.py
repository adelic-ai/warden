"""Persistent vantage-VM lifecycle (VANTAGE-PLAN.md phase 1) — the base of the container-in-VM
shape (decision B, `REFACTOR.md`). This is the thing that makes a nested container's eBPF probe
run on a kernel above it instead of on the base host's own kernel.

Distinct from `build_vm.BuildVmRunner`: that spins a VM up and tears it down per build, one atomic
`submit_build` dispatch, no persistence between calls. A vantage VM is the opposite — created once,
reused across every `dev` invocation after, the way the `dev` home it goes on to host already is.
So this module reuses `build_vm.py`'s substrate/profile/wait-ready pieces (`ensure_build_vm_substrate`,
`build_vm_profile`, the wait-ready poll shape) and adds the one thing that path deliberately has
none of: create-if-absent instead of create-and-destroy.

`wait_ready` is intentionally NOT `warden/recover.py`'s wedge diagnosis. Applying `recover.py`'s L2
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
#: NOT "default" — that project is shared with unrelated tenants on a real host (e.g. CageTheAgent's
#: cta-dev-vm on pop-os). ensure_build_vm_substrate restricts a project's allowed networks down to
#: wardenbr0; doing that against a shared project breaks whatever else lives there and Incus rightly
#: refuses. Dedicated, same as build_vm.py's own ephemeral builds already use, for the same reason.
DEFAULT_PROJECT = "warden"
PROFILE_NAME = "warden-vantage-vm"
#: Produced by warden/mold.py phase 2, consumed here by phase 3. Defined here, not in mold.py, so
#: mold.py imports it from vantage.py rather than the reverse — mold.py already imports
#: refuse_if_foreign/wait_ready from this module, and a mold.py -> vantage.py -> mold.py import
#: would be circular.
GOLDEN_ALIAS = "warden-vantage-golden"

#: The nested wardenbr0's subnet — deliberately different from `profiles.BRIDGE_SUBNET`
#: (172.29.0.1/24), which the OUTER bridge a vantage VM's own NIC sits on already uses. Reusing it
#: for the nested bridge too means the nested interface locally shadows that address inside the
#: guest, so anything inside the VM trying to reach 172.29.0.1 (the outer proxy) resolves to its
#: own local interface instead and never leaves — real-host incident, phase 5. mold.py and
#: remote_dev.py both pass this via profiles.NESTED_BRIDGE_SUBNET_ENV_VAR when driving anything
#: that runs *inside* a vantage VM; every other, non-nested caller is unaffected.
NESTED_BRIDGE_SUBNET = "172.30.0.1/24"

#: Bounding the per-attempt liveness exec while waiting for the guest agent.
PROBE_TIMEOUT = 15.0
#: Matches build_vm.BuildVmRunner.WAIT_READY_TIMEOUT and VANTAGE-PLAN.md's observed cold-boot time
#: (Shape A's reference build: up to ~120s for the guest agent to answer after `incus launch`).
WAIT_READY_TIMEOUT = 120.0


class VantageError(RuntimeError):
    """A step of `ensure_vantage_vm` failed — substrate, launch, or the first-boot wait. Never
    raised for the VM already existing; that's the success path this module exists for."""


class VantageProjectConflict(VantageError):
    """The target project already exists and already hosts instance(s) that aren't the vantage VM
    itself. `ensure_build_vm_substrate` converges that project's network policy — doing that against
    a project with unknown tenants is exactly what broke `cta-dev-vm` on pop-os's `default` project
    (real-host incident, VANTAGE-PLAN.md phase 1). Refuses rather than guessing whether it's safe;
    a project that's brand new, empty, or already only hosts this VM converges without complaint."""


@dataclass(frozen=True)
class VantageInfo:
    name: str
    project: str
    #: False when `ensure_vantage_vm` found it already running and did nothing — the common case
    #: after the first call, and the whole point of create-if-absent over create-and-destroy.
    created: bool
    #: Which image the launch actually came from — GOLDEN_ALIAS if the mold (phase 2) has produced
    #: one, the stock IMAGE otherwise. None when created=False (nothing was launched this call, so
    #: there's nothing to report — the existing VM's origin isn't re-derived).
    image: str | None = None


def refuse_if_foreign(client, project: str, name: str) -> None:
    if not client.project_exists(project):
        return  # brand new - nothing to collide with
    others = [n for n in client.list_instances(project) if n != name]
    if others:
        raise VantageProjectConflict(
            f"project {project!r} already exists and already hosts instance(s) {others} that "
            f"aren't {name!r} — refusing to converge its network policy onto them. Pass a project "
            f"dedicated to warden's own infrastructure (e.g. the default {DEFAULT_PROJECT!r}), or "
            f"clean up the collision by hand first."
        )


def wait_ready(client, instance: str, project: str, timeout: float = WAIT_READY_TIMEOUT) -> None:
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
    shape `build_vm.py` already validates) unmodified; the new logic here is the existence check
    plus `refuse_if_foreign` — raises `VantageProjectConflict` rather than converging network
    policy onto a project that already has other tenants in it.

    Launches from `GOLDEN_ALIAS` (VANTAGE-PLAN.md phase 2's mold output) when one exists in this
    project, falling back to the stock `IMAGE` otherwise — automatic, not a caller-supplied flag, so
    every call benefits the moment a mold has been built, with no code change at the call site.
    """
    client = app.client
    if client.instance_exists(name, project):
        return VantageInfo(name=name, project=project, created=False)

    refuse_if_foreign(client, project, name)
    profile_spec = build_vm_profile(name=PROFILE_NAME, mem=mem, cpu=cpu, pool=app.pool)
    app.ensure_build_vm_substrate(project, profile_spec)
    image = GOLDEN_ALIAS if client.image_exists(GOLDEN_ALIAS, project=project) else IMAGE
    client.launch(image, name, project, profile_spec.name, instance_type="virtual-machine")
    wait_ready(client, name, project)
    return VantageInfo(name=name, project=project, created=True, image=image)
