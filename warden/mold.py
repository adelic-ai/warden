"""VANTAGE-PLAN.md phase 2 — the mold: build the golden vantage-VM image once, so every subsequent
persistent vantage VM (`warden/vantage.py`, phase 1) can launch from it instead of paying `apt`'s
cost every time.

Scope is deliberately narrow, per VANTAGE-PLAN.md's design goals: OS + Incus + `admin init` (plus a
couple of small, stable OS packages the deploy step needs — `git`, `curl`). warden and agentwatch do
**not** go in here — they're under active development, and baking them in reproduces exactly the
class of bug D29 fixed, a golden copy silently drifting from the real one. Phase 4 deploys them
fresh onto every VM launched from this image, every time.

Triggered manually (a rebuild command), not on every `dev` — VANTAGE-PLAN.md's build order.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from warden.build_vm import IMAGE, build_vm_profile
from warden.vantage import DEFAULT_PROJECT, refuse_if_foreign, wait_ready

if TYPE_CHECKING:
    from warden.app import WardenApp

MOLD_INSTANCE_NAME = "warden-vantage-mold-build"
GOLDEN_ALIAS = "warden-vantage-golden"
PROFILE_NAME = "warden-vantage-mold-vm"
INSTALL_SCRIPT_REMOTE_PATH = "/root/install-incus-nested.sh"

#: apt prereqs baked into the mold: curl (install-incus-nested.sh needs it for the zabbly repo, per
#: Shape A step 3) and git (stable OS tooling phase 4's code deploy needs every launch — baking it
#: in once here means phase 4 never re-installs it).
PREREQ_PACKAGES = ("curl", "ca-certificates", "git")

EGRESS_CHECK_TIMEOUT = 60.0
PREREQ_INSTALL_TIMEOUT = 120.0
#: install-incus-nested.sh: apt + the zabbly repo + `incus admin init`. Generous but bounded — an
#: unattended run that hangs (apt lock, stalled download) must fail loud, not hang forever
#: (VANTAGE-PLAN.md's failure-handling section). Reuses exec()'s own timeout param rather than a
#: shell-level `timeout(1)` wrap — the mechanism already exists, no need to reinvent it here.
INSTALL_TIMEOUT = 600.0
DEP_CHECK_TIMEOUT = 30.0


class MoldError(RuntimeError):
    """A step of `build_vantage_mold` failed — egress check, the install script, the dependency
    check, or publish. The build instance is deliberately left running on failure, not torn down:
    a human debugging a broken mold needs to see what state it died in."""


@dataclass(frozen=True)
class MoldResult:
    alias: str
    fingerprint: str


def _exec_ok(client, instance: str, project: str, argv: list[str], what: str, timeout: float):
    result = client.exec(instance, argv, project=project, timeout=timeout)
    if not result.ok:
        raise MoldError(
            f"{instance}: {what} failed (rc={result.returncode}): "
            f"{(result.stderr or result.stdout).strip()[:2000]}"
        )
    return result


def build_vantage_mold(
    app: "WardenApp",
    install_script: str,
    *,
    instance: str = MOLD_INSTANCE_NAME,
    project: str = DEFAULT_PROJECT,
    alias: str = GOLDEN_ALIAS,
    mem: str = "3GiB",
    cpu: str = "2",
) -> MoldResult:
    """Launch a fresh build VM, run `install_script` (the contents of `install-incus-nested.sh`)
    unattended, verify Incus + the prereq packages actually work, publish it as `alias`, then tear
    the build instance down — the image is the durable artifact from here, not the VM that made it.

    `install_script` is passed in as text (the caller reads `scripts/install-incus-nested.sh`)
    rather than this module reaching into the filesystem itself — keeps the same seam `up()`'s
    other file-pushing callers already use (`file_push` takes content, never a path).
    """
    client = app.client
    refuse_if_foreign(client, project, instance)

    profile_spec = build_vm_profile(name=PROFILE_NAME, mem=mem, cpu=cpu, pool=app.pool)
    app.ensure_build_vm_substrate(project, profile_spec)
    if not client.instance_exists(instance, project):
        client.launch(IMAGE, instance, project, profile_spec.name, instance_type="virtual-machine")
    wait_ready(client, instance, project)

    # -- egress sanity check (Shape A step 2): fail fast if the VM can't reach package mirrors,
    # rather than let the install script itself produce a confusing mid-script failure.
    _exec_ok(
        client, instance, project,
        ["sh", "-c", "apt-get update -qq 2>&1 | tail -3"],
        "egress check (apt-get update)", EGRESS_CHECK_TIMEOUT,
    )

    # -- prereqs + the install script itself (Shape A steps 3-5, minus the mid-build patch: D29 is
    # already on main, so this should succeed in one pass rather than needing a re-run).
    _exec_ok(
        client, instance, project,
        ["sh", "-c", f"DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {' '.join(PREREQ_PACKAGES)}"],
        f"prereq install ({', '.join(PREREQ_PACKAGES)})", PREREQ_INSTALL_TIMEOUT,
    )
    client.file_push(instance, install_script.encode(), INSTALL_SCRIPT_REMOTE_PATH, project=project)
    _exec_ok(
        client, instance, project,
        ["bash", INSTALL_SCRIPT_REMOTE_PATH],
        "install-incus-nested.sh", INSTALL_TIMEOUT,
    )

    # -- verify before trusting the image: nested Incus actually answers, prereqs actually present.
    _exec_ok(
        client, instance, project,
        ["sh", "-c", "incus version && python3 --version && git --version"],
        "dependency check (incus/python3/git)", DEP_CHECK_TIMEOUT,
    )

    client.stop(instance, project=project)
    fingerprint = client.publish(instance, alias, project=project)
    client.delete(instance, project=project)
    return MoldResult(alias=alias, fingerprint=fingerprint)
