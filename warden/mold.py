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

from warden.build_vm import IMAGE, build_vm_profile, set_proxy_env
from warden.flavors import DEBIAN_SETUP
from warden.profiles import NESTED_BRIDGE_SUBNET_ENV_VAR
from warden.vantage import (
    DEFAULT_PROJECT,
    GOLDEN_ALIAS,
    NESTED_BRIDGE_SUBNET,
    refuse_if_foreign,
    wait_ready,
)

if TYPE_CHECKING:
    from warden.app import WardenApp

MOLD_INSTANCE_NAME = "warden-vantage-mold-build"
PROFILE_NAME = "warden-vantage-mold-vm"
INSTALL_SCRIPT_REMOTE_PATH = "/root/install-incus-nested.sh"

#: apt prereqs baked into the mold: curl (install-incus-nested.sh needs it for the zabbly repo, per
#: Shape A step 3) and git (stable OS tooling phase 4's code deploy needs every launch — baking it
#: in once here means phase 4 never re-installs it).
PREREQ_PACKAGES = ("curl", "ca-certificates", "git")

#: The bridge ACL default-drops direct egress (same as every container/VM warden manages) — a VM
#: reaches nothing until its traffic is routed through warden's own proxy AND that proxy's allowlist
#: names the hosts it needs. DEBIAN_SETUP is the standing apt-mirror allowlist entry (flavors.py);
#: pkgs.zabbly.com is install-incus-nested.sh's own repo. Real-host lesson: the first mold attempt
#: failed with "Network is unreachable" reaching deb.debian.org because this wiring was missing
#: entirely — not a transient network issue, a real gap.
MOLD_ALLOWLIST: tuple[str, ...] = (*DEBIAN_SETUP, "pkgs.zabbly.com")

EGRESS_CHECK_TIMEOUT = 60.0
PREREQ_INSTALL_TIMEOUT = 300.0
#: install-incus-nested.sh: apt + the zabbly repo + `incus admin init`. Generous but bounded — an
#: unattended run that hangs (apt lock, stalled download) must fail loud, not hang forever
#: (VANTAGE-PLAN.md's failure-handling section). Reuses exec()'s own timeout param rather than a
#: shell-level `timeout(1)` wrap — the mechanism already exists, no need to reinvent it here.
#:
#: 600s was the original bound and was wrong, not conservative — real-host runs on pop-os (an
#: active desktop with two logged-in users and their own Chrome/GNOME load, not a dedicated build
#: box) showed dpkg genuinely still making progress (nonzero, slowly climbing CPU time) well past
#: 600s under real contention, not stuck. A fresh, empty storage pool made no difference (ruling
#: out wardenpool fragmentation specifically), and the host disk itself showed zero IOs in
#: progress while the guest sat in D-state — the bottleneck is contention for the shared host's
#: CPU/scheduler, not a hang. 1800s gives real headroom without being unbounded.
INSTALL_TIMEOUT = 1800.0
DEP_CHECK_TIMEOUT = 30.0


class MoldError(RuntimeError):
    """A step of `build_vantage_mold` failed — egress check, the install script, the dependency
    check, or publish. The build instance is deliberately left running on failure, not torn down:
    a human debugging a broken mold needs to see what state it died in."""


@dataclass(frozen=True)
class MoldResult:
    alias: str
    fingerprint: str


def _exec_ok(
    client, instance: str, project: str, argv: list[str], what: str, timeout: float, env=None
):
    result = client.exec(instance, argv, project=project, timeout=timeout, env=env)
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

    # Route the guest through warden's proxy and open it to exactly what the mold needs (apt
    # mirrors + zabbly) — without this, apt can reach nothing at all, per the bridge ACL's
    # default-drop. Both required; env alone with an empty allowlist still gets refused at the proxy.
    set_proxy_env(client, instance, project)
    if app.proxy_controller is not None:
        app.proxy_controller.set_allowlist(MOLD_ALLOWLIST)

    # -- egress sanity check (Shape A step 2): fail fast if the VM can't reach package mirrors,
    # rather than let the install script itself produce a confusing mid-script failure. `bash -c
    # 'set -o pipefail; ...'`, not `sh -c '... | tail -3'` — piping through tail masks apt-get's own
    # exit code with tail's (nearly always 0), which would make this check always "pass" regardless
    # of whether apt-get actually failed. Caught for real: without pipefail this silently swallowed
    # the exact "Network is unreachable" failure this check exists to catch.
    _exec_ok(
        client, instance, project,
        ["bash", "-c", "set -o pipefail; apt-get update -qq 2>&1 | tail -3"],
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
    # NESTED_BRIDGE_SUBNET, not the outer profiles.BRIDGE_SUBNET the script defaults to — this is
    # always the nested case (molding only ever happens for a vantage VM), so no detection needed,
    # just always pass it. Real-host lesson: reusing the outer subnet here is what let the nested
    # wardenbr0 locally shadow the outer proxy's address (phase 5 incident).
    _exec_ok(
        client, instance, project,
        ["bash", INSTALL_SCRIPT_REMOTE_PATH],
        "install-incus-nested.sh", INSTALL_TIMEOUT,
        env={NESTED_BRIDGE_SUBNET_ENV_VAR: NESTED_BRIDGE_SUBNET},
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
