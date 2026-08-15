"""VANTAGE-PLAN.md phase 4 — code deploy: bundle-push-clone warden + agentwatch onto an existing
vantage VM, fresh on every launch, from whatever's checked out locally right now.

Deliberately not baked into the golden image (`mold.py`'s scope, phase 2) — warden and agentwatch
are under active development, and a golden copy of either would drift from the real one exactly the
way D29 did (`DECISIONS.md`), just one layer up. This module is the "deploy fresh every time" half
of that split: cheap (a git bundle + clone), so paying it on every launch is the actual point, not a
cost to optimize away.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from warden.vantage import DEFAULT_PROJECT

if TYPE_CHECKING:
    from warden.app import WardenApp

WARDEN_BUNDLE_REMOTE = "/root/warden.bundle"
AGENTWATCH_BUNDLE_REMOTE = "/root/agentwatch.bundle"
WARDEN_REMOTE_DIR = "/root/warden"
AGENTWATCH_REMOTE_DIR = "/root/agentwatch"
VERIFY_SCRIPT_LOCAL = Path(__file__).resolve().parent.parent / "scripts" / "verify-vantage-vm.py"
VERIFY_SCRIPT_REMOTE = "/root/verify-vantage-vm.py"

CLONE_TIMEOUT = 60.0
VERIFY_TIMEOUT = 30.0


class DeployError(RuntimeError):
    """A step of `deploy_code` failed — bundling, pushing, cloning, or post-deploy verification.
    The latter is the one that matters most: it's what would have caught D29's staged-vs-checked-out
    divergence automatically, had it existed at the time (VANTAGE-PLAN.md's Testing section)."""


@dataclass(frozen=True)
class DeployResult:
    warden_commit: str
    #: None when deployed with include_agentwatch=False — the capture plane itself (auditd/bpftrace/
    #: cgroups) is baked into the golden image and needs no code at all; agentwatch is purely a
    #: consumer of it, only needed by `report`, not by `dev` standing the home up in the first place.
    agentwatch_commit: Optional[str]


def _discover_agentwatch_path() -> Path:
    """Same discovery order as `report.py`'s `_import_agentwatch`: `WARDEN_AGENTWATCH_PATH`, then a
    sibling checkout beside this repo. Duplicated rather than shared — that function's job is making
    agentwatch *importable* (sys.path mutation, import attempts, tailored error messages); this one
    just needs a bare path to bundle from, a smaller and different contract."""
    env = os.environ.get("WARDEN_AGENTWATCH_PATH")
    if env:
        candidate = Path(env).expanduser()
        if (candidate / "agentwatch" / "run.py").exists():
            return candidate
    sibling = Path(__file__).resolve().parent.parent.parent / "agentwatch"
    if (sibling / "agentwatch" / "run.py").exists():
        return sibling
    raise DeployError(
        "agentwatch not found for bundling — set WARDEN_AGENTWATCH_PATH or check it out beside "
        "this repo as ./agentwatch (same discovery report.py's _import_agentwatch uses)."
    )


def _bundle_head(repo_path: Path) -> tuple[bytes, str]:
    """git bundle of the CURRENT HEAD, whatever branch that is — VANTAGE-PLAN.md's design goal is
    deploying whatever's checked out locally, not a pinned branch name, unlike Shape A's manual
    build (which bundled a named feature branch by hand)."""
    if not (repo_path / ".git").exists():
        raise DeployError(f"{repo_path}: not a git repo (no .git) — cannot bundle for deploy")
    commit = subprocess.run(
        ["git", "-C", str(repo_path), "rev-parse", "--short", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    with tempfile.NamedTemporaryFile(suffix=".bundle") as f:
        subprocess.run(
            ["git", "-C", str(repo_path), "bundle", "create", f.name, "HEAD"],
            capture_output=True, check=True,
        )
        return Path(f.name).read_bytes(), commit


def deploy_code(
    app: "WardenApp",
    *,
    instance: str,
    project: str = DEFAULT_PROJECT,
    warden_path: Optional[Path] = None,
    agentwatch_path: Optional[Path] = None,
    include_agentwatch: bool = True,
) -> DeployResult:
    """Push fresh warden (+ agentwatch, unless `include_agentwatch=False`) onto `instance` as
    `/root/warden` and `/root/agentwatch` siblings — the exact layout `scripts/verify-vantage-vm.py`
    already expects — then run that script and raise `DeployError` if it reports anything other than
    all-green. Overwrites whatever was deployed there before (`rm -rf` then clone), matching "fresh
    every launch," not incremental — that includes removing a stale `/root/agentwatch` from an
    earlier deploy when this call skips it, so the instance's state is never ambiguous about whether
    agentwatch is actually there.

    `include_agentwatch=False` is for a caller that only wants the persistent home itself standing
    up — the capture plane (auditd/bpftrace/cgroups) is baked into the golden image and needs no
    code at all; agentwatch is purely `report`'s dependency, not `dev`'s. A later `report --live
    --vantage` against an instance deployed this way fails fast with a clear message
    (`remote_report.py`), not a confusing import error.
    """
    client = app.client
    warden_path = warden_path or Path(__file__).resolve().parent.parent

    warden_bundle, warden_commit = _bundle_head(warden_path)
    client.file_push(instance, warden_bundle, WARDEN_BUNDLE_REMOTE, project=project)

    agentwatch_commit: Optional[str] = None
    clone_cmd = "cd /root && rm -rf warden agentwatch"
    clone_cmd += f" && git clone -q {WARDEN_BUNDLE_REMOTE} warden"
    if include_agentwatch:
        agentwatch_path = agentwatch_path or _discover_agentwatch_path()
        agentwatch_bundle, agentwatch_commit = _bundle_head(agentwatch_path)
        client.file_push(instance, agentwatch_bundle, AGENTWATCH_BUNDLE_REMOTE, project=project)
        clone_cmd += f" && git clone -q {AGENTWATCH_BUNDLE_REMOTE} agentwatch"

    clone_result = client.exec(
        instance, ["sh", "-c", clone_cmd], project=project, timeout=CLONE_TIMEOUT,
    )
    if not clone_result.ok:
        raise DeployError(
            f"{instance}: clone failed: "
            f"{(clone_result.stderr or clone_result.stdout).strip()[:2000]}"
        )

    client.file_push(
        instance, VERIFY_SCRIPT_LOCAL.read_bytes(), VERIFY_SCRIPT_REMOTE, project=project
    )
    verify_argv = ["python3", VERIFY_SCRIPT_REMOTE]
    if not include_agentwatch:
        verify_argv.append("--no-agentwatch")
    verify_result = client.exec(instance, verify_argv, project=project, timeout=VERIFY_TIMEOUT)
    if not verify_result.ok:
        raise DeployError(
            f"{instance}: post-deploy verification failed:\n{verify_result.stdout}{verify_result.stderr}"
        )

    return DeployResult(warden_commit=warden_commit, agentwatch_commit=agentwatch_commit)
