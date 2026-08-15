"""Closes VANTAGE-PLAN.md's stated gap: `warden report --live` taught the double hop.

The auditd plane and the eBPF probe are both properties of a KERNEL, and for a `dev --vantage` home
that kernel is the vantage VM's, not the base host's — a container inside a VM shares the VM's
kernel, not the outer host's (that separation is the entire point of decision B: it's what gives
eBPF a kernel above the container to attach to). So this does not reach into the nested container
remotely the way `remote_dev.create_nested_dev`'s provisioning does; there is no plane to read from
the base host's side at all. Instead it remote-drives the SAME `warden report --live` command
*inside* the vantage VM, against the VM's own local (single-hop) nested Incus — exactly the pattern
phase 5 already established for `dev` itself — then pulls the resulting artifacts back.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, TYPE_CHECKING

from warden.transfer import pull_from_vm
from warden.vantage import DEFAULT_PROJECT

if TYPE_CHECKING:
    from warden.app import WardenApp

REMOTE_PYTHONPATH = "/root/warden:/root/agentwatch"
REMOTE_OUT_ROOT = "/root/.warden/runs"
#: deploy_code's own layout — a clone of the agentwatch repo lands its package one level down.
AGENTWATCH_MARKER = "/root/agentwatch/agentwatch/run.py"

#: The auditd path (collector + ausearch) is normally fast; generous headroom for a contended host.
REPORT_TIMEOUT = 120.0
#: --ebpf additionally blocks for the capture window itself (report.py's DEFAULT_EBPF_CAPTURE_SECONDS
#: is 30s) plus reconcile overhead — bounded, not unbounded, but needs more room than the plain path.
EBPF_REPORT_TIMEOUT = 300.0


class RemoteReportError(RuntimeError):
    """The remote `report --live` was never going to succeed for a reason knowable BEFORE spending
    the round trip — right now, exactly one case: `dev --vantage --no-agentwatch` was used to stand
    the home up, so there is no agentwatch on the VM to reconcile with. Checked locally rather than
    left to surface as the remote command's own (base-host-flavored, misleading here) import error."""


@dataclass(frozen=True)
class RemoteReportResult:
    stdout: str
    stderr: str
    returncode: int
    local_out_dir: Path
    #: False when the remote `report` failed early enough that it never wrote an artifact directory
    #: at all (e.g. `--since` could not be resolved) — the pull is then expected to have nothing to
    #: fetch, not a transfer bug. `stdout`/`stderr` still carry report's own honest error either way;
    #: this flag exists so the CLI does not print a confusing "artifact pull failed" over a remote
    #: message that already explained itself.
    artifacts_pulled: bool
    pull_error: Optional[str] = None


def report_nested_live(
    app: "WardenApp",
    *,
    vantage_instance: str,
    container_name: str,
    llm: str,
    local_out_dir: Path,
    vantage_project: str = DEFAULT_PROJECT,
    nested_project: str = "warden",
    since: Optional[str] = None,
    ebpf: bool = False,
    capture_seconds: Optional[int] = None,
    host: Optional[str] = None,
) -> RemoteReportResult:
    """Run `python3 -m warden.cli report --live [--ebpf] --llm <llm> --instance <container_name>
    --project <nested_project> --out <REMOTE_OUT_ROOT>` inside `vantage_instance`, then pull the
    artifact directory it wrote (on the VM's OWN disk, not inside the container — same reasoning as
    the module docstring) back to `local_out_dir` on the base host.

    `report`'s own exit code (0 / 1 / 2) is relayed verbatim, not reinterpreted — it already carries
    an honest verdict (§7's bar applies here unchanged); this wrapper's only job is getting that
    verdict, its stdout, and its artifacts across the extra hop.

    Raises `RemoteReportError` immediately, before the round trip, if agentwatch was never deployed
    here (`dev --vantage --no-agentwatch`) — the remote command would fail anyway, but with an
    import error written for a base-host operator, not "redeploy with agentwatch included."
    """
    client = app.client
    marker = client.exec(
        vantage_instance, ["test", "-f", AGENTWATCH_MARKER], project=vantage_project, timeout=15.0,
    )
    if not marker.ok:
        raise RemoteReportError(
            f"{vantage_instance}: no agentwatch deployed here — this dev home was stood up with "
            f"--no-agentwatch, or predates it. Re-run `dev --vantage` WITHOUT --no-agentwatch to "
            f"redeploy with agentwatch included before reconciling."
        )

    argv = [
        "python3", "-m", "warden.cli", "report", "--live",
        "--llm", llm, "--instance", container_name, "--project", nested_project,
        "--out", REMOTE_OUT_ROOT,
    ]
    if since:
        argv += ["--since", since]
    if host:
        argv += ["--host", host]
    if ebpf:
        argv += ["--ebpf"]
        if capture_seconds is not None:
            argv += ["--capture-seconds", str(capture_seconds)]

    timeout = EBPF_REPORT_TIMEOUT if ebpf else REPORT_TIMEOUT
    result = client.exec(
        vantage_instance, argv, project=vantage_project,
        env={"PYTHONPATH": REMOTE_PYTHONPATH}, timeout=timeout,
    )

    remote_dir = f"{REMOTE_OUT_ROOT}/{nested_project}/{container_name}"
    pull_error: Optional[str] = None
    artifacts_pulled = False
    try:
        pull_from_vm(
            app, vantage_instance=vantage_instance, vantage_project=vantage_project,
            remote_path=remote_dir, local_path=local_out_dir,
        )
        artifacts_pulled = True
    except Exception as exc:
        # Best-effort, not fatal: a remote `report` that failed before writing anything (e.g. it
        # could not resolve --since) has nothing to pull, and that is report's own honest failure —
        # already carried in `result.stdout`/`stderr` — not a transfer bug. Recorded rather than
        # raised so the caller sees report's real message instead of a confusing pull error over it.
        pull_error = str(exc)

    return RemoteReportResult(
        stdout=result.stdout, stderr=result.stderr, returncode=result.returncode,
        local_out_dir=local_out_dir, artifacts_pulled=artifacts_pulled, pull_error=pull_error,
    )
