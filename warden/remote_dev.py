"""VANTAGE-PLAN.md phase 5 — remote-drive container creation: invoke `warden dev`'s own
provisioning logic *inside* the vantage VM, over `incus exec` from the base host, so it talks to
the VM's own nested Incus daemon instead of whatever's running the base host's.

No container-side code changes — `up()`/`dev`'s existing idmap/egress/auditd logic already worked,
unmodified, the moment Shape A ran it one level up (reference step 8, VANTAGE-PLAN.md). This module
only adds the remote-invocation wrapper Shape A did by hand over SSH.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from warden.vantage import DEFAULT_PROJECT

if TYPE_CHECKING:
    from warden.app import WardenApp

DEFAULT_DEV_NAME = "warden-dev"
#: Both siblings, matching deploy.py's layout - dev itself likely only needs warden/cli.py's own
#: module tree, but agentwatch costs nothing to include and matches what Shape A actually had
#: present when it ran this by hand.
REMOTE_PYTHONPATH = "/root/warden:/root/agentwatch"

#: Furnishing a fresh dev home is slow and — a known, not-yet-fixed gap (VANTAGE-PLAN.md's
#: failure-handling section: the progress log isn't wired to the CLI's stdout) — silent while it
#: happens. Generous bound so an unattended run fails loud eventually instead of hanging forever;
#: not a claim that furnishing normally takes this long.
DEV_TIMEOUT = 300.0
VERIFY_TIMEOUT = 15.0


class RemoteDevError(RuntimeError):
    """The remote `warden dev` invocation failed, timed out, or the nested container it was
    supposed to create doesn't actually exist afterward — a non-zero exit isn't trusted alone
    (report.py's own principle elsewhere: verify, don't assume)."""


@dataclass(frozen=True)
class RemoteDevResult:
    name: str
    #: The nested nested-Incus project the container landed in — NOT vantage_project (that's the
    #: OUTER project the vantage VM itself lives in on the base host). `warden dev` inside the VM
    #: creates its own `warden` project in the VM's own Incus, same default as everywhere else.
    nested_project: str


def create_nested_dev(
    app: "WardenApp",
    *,
    vantage_instance: str,
    vantage_project: str = DEFAULT_PROJECT,
    llm: str,
    name: str = DEFAULT_DEV_NAME,
    mem: str = "2GiB",
    cpu: str = "2",
    nested_project: str = "warden",
    timeout: float = DEV_TIMEOUT,
) -> RemoteDevResult:
    """Runs `python3 -m warden.cli dev --llm <llm> --name <name> --mem <mem> --cpu <cpu> --no-shell`
    inside `vantage_instance`. `--no-shell` matches Shape A: an unattended, scripted invocation has
    no interactive terminal to drop into anyway.
    """
    client = app.client
    argv = [
        "python3", "-m", "warden.cli", "dev",
        "--llm", llm, "--name", name, "--mem", mem, "--cpu", cpu, "--no-shell",
    ]
    result = client.exec(
        vantage_instance, argv, project=vantage_project,
        env={"PYTHONPATH": REMOTE_PYTHONPATH}, timeout=timeout,
    )
    if not result.ok:
        raise RemoteDevError(
            f"{vantage_instance}: remote `warden dev` failed (rc={result.returncode}): "
            f"{(result.stderr or result.stdout).strip()[:2000]}"
        )

    # Verify against the VM's OWN nested Incus, not the outer one — a clean exit code alone isn't
    # trusted; the container it claims to have created must actually be there.
    verify = client.exec(
        vantage_instance,
        ["incus", "list", name, "--project", nested_project, "--format", "csv", "-c", "n"],
        project=vantage_project, timeout=VERIFY_TIMEOUT,
    )
    if not verify.ok or name not in verify.stdout:
        raise RemoteDevError(
            f"{vantage_instance}: `warden dev` exited 0 but {name!r} is not running in the "
            f"nested Incus's {nested_project!r} project — not trusting the exit code alone."
        )

    return RemoteDevResult(name=name, nested_project=nested_project)
