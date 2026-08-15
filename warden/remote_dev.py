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

from warden.flavors import Flavor, resolve as resolve_flavor
from warden.profiles import (
    BRIDGE_GATEWAY,
    NESTED_BRIDGE_SUBNET_ENV_VAR,
    PROXY_PORT,
    UPSTREAM_PROXY_ENV_VAR,
)
from warden.vantage import DEFAULT_PROJECT, NESTED_BRIDGE_SUBNET

if TYPE_CHECKING:
    from warden.app import WardenApp

DEFAULT_DEV_NAME = "warden-dev"
#: Both siblings, matching deploy.py's layout - dev itself likely only needs warden/cli.py's own
#: module tree, but agentwatch costs nothing to include and matches what Shape A actually had
#: present when it ran this by hand.
REMOTE_PYTHONPATH = "/root/warden:/root/agentwatch"

#: Real-host lesson: `incus launch images:debian/12 ...` inside the vantage VM needs the NESTED
#: incusd itself to reach images.linuxcontainers.org, and mold.py's set_proxy_env doesn't cover
#: this — that sets environment.* config, which only applies to processes spawned per incus-exec
#: call, not to a persistent systemd service like the nested incusd that's been running since boot.
#: The nested daemon needs its own server-level proxy config instead (core.proxy_https/proxy_http,
#: real Incus config keys, confirmed by `incus config get` succeeding rather than erroring).
NESTED_IMAGE_HOST = "images.linuxcontainers.org"
OUTER_PROXY_HOSTPORT = f"{BRIDGE_GATEWAY}:{PROXY_PORT}"
OUTER_PROXY_URL = f"http://{OUTER_PROXY_HOSTPORT}"

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

    Before that: points the vantage VM's own nested incusd at the outer proxy (server-level config,
    not per-exec environment — see `OUTER_PROXY_URL`'s docstring) and opens the outer proxy's
    allowlist to `NESTED_IMAGE_HOST` plus `Flavor.DEV`'s own provisioning allowlist for `llm`,
    replacing whatever was there (the mold's apt-era entries are no longer relevant by the time
    this runs). Real-host lesson: with proxy chaining now working (`warden/proxy.py`), the
    container's own provisioning traffic (apt, npm, the LLM CLI install) flows through this same
    outer proxy too, not just the VM's own image fetch — narrowing this to just
    `NESTED_IMAGE_HOST` produced a fast, correct 403 the moment chaining started actually
    reaching this far. Reusing `flavors.resolve`'s own computation rather than a second,
    hand-maintained list that could drift from what the deployed container-provisioning code
    itself uses.
    """
    client = app.client
    if app.proxy_controller is not None:
        container_allowlist = resolve_flavor(Flavor.DEV, llm).provisioning_allowlist
        app.proxy_controller.set_allowlist((NESTED_IMAGE_HOST, *container_allowlist))
    proxy_cfg = client.exec(
        vantage_instance,
        ["incus", "config", "set",
         "core.proxy_https", OUTER_PROXY_URL, "core.proxy_http", OUTER_PROXY_URL],
        project=vantage_project, timeout=VERIFY_TIMEOUT,
    )
    if not proxy_cfg.ok:
        raise RemoteDevError(
            f"{vantage_instance}: could not configure the nested incusd's proxy "
            f"(core.proxy_https/proxy_http): {(proxy_cfg.stderr or proxy_cfg.stdout).strip()[:500]}"
        )

    argv = [
        "python3", "-m", "warden.cli", "dev",
        "--llm", llm, "--name", name, "--mem", mem, "--cpu", cpu, "--no-shell",
    ]
    # NESTED_BRIDGE_SUBNET travels with this exec too — the deployed warden code's own
    # ensure_substrate() would otherwise converge the nested wardenbr0 back to profiles.py's
    # default (the outer subnet), silently re-creating the collision the mold's install already
    # avoided (phase 5 real-host incident #1). UPSTREAM_PROXY does too — without it, the nested
    # `warden dev`'s own proxy (serving the container it creates) tries direct connections to
    # every target, which the outer ACL blocks; the request hangs until TCP gives up rather than
    # failing fast (phase 5 real-host incident #2, confirmed empirically: 522s before a 502).
    result = client.exec(
        vantage_instance, argv, project=vantage_project,
        env={
            "PYTHONPATH": REMOTE_PYTHONPATH,
            NESTED_BRIDGE_SUBNET_ENV_VAR: NESTED_BRIDGE_SUBNET,
            UPSTREAM_PROXY_ENV_VAR: OUTER_PROXY_HOSTPORT,
        },
        timeout=timeout,
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
