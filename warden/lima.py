"""Lima VM lifecycle — the Mac-native analog of `vantage.py`'s `ensure_vantage_vm`, for a target
that isn't Incus-managed at the outer layer at all.

A Lima VM's own kernel is already a separate kernel from the macOS host — that's decision B's
"kernel above the container" for free, no container-in-VM nesting required. So this module has no
`mold.py` counterpart: there's no outer Incus daemon whose network/project/ACL substrate needs
converging first, and no golden-image concept to build. `ensure_lima_vm()` creates-if-absent a
persistent Lima VM; `bootstrap_incus()` installs Incus inside it via the SAME
`install-incus-nested.sh` the direct/bare-host path already uses, completely unmodified — proven to
work there already, arm64 and all (confirmed live on `vantage-mold-test`, this session).

Getting from here to a working `LimaIncusClient` (a full `IncusClient` Protocol implementation
translating every call to `limactl shell <name> -- incus ...`) is the next, separate piece — this
module only stands the VM up and gets Incus running inside it, matching the same phased,
validate-each-layer-before-building-on-it discipline the vantage-VM work used.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Callable, Optional

LIMACTL_BIN = "limactl"
DEFAULT_NAME = "warden-lima"
LIMA_TEMPLATE = "template:debian-12"
DEFAULT_CPUS = 2
DEFAULT_MEMORY_GIB = 3.0
DEFAULT_DISK_GIB = 15.0

#: `limactl start` blocks until the guest agent answers (confirmed empirically — it prints "READY."
#: itself before returning), unlike `incus launch`, which returns as soon as the instance object is
#: created and needs a separate wait-for-guest-agent poll. So there's no vantage.py-style wait_ready
#: here; the bound below is `limactl`'s own, generous for a cold image pull + first boot.
START_TIMEOUT = 300.0
SHELL_TIMEOUT = 60.0
INSTALL_TIMEOUT = 1800.0  # matches mold.py's INSTALL_TIMEOUT — same script, same real-host cost

RunFn = Callable[..., subprocess.CompletedProcess]


class LimaError(RuntimeError):
    """A step of `ensure_lima_vm`/`bootstrap_incus` failed."""


class LimaNotFoundError(RuntimeError):
    """No `limactl` binary on PATH. Lima is a user-installed prerequisite (`brew install lima`),
    the Mac-equivalent of the direct path's "provision a plain Linux VM" step — not something this
    module bootstraps for you."""

    def __init__(self, binary: str = LIMACTL_BIN):
        super().__init__(
            f"{binary!r} not found on PATH. Install Lima first (e.g. `brew install lima`) — "
            "same category as the direct path's own base-host prerequisite, outside warden's job."
        )


class LimaTimeoutError(LimaError):
    def __init__(self, argv: list[str], timeout: float):
        self.argv = argv
        self.timeout = timeout
        super().__init__(f"`{' '.join(argv)}` timed out after {timeout:g}s with no response.")


@dataclass(frozen=True)
class LimaInfo:
    name: str
    #: False when `ensure_lima_vm` found it already running (or stopped-and-restarted) and did not
    #: create a new instance — the common case after the first call.
    created: bool


def _run(
    argv: list[str], *, timeout: float, input_bytes: Optional[bytes] = None
) -> subprocess.CompletedProcess:
    if shutil.which(LIMACTL_BIN) is None:
        raise LimaNotFoundError()
    try:
        return subprocess.run(
            argv, capture_output=True, input=input_bytes,
            stdin=subprocess.DEVNULL if input_bytes is None else None,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise LimaTimeoutError(argv, timeout) from None


def _list_vms(run: RunFn = _run) -> dict[str, dict]:
    """`limactl list --json` — JSON Lines, one object per VM, not a single JSON array."""
    proc = run([LIMACTL_BIN, "list", "--json"], timeout=SHELL_TIMEOUT)
    if proc.returncode != 0:
        raise LimaError(f"limactl list failed: {proc.stderr.decode(errors='replace').strip()}")
    import json
    vms: dict[str, dict] = {}
    for line in proc.stdout.decode(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        vms[obj["name"]] = obj
    return vms


def instance_exists(name: str = DEFAULT_NAME, *, run: RunFn = _run) -> bool:
    return name in _list_vms(run=run)


def ensure_lima_vm(
    name: str = DEFAULT_NAME,
    *,
    cpus: int = DEFAULT_CPUS,
    memory_gib: float = DEFAULT_MEMORY_GIB,
    disk_gib: float = DEFAULT_DISK_GIB,
    run: RunFn = _run,
) -> LimaInfo:
    """Create-if-absent: return the existing Lima VM if one is already running (starting it first
    if it exists but is stopped), otherwise stand one up fresh from `LIMA_TEMPLATE`."""
    vms = _list_vms(run=run)
    existing = vms.get(name)
    if existing is not None:
        if existing.get("status") != "Running":
            proc = run([LIMACTL_BIN, "start", name], timeout=START_TIMEOUT)
            if proc.returncode != 0:
                raise LimaError(
                    f"{name}: failed to start existing Lima VM: "
                    f"{proc.stderr.decode(errors='replace').strip()}"
                )
        return LimaInfo(name=name, created=False)

    proc = run(
        [
            LIMACTL_BIN, "start", "-y", f"--name={name}",
            f"--cpus={cpus}", f"--memory={memory_gib}", f"--disk={disk_gib}",
            LIMA_TEMPLATE,
        ],
        timeout=START_TIMEOUT,
    )
    if proc.returncode != 0:
        raise LimaError(
            f"{name}: failed to create Lima VM: {proc.stderr.decode(errors='replace').strip()}"
        )
    return LimaInfo(name=name, created=True)


def bootstrap_incus(
    name: str, install_script: str, *, prereq_packages: tuple[str, ...], run: RunFn = _run
) -> None:
    """Install `prereq_packages` (caller passes `mold.PREREQ_PACKAGES` — reused, not duplicated, so
    this never drifts from what the vantage-VM path already decided it needs) and run
    `install_script` (the contents of `scripts/install-incus-nested.sh`, unmodified) inside the Lima
    VM. Idempotent by the script's own design (`install-incus-nested.sh` already skips the package
    step if Incus is present) — safe to call again.
    """
    prereq = run(
        [LIMACTL_BIN, "shell", name, "--",
         "sudo", "sh", "-c",
         f"DEBIAN_FRONTEND=noninteractive apt-get update -qq && "
         f"DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {' '.join(prereq_packages)}"],
        timeout=INSTALL_TIMEOUT,
    )
    if prereq.returncode != 0:
        raise LimaError(
            f"{name}: prereq install failed: {prereq.stderr.decode(errors='replace').strip()[:2000]}"
        )

    push = run(
        [LIMACTL_BIN, "shell", name, "--", "sudo", "sh", "-c",
         "cat > /tmp/install-incus-nested.sh"],
        timeout=SHELL_TIMEOUT, input_bytes=install_script.encode(),
    )
    if push.returncode != 0:
        raise LimaError(
            f"{name}: could not stage install-incus-nested.sh: "
            f"{push.stderr.decode(errors='replace').strip()}"
        )

    install = run(
        [LIMACTL_BIN, "shell", name, "--", "sudo", "bash", "/tmp/install-incus-nested.sh"],
        timeout=INSTALL_TIMEOUT,
    )
    if install.returncode != 0:
        raise LimaError(
            f"{name}: install-incus-nested.sh failed: "
            f"{install.stderr.decode(errors='replace').strip()[:2000]}"
        )
