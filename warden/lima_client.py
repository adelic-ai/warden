"""`LimaIncusClient` — a full `IncusClient` Protocol implementation backed by an Incus daemon
running inside a Lima VM instead of locally, for the Mac/no-nesting path (`warden/lima.py`).

Subclasses `RealIncusClient` and overrides only the one seam it funnels every subprocess call
through (`_run`), plus the two methods that bypass it (`_run_ok`, which needs the corrected argv
for its own error messages, and `file_pull`, the one Protocol method `RealIncusClient` never routes
through `_run` at all). Every other Protocol method — `project_create`, `launch`, `exec`, `snapshot`,
`restore`, `delete`, `list_instances`, ~26 of them — is inherited completely unchanged, because
they're all already built purely on top of `_run`/`_run_ok`. That's the same "one seam" property
`DECISIONS.md` names as the whole reason `IncusClient` is a Protocol at all, one level deeper: the
seam inside `RealIncusClient` itself turns out to be just as reusable as the Protocol boundary above
it.
"""
from __future__ import annotations

import shutil
import subprocess
from typing import Optional

from warden.incus import (
    LIFECYCLE_TIMEOUT,
    QUERY_TIMEOUT,
    IncusCommandError,
    IncusNotFoundError,
    IncusTimeoutError,
    RealIncusClient,
)
from warden.lima import LIMACTL_BIN
from warden.privilege import SUDO


class LimaIncusClient(RealIncusClient):
    def __init__(self, vm_name: str, *, binary: str = "incus"):
        super().__init__(binary=binary)
        self._vm_name = vm_name

    def _shell_argv(self, args: list[str]) -> list[str]:
        # `limactl shell` drops you in as the VM's configured default user, not root — unlike
        # `incus exec` into a container/VM, which already IS root. So `sudo` is needed here, and
        # `-n` for the same reason `warden.privilege.SUDO` exists everywhere else: a hands-off run
        # that blocks on a password is a hang with no output, not a fast, clear failure.
        return [LIMACTL_BIN, "shell", self._vm_name, "--", *SUDO, self._bin, *args]

    def _run(
        self, args: list[str], *, input_bytes: Optional[bytes] = None, timeout: float = QUERY_TIMEOUT
    ) -> subprocess.CompletedProcess:
        # Pre-flight checks `limactl`, not `incus` — `incus` lives inside the VM, not on this Mac,
        # so a local `which incus` would always fail here regardless of whether the VM is fine. A
        # missing `incus` INSIDE the VM (never bootstrapped) surfaces as a normal non-zero exit from
        # the shell call instead, same as any other command failure.
        if shutil.which(LIMACTL_BIN) is None:
            raise IncusNotFoundError(LIMACTL_BIN)
        argv = self._shell_argv(args)
        try:
            return subprocess.run(
                argv, capture_output=True, input=input_bytes,
                stdin=subprocess.DEVNULL if input_bytes is None else None,
                text=input_bytes is None, timeout=timeout,
            )
        except FileNotFoundError:
            raise IncusNotFoundError(LIMACTL_BIN) from None
        except subprocess.TimeoutExpired:
            raise IncusTimeoutError(argv, timeout) from None

    def _run_ok(
        self, args: list[str], *, input_bytes: Optional[bytes] = None, timeout: float = QUERY_TIMEOUT
    ) -> subprocess.CompletedProcess:
        proc = self._run(args, input_bytes=input_bytes, timeout=timeout)
        if proc.returncode != 0:
            stderr = proc.stderr if isinstance(proc.stderr, str) else proc.stderr.decode(errors="replace")
            # The argv that actually ran (limactl shell ... -- sudo incus ...), not RealIncusClient's
            # own elevate([...]) reconstruction — the parent's version would show the wrong command.
            raise IncusCommandError(self._shell_argv(args), proc.returncode, stderr)
        return proc

    def file_pull(self, name: str, remote_path: str, project: str = "default") -> bytes:
        if shutil.which(LIMACTL_BIN) is None:
            raise IncusNotFoundError(LIMACTL_BIN)
        argv = self._shell_argv(["file", "pull", f"{name}/{remote_path}", "-", "--project", project])
        try:
            proc = subprocess.run(
                argv, capture_output=True, stdin=subprocess.DEVNULL, timeout=LIFECYCLE_TIMEOUT
            )
        except FileNotFoundError:
            raise IncusNotFoundError(LIMACTL_BIN) from None
        except subprocess.TimeoutExpired:
            raise IncusTimeoutError(argv, LIFECYCLE_TIMEOUT) from None
        if proc.returncode != 0:
            stderr = proc.stderr.decode(errors="replace")
            if "not found" in stderr.lower() or "no such file" in stderr.lower():
                raise FileNotFoundError(f"{name}:{remote_path}")
            raise IncusCommandError(argv, proc.returncode, stderr)
        return proc.stdout
