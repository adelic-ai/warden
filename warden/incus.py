"""The one seam between warden's logic and a real Incus daemon.

`IncusClient` is the interface every other module programs against.
`RealIncusClient` shells out to the `incus` CLI. `tests/fakes.py:FakeIncusClient`
is an in-memory model of the same interface used in tests — see
DECISIONS.md ("Dependency injection over subprocess mocking").
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


class IncusCommandError(RuntimeError):
    """An `incus` invocation failed for a reason other than "doesn't exist"."""

    def __init__(self, argv: list[str], returncode: int, stderr: str):
        self.argv = argv
        self.returncode = returncode
        self.stderr = stderr
        super().__init__(f"`{' '.join(argv)}` exited {returncode}: {stderr.strip()}")


class IncusNotFoundError(RuntimeError):
    """No `incus` binary on PATH — a clear, actionable failure instead of
    a raw FileNotFoundError traceback. See NEEDS-HUMAN.md and
    scripts/install-incus-nested.sh."""

    def __init__(self, binary: str):
        super().__init__(
            f"{binary!r} not found on PATH. Incus isn't installed here — see "
            "NEEDS-HUMAN.md and scripts/install-incus-nested.sh (needs root)."
        )


@dataclass(frozen=True)
class ExecResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


@runtime_checkable
class IncusClient(Protocol):
    """Everything `warden` needs from an Incus host. Kept intentionally
    narrow — add a method here only when a real caller needs it."""

    # -- existence / idempotency -----------------------------------------
    def project_exists(self, name: str) -> bool: ...
    def profile_exists(self, name: str, project: str) -> bool: ...
    def network_exists(self, name: str) -> bool: ...
    def instance_exists(self, name: str, project: str) -> bool: ...
    def snapshot_exists(self, name: str, snapshot: str, project: str) -> bool: ...
    def storage_pool_exists(self, name: str) -> bool: ...

    # -- create / define ----------------------------------------------------
    def project_create(self, name: str, config: dict[str, str]) -> None: ...
    def profile_create(
        self, name: str, project: str, config: dict[str, str], devices: dict[str, dict]
    ) -> None: ...
    def network_create(self, name: str, config: dict[str, str]) -> None: ...
    def storage_pool_create(self, name: str, driver: str = "btrfs") -> None: ...
    def launch(
        self, image: str, name: str, project: str, profile: str
    ) -> None: ...

    # -- convergence: project / network / profile-device settings ------------
    def project_set(self, name: str, key: str, value: str) -> None: ...
    def project_unset(self, name: str, key: str) -> None: ...
    def network_set(self, name: str, key: str, value: str) -> None: ...
    def profile_device_set(
        self, profile: str, project: str, device: str, key: str, value: str
    ) -> None: ...

    # -- network ACLs (the egress enforcement point) -------------------------
    def network_acl_get(self, name: str) -> dict | None: ...
    def network_acl_put(self, name: str, document: dict) -> None: ...

    # -- instance config / lifecycle ----------------------------------------
    def config_get(self, name: str, key: str, project: str = "default") -> str: ...
    def config_set(self, name: str, key: str, value: str, project: str = "default") -> None: ...
    def exec(
        self,
        name: str,
        argv: list[str],
        project: str = "default",
        env: dict[str, str] | None = None,
    ) -> ExecResult: ...
    def file_push(
        self, name: str, content: bytes, remote_path: str, project: str = "default"
    ) -> None: ...
    def snapshot(self, name: str, snapshot: str, project: str = "default") -> None: ...
    def restore(self, name: str, snapshot: str, project: str = "default") -> None: ...
    def delete(self, name: str, project: str = "default") -> None: ...
    def list_instances(self, project: str) -> list[str]: ...


class RealIncusClient:
    """Subprocess-backed `IncusClient` for a real `incus` install."""

    def __init__(self, binary: str = "incus"):
        self._bin = binary

    def _run(self, args: list[str], *, input_bytes: bytes | None = None) -> subprocess.CompletedProcess:
        argv = [self._bin, *args]
        try:
            return subprocess.run(
                argv, capture_output=True, input=input_bytes,
                text=input_bytes is None,
            )
        except FileNotFoundError:
            raise IncusNotFoundError(self._bin) from None

    def _run_ok(self, args: list[str], *, input_bytes: bytes | None = None) -> subprocess.CompletedProcess:
        proc = self._run(args, input_bytes=input_bytes)
        if proc.returncode != 0:
            stderr = proc.stderr if isinstance(proc.stderr, str) else proc.stderr.decode(errors="replace")
            raise IncusCommandError([self._bin, *args], proc.returncode, stderr)
        return proc

    # -- existence ------------------------------------------------------
    def project_exists(self, name: str) -> bool:
        return self._run(["project", "show", name]).returncode == 0

    def profile_exists(self, name: str, project: str) -> bool:
        return self._run(["profile", "show", name, "--project", project]).returncode == 0

    def network_exists(self, name: str) -> bool:
        return self._run(["network", "show", name]).returncode == 0

    def instance_exists(self, name: str, project: str) -> bool:
        return self._run(["config", "show", name, "--project", project]).returncode == 0

    def snapshot_exists(self, name: str, snapshot: str, project: str) -> bool:
        return self._run(
            ["config", "show", f"{name}/{snapshot}", "--project", project]
        ).returncode == 0

    def storage_pool_exists(self, name: str) -> bool:
        return self._run(["storage", "show", name]).returncode == 0

    # -- create -----------------------------------------------------------
    def project_create(self, name: str, config: dict[str, str]) -> None:
        self._run_ok(["project", "create", name])
        for key, value in config.items():
            self._run_ok(["project", "set", name, key, value])

    def storage_pool_create(self, name: str, driver: str = "btrfs") -> None:
        self._run_ok(["storage", "create", name, driver])

    # -- convergence ---------------------------------------------------------
    def project_set(self, name: str, key: str, value: str) -> None:
        self._run_ok(["project", "set", name, key, value])

    def project_unset(self, name: str, key: str) -> None:
        self._run_ok(["project", "unset", name, key])

    def network_set(self, name: str, key: str, value: str) -> None:
        self._run_ok(["network", "set", name, key, value])

    def profile_device_set(
        self, profile: str, project: str, device: str, key: str, value: str
    ) -> None:
        self._run_ok(
            ["profile", "device", "set", profile, device, f"{key}={value}", "--project", project]
        )

    # -- network ACLs ---------------------------------------------------------
    def network_acl_get(self, name: str) -> dict | None:
        proc = self._run(["query", f"/1.0/network-acls/{name}"])
        if proc.returncode != 0:
            return None
        try:
            return json.loads(proc.stdout)
        except json.JSONDecodeError:
            return None

    def network_acl_put(self, name: str, document: dict) -> None:
        """Create the ACL if absent, then push the whole document.

        `incus network acl edit` takes YAML on stdin, and JSON is valid
        YAML — so one `edit` converges the entire rule set rather than
        accumulating `rule add`s that can never be un-added idempotently.
        """
        if self.network_acl_get(name) is None:
            self._run_ok(["network", "acl", "create", name])
        self._run_ok(["network", "acl", "edit", name], input_bytes=json.dumps(document).encode())

    def profile_create(
        self, name: str, project: str, config: dict[str, str], devices: dict[str, dict]
    ) -> None:
        self._run_ok(["profile", "create", name, "--project", project])
        for key, value in config.items():
            self._run_ok(["profile", "set", name, key, value, "--project", project])
        for dev_name, dev in devices.items():
            args = ["profile", "device", "add", name, dev_name, dev["type"], "--project", project]
            for k, v in dev.items():
                if k == "type":
                    continue
                args.append(f"{k}={v}")
            self._run_ok(args)

    def network_create(self, name: str, config: dict[str, str]) -> None:
        args = ["network", "create", name, "--type=bridge"]
        for key, value in config.items():
            args.append(f"{key}={value}")
        self._run_ok(args)

    def launch(self, image: str, name: str, project: str, profile: str) -> None:
        self._run_ok([
            "launch", image, name,
            "--project", project,
            "--profile", profile,
        ])

    # -- instance ops -----------------------------------------------------
    def config_get(self, name: str, key: str, project: str = "default") -> str:
        proc = self._run_ok(["config", "get", name, key, "--project", project])
        return proc.stdout.strip()

    def config_set(self, name: str, key: str, value: str, project: str = "default") -> None:
        self._run_ok(["config", "set", name, key, value, "--project", project])

    def exec(
        self,
        name: str,
        argv: list[str],
        project: str = "default",
        env: dict[str, str] | None = None,
    ) -> ExecResult:
        cmd = ["exec", name, "--project", project]
        for k, v in (env or {}).items():
            cmd += ["--env", f"{k}={v}"]
        cmd += ["--", *argv]
        proc = self._run(cmd)
        return ExecResult(proc.returncode, proc.stdout, proc.stderr)

    def file_push(
        self, name: str, content: bytes, remote_path: str, project: str = "default"
    ) -> None:
        self._run_ok(
            ["file", "push", "-", f"{name}/{remote_path}", "--project", project],
            input_bytes=content,
        )

    def snapshot(self, name: str, snapshot: str, project: str = "default") -> None:
        self._run_ok(["snapshot", "create", name, snapshot, "--project", project])

    def restore(self, name: str, snapshot: str, project: str = "default") -> None:
        self._run_ok(["snapshot", "restore", name, snapshot, "--project", project])

    def delete(self, name: str, project: str = "default") -> None:
        self._run(["stop", name, "--project", project, "--force"])
        self._run_ok(["delete", name, "--project", project])

    def list_instances(self, project: str) -> list[str]:
        proc = self._run_ok(["list", "--project", project, "--format", "json"])
        return [item["name"] for item in json.loads(proc.stdout)]
