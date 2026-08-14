"""The one seam between warden's logic and a real Incus daemon.

`IncusClient` is the interface every other module programs against.
`RealIncusClient` shells out to the `incus` CLI. `tests/fakes.py:FakeIncusClient`
is an in-memory model of the same interface used in tests — see
DECISIONS.md ("Dependency injection over subprocess mocking").
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from warden.privilege import elevate

# Every `incus` invocation is bounded. The validation run caught the reason:
# an `incus launch` client sat for 25 minutes while the daemon had in fact
# already created and started the instance — the client simply never stopped
# waiting for its response. Nothing in `warden up` could notice, because a
# subprocess with no timeout has no failure mode, only an absence of progress.
#
# The values differ per operation because the honest bound does: a metadata
# read that takes a minute is broken, while `apt-get install` through the
# allowlist proxy legitimately takes several. They are deliberately generous —
# this is a stuck-forever backstop, not a latency SLO. Anything tighter would
# start failing slow-but-working runs, which is the more expensive mistake.
QUERY_TIMEOUT = 60.0       # show/get/set/list/acl — metadata, should be instant
LIFECYCLE_TIMEOUT = 600.0  # snapshot, restore, delete, file push
LAUNCH_TIMEOUT = 900.0     # may include an image download
EXEC_TIMEOUT = 1800.0      # apt-get / git clone inside the guest, via the proxy


class IncusCommandError(RuntimeError):
    """An `incus` invocation failed for a reason other than "doesn't exist"."""

    def __init__(self, argv: list[str], returncode: int, stderr: str):
        self.argv = argv
        self.returncode = returncode
        self.stderr = stderr
        super().__init__(f"`{' '.join(argv)}` exited {returncode}: {stderr.strip()}")


class IncusTimeoutError(IncusCommandError):
    """An `incus` invocation was still running when its bound expired.

    Deliberately a subclass of `IncusCommandError` so that every existing
    handler — `warden up`'s error path, `_wait_ready`'s retry loop — treats a
    hang as the failure it is, with no new call sites needed.

    **A timeout means "we stopped waiting", not "it did not happen."** Killing
    the `incus` client does not cancel the operation on the daemon: the run
    that motivated this bound had the instance created, started and running
    while its client hung. So this must never be swallowed into a False by an
    existence check — a timed-out `project_exists` reporting "absent" would
    send warden off to recreate something that already exists, which is the
    confident-wrong-answer shape this build keeps having to dig out.

    Recovery is a re-run: `up` is idempotent and re-derives rather than
    assuming, so it converges on whatever the daemon actually did.
    """

    def __init__(self, argv: list[str], timeout: float):
        self.timeout = timeout
        super().__init__(
            argv,
            124,  # conventional shell timeout status
            f"timed out after {timeout:g}s with no response. The operation may still have "
            f"completed on the daemon — re-run to converge rather than assuming it did not.",
        )


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
        self, image: str, name: str, project: str, profile: str, instance_type: str = "container"
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
        timeout: float = EXEC_TIMEOUT,
    ) -> ExecResult: ...
    def file_push(
        self, name: str, content: bytes, remote_path: str, project: str = "default"
    ) -> None: ...
    def file_pull(self, name: str, remote_path: str, project: str = "default") -> bytes: ...
    def snapshot(self, name: str, snapshot: str, project: str = "default") -> None: ...
    def restore(self, name: str, snapshot: str, project: str = "default") -> None: ...
    def delete(self, name: str, project: str = "default") -> None: ...
    def list_instances(self, project: str) -> list[str]: ...
    def stop(self, name: str, project: str = "default", force: bool = False) -> None: ...
    # -- image publishing (VANTAGE-PLAN.md phase 2, the mold) ---------------
    def image_exists(self, alias: str, project: str = "default") -> bool: ...
    def publish(self, name: str, alias: str, project: str = "default") -> str: ...
    # -- operational recovery (warden/recover.py) --
    def responsive(self, timeout: float = QUERY_TIMEOUT) -> bool: ...
    def operations(self) -> list[dict]: ...
    def operation_delete(self, op_id: str) -> None: ...
    def restart(self, name: str, project: str = "default", force: bool = False) -> None: ...


class RealIncusClient:
    """Subprocess-backed `IncusClient` for a real `incus` install."""

    def __init__(self, binary: str = "incus"):
        self._bin = binary

    def _run(
        self,
        args: list[str],
        *,
        input_bytes: bytes | None = None,
        timeout: float = QUERY_TIMEOUT,
    ) -> subprocess.CompletedProcess:
        # Checked before the elevation prefix goes on, not after. With `sudo -n incus …` the
        # process that actually launches is `sudo`, which exists — so a missing `incus` comes back
        # as sudo's own rc=1 "command not found" rather than a FileNotFoundError, and the clear
        # "Incus isn't installed here, see install-incus-nested.sh" message was silently replaced
        # by an opaque exit code the moment elevation was introduced.
        if shutil.which(self._bin) is None:
            raise IncusNotFoundError(self._bin)
        argv = elevate([self._bin, *args])
        try:
            return subprocess.run(
                argv, capture_output=True, input=input_bytes,
                text=input_bytes is None, timeout=timeout,
            )
        except FileNotFoundError:
            raise IncusNotFoundError(self._bin) from None
        except subprocess.TimeoutExpired:
            # subprocess.run has already killed and reaped the client. Raising
            # (rather than returning a non-zero result) is load-bearing: the
            # existence checks below read `.returncode`, so a returned timeout
            # would quietly become "doesn't exist". See IncusTimeoutError.
            raise IncusTimeoutError(argv, timeout) from None

    def _run_ok(
        self,
        args: list[str],
        *,
        input_bytes: bytes | None = None,
        timeout: float = QUERY_TIMEOUT,
    ) -> subprocess.CompletedProcess:
        proc = self._run(args, input_bytes=input_bytes, timeout=timeout)
        if proc.returncode != 0:
            stderr = proc.stderr if isinstance(proc.stderr, str) else proc.stderr.decode(errors="replace")
            # The elevated argv, so the message is the command that actually ran.
            raise IncusCommandError(elevate([self._bin, *args]), proc.returncode, stderr)
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
        self._run_ok(["storage", "create", name, driver], timeout=LIFECYCLE_TIMEOUT)

    # -- convergence ---------------------------------------------------------
    def project_set(self, name: str, key: str, value: str) -> None:
        self._run_ok(["project", "set", name, key, value])

    def project_unset(self, name: str, key: str) -> None:
        self._run_ok(["project", "unset", name, key])

    def network_set(self, name: str, key: str, value: str) -> None:
        # `key=value`, not `key value`: Incus 7.x warns the space-separated
        # form is deprecated, and `ensure_substrate` now calls this on every
        # `up` to converge the bridge subnet — a call site that has to keep
        # working. `profile_device_set` already used the supported form.
        self._run_ok(["network", "set", name, f"{key}={value}"])

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

    def launch(
        self, image: str, name: str, project: str, profile: str, instance_type: str = "container"
    ) -> None:
        # The long bound is the image download; the bound existing at all is
        # the hung-client hang this whole mechanism exists for.
        if instance_type not in ("container", "virtual-machine"):
            raise ValueError(f"unknown instance_type {instance_type!r}")
        args = ["launch", image, name, "--project", project, "--profile", profile]
        if instance_type == "virtual-machine":
            args.append("--vm")
        self._run_ok(args, timeout=LAUNCH_TIMEOUT)

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
        timeout: float = EXEC_TIMEOUT,
    ) -> ExecResult:
        """Run a command in the guest. `timeout` bounds the whole call.

        The default is long because provisioning genuinely is: `apt-get
        install` through the allowlist proxy took minutes on the validation
        host. Callers polling for a condition should pass something far
        shorter — a probe inside a retry loop must not be able to outlive the
        loop's own deadline.
        """
        cmd = ["exec", name, "--project", project]
        for k, v in (env or {}).items():
            cmd += ["--env", f"{k}={v}"]
        cmd += ["--", *argv]
        proc = self._run(cmd, timeout=timeout)
        return ExecResult(proc.returncode, proc.stdout, proc.stderr)

    def file_push(
        self, name: str, content: bytes, remote_path: str, project: str = "default"
    ) -> None:
        self._run_ok(
            ["file", "push", "-", f"{name}/{remote_path}", "--project", project],
            input_bytes=content,
            timeout=LIFECYCLE_TIMEOUT,
        )

    def file_pull(self, name: str, remote_path: str, project: str = "default") -> bytes:
        """Read a file out of the instance, as **bytes**.

        Bytes, not text, because `export` pulls a tar of the built repo through
        here and a text-mode decode would corrupt it silently — the worst
        available failure for an artifact whose whole job is to be verbatim.

        `FileNotFoundError` for an absent guest path, so a caller can tell
        "the agent produced no transcript" from "the pull broke", which are
        very different things to report.
        """
        if shutil.which(self._bin) is None:
            raise IncusNotFoundError(self._bin)
        argv = elevate([self._bin, "file", "pull", f"{name}/{remote_path}", "-", "--project", project])
        try:
            proc = subprocess.run(argv, capture_output=True, timeout=LIFECYCLE_TIMEOUT)
        except FileNotFoundError:
            raise IncusNotFoundError(self._bin) from None
        except subprocess.TimeoutExpired:
            raise IncusTimeoutError(argv, LIFECYCLE_TIMEOUT) from None
        if proc.returncode != 0:
            stderr = proc.stderr.decode(errors="replace")
            if "not found" in stderr.lower() or "no such file" in stderr.lower():
                raise FileNotFoundError(f"{name}:{remote_path}")
            raise IncusCommandError(argv, proc.returncode, stderr)
        return proc.stdout

    def snapshot(self, name: str, snapshot: str, project: str = "default") -> None:
        self._run_ok(
            ["snapshot", "create", name, snapshot, "--project", project],
            timeout=LIFECYCLE_TIMEOUT,
        )

    def restore(self, name: str, snapshot: str, project: str = "default") -> None:
        # A restore stops and restarts the container, so it is a lifecycle
        # operation's worth of work, not a metadata write.
        self._run_ok(
            ["snapshot", "restore", name, snapshot, "--project", project],
            timeout=LIFECYCLE_TIMEOUT,
        )

    def delete(self, name: str, project: str = "default") -> None:
        self._run(["stop", name, "--project", project, "--force"], timeout=LIFECYCLE_TIMEOUT)
        self._run_ok(["delete", name, "--project", project], timeout=LIFECYCLE_TIMEOUT)

    def list_instances(self, project: str) -> list[str]:
        proc = self._run_ok(["list", "--project", project, "--format", "json"])
        return [item["name"] for item in json.loads(proc.stdout)]

    def stop(self, name: str, project: str = "default", force: bool = False) -> None:
        argv = ["stop", name, "--project", project]
        if force:
            argv.append("--force")
        self._run_ok(argv, timeout=LIFECYCLE_TIMEOUT)

    # -- image publishing (VANTAGE-PLAN.md phase 2, the mold) -----------------
    def image_exists(self, alias: str, project: str = "default") -> bool:
        proc = self._run_ok(["image", "list", alias, "--project", project, "--format", "json"])
        return len(json.loads(proc.stdout or "[]")) > 0

    def publish(self, name: str, alias: str, project: str = "default") -> str:
        """Publish a (stopped) instance to a local image under `alias`. Returns the fingerprint —
        `incus publish`'s own success line is "Instance published with fingerprint: <hash>"; parsed
        rather than trusted to a fixed column position, and falls back to the raw line if the
        format ever drifts (same dialect-tolerance principle as auditd.py's parsing)."""
        proc = self._run_ok(
            ["publish", name, "--project", project, "--alias", alias], timeout=LIFECYCLE_TIMEOUT
        )
        stdout = proc.stdout.strip()
        marker = "fingerprint:"
        if marker in stdout:
            return stdout.rsplit(marker, 1)[1].strip()
        return stdout

    # -- operational recovery (see warden/recover.py) ------------------------
    def responsive(self, timeout: float = QUERY_TIMEOUT) -> bool:
        """Did the daemon answer a cheap bounded query? A timeout here is the L3 signal — the daemon
        itself is wedged, not one instance — so this returns False rather than raising, letting the
        recovery path branch on it. Every other failure still raises (a wedged daemon is not the
        same as a broken one, and only the timeout means 'unresponsive')."""
        try:
            self._run(["project", "list", "--format", "csv"], timeout=timeout)
            return True
        except IncusTimeoutError:
            return False

    def operations(self) -> list[dict]:
        proc = self._run_ok(["operation", "list", "--format", "json"])
        return json.loads(proc.stdout or "[]")

    def operation_delete(self, op_id: str) -> None:
        self._run_ok(["operation", "delete", op_id])

    def restart(self, name: str, project: str = "default", force: bool = False) -> None:
        argv = ["restart", name, "--project", project]
        if force:
            argv.append("--force")
        self._run_ok(argv, timeout=LIFECYCLE_TIMEOUT)
