"""VM-root build spec + profile — the narrow real-kernel-privilege escape hatch
(ROADMAP step 4: `~/dev/cagetheagent/ROADMAP.md`).

Deliberately NOT a `Flavor`/`FlavorSpec` (see flavors.py). Those exist for the
container path `WardenApp.up()` drives: derive_idmap -> assert_unprivileged ->
wire_auditd, the unforgeable-audit trust model made concrete. A VM-root build has
to skip all three (no idmap on a VM; it is genuinely privileged, so
assert_unprivileged would be a lie; there is no in-guest audit to trust) — three
conditional skips of `up()`'s core wouldn't be reuse, they'd be `up()` pretending
two opposite trust models are one flavor. A separate spec/orchestration path keeps
the trust boundary structural instead of hidden behind branches.

**Not zero unforgeable signal.** The VM's NIC rides the same warden bridge, under
the same `security.acls` ACL (profiles.py/egress.py) that already governs every
container — enforced at the bridge, outside the guest kernel entirely. A VM-root
build can tamper its own in-guest audit but cannot tamper what the external proxy
logged it tried to reach. Governance for this path is output-verification (the
build's artifacts, once collected) **plus** that external egress log — never
output-verification alone.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Iterable, Optional

from warden.config import resolve_llm_auth
from warden.egress import ACL_NAME as EGRESS_ACL_NAME
from warden.flavors import BUILDER_REGISTRIES, DEBIAN_SETUP, LLM_ENDPOINTS, NODE_SETUP
from warden.incus import EXEC_TIMEOUT, ExecResult, IncusCommandError, IncusTimeoutError
from warden.profiles import (
    BRIDGE_GATEWAY,
    BRIDGE_NAME,
    PROXY_PORT,
    STORAGE_POOL,
    ProfileSpec,
    validate_no_host_mounts,
)

if TYPE_CHECKING:
    from warden.app import WardenApp

IMAGE = "images:debian/12"
#: Everything a build touches lives here, mirroring workload.py's RUN_DIR convention — one place,
#: so a caller (or a future `export`-style verb) has one path to look under.
BUILD_DIR = "/root/build"
#: The build script's contract: whatever it wants verified must land here. `submit_build` tars
#: exactly this directory — nothing outside it is collected.
BUILD_OUT_DIR = f"{BUILD_DIR}/out"
BUILD_SECRET_PATH = f"{BUILD_DIR}/llm.key"
BUILD_SCRIPT_PATH = f"{BUILD_DIR}/build.sh"
ARTIFACT_TAR_PATH = f"{BUILD_DIR}/artifacts.tar.gz"
DEFAULT_BUILD_WALL_CLOCK_SECONDS = 3600.0


@dataclass(frozen=True)
class BuildVmSpec:
    name: str
    llm: str
    provisioning_allowlist: tuple[str, ...]
    runtime_allowlist: tuple[str, ...]


def resolve(llm: str, extra_allow: Iterable[str] = ()) -> BuildVmSpec:
    """Same allowlist shape as `flavors.resolve(Flavor.BUILDER, ...)` — a build
    needs the same registries/setup hosts a container builder does. What differs
    is everything *after* provisioning: no idmap, no auditd, no snapshot/restore —
    this spec carries only what egress needs to know."""
    if llm not in LLM_ENDPOINTS:
        raise ValueError(f"unknown llm {llm!r}; expected one of {tuple(LLM_ENDPOINTS)}")
    llm_hosts = LLM_ENDPOINTS[llm]
    extra = tuple(extra_allow)
    provisioning = tuple(sorted(
        set(DEBIAN_SETUP) | set(NODE_SETUP) | set(BUILDER_REGISTRIES) | set(llm_hosts) | set(extra)
    ))
    runtime = tuple(sorted(set(BUILDER_REGISTRIES) | set(llm_hosts) | set(extra)))
    return BuildVmSpec(
        name="build-vm",
        llm=llm,
        provisioning_allowlist=provisioning,
        runtime_allowlist=runtime,
    )


def build_vm_profile(
    *,
    mem: str = "4GiB",
    cpu: str = "2",
    pool: str = STORAGE_POOL,
    bridge: str = BRIDGE_NAME,
    acl: str = EGRESS_ACL_NAME,
) -> ProfileSpec:
    """No `security.privileged`/`security.nesting`/`security.idmap.isolated` —
    those are container idmap/nesting knobs and do not apply to a VM (a VM owns
    its own kernel; there is no host user-namespace mapping to isolate). The NIC
    device is identical to a container's: the ACL is bridge-level, so it governs
    a VM's egress exactly the way it governs a container's, with no VM-specific
    code needed to make that true.
    """
    devices = {
        "root": {"type": "disk", "pool": pool, "path": "/"},
        "eth0": {"type": "nic", "network": bridge, "security.acls": acl},
    }
    validate_no_host_mounts(devices)
    config = {
        "limits.memory": mem,
        "limits.cpu": cpu,
    }
    return ProfileSpec(name="warden-build-vm", config=config, devices=devices)


class BuildVmError(RuntimeError):
    """A step of `submit_build` failed outside the build script itself — launch, staging, teardown.

    Mirrors `workload.WorkloadError`: never raised for a non-zero *build* exit. A build that fails
    at its task still produced output worth collecting, and `BuildResult.ok` is how a caller reads
    that outcome — this exception is only for warden's own orchestration breaking."""


@dataclass(frozen=True)
class BuildResult:
    """What `submit_build` hands back — the product for the output-verifier (ROADMAP step 4) to
    judge, plus the description (never the content) of where any injected secret came from.

    No idmap fields, unlike `workload.RunManifest`: a VM-root build has none to record. Governance
    for what's in here is the caller's job — this type's contract ends at "here is what came out,
    and here is what the external egress log would separately show it tried to reach."
    """

    instance: str
    project: str
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool
    started_at: float
    ended_at: float
    secret_source: Optional[str]
    #: tar.gz bytes of BUILD_OUT_DIR, or None if the build produced nothing there.
    artifacts: Optional[bytes]

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


class BuildVmRunner:
    """Spins a fresh VM-root sibling, runs a build hands-off, collects its output, tears the VM
    down — one atomic dispatch (`submit_build`), not a multi-verb lifecycle like the container path
    (`up`/`run`/`report`/`down`). A VM-root build has no idmap/auditd to converge across separate
    calls, so there is nothing for a separate `up` verb to do here.

    Delegates substrate setup to `WardenApp.ensure_build_vm_substrate` — the pool/project/network/
    ACL are identical to the container path's; only the profile differs. Composition, not
    inheritance: this class owns everything that's genuinely different about a VM-root build
    (`--vm` launch, no idmap, artifact collection), and nothing more.
    """

    PROBE_TIMEOUT = 15.0
    #: Longer than app.py's 60s container bound — a VM's firmware+kernel boot is slower than a
    #: container's namespace start.
    WAIT_READY_TIMEOUT = 120.0

    def __init__(self, app: "WardenApp"):
        self.app = app
        self.client = app.client

    # -- helpers (instance/project directly — a VM-root build has no WardenConfig/FlavorSpec) ------
    def _exec_ok(
        self, instance: str, project: str, argv: list[str], what: str, timeout: float = EXEC_TIMEOUT
    ) -> ExecResult:
        result = self.client.exec(instance, argv, project=project, timeout=timeout)
        if not result.ok:
            raise BuildVmError(
                f"{instance}: {what} failed (rc={result.returncode}): "
                f"{(result.stderr or result.stdout).strip()[:2000]}"
            )
        return result

    def _wait_ready(self, instance: str, project: str) -> None:
        deadline = time.monotonic() + self.WAIT_READY_TIMEOUT
        last = ""
        while time.monotonic() < deadline:
            try:
                if self.client.exec(
                    instance, ["/bin/true"], project=project, timeout=self.PROBE_TIMEOUT
                ).ok:
                    return
            except IncusCommandError as exc:  # pragma: no cover - timing dependent
                last = str(exc)
            time.sleep(1.0)
        raise BuildVmError(f"{instance}: not ready within {self.WAIT_READY_TIMEOUT}s {last}")

    def _set_proxy_env(self, instance: str, project: str) -> None:
        url = f"http://{BRIDGE_GATEWAY}:{PROXY_PORT}"
        for key in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
            self.client.config_set(instance, f"environment.{key}", url, project=project)
        self.client.config_set(
            instance, "environment.no_proxy", f"127.0.0.1,localhost,{BRIDGE_GATEWAY}", project=project
        )

    def _collect_artifacts(self, instance: str, project: str) -> Optional[bytes]:
        """tar.gz of BUILD_OUT_DIR, via a staged file + `file_pull` — the same pattern export.py
        uses, and for the same reason: `file_pull` reads bytes, never text-decodes, so a binary
        tarball survives the trip intact. An empty/missing BUILD_OUT_DIR returns None rather than
        raising: a build that produced nothing there is a legitimate outcome for the output-verifier
        to see, not a warden-internal failure."""
        check = self.client.exec(
            instance, ["sh", "-c", f'[ -n "$(ls -A {BUILD_OUT_DIR} 2>/dev/null)" ]'], project=project
        )
        if not check.ok:
            return None
        self._exec_ok(
            instance, project,
            ["sh", "-c", f"tar -czf {ARTIFACT_TAR_PATH} -C {BUILD_OUT_DIR} ."],
            "tar build output",
        )
        try:
            return self.client.file_pull(instance, ARTIFACT_TAR_PATH, project=project)
        except FileNotFoundError:
            return None

    # -- the dispatch ---------------------------------------------------------------------------
    def submit_build(
        self,
        *,
        spec: BuildVmSpec,
        instance: str,
        project: str,
        build_script: str,
        secret_file: Optional[Path] = None,
        mem: str = "4GiB",
        cpu: str = "2",
        wall_clock_seconds: float = DEFAULT_BUILD_WALL_CLOCK_SECONDS,
        teardown: bool = True,
        _now=time.time,
    ) -> BuildResult:
        """Spin a fresh VM-root sibling, run `build_script` hands-off, collect BUILD_OUT_DIR as
        artifacts, tear the VM down (unless `teardown=False`, for debugging a failed dispatch).

        `build_script` must itself populate BUILD_OUT_DIR — what "done" means for a given build is
        the caller's contract to define, not warden's. The secret (if any) is never handled as a
        Python string beyond one read-and-push: written into the guest as a file and dereferenced
        there via `$(cat …)`, the same discipline `workload.py` uses and for the same reason — it
        must not appear in any argv, host- or guest-side, that auditd or `ps` could ever see.
        """
        profile_spec = build_vm_profile(mem=mem, cpu=cpu, pool=self.app.pool)
        self.app.ensure_build_vm_substrate(project, profile_spec)

        if self.client.instance_exists(instance, project):
            raise BuildVmError(
                f"{instance}: already exists in project {project} — submit_build always starts "
                "from a fresh VM; use a new instance name or tear down the existing one first"
            )
        self.client.launch(
            IMAGE, instance, project, profile_spec.name, instance_type="virtual-machine"
        )

        try:
            self._set_proxy_env(instance, project)
            self._wait_ready(instance, project)

            # wide provisioning allowlist -> narrow runtime one, same discipline as up()/run()
            if self.app.proxy_controller is not None:
                self.app.proxy_controller.set_allowlist(spec.provisioning_allowlist)
            self._exec_ok(instance, project, ["sh", "-c", "apt-get update -qq"], "apt-get update")
            self._exec_ok(
                instance, project,
                ["sh", "-c", "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
                             "--no-install-recommends git ca-certificates"],
                "apt-get install git",
            )
            self._exec_ok(instance, project, ["sh", "-c", f"mkdir -p {BUILD_OUT_DIR}"], "create build dirs")

            secret_source = None
            if secret_file is not None:
                secret_source = resolve_llm_auth(spec.llm, secret_file=secret_file)  # raises NeedsHumanError
                self.client.file_push(
                    instance, Path(secret_file).read_bytes().strip(), BUILD_SECRET_PATH, project=project
                )
                self._exec_ok(
                    instance, project, ["chmod", "600", BUILD_SECRET_PATH], "restrict secret file mode"
                )

            self.client.file_push(instance, build_script.encode(), BUILD_SCRIPT_PATH, project=project)
            self._exec_ok(
                instance, project, ["chmod", "700", BUILD_SCRIPT_PATH], "make build script executable"
            )

            if self.app.proxy_controller is not None:
                self.app.proxy_controller.set_allowlist(spec.runtime_allowlist)

            started_at = _now()
            timed_out = False
            try:
                result = self.client.exec(
                    instance, ["sh", "-c", BUILD_SCRIPT_PATH], project=project, timeout=wall_clock_seconds
                )
                returncode, stdout, stderr = result.returncode, result.stdout, result.stderr
            except IncusTimeoutError:
                # A wall-clock cap is a documented outcome, not a crash — see workload.py's `run`,
                # same shape. The VM is still torn down below; nothing about a cap requires keeping
                # a wedged build around.
                timed_out = True
                returncode, stdout, stderr = 124, "", ""
            ended_at = _now()

            artifacts = self._collect_artifacts(instance, project)

            return BuildResult(
                instance=instance,
                project=project,
                returncode=returncode,
                stdout=stdout,
                stderr=stderr,
                timed_out=timed_out,
                started_at=started_at,
                ended_at=ended_at,
                secret_source=secret_source,
                artifacts=artifacts,
            )
        finally:
            if teardown:
                self.client.delete(instance, project=project)
