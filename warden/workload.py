"""`warden run` — one prompt, hands-off, inside the instance (DEMO-SPEC §3, §11.2).

The workload lifecycle's middle verb. `up` built the substrate; this runs the agent to completion
against a single prompt with no human in the loop, and records a **run manifest** precise enough
that `report` can scope the reconciliation afterwards without guessing.

Three things here are load-bearing and none of them are the exec itself:

**The phase boundary is drawn by the clock, and the clock is drawn honestly.** DEMO-SPEC §1 splits
`run` into *provisioning* (clone, install, environment prep — actions that often have no
authorizing tool call and are *expected*) and *work* (the accountable phase). Installing the agent
CLI is provisioning by any reading, so it happens **before** `started_at` is stamped, behind the
wide provisioning allowlist, which is then narrowed back to runtime before the agent ever runs —
the same narrow-after-provisioning discipline `app.up` already follows (D13). If installation were
inside the work window it would flood the work phase with hundreds of `npm`/`dpkg` execs that no
tool call authorizes, and the demo would be showing reconciliation noise as reconciliation.

**The secret never enters an argv, on either side of the boundary.** `incus exec --env K=V` puts
the value in the *host's* `incus` argv, visible to `ps`; a `sh -c "K=$KEY ..."` built on the host
puts it in the guest's. So the key is written into the instance as a file (bytes, never decoded,
never logged) and dereferenced *inside* the guest by a `$(cat …)` that is literal text in every
argv that exists. auditd captures syscall arguments, not environments — so the key is absent from
the ground-truth plane by construction rather than by redaction. `resolve_llm_auth` returns a
*description* of where the secret came from, and that description is what lands in the manifest.

**The manifest records the derived idmap; it is not a source for it.** The range is derived here
so the record of the run is complete, and `report` derives it *again* rather than reading it back.
That is §1's never-freeze-the-idmap rule applied to a new file: a manifest is exactly the kind of
plausible cache that would reintroduce the bug that has already bitten three times.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from warden.config import WardenConfig, resolve_llm_auth
from warden.idmap import derive_idmap
from warden.incus import EXEC_TIMEOUT, ExecResult, IncusClient, IncusTimeoutError
from warden.proxy import ProxyAllowlistController

#: Bumped only for a breaking change to the manifest's shape. DEMO-SPEC §10 asks that the demo's
#: outputs stay schema-stable and versioned because they are the eventual input to the cohort /
#: calibration layers — a corpus assembled from silently-drifting records is not a corpus.
RUN_MANIFEST_SCHEMA_VERSION = 1

#: Everything `run` puts inside the instance lives here, so `report`/`export` have one place to
#: look and `down` takes it all with the instance.
RUN_DIR = "/root/.warden-run"
PROMPT_PATH = f"{RUN_DIR}/prompt.txt"
SECRET_PATH = f"{RUN_DIR}/llm.key"
MANIFEST_NAME = "manifest.json"

#: The agent's working directory — the work-product plane. Deliberately not `/root/repo` (which
#: `up --repo` clones into): the example builds its own repo, so a run with no `--repo` still has
#: a git history to export, and a run *with* one keeps them separate.
WORKDIR = "/root/work"

DEFAULT_WALL_CLOCK_SECONDS = 1800.0


class WorkloadError(RuntimeError):
    """A step of `warden run` failed. Never raised for a non-zero *agent* exit — an agent that
    fails at its task still produced a transcript and a trace, and that run is still reportable."""


# --- per-runtime specifics -------------------------------------------------------------------
# The only per-LLM knowledge in warden. Kept as data for the same reason the flavor table is data,
# and pointing at agentwatch's runtime profile by name rather than re-deriving the mapping.


@dataclass(frozen=True)
class RuntimeSpec:
    llm: str
    #: `agentwatch.runtimes` profile name — selects adapter + drift gate + scope tuning together.
    agentwatch_runtime: str
    #: In-container path the adapter reads. A glob for runtimes that write per-session files.
    transcript_glob: str
    #: Written before the run; `{run_dir}` is substituted.
    settings_files: dict[str, str] = field(default_factory=dict)
    #: Set to False where warden has never actually driven this runtime end to end.
    validated: bool = False

    def install_script(self) -> str:
        raise NotImplementedError

    def version_argv(self) -> list[str]:
        raise NotImplementedError

    def invoke_script(self, *, has_secret: bool) -> str:
        raise NotImplementedError


# Node 22 from NodeSource: Debian 12 ships Node 18, and both CLIs need >= 20. `deb.nodesource.com`
# is already in the builder's *provisioning* allowlist (flavors.py) and deliberately not in its
# runtime one — which is precisely why installation has to happen before the narrow-back.
_NODE_INSTALL = (
    "command -v node >/dev/null 2>&1 && node -v | grep -qE '^v(2[0-9]|[3-9][0-9])' || { "
    "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends curl ca-certificates && "
    "curl -fsSL https://deb.nodesource.com/setup_22.x -o /tmp/nodesource_setup.sh && "
    "bash /tmp/nodesource_setup.sh && "
    "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nodejs; "
    "}"
)


@dataclass(frozen=True)
class _GeminiSpec(RuntimeSpec):
    def install_script(self) -> str:
        return (
            _NODE_INSTALL
            + " && command -v gemini >/dev/null 2>&1 || npm install -g --silent @google/gemini-cli"
        )

    def version_argv(self) -> list[str]:
        return ["gemini", "--version"]

    def invoke_script(self, *, has_secret: bool) -> str:
        # `--skip-trust` + a single `-p` prompt is DEMO-SPEC §3's hands-off shape. The prompt is
        # read from a file rather than interpolated into this string: a prompt containing a quote
        # would otherwise change the *shell command*, which is a bug class warden should not have.
        prefix = f'GEMINI_API_KEY="$(cat {SECRET_PATH})" ' if has_secret else ""
        return (
            f"cd {WORKDIR} && "
            f'{prefix}gemini --skip-trust -p "$(cat {PROMPT_PATH})"'
        )


@dataclass(frozen=True)
class _ClaudeSpec(RuntimeSpec):
    def install_script(self) -> str:
        return (
            _NODE_INSTALL
            + " && command -v claude >/dev/null 2>&1 || npm install -g --silent @anthropic-ai/claude-code"
        )

    def version_argv(self) -> list[str]:
        return ["claude", "--version"]

    def invoke_script(self, *, has_secret: bool) -> str:
        return (
            f"cd {WORKDIR} && "
            f'claude --dangerously-skip-permissions -p "$(cat {PROMPT_PATH})"'
        )


# Telemetry config for Gemini CLI. `logPrompts:false` is set even though this matters less than it
# looks: capsule D8 established the flag does NOT scrub `_body`, and agentwatch's Gemini adapter
# never reads `_body` at all. Belt and braces, with the braces being the ones that hold.
_GEMINI_SETTINGS = json.dumps(
    {
        "telemetry": {
            "enabled": True,
            "target": "local",
            "otlpEndpoint": "",
            "outfile": f"{RUN_DIR}/telemetry.txt",
            "logPrompts": False,
        }
    },
    indent=2,
)

GEMINI = _GeminiSpec(
    llm="gemini",
    agentwatch_runtime="gemini",
    transcript_glob=f"{RUN_DIR}/telemetry.txt",
    settings_files={"/root/.gemini/settings.json": _GEMINI_SETTINGS},
    # The Gemini adapter was measured against a real capture (agentwatch G6/G23); warden's own
    # end-to-end drive of it is what this demo build is for.
    validated=False,
)

CLAUDE = _ClaudeSpec(
    llm="claude",
    agentwatch_runtime="claude",
    # Claude Code writes one JSONL per session under a cwd-derived slug.
    transcript_glob="/root/.claude/projects/*/*.jsonl",
    validated=False,
)

RUNTIME_SPECS: dict[str, RuntimeSpec] = {"gemini": GEMINI, "claude": CLAUDE}


def runtime_spec(llm: str) -> RuntimeSpec:
    try:
        return RUNTIME_SPECS[llm]
    except KeyError:
        raise ValueError(f"unknown llm {llm!r}; expected one of {sorted(RUNTIME_SPECS)}") from None


# --- the run manifest ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RunManifest:
    """What `report` needs to scope the reconciliation, and what a reader needs to know what ran.

    `prompt` is carried in full: the example prompt is shipped, synthetic and benign, and a report
    that cannot show what the agent was asked to do is not accountability. A deployment running
    real prompts should treat this file as prompt-bearing and handle it accordingly — `export`
    puts it in the tarball, which is a copy-all by design.
    """

    schema_version: int
    instance: str
    project: str
    llm: str
    flavor: str
    auditd_wired: bool
    agentwatch_runtime: str
    prompt: str
    prompt_source: str  # "example" | "argument"
    prompt_sha256: str
    llm_version: Optional[str]
    started_at: float
    ended_at: float
    returncode: int
    timed_out: bool
    #: The idmap AS DERIVED AT RUN TIME. A record, never an input — `report` re-derives.
    idmap_uid_start: int
    idmap_uid_end: int
    transcript_glob: str
    workdir: str
    run_dir: str
    #: Where the secret came from, never what it was (see `config.resolve_llm_auth`).
    secret_source: Optional[str]

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)

    @classmethod
    def load(cls, path: Path) -> "RunManifest":
        data = json.loads(Path(path).read_text())
        version = data.get("schema_version")
        if version != RUN_MANIFEST_SCHEMA_VERSION:
            raise WorkloadError(
                f"{path}: run manifest schema_version {version!r}, this warden speaks "
                f"{RUN_MANIFEST_SCHEMA_VERSION}. Refusing to guess at the difference."
            )
        return cls(**data)


def run_dir_for(out_root: Path, project: str, instance: str) -> Path:
    """Host-side artifact directory for one instance's run. One place, so `export` is a copy."""
    return Path(out_root).expanduser() / project / instance


# --- the runner ---------------------------------------------------------------------------------


class WorkloadRunner:
    """Drives one hands-off prompt to completion inside an instance.

    Takes an `IncusClient` rather than reaching for a real one, for the same reason `WardenApp`
    does: everything below is exercised against `FakeIncusClient` in tests, and the only untestable
    part is the subprocess adapter.
    """

    PROBE_TIMEOUT = 15.0
    INSTALL_TIMEOUT = EXEC_TIMEOUT

    def __init__(
        self,
        client: IncusClient,
        proxy_controller: Optional[ProxyAllowlistController] = None,
    ) -> None:
        self.client = client
        self.proxy_controller = proxy_controller

    # -- helpers ---------------------------------------------------------------
    def _exec_ok(self, cfg: WardenConfig, argv: list[str], what: str, timeout: float = EXEC_TIMEOUT) -> ExecResult:
        result = self.client.exec(cfg.instance, argv, project=cfg.project, timeout=timeout)
        if not result.ok:
            raise WorkloadError(
                f"{cfg.instance}: {what} failed (rc={result.returncode}): "
                f"{(result.stderr or result.stdout).strip()[:2000]}"
            )
        return result

    def _sh(self, cfg: WardenConfig, script: str, what: str, timeout: float = EXEC_TIMEOUT) -> ExecResult:
        return self._exec_ok(cfg, ["sh", "-c", script], what, timeout=timeout)

    # -- provisioning (before the work window) ---------------------------------
    def ensure_runtime(self, cfg: WardenConfig, spec: RuntimeSpec) -> Optional[str]:
        """Install the agent CLI if absent and return its version string.

        Idempotent, and behind the **provisioning** allowlist: the node/npm sources a first install
        needs are deliberately absent from the runtime allowlist, so this cannot be deferred into
        the work phase even if someone wanted to.
        """
        if self.proxy_controller is not None:
            self.proxy_controller.set_allowlist(cfg.spec.provisioning_allowlist)
        try:
            self._sh(cfg, spec.install_script(), f"install {spec.llm} CLI", timeout=self.INSTALL_TIMEOUT)
            probe = self.client.exec(
                cfg.instance, spec.version_argv(), project=cfg.project, timeout=self.PROBE_TIMEOUT
            )
        finally:
            # Narrow back even on failure. A half-finished install must not leave the wide
            # provisioning allowlist active for whatever runs next.
            if self.proxy_controller is not None:
                self.proxy_controller.set_allowlist(cfg.spec.runtime_allowlist)
        if not probe.ok:
            # Not fatal: the version is provenance, not a precondition. Recorded as absent rather
            # than as a guess — a manifest that invents a version is worse than one that admits it
            # could not read one (agentwatch G21, in a different file).
            return None
        return probe.stdout.strip() or None

    def stage_inputs(
        self,
        cfg: WardenConfig,
        spec: RuntimeSpec,
        prompt: str,
        secret_file: Optional[Path],
    ) -> Optional[str]:
        """Push the prompt, the runtime's settings, and (if any) the secret into the instance.

        Returns the secret's *description*, never its content. The bytes are read and pushed
        without ever being decoded, formatted, or logged.
        """
        self._sh(cfg, f"mkdir -p {RUN_DIR} {WORKDIR}", "create run/work dirs")
        self.client.file_push(cfg.instance, prompt.encode(), PROMPT_PATH, project=cfg.project)
        for path, content in spec.settings_files.items():
            parent = path.rsplit("/", 1)[0]
            self._sh(cfg, f"mkdir -p {parent}", f"create {parent}")
            self.client.file_push(cfg.instance, content.encode(), path, project=cfg.project)

        if secret_file is None:
            return None
        source = resolve_llm_auth(cfg.llm, secret_file=secret_file)  # raises NeedsHumanError
        self.client.file_push(
            cfg.instance, Path(secret_file).read_bytes().strip(), SECRET_PATH, project=cfg.project
        )
        # Readable only by container root. The container is unprivileged, so this is a host-uid
        # in the instance's own idmap range — not a real account (DESIGN §2, operator posture).
        self._sh(cfg, f"chmod 600 {SECRET_PATH}", "restrict secret file mode")
        return source

    # -- the work window -------------------------------------------------------
    def run(
        self,
        cfg: WardenConfig,
        prompt: str,
        *,
        prompt_source: str = "argument",
        secret_file: Optional[Path] = None,
        wall_clock_seconds: float = DEFAULT_WALL_CLOCK_SECONDS,
        _now=time.time,
    ) -> RunManifest:
        spec = runtime_spec(cfg.llm)

        # --- provisioning phase ------------------------------------------------
        llm_version = self.ensure_runtime(cfg, spec)
        secret_source = self.stage_inputs(cfg, spec, prompt, secret_file)
        # Derived, not cached from `up` — and derived here only so the manifest is a complete
        # record. `report` derives it again; see the module docstring.
        idmap = derive_idmap(self.client, cfg.instance, project=cfg.project)

        # --- work phase --------------------------------------------------------
        started_at = _now()
        timed_out = False
        try:
            result = self.client.exec(
                cfg.instance,
                ["sh", "-c", spec.invoke_script(has_secret=secret_source is not None)],
                project=cfg.project,
                timeout=wall_clock_seconds,
            )
            returncode = result.returncode
        except IncusTimeoutError:
            # A wall-clock cap is a documented outcome of `run`, not a crash: the transcript and
            # the audit trail up to the cap are still real and still reportable. It is recorded
            # rather than swallowed, because a capped run's trace is *truncated* and a reader has
            # to know that before drawing conclusions from what is missing.
            timed_out = True
            returncode = 124
        ended_at = _now()

        return RunManifest(
            schema_version=RUN_MANIFEST_SCHEMA_VERSION,
            instance=cfg.instance,
            project=cfg.project,
            llm=cfg.llm,
            flavor=cfg.spec.name,
            auditd_wired=cfg.spec.auditd_wired,
            agentwatch_runtime=spec.agentwatch_runtime,
            prompt=prompt,
            prompt_source=prompt_source,
            prompt_sha256=hashlib.sha256(prompt.encode()).hexdigest(),
            llm_version=llm_version,
            started_at=started_at,
            ended_at=ended_at,
            returncode=returncode,
            timed_out=timed_out,
            idmap_uid_start=idmap.uid.host_start,
            idmap_uid_end=idmap.uid.host_end,
            transcript_glob=spec.transcript_glob,
            workdir=WORKDIR,
            run_dir=RUN_DIR,
            secret_source=secret_source,
        )
