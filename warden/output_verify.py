"""The functional half of step 4's output-verification (ROADMAP step 4,
`~/dev/cagetheagent/ROADMAP.md`): tests pass, artifacts present.

**The load-bearing rule this module exists to enforce**: `BuildResult.returncode`/`stdout` are the
VM-root build's own self-report, and VM-root is precisely the untrusted, forgeable component
(build_vm.py) — a build can `exit 0` and print "all tests passed" regardless of what actually
happened, whether that's malice or a bug. Treating that returncode as verification would reintroduce
trust-the-agent through the back door of the one path built specifically because agent self-report
isn't trustworthy. So this module never fuses the build's self-report into a verdict — same
discipline `report.py` keeps between CONFIRMED (evidenced) and NONE (unobserved): forgeable and
unforgeable signals stay labeled and separate, never merged into one boolean.

Two kinds of check, kept apart in `FunctionalVerdict`:

- **Host-verifiable (`ArtifactCheck`)**: warden already holds the pulled artifact bytes
  (`BuildResult.artifacts`) — the build cannot lie about what is actually in them. Presence,
  file count, a hash. Real verification, no re-execution needed.
- **Trusted re-run (`TrustedRerun`)**: for "tests actually pass," self-report isn't enough — the
  trustworthy path is to re-run warden's own chosen test command over the pulled artifacts in a
  **fresh** container-in-VM instance the build never touched. Freshness is what buys the trust, not
  "container vs VM": a clean-room instance can't have had its test runner monkey-patched, its PATH
  poisoned, or a fake assertion library planted by the process being verified. warden specifies and
  runs the command itself, rather than reading any claim the build already made about what its tests
  even were.

`BuildResult.returncode`/`stdout` still ride along in `FunctionalVerdict` as `BuildSelfReport` — a
hint for a human reading the report, explicitly labeled forgeable, never read by `FunctionalVerdict.
tests_verified`.
"""

from __future__ import annotations

import hashlib
import io
import tarfile
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from warden.build_vm import BuildResult
from warden.config import WardenConfig, build_config

if TYPE_CHECKING:
    from warden.app import WardenApp

VERIFY_DIR = "/root/verify"
VERIFY_ARTIFACT_PATH = f"{VERIFY_DIR}/artifacts.tar.gz"
VERIFY_SRC_DIR = f"{VERIFY_DIR}/src"
#: Truncated for a report — a stdout/stderr dump is provenance, not something to keep unbounded.
_SELF_REPORT_TAIL = 4000


@dataclass(frozen=True)
class ArtifactCheck:
    """Host-verifiable: derived only from bytes warden already pulled off the build VM. The build
    has no opportunity to influence this check after the fact."""

    present: bool
    file_count: int
    sha256: Optional[str]
    problems: tuple[str, ...]


@dataclass(frozen=True)
class BuildSelfReport:
    """Forgeable: the build's own claim about itself. Carried through for a human to read, never
    consulted by `FunctionalVerdict.tests_verified` — see the module docstring."""

    returncode: int
    timed_out: bool
    stdout_tail: str
    stderr_tail: str


@dataclass(frozen=True)
class TrustedRerun:
    """Unforgeable (to the extent a fresh, warden-driven re-run can be): `ran=True` means warden's
    own chosen `test_cmd` executed, in a fresh instance the build never touched, and this is that
    execution's real returncode — not anything the build claimed."""

    ran: bool
    returncode: Optional[int]
    stdout: str
    stderr: str
    skip_reason: Optional[str]


@dataclass(frozen=True)
class FunctionalVerdict:
    artifact_check: ArtifactCheck
    build_self_report: BuildSelfReport
    #: None means no trusted re-run was requested at all (caller passed no test_cmd) — distinct
    #: from a `TrustedRerun(ran=False, ...)`, which means one was requested but could not run.
    trusted_rerun: Optional[TrustedRerun]

    @property
    def artifacts_present(self) -> bool:
        return self.artifact_check.present

    @property
    def tests_verified(self) -> Optional[bool]:
        """True/False only from a completed trusted re-run. None if no re-run happened at all
        (not requested, or requested but skipped) — never derived from `build_self_report`."""
        if self.trusted_rerun is None or not self.trusted_rerun.ran:
            return None
        return self.trusted_rerun.returncode == 0


def check_artifacts(build_result: BuildResult) -> ArtifactCheck:
    if not build_result.artifacts:
        return ArtifactCheck(present=False, file_count=0, sha256=None, problems=("no artifacts produced",))
    try:
        with tarfile.open(fileobj=io.BytesIO(build_result.artifacts), mode="r:gz") as tar:
            members = [m for m in tar.getmembers() if m.isfile()]
    except tarfile.TarError as exc:
        return ArtifactCheck(present=False, file_count=0, sha256=None, problems=(f"corrupt tarball: {exc}",))
    digest = hashlib.sha256(build_result.artifacts).hexdigest()
    problems = () if members else ("tarball contains no files",)
    return ArtifactCheck(present=bool(members), file_count=len(members), sha256=digest, problems=problems)


def self_report(build_result: BuildResult) -> BuildSelfReport:
    return BuildSelfReport(
        returncode=build_result.returncode,
        timed_out=build_result.timed_out,
        stdout_tail=build_result.stdout[-_SELF_REPORT_TAIL:],
        stderr_tail=build_result.stderr[-_SELF_REPORT_TAIL:],
    )


class FunctionalVerifier:
    """Owns the trusted re-run — the one part of this module that has to touch Incus, because
    "trusted" here means warden actually executing something, not reading a claim."""

    def __init__(self, app: "WardenApp"):
        self.app = app

    def trusted_rerun(
        self,
        build_result: BuildResult,
        *,
        test_cmd: list[str],
        instance: str,
        project: str,
        wall_clock_seconds: float = 1800.0,
    ) -> TrustedRerun:
        """Extract the pulled artifact bytes into a FRESH instance and run `test_cmd` there —
        never anything the build itself proposed as "the test command". `builder` (no `repo_url`,
        so `up()` clones nothing) is a bare, already-proven container; nothing VM-root-specific
        survives into this instance for the build to have tampered."""
        if not build_result.artifacts:
            return TrustedRerun(ran=False, returncode=None, stdout="", stderr="", skip_reason="no artifacts to verify")

        cfg: WardenConfig = build_config(instance=instance, flavor="builder", llm="claude", project=project)
        self.app.up(cfg)
        try:
            self.app.client.exec(instance, ["sh", "-c", f"mkdir -p {VERIFY_SRC_DIR}"], project=project)
            self.app.client.file_push(instance, build_result.artifacts, VERIFY_ARTIFACT_PATH, project=project)
            extract = self.app.client.exec(
                instance, ["sh", "-c", f"tar -xzf {VERIFY_ARTIFACT_PATH} -C {VERIFY_SRC_DIR}"], project=project
            )
            if not extract.ok:
                return TrustedRerun(
                    ran=False, returncode=None, stdout="", stderr="",
                    skip_reason=f"artifact extraction failed: {(extract.stderr or extract.stdout).strip()[:500]}",
                )
            script = f"cd {VERIFY_SRC_DIR} && " + " ".join(test_cmd)
            result = self.app.client.exec(
                instance, ["sh", "-c", script], project=project, timeout=wall_clock_seconds
            )
            return TrustedRerun(
                ran=True, returncode=result.returncode, stdout=result.stdout, stderr=result.stderr,
                skip_reason=None,
            )
        finally:
            self.app.down(instance, project, force=True)

    def verify(
        self,
        build_result: BuildResult,
        *,
        test_cmd: Optional[list[str]] = None,
        instance: Optional[str] = None,
        project: Optional[str] = None,
    ) -> FunctionalVerdict:
        rerun: Optional[TrustedRerun] = None
        if test_cmd is not None:
            assert instance is not None and project is not None, "trusted re-run needs instance/project"
            rerun = self.trusted_rerun(build_result, test_cmd=test_cmd, instance=instance, project=project)
        return FunctionalVerdict(
            artifact_check=check_artifacts(build_result),
            build_self_report=self_report(build_result),
            trusted_rerun=rerun,
        )
