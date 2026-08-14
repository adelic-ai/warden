"""`warden report` — the agentwatch↔wizard integration (DEMO-SPEC §4, §11.3).

This is the verb the whole stack exists for: take the two planes this container has — the agent's
own self-report and the host's unforgeable syscall record — and reconcile them, producing
`findings.jsonl`, `verdicts.jsonl` and a summary that is honest about what it does and does not
know.

It is **glue**. Every reconciliation decision is agentwatch's (`run_once`, the reconcilers,
`canon_emit`); every custody decision is canon's. warden contributes four things agentwatch cannot
know on its own:

1. **Which uid to scope to** — the container's *derived* idmap range, re-derived here and never
   read back from the manifest (§1's rule; the frozen-idmap bug has bitten three times).
2. **Proof the plane is live** — a marker exec captured under *this instance's own key* before the
   ground truth is trusted at all. `auditctl -l` proves a rule is loaded text, not that it matches
   (D14: a dead instance's rule with an overlapping range tagged a live instance's execs).
3. **Where the phase boundary is** — the run manifest's `started_at`, so provisioning noise does
   not drown the work-phase signal (§1).
4. **The privilege split** — a tiny root collector copies the records out; everything here runs
   unprivileged over that file (DESIGN §4).

## The honesty bar (§7), and where each clause is enforced

* **No analysis engine.** This module counts and segments. It does not score, threshold, trend or
  interpret. `verdicts.jsonl`/`findings.jsonl` are the product; the summary is a *view* over them.
* **Separate the verdict kinds; never collapse them.** `Summary` carries `authorized`, `CONFIRMED`,
  `NONE` (with reasons), `GAP` and `not_evaluated` as distinct fields with no total that fuses
  them. There is deliberately no "deviations" number, because a run that only hits coverage
  boundaries must read as *blind spots*, not misbehaviour — and one number cannot say both.
* **Recall is shell-out-only.** Reported as a stated limit, and the fork gap rides out as canon's
  `fidelity_attestation` (`cause=missing-telemetry`) rather than being hidden or staged.
* **Not calibrated.** `calibrated: false` is a field, not a footnote. No triggers, no thresholds.
* **Canon tiers ≤ well_formed, calibration absent.** Asserted over the emitted verdicts, and the
  assertion's own availability is reported rather than assumed.

## The one duplication, and why it is a cross-check rather than a smell

`run_once` owns the durable artifacts — it must, or the schema drifts from agentwatch's (§10).
But it returns only *newly written* findings, and the summary needs the whole candidate
population including the ones that were correctly silent. So the candidate pass is run here too,
over the same two files. Reconciliation is deterministic over its inputs, so the two agree — and
`Summary.consistent` asserts they do. A disagreement means one of the passes is wrong, and the
report says so instead of printing a confident number.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from warden import auditd
from warden.config import WardenConfig
from warden.idmap import Idmap, derive_idmap
from warden.incus import IncusClient
from warden.workload import RUN_MANIFEST_SCHEMA_VERSION, RunManifest, runtime_spec

#: Bumped only for a breaking change to `report.json`. Same reasoning as the run manifest: §10
#: wants these outputs stable and versioned because they are the corpus the calibration layers
#: will eventually be built from.
REPORT_SCHEMA_VERSION = 1

FINDINGS_NAME = "findings.jsonl"
VERDICTS_NAME = "verdicts.jsonl"
REPORT_NAME = "report.json"
AUDIT_CAPTURE_NAME = "audit.raw"
TRANSCRIPT_NAME = "transcript.txt"
STATE_NAME = "agentwatch_state.json"

COLLECTOR = Path(__file__).resolve().parent.parent / "scripts" / "warden-collect-audit.sh"

#: Default eBPF live-capture window. Unlike the auditd log (persistent, reconciled after the fact),
#: eBPF's ring buffer is live-only — the probe must run *while* the agent acts — so a window is
#: intrinsic to the capture, not an afterthought. See `Reporter.reconcile_ebpf_live`.
DEFAULT_EBPF_CAPTURE_SECONDS = 30


@dataclass
class EbpfLiveResult:
    """What a decision-B live eBPF reconcile produced. Deliberately small: run_once owns the durable
    artifacts (findings.jsonl etc.); this is the at-a-glance count the CLI renders."""

    findings_written: int
    ground_truth_execs: int
    capture_skipped: int
    capture_window_s: int

#: The three windows an agent-uid exec can fall in, split by the run manifest's clock.
#:
#: `after_run` exists because two of the things that land there are warden's own: the capture-proof
#: marker exec `report` runs *now*, and anything an operator does between `run` and `report`. Folding
#: those into the work phase would inflate the accountable window with the observer's own footprint,
#: which is precisely the kind of quiet miscount this report is supposed to make impossible.
PHASE_PROVISIONING = "provisioning"
PHASE_WORK = "work"
PHASE_AFTER = "after_run"
PHASES = (PHASE_PROVISIONING, PHASE_WORK, PHASE_AFTER)


class ReportError(RuntimeError):
    """`report` cannot produce an honest reconciliation. Never downgraded to a partial one."""


class AgentwatchUnavailable(ReportError):
    """agentwatch is not importable. Reported as a missing dependency, never worked around —
    there is no warden-local reimplementation of the reconciler, and there must not be."""


def _try_import_agentwatch() -> None:
    from agentwatch import canon_emit, runtimes  # noqa: F401
    from agentwatch.events import EXEC  # noqa: F401
    from agentwatch.groundtruth import audit_log  # noqa: F401
    from agentwatch.reconciler.orphan import reconcile_orphans_scoped  # noqa: F401
    from agentwatch.reconciler.parse_health import assess_parse_health  # noqa: F401
    from agentwatch.reconciler.verdict import Verdict  # noqa: F401
    from agentwatch.run import Config, run_once  # noqa: F401


def _import_agentwatch():
    """Make agentwatch importable, then import the names `report` uses.

    agentwatch is NOT on PyPI — it is found on the import path, not installed from an index. Try it
    already-on-path first (a `pip install -e` or a set PYTHONPATH), then discover it the same way the
    test conftest does so a plain sibling checkout works with no setup: WARDEN_AGENTWATCH_PATH, then
    an `agentwatch` checkout beside this repo (`~/dev/agentwatch` next to `~/dev/warden`)."""
    repo_root = Path(__file__).resolve().parent.parent
    roots: list[Optional[Path]] = [None]  # None = "already on sys.path"
    env = os.environ.get("WARDEN_AGENTWATCH_PATH")
    if env:
        roots.append(Path(env).expanduser())
    roots.append(repo_root.parent / "agentwatch")

    last_exc: Optional[ImportError] = None
    for root in roots:
        if root is not None:
            if not (root / "agentwatch" / "run.py").exists():
                continue
            if str(root) not in sys.path:
                sys.path.insert(0, str(root))
        try:
            _try_import_agentwatch()
            return
        except ImportError as exc:
            last_exc = exc

    raise AgentwatchUnavailable(
        f"agentwatch is not importable ({last_exc}). `warden report` is the agentwatch integration; "
        "it has no local reimplementation of the reconciler and will not invent one. agentwatch is "
        "not on PyPI — put the merged standalone (~/dev/agentwatch / github.com/adelic-ai/agentwatch) "
        "on PYTHONPATH, `pip install -e` it, set WARDEN_AGENTWATCH_PATH, or check it out beside this "
        "repo as ./agentwatch."
    ) from last_exc


# --- live reconcile of a persistent dev home (no run manifest) -------------------------------

#: Stamped on a persistent `dev` home when `up` finishes provisioning it. It is the phase boundary
#: a live reconcile needs and a workload gets from the run manifest's `started_at`: execs before it
#: are the one-time furnishing (node/npm/apt), execs after it are the interactive session — the
#: accountable window. Kept on the instance so it survives across sessions, like the home itself.
PROVISIONED_AT_KEY = "user.warden.provisioned_at"

#: Stamped by `warden dev` at the moment it hands you the interactive shell — so warden's own entry
#: execs (readiness probe, capture marker) fall BEFORE it, and the window is your session's activity
#: only. This is what makes "reconcile what I did this session" the zero-config default: a live
#: reconcile scopes to this if present, so no `--since` and no manual boundary reset is needed.
SESSION_STARTED_KEY = "user.warden.session_started_at"

_SINCE_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_since(spec: str) -> Optional[float]:
    """A `--since` window as seconds-of-lookback, e.g. `45m`, `2h`, `3d`. Returns None if unparseable
    (an absolute epoch is handled by the caller). Deliberately tiny: the point is a window, not a
    date library."""
    spec = spec.strip()
    if len(spec) >= 2 and spec[-1] in _SINCE_UNITS and spec[:-1].isdigit():
        return int(spec[:-1]) * _SINCE_UNITS[spec[-1]]
    return None


def live_manifest(client: IncusClient, cfg: WardenConfig, *, since: float, out_dir: Path) -> RunManifest:
    """Synthesize the manifest `report` needs from a LIVE dev home, so the free-form loop reconciles
    through the exact same engine a workload does — no second reconciler, no lowered honesty bar.

    The only real inputs are the derived idmap (never frozen — re-derived here as everywhere) and the
    `since` boundary that plays the role a workload's `started_at` plays: the split between the
    one-time furnishing and the interactive session. `ended_at` is now. Everything else is either a
    constant of the dev flavor (auditd wired, no injected secret) or looked up from the runtime spec
    (the transcript glob, which for Claude Code is where it writes interactively too)."""
    idmap = derive_idmap(client, cfg.instance, project=cfg.project)
    spec = runtime_spec(cfg.llm)
    return RunManifest(
        schema_version=RUN_MANIFEST_SCHEMA_VERSION,
        instance=cfg.instance,
        project=cfg.project,
        llm=cfg.llm,
        flavor="dev",
        auditd_wired=True,
        agentwatch_runtime=spec.agentwatch_runtime,
        prompt="(interactive dev home — no single prompt; reconciled over a --since window)",
        prompt_source="interactive",
        prompt_sha256="",
        llm_version=None,
        started_at=since,
        ended_at=time.time(),
        returncode=0,
        timed_out=False,
        idmap_uid_start=idmap.uid.host_start,
        idmap_uid_end=idmap.uid.host_end,
        transcript_glob=spec.transcript_glob,
        workdir="/root",
        run_dir=str(out_dir),
        secret_source=None,
    )


# --- the privileged collector (DESIGN §4) ---------------------------------------------------


class AuditCollector:
    """Runs the root collector and returns the path it wrote. Injected so tests can supply a
    double — the real one needs root, which is the whole point of it being separate."""

    def __init__(self, script: Path = COLLECTOR, sudo: bool = True) -> None:
        self.script = Path(script)
        self.sudo = sudo

    def collect(self, rule_key: str, out_path: Path, owner_uid: int) -> Path:
        argv: list[str] = []
        if self.sudo:
            # `-n`: never prompt. A collector that blocks on a password turns a hands-off run into
            # a hang with no output, which reads exactly like a broken plane.
            argv += ["sudo", "-n"]
        argv += [str(self.script), rule_key, str(out_path), str(owner_uid)]
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            raise ReportError(
                f"audit collector failed (rc={proc.returncode}): {proc.stderr.strip()}\n"
                f"  argv: {' '.join(argv)}\n"
                "  This is the privileged half of the split (DESIGN §4) and it needs root. "
                "Grant a scoped, passwordless sudo rule for exactly this script."
            )
        return Path(out_path)


# --- the summary ------------------------------------------------------------------------------


@dataclass
class PhaseCounts:
    """One phase's verdict-kind breakout. **No total that fuses these.**

    `authorized` is not a verdict — it is a candidate the reconciler *matched* to an authorizing
    tool call. It is counted alongside so the denominator is visible: "3 CONFIRMED" means something
    different against 5 execs than against 500.

    `execs` counts every agent-uid exec in the window; `not_evaluated` is the remainder the
    reconciler never judged because the pid is outside the agent's session subtree. That remainder
    is where provisioning noise actually goes — `RuntimeScope` excludes it, not the phase split —
    and it is reported per phase rather than as one number, because "47 unevaluated execs, all in
    the provisioning window" and "47 unevaluated execs in the work window" mean opposite things.
    """

    execs: int = 0
    authorized: int = 0
    confirmed: int = 0
    none: int = 0
    gap: int = 0
    #: NONE reasons, counted. This is what makes a NONE readable as a *blind spot* rather than a
    #: silent pass — "the plane structurally cannot observe this" is a claim that must name itself.
    none_reasons: dict = field(default_factory=dict)
    #: `comm` -> count for the execs the reconciler never judged. Added after the first real run,
    #: which made the case unanswerably: the work phase reported "not evaluated 15", and those 15
    #: turned out to be `git init` / `git checkout -b` / `git add` / `git commit` / `python3 -m
    #: unittest` — i.e. **the entire work product**. Their parent shells forked without ever
    #: execve'ing, so the ancestry walk terminated before reaching the runtime pid and the whole
    #: subtree fell out of scope (the fork gap, agentwatch G23).
    #:
    #: The count alone was true and useless. A reader seeing "0 CONFIRMED, 15 not evaluated" would
    #: reasonably conclude the run was clean and the remainder was noise, when in fact the actions
    #: that produced the commits were the unexamined ones. Naming them is the difference between
    #: disclosing a blind spot and merely not lying about it.
    not_evaluated_by_comm: dict = field(default_factory=dict)

    @property
    def evaluated(self) -> int:
        return self.authorized + self.confirmed + self.none + self.gap

    @property
    def not_evaluated(self) -> int:
        return max(0, self.execs - self.evaluated)

    def as_dict(self) -> dict:
        data = asdict(self)
        data["evaluated"] = self.evaluated
        data["not_evaluated"] = self.not_evaluated
        return data

    def add(self, verdict_name: Optional[str], reason: str, matched: bool) -> None:
        if matched:
            self.authorized += 1
            return
        if verdict_name == "CONFIRMED":
            self.confirmed += 1
        elif verdict_name == "GAP":
            self.gap += 1
        elif verdict_name == "NONE":
            self.none += 1
            short = reason.split(" - ")[0].split(" — ")[0].strip() or "unclassified"
            self.none_reasons[short] = self.none_reasons.get(short, 0) + 1


@dataclass
class Summary:
    schema_version: int
    instance: str
    project: str
    llm: str
    agentwatch_runtime: str
    host: str
    #: The range reconciliation was scoped to — DERIVED at report time, not read from the manifest.
    agent_uid: int
    uid_range: str
    capture_proven: bool
    #: `started_at`/`ended_at` from the manifest: the work window. Everything before is provisioning.
    work_from: float
    work_until: float
    phases: dict
    #: Execs at the agent uid the reconciler did not evaluate at all (out of the session subtree).
    #: Reported rather than dropped — an unevaluated exec is not a clean one.
    not_evaluated: int
    parse_degraded: bool
    parse_reasons: list
    transcript_events: int
    ground_truth_execs: int
    #: Audit records the parser could not read. Surfaced because an unreadable capture and an
    #: empty one look identical in a count of execs, and they mean opposite things.
    ground_truth_skipped: int
    ground_truth_skip_reasons: dict
    findings_written: int
    verdicts_written: int
    verdicts_available: bool
    verdicts_unavailable_reason: Optional[str]
    consistent: bool
    consistency_note: str
    fork_gap_attestation: Optional[dict]
    honesty: dict

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)


def _honesty_block() -> dict:
    """The §7 bar, as data in the artifact rather than as prose in a README nobody exports."""
    return {
        "analysis_engine": False,
        "analysis_engine_note": (
            "warden produces and exports; consumers analyse. No scoring, thresholds or trends are "
            "computed here."
        ),
        "calibrated": False,
        "calibration_note": (
            "This is the mechanism demonstrated on one run. It is NOT an FP/FN rate. Rates need a "
            "corpus of completed workloads (DEMO-SPEC §10); none exists yet, so no trigger, "
            "threshold or acceptable band is offered."
        ),
        "recall_validated_for": "shell-out only",
        "recall_note": (
            "Recall is validated for the case where a tool call shells out and the shell execs "
            "(agentwatch G23). Fork-without-exec is invisible to an execve-only auditd config and "
            "is REPORTED as a fidelity attestation (cause=missing-telemetry), not caught."
        ),
        "verdict_kinds_note": (
            "CONFIRMED (an action with no authorizing intent), NONE (the plane structurally could "
            "not observe this class of action), GAP and authorized are kept separate on purpose. "
            "There is no combined 'deviation' number: a run that only hits coverage boundaries is "
            "showing blind spots, not misbehaviour, and one number cannot say both."
        ),
        "guarantee_tier_max": "well_formed",
        "calibration_field": "absent",
    }


def _ssh_run(vm_host: str):
    """A `subprocess.run`-shaped callable that executes the WHOLE argv on `vm_host` over ssh, for the
    container-in-VM shape: the eBPF probe must load on the vantage kernel above the container, not on
    whatever host `warden report` itself runs on. `ebpf_capture.capture_argv()` already orders
    elevation before `timeout` before `bpftrace` correctly for a single local exec; ssh only accepts
    one remote command string, so that argv is re-joined with shlex for the hop rather than re-ordered
    or partially elevated. `BatchMode=yes` matches privilege.py's `sudo -n`: a hands-off run must fail
    fast on a host-key or password prompt, not hang."""
    import shlex

    def run(argv, **kwargs):
        remote_cmd = shlex.join(argv)
        return subprocess.run(["ssh", "-o", "BatchMode=yes", vm_host, remote_cmd], **kwargs)

    return run


# --- the reporter -----------------------------------------------------------------------------


class Reporter:
    def __init__(
        self,
        client: IncusClient,
        collector: Optional[AuditCollector] = None,
        event_source_factory=None,
    ) -> None:
        self.client = client
        self.collector = collector if collector is not None else AuditCollector()
        self.event_source_factory = event_source_factory

    # -- plane acquisition -----------------------------------------------------
    def derive_scope(self, cfg: WardenConfig, manifest: RunManifest) -> Idmap:
        """Re-derive the idmap and refuse to reconcile across a reallocation.

        §8.7 wants the audit scope to use the *derived* range, never a frozen one. That is done
        here. The equality check against the manifest is the other half: if the instance was
        restored (or otherwise reallocated) between `run` and `report`, the run's records carry the
        OLD host uids while the live rule watches the new ones. Reconciling at either value would
        produce a confident wrong answer — the new range matches none of the run's records and
        would read as a clean run; the old one would be a frozen value, the bug §1 exists about.
        So it stops instead.
        """
        idmap = derive_idmap(self.client, cfg.instance, project=cfg.project)
        if idmap.uid.host_start != manifest.idmap_uid_start:
            raise ReportError(
                f"{cfg.instance}: idmap was reallocated between `run` and `report` "
                f"(run: {manifest.idmap_uid_start}-{manifest.idmap_uid_end}, "
                f"now: {idmap.uid}). The run's audit records carry the old host uids and the live "
                "rule watches the new ones, so neither range reconciles this run correctly. "
                "Re-run the workload; do not reconcile across a reallocation."
            )
        return idmap

    def prove_plane(self, cfg: WardenConfig, idmap: Idmap) -> auditd.AuditEvent:
        """Marker exec, captured under this instance's own key, before the plane is trusted.

        Not decoration and not a substitute for anything: `auditctl -l` proves a rule is loaded
        text, not that it matches. D14 had a deleted instance's rule with an overlapping uid range
        tagging a live instance's execs under the dead key — which uid-only matching called a pass
        while `ausearch -k <this instance>` found nothing.
        """
        if self.event_source_factory is None:
            raise ReportError("no event_source_factory wired — cannot prove capture")
        source = self.event_source_factory(cfg.instance)
        return auditd.prove_capture(
            self.client, source, cfg.instance, idmap.uid, project=cfg.project
        )

    def pull_transcript(self, cfg: WardenConfig, manifest: RunManifest, dest: Path) -> Optional[Path]:
        """Copy the agent's self-report out of the instance.

        A missing transcript is returned as None, not raised: "the agent produced no self-report"
        is a *finding about the run*, and parse-health downstream turns it into a degraded verdict
        rather than a clean one. Raising here would lose that.
        """
        path = manifest.transcript_glob
        if "*" in path:
            listing = self.client.exec(
                cfg.instance, ["sh", "-c", f"ls -1 {path} 2>/dev/null | head -n 50"],
                project=cfg.project,
            )
            candidates = [line for line in listing.stdout.splitlines() if line.strip()]
            if not candidates:
                return None
            # Concatenating per-session files is correct for JSONL and would be wrong for the
            # concatenated-object Gemini format — which is why only Claude's glob expands.
            blobs = []
            for candidate in candidates:
                try:
                    blobs.append(self.client.file_pull(cfg.instance, candidate, project=cfg.project))
                except FileNotFoundError:
                    continue
            if not blobs:
                return None
            dest.write_bytes(b"".join(blobs))
            return dest
        try:
            dest.write_bytes(self.client.file_pull(cfg.instance, path, project=cfg.project))
        except FileNotFoundError:
            return None
        return dest

    # -- the reconciliation ----------------------------------------------------
    def report(
        self,
        cfg: WardenConfig,
        manifest: RunManifest,
        out_dir: Path,
        *,
        host: Optional[str] = None,
    ) -> Summary:
        _import_agentwatch()
        from agentwatch import canon_emit, runtimes
        from agentwatch.events import EXEC, TOOL_USE, ParseStats
        from agentwatch.groundtruth import audit_log
        from agentwatch.reconciler.orphan import reconcile_orphans_scoped
        from agentwatch.reconciler.parse_health import assess_parse_health
        from agentwatch.run import Config, run_once

        if not manifest.auditd_wired:
            raise ReportError(
                f"{cfg.instance} was not created with the ground-truth plane wired. Reconciliation "
                "needs both planes; with only the self-report one there is nothing to check it "
                "against. Re-create with `warden up --audit`."
            )

        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        host = host or socket.gethostname()

        idmap = self.derive_scope(cfg, manifest)
        proof = self.prove_plane(cfg, idmap)
        agent_uid = idmap.uid.host_start  # container root -> this host uid

        audit_path = self.collector.collect(
            auditd.rule_key(cfg.instance), out_dir / AUDIT_CAPTURE_NAME, os.getuid()
        )
        transcript_path = self.pull_transcript(cfg, manifest, out_dir / TRANSCRIPT_NAME)

        # --- agentwatch owns the durable artifacts ----------------------------
        config = Config(
            agent_uid=agent_uid,
            transcript_paths=[transcript_path] if transcript_path else [],
            audit_log_path=audit_path,
            findings_path=out_dir / FINDINGS_NAME,
            state_path=out_dir / STATE_NAME,
            verdicts_path=out_dir / VERDICTS_NAME,
            runtime=manifest.agentwatch_runtime,
            host=host,
            # The self-mod detector watches host paths belonging to the *monitor*, not the
            # container. Out of scope for a workload report, and it would make the finding count
            # depend on the operator's own filesystem.
            self_mod_watched_paths=(),
        )
        new_findings = run_once(config)
        # A clean run writes no findings, and `FindingsStore` only creates the file on append — so
        # a genuinely clean reconciliation and a report that never ran are byte-identical on disk
        # (both: no file). An empty file says "I looked and found nothing"; an absent one says
        # nothing at all, and `export` would silently ship a tarball missing the headline artifact.
        (out_dir / FINDINGS_NAME).touch()
        # verdicts.jsonl is NOT touched when canon is unavailable: an empty verdicts file would
        # imply the canon projection ran and produced none, which is a different claim from "canon
        # was not importable here". That distinction is the whole point of the field below.
        if canon_emit.CANON_AVAILABLE:
            (out_dir / VERDICTS_NAME).touch()

        # --- the candidate pass, for the summary (see the module docstring) ----
        profile = runtimes.resolve(manifest.agentwatch_runtime)
        with audit_path.open(encoding="utf-8", errors="replace") as fh:
            gt_events, gt_stats = audit_log.parse_lines(fh)
        transcript_events: list = []
        # An empty ParseStats when there is no transcript at all: skip_rate 0 over 0 lines, which
        # is honest (nothing failed to parse) and lets the *structural* check — execs exist but no
        # tool_use does — be the thing that fires. A missing self-report should read as degraded
        # because of what it cannot explain, not because of a made-up skip rate.
        parse_stats = ParseStats()
        if transcript_path is not None:
            adapter = profile.adapter_factory()
            transcript_events = list(adapter.parse_file(transcript_path))
            parse_stats = adapter.stats

        tool_use_count = sum(1 for e in transcript_events if e.kind == TOOL_USE)
        exec_count = sum(1 for e in gt_events if e.kind == EXEC)
        health = assess_parse_health(
            parse_stats,
            tool_use_count=tool_use_count,
            exec_count=exec_count,
            known_versions=profile.known_versions,
        )

        candidates = reconcile_orphans_scoped(
            gt_events,
            transcript_events,
            agent_uid=agent_uid,
            degraded=health.degraded,
            scope_tuning=profile.scope_tuning,
        )

        def phase_of(ts: float) -> str:
            if ts < manifest.started_at:
                return PHASE_PROVISIONING
            if ts <= manifest.ended_at:
                return PHASE_WORK
            return PHASE_AFTER

        phases = {name: PhaseCounts() for name in PHASES}
        # The denominator first: every agent-uid exec the capture contains, in its window. The
        # reconciler judges a subset of these; the rest is the not-evaluated remainder, and it has
        # to be visible or an unevaluated exec reads as a clean one.
        for ev in gt_events:
            if ev.kind == EXEC and ev.uid == agent_uid:
                phases[phase_of(ev.ts)].execs += 1
        for candidate in candidates:
            phases[phase_of(candidate.event.ts)].add(
                candidate.verdict.value if candidate.verdict else None,
                candidate.reason,
                # `matched` = an authorizing tool_use was actually found — NOT merely "not an orphan".
                # The consolidated agentwatch emits UNEVALUABLE candidates (is_orphan=False AND
                # matched_pid=None: it could not look, so it neither matched nor orphaned — e.g.
                # warden's own after-run capture marker, which its clone-capture fix now bridges into
                # scope). `not is_orphan` counted those as authorized and inflated the accountable
                # window; keying off matched_pid leaves an UNEVALUABLE exec correctly un-evaluated.
                matched=candidate.matched_pid is not None,
            )
        # Name the unevaluated remainder. `(ts, pid)` rather than pid alone: a pid can execve more
        # than once (a PATH search records the failed attempt and then the successful one), and
        # keying on the pid would mark the second exec evaluated because the first was.
        judged = {(c.event.ts, c.event.pid) for c in candidates}
        for ev in gt_events:
            if ev.kind != EXEC or ev.uid != agent_uid or (ev.ts, ev.pid) in judged:
                continue
            counts = phases[phase_of(ev.ts)].not_evaluated_by_comm
            name = ev.comm or (ev.exe or "?").rsplit("/", 1)[-1]
            counts[name] = counts.get(name, 0) + 1
        not_evaluated = sum(p.not_evaluated for p in phases.values())

        # --- cross-check, not decoration --------------------------------------
        confirmed_here = sum(p.confirmed for p in phases.values())
        orphan_findings = self._count_orphan_findings(out_dir / FINDINGS_NAME)
        consistent = confirmed_here == orphan_findings
        note = (
            "candidate pass and run_once agree"
            if consistent
            else (
                f"DISAGREEMENT: this pass counted {confirmed_here} CONFIRMED, run_once wrote "
                f"{orphan_findings} orphan findings. One of them is wrong — do not read the "
                "counts below as authoritative until this is resolved."
            )
        )

        verdicts_available = canon_emit.CANON_AVAILABLE
        verdicts_written = self._count_lines(out_dir / VERDICTS_NAME) if verdicts_available else 0
        attestation = None
        if verdicts_available:
            # The fork gap, REPORTED. §7: never hidden, never staged as a catch.
            attestation = canon_emit.fork_gap_attestation()

        return Summary(
            schema_version=REPORT_SCHEMA_VERSION,
            instance=cfg.instance,
            project=cfg.project,
            llm=manifest.llm,
            agentwatch_runtime=manifest.agentwatch_runtime,
            host=host,
            agent_uid=agent_uid,
            uid_range=str(idmap.uid),
            capture_proven=proof is not None,
            work_from=manifest.started_at,
            work_until=manifest.ended_at,
            phases={name: counts.as_dict() for name, counts in phases.items()},
            not_evaluated=not_evaluated,
            parse_degraded=health.degraded,
            parse_reasons=list(health.reasons),
            transcript_events=len(transcript_events),
            ground_truth_execs=exec_count,
            ground_truth_skipped=gt_stats.lines_skipped,
            ground_truth_skip_reasons=dict(gt_stats.skip_reasons),
            findings_written=len(new_findings),
            verdicts_written=verdicts_written,
            verdicts_available=verdicts_available,
            verdicts_unavailable_reason=(
                None if verdicts_available
                else "canon is not importable in this environment; verdicts.jsonl was not written"
            ),
            consistent=consistent,
            consistency_note=note,
            fork_gap_attestation=attestation,
            honesty=_honesty_block(),
        )

    # -- decision B: live eBPF reconcile ---------------------------------------
    def reconcile_ebpf_live(
        self,
        out_dir: Path,
        *,
        agent_uid: int,
        duration_s: int = DEFAULT_EBPF_CAPTURE_SECONDS,
        transcript_path: Optional[Path] = None,
        runtime: Optional[str] = None,
        host: Optional[str] = None,
        vm_host: Optional[str] = None,
        _capture=None,
    ) -> EbpfLiveResult:
        """Decision B, live: agentwatch loads its OWN eBPF probe on the vantage and reads its own
        buffer; warden only supplies the privilege (`privilege.elevation_prefix()`) and invokes. The
        captured events reconcile through the SAME `run_once` the auditd path uses — no second
        reconciler, no lowered honesty bar (report.py's principle).

        `vm_host`: the container-in-VM shape needs the probe loaded on the VM kernel ABOVE the
        container, which is not necessarily the host `warden report` itself runs on. When set, the
        real capture's whole argv — elevation, `timeout`, `bpftrace` — is shipped over ssh to run on
        `vm_host` (`_ssh_run`), instead of executing locally. `elevation_prefix()` is still computed
        and still travels with the argv; `sudo -n` must run on the vantage, not on the caller's host.
        Omitted, behaviour is unchanged (local exec, as before P5's topology fix).

        This is a distinct entry point from `report()`, not a flag on it, because the capture models
        genuinely differ: auditd is a persistent log reconciled after the fact, while eBPF's ring
        buffer is live-only — the probe must run CONCURRENTLY with agent activity, so this captures a
        `duration_s` window rather than collecting a log that already exists. That live shape is also
        exactly the injection scenario the fork-gap fix must close (a host-root `incus exec` into the
        cage while the probe watches).

        `agent_uid` + `transcript_path` are the container identity and self-report location warden
        hands over (REFACTOR.md's B boundary). The session cgroup self-seeds from the runtime's own
        exec in the capture stream (agentwatch runtime_scope), so no cgroup argument is needed for the
        basic path; an authoritative cgroup handover is the P2 enhancement.

        `_capture` is a seam for tests — it defaults to the real `ebpf_capture.run_capture`, which
        spawns bpftrace and needs a kernel the operator owns (validated on gembox, not in unit tests).
        """
        _import_agentwatch()
        from agentwatch import runtimes
        from agentwatch.events import EXEC
        from agentwatch.groundtruth import ebpf_capture
        from agentwatch.run import Config, run_once
        from warden.privilege import elevation_prefix

        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        host = host or socket.gethostname()
        runtime = runtime or runtimes.CLAUDE.name  # the interactive dev-home default
        capture = _capture if _capture is not None else ebpf_capture.run_capture
        # _run only makes sense against the real capture — a test double's `cap(*, duration_s,
        # elevation_prefix)` has no _run parameter, and mocking bpftrace already stands in for
        # wherever it would have run.
        capture_kwargs = {"_run": _ssh_run(vm_host)} if (_capture is None and vm_host) else {}

        events, stats = capture(
            duration_s=duration_s, elevation_prefix=elevation_prefix(), **capture_kwargs
        )
        config = Config(
            agent_uid=agent_uid,
            transcript_paths=[transcript_path] if transcript_path else [],
            ground_truth_events=events,
            findings_path=out_dir / FINDINGS_NAME,
            state_path=out_dir / STATE_NAME,
            verdicts_path=out_dir / VERDICTS_NAME,
            runtime=runtime,
            host=host,
            # Same as report(): the self-mod detector watches the monitor's host paths, out of scope
            # for a container reconcile and it would make the count depend on the operator's own FS.
            self_mod_watched_paths=(),
        )
        new_findings = run_once(config)
        # Same "clean != never-ran" rule as report(): an empty findings file says "looked, found
        # nothing"; an absent one says nothing at all. FindingsStore only creates on append.
        (out_dir / FINDINGS_NAME).touch()
        return EbpfLiveResult(
            findings_written=len(new_findings),
            ground_truth_execs=sum(1 for e in events if e.kind == EXEC),
            capture_skipped=stats.lines_skipped,
            capture_window_s=duration_s,
        )

    # -- small helpers ---------------------------------------------------------
    @staticmethod
    def _count_lines(path: Path) -> int:
        if not Path(path).exists():
            return 0
        return sum(1 for line in Path(path).read_text().splitlines() if line.strip())

    @staticmethod
    def _count_orphan_findings(path: Path) -> int:
        if not Path(path).exists():
            return 0
        count = 0
        for line in Path(path).read_text().splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("detector") == "orphan_syscall":
                count += 1
        return count


# --- the printed rollup -------------------------------------------------------------------------


def render(summary: Summary) -> str:
    """Human-readable, and structured so the verdict kinds cannot be read as one number.

    The NONE reasons are printed in full rather than summarised, because a NONE is a claim about
    the *observer* ("this plane structurally cannot see this class of action"), and a claim like
    that has to be legible enough to argue with.
    """
    lines: list[str] = []
    add = lines.append
    add(f"warden report — {summary.instance} ({summary.llm}/{summary.agentwatch_runtime}) on {summary.host}")
    add(f"  scope        uid {summary.uid_range} (derived at report time, never frozen)")
    add(f"  plane        capture proven: {'yes' if summary.capture_proven else 'NO'}"
        f" · {summary.ground_truth_execs} ground-truth execs"
        f" · {summary.transcript_events} self-report events")
    if summary.ground_truth_skipped:
        add(f"               {summary.ground_truth_skipped} audit records UNREAD "
            f"{summary.ground_truth_skip_reasons} — an unreadable capture and an empty one "
            "look the same in an exec count")
    if summary.parse_degraded:
        add("  parse        DEGRADED — CONFIRMED verdicts were downgraded to NONE:")
        for reason in summary.parse_reasons:
            add(f"                 - {reason}")

    headers = {
        PHASE_PROVISIONING: (
            "provisioning phase — before the work window. Actions here often have no authorizing "
            "tool call and are EXPECTED (clone, install, env prep)."
        ),
        PHASE_WORK: "work phase — the accountable one.",
        PHASE_AFTER: (
            "after the run — includes warden's own capture-proof marker exec, which `report` runs "
            "now. Not part of the accountable window."
        ),
    }
    for phase in PHASES:
        counts = summary.phases.get(phase, {})
        if not counts.get("execs"):
            continue
        add("")
        add(f"  {headers[phase]}")
        add(f"    agent-uid execs  {counts.get('execs', 0)}")
        add(f"    evaluated        {counts.get('evaluated', 0)}")
        add(f"      authorized     {counts.get('authorized', 0)}   matched to an authorizing tool call")
        add(f"      CONFIRMED      {counts.get('confirmed', 0)}   action with no authorizing intent")
        add(f"      NONE           {counts.get('none', 0)}   the plane structurally could not observe this")
        for reason, n in sorted(counts.get("none_reasons", {}).items(), key=lambda kv: -kv[1]):
            add(f"                     {n}x {reason}")
        add(f"      GAP            {counts.get('gap', 0)}   entailed counterpart absent on a collected channel")
        add(f"    not evaluated    {counts.get('not_evaluated', 0)}   outside the agent's session "
            "subtree — NOT judged either way")
        by_comm = counts.get("not_evaluated_by_comm", {})
        for name, n in sorted(by_comm.items(), key=lambda kv: -kv[1])[:12]:
            add(f"                     {n}x {name}")
        if by_comm and phase == PHASE_WORK:
            # The lesson of the first real run, printed where it is needed rather than filed in a
            # design doc: these are work-phase actions with no verdict at all, and a reader who
            # skims "0 CONFIRMED" needs to see that before drawing a conclusion from it.
            add("                     ^ these were never reconciled. A forked parent that never")
            add("                       execve'd breaks the ancestry walk, so its whole subtree")
            add("                       falls out of scope — the fork gap. Absence of a CONFIRMED")
            add("                       here is absence of evidence, not evidence of absence.")

    add("")
    add(f"  artifacts    findings: {summary.findings_written} new · verdicts: {summary.verdicts_written}")
    if not summary.verdicts_available:
        add(f"               verdicts NOT emitted — {summary.verdicts_unavailable_reason}")
    if not summary.consistent:
        add(f"  !! {summary.consistency_note}")

    add("")
    add("  honesty")
    add("    not calibrated — this is the mechanism on one run, not an FP/FN rate. No triggers.")
    add("    recall validated for the shell-out case only; the fork gap is reported, not caught.")
    add("    CONFIRMED / NONE / GAP / authorized are separate on purpose — there is no combined")
    add("    'deviation' number, because blind spots and misbehaviour are not the same finding.")
    add("    canon guarantee tier ≤ well_formed; calibration absent.")
    if summary.fork_gap_attestation:
        cause = (summary.fork_gap_attestation.get("cause") or {}).get("kind")
        add(f"    fork-gap fidelity attestation emitted (cause={cause}).")
    return "\n".join(lines)
