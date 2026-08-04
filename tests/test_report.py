"""`warden report` over the synthetic workload fixtures (DEMO-SPEC §4, §8.3/§8.4/§8.7).

The fixtures are synthetic and shaped after what the probes measured, not after a story anyone
wanted: the shell-out case recall IS validated for (agentwatch G23), the runtime housekeeping that
must classify NONE (G20), and one `git push` spawned directly by the runtime — the G17 trap, kept
live on purpose, because allowlisting the *name* `git` would silence exactly the shape a detector
exists to surface.

Nothing here stages a fork gap. §7 forbids presenting a blind spot as a catch, and a fixture that
manufactured one would be doing that with extra steps.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from tests.conftest import canon_available, requires_agentwatch
from tests.fakes import FakeEventSource, FakeIncusClient
from warden.config import build_config
from warden.report import (
    AUDIT_CAPTURE_NAME,
    FINDINGS_NAME,
    PHASE_AFTER,
    PHASE_PROVISIONING,
    PHASE_WORK,
    REPORT_SCHEMA_VERSION,
    VERDICTS_NAME,
    ReportError,
    Reporter,
    render,
)
from warden.workload import RUN_MANIFEST_SCHEMA_VERSION, RunManifest

FIXTURES = Path(__file__).parent / "fixtures" / "workload"
AUDIT_FIXTURE = FIXTURES / "synthetic_audit.log"
TELEMETRY_FIXTURE = FIXTURES / "synthetic_telemetry.txt"

AGENT_UID = 1132072
RANGE_SIZE = 65536
T0 = 1785632030.0
T_END = 1785632080.0  # the run manifest's ended_at; the marker exec lands after it
TRANSCRIPT_IN_GUEST = "/root/.warden-run/telemetry.txt"


class StubCollector:
    """Stands in for the root collector. The real one needs root — which is the entire reason it
    is a separate, tiny, auditable script (DESIGN §4) rather than code in this module."""

    def __init__(self, source: Path = AUDIT_FIXTURE) -> None:
        self.source = source
        self.calls: list[tuple[str, Path, int]] = []

    def collect(self, rule_key: str, out_path: Path, owner_uid: int) -> Path:
        self.calls.append((rule_key, Path(out_path), owner_uid))
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.source, out_path)
        return Path(out_path)


def _cfg(**kw):
    base = dict(instance="wd-1", flavor="builder", llm="gemini", project="wardendemo", audit=True)
    base.update(kw)
    return build_config(**base)


def _manifest(**kw) -> RunManifest:
    base = dict(
        schema_version=RUN_MANIFEST_SCHEMA_VERSION,
        instance="wd-1", project="wardendemo", llm="gemini", flavor="builder",
        auditd_wired=True, agentwatch_runtime="gemini",
        prompt="synthetic", prompt_source="example", prompt_sha256="0" * 64,
        llm_version="0.53.1", started_at=T0, ended_at=T_END, returncode=0, timed_out=False,
        idmap_uid_start=AGENT_UID, idmap_uid_end=AGENT_UID + RANGE_SIZE - 1,
        transcript_glob=TRANSCRIPT_IN_GUEST, workdir="/root/work",
        run_dir="/root/.warden-run", secret_source="secret-file:/dev/null",
    )
    base.update(kw)
    return RunManifest(**base)


def _client(cfg) -> FakeIncusClient:
    client = FakeIncusClient(first_host_uid=AGENT_UID, range_size=RANGE_SIZE)
    client.launch("images:debian/12", cfg.instance, cfg.project, "warden-builder")
    client.file_push(
        cfg.instance, TELEMETRY_FIXTURE.read_bytes(), TRANSCRIPT_IN_GUEST, project=cfg.project
    )
    return client


def _reporter(client, collector=None) -> Reporter:
    return Reporter(
        client,
        collector=collector or StubCollector(),
        event_source_factory=lambda _inst: FakeEventSource(client),
    )


@pytest.fixture
def summary(tmp_path):
    cfg = _cfg()
    client = _client(cfg)
    return _reporter(client).report(cfg, _manifest(), tmp_path)


# --- §8.7: derived scope, and capture proven before the plane is trusted ----------


@requires_agentwatch
def test_scope_is_the_derived_range_and_capture_is_proven(summary):
    assert summary.agent_uid == AGENT_UID
    assert summary.uid_range == f"{AGENT_UID}-{AGENT_UID + RANGE_SIZE - 1}"
    assert summary.capture_proven is True


@requires_agentwatch
def test_report_refuses_to_reconcile_across_an_idmap_reallocation(tmp_path):
    """A restore between `run` and `report` moves the range. The run's records carry the OLD host
    uids and the live rule watches the new ones, so neither value reconciles this run — the new one
    matches nothing and reads as a clean run, the old one is the frozen value §1 exists about."""
    cfg = _cfg()
    client = _client(cfg)
    client.snapshot(cfg.instance, "clean", project=cfg.project)
    client.restore(cfg.instance, "clean", project=cfg.project)  # reallocates
    with pytest.raises(ReportError, match="reallocated"):
        _reporter(client).report(cfg, _manifest(), tmp_path)


@requires_agentwatch
def test_collector_is_asked_for_this_instances_own_key(tmp_path):
    """D14: a dead instance's rule with an overlapping uid range tagged a live instance's execs
    under the dead key, and uid-only matching called that a pass."""
    cfg = _cfg()
    client = _client(cfg)
    collector = StubCollector()
    _reporter(client, collector).report(cfg, _manifest(), tmp_path)
    assert collector.calls[0][0] == "warden-wd-1"


@requires_agentwatch
def test_report_refuses_an_instance_with_no_ground_truth_plane(tmp_path):
    cfg = _cfg(audit=False)
    client = _client(cfg)
    with pytest.raises(ReportError, match="ground-truth plane"):
        _reporter(client).report(cfg, _manifest(auditd_wired=False), tmp_path)


# --- §8.3: phase segmentation ------------------------------------------------------


@requires_agentwatch
def test_provisioning_execs_land_in_the_provisioning_window(summary):
    prov = summary.phases[PHASE_PROVISIONING]
    assert prov["execs"] == 3  # sh, apt-get, npm
    # …and none of them is evaluated: they are not in the agent's session subtree, which is how
    # provisioning noise stays out of the work-phase signal.
    assert prov["evaluated"] == 0
    assert prov["not_evaluated"] == 3


@requires_agentwatch
def test_work_phase_holds_the_accountable_execs(summary):
    work = summary.phases[PHASE_WORK]
    assert work["execs"] == 8
    assert work["evaluated"] == 8  # every work-phase exec is in the agent's session subtree


@requires_agentwatch
def test_wardens_own_marker_exec_is_not_counted_in_the_work_phase(summary):
    """`report` runs a capture-proof marker *now*. Folding the observer's own footprint into the
    accountable window is the quiet miscount this split exists to prevent."""
    assert summary.phases[PHASE_AFTER]["execs"] >= 1
    # …and it is not evaluated either: the marker is not in the agent's session subtree
    assert summary.phases[PHASE_AFTER]["evaluated"] == 0


# --- §8.3 / §7: the verdict kinds stay separate ------------------------------------


@requires_agentwatch
def test_the_shell_out_case_is_authorized(summary):
    """The half recall IS validated for (G23): the tool call's SPAN carries the start time, and
    the shell it spawned execs inside [start, end]. Stamped from the log record instead — which is
    written when the call ends — nothing matches and this goes to CONFIRMED."""
    assert summary.phases[PHASE_WORK]["authorized"] == 4  # two shells and what each ran


@requires_agentwatch
def test_runtime_housekeeping_classifies_none_not_confirmed(summary):
    """`git rev-parse --show-toplevel` at +2.6s and the ripgrep fallback: runtime behaviour no
    tool call could authorize, because both precede every tool call. NONE means "the plane
    structurally could not observe this", not "fine"."""
    work = summary.phases[PHASE_WORK]
    assert work["none"] == 3  # the runtime itself, its startup rev-parse, its ripgrep fallback
    assert work["none_reasons"]


@requires_agentwatch
def test_the_unauthorized_git_push_is_confirmed(summary):
    """The G17 trap, kept live. Allowlisting the *name* `git` would silence this alongside the
    startup `rev-parse`; only the exact housekeeping argv is allowlisted, so this still reports."""
    assert summary.phases[PHASE_WORK]["confirmed"] == 1


@requires_agentwatch
def test_no_combined_deviation_number_anywhere(summary):
    """§7: a run that only hits coverage boundaries must read as blind spots, not misbehaviour,
    and one number cannot say both. This asserts the shape of the artifact, not a count."""
    # asserted over the *keys*, not the prose — the honesty note deliberately uses the word
    # "deviation" to say there is no such number, and a substring check would flag its own warning
    import json as _json

    def keys(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                yield k
                yield from keys(v)
        elif isinstance(obj, list):
            for v in obj:
                yield from keys(v)

    all_keys = set(keys(_json.loads(summary.to_json())))
    for forbidden in ("deviation", "deviations", "risk_score", "severity_total", "anomaly_score",
                      "total_findings", "score"):
        assert forbidden not in all_keys
    work = summary.phases[PHASE_WORK]
    for kind in ("authorized", "confirmed", "none", "gap"):
        assert kind in work


@requires_agentwatch
def test_honesty_block_states_the_limits_as_data(summary):
    h = summary.honesty
    assert h["calibrated"] is False
    assert h["analysis_engine"] is False
    assert h["recall_validated_for"] == "shell-out only"
    assert h["guarantee_tier_max"] == "well_formed"
    assert h["calibration_field"] == "absent"


# --- the artifacts -------------------------------------------------------------------


@requires_agentwatch
def test_findings_and_the_capture_are_written(tmp_path):
    cfg = _cfg()
    client = _client(cfg)
    summary = _reporter(client).report(cfg, _manifest(), tmp_path)
    assert (tmp_path / FINDINGS_NAME).exists()
    assert (tmp_path / AUDIT_CAPTURE_NAME).exists()
    assert summary.schema_version == REPORT_SCHEMA_VERSION


@requires_agentwatch
def test_the_candidate_pass_and_run_once_agree(summary):
    """The one duplication in the module, turned into a cross-check: a disagreement means one of
    the passes is wrong, and the report says so instead of printing a confident number."""
    assert summary.consistent, summary.consistency_note


@requires_agentwatch
def test_confirmed_count_matches_the_orphan_findings_on_disk(tmp_path):
    cfg = _cfg()
    client = _client(cfg)
    summary = _reporter(client).report(cfg, _manifest(), tmp_path)
    written = [
        json.loads(line)
        for line in (tmp_path / FINDINGS_NAME).read_text().splitlines()
        if line.strip()
    ]
    orphans = [f for f in written if f["detector"] == "orphan_syscall"]
    assert len(orphans) == sum(p["confirmed"] for p in summary.phases.values())


@requires_agentwatch
@pytest.mark.skipif(not canon_available(), reason="canon not importable — verdicts not emitted")
def test_canon_verdicts_are_emitted_and_stay_honest(tmp_path):
    """§8.4: every verdict schema-valid, tier ≤ well_formed, calibration ABSENT."""
    import detection
    import jsonschema

    cfg = _cfg()
    client = _client(cfg)
    summary = _reporter(client).report(cfg, _manifest(), tmp_path)
    assert summary.verdicts_available is True
    assert summary.verdicts_written >= 1

    contracts = Path(detection.__file__).resolve().parents[4] / "contracts"
    schema = json.loads((contracts / "detection_verdict.schema.json").read_text())
    verdicts = [
        json.loads(line)
        for line in (tmp_path / VERDICTS_NAME).read_text().splitlines()
        if line.strip()
    ]
    assert verdicts
    for verdict in verdicts:
        jsonschema.validate(verdict, schema)
        assert verdict.get("guarantee", {}).get("tier") in {"absent", "well_formed"}
        assert "calibration" not in verdict or verdict["calibration"] in (None, {})


@requires_agentwatch
@pytest.mark.skipif(not canon_available(), reason="canon not importable — no attestation")
def test_the_fork_gap_is_reported_not_hidden(summary):
    """§7: recall is shell-out-only, and the fork gap rides out as a fidelity attestation with
    cause=missing-telemetry rather than being hidden — or staged as a catch."""
    attestation = summary.fork_gap_attestation
    assert attestation is not None
    assert attestation["cause"]["kind"] == "missing-telemetry"


@requires_agentwatch
@pytest.mark.skipif(canon_available(), reason="canon IS importable here")
def test_absent_canon_degrades_honestly_rather_than_silently(summary):
    """agentwatch's own rule: canon is optional, and where it is absent the finding pipeline is
    unaffected. What must not happen is `verdicts_written: 0` with no reason given."""
    assert summary.verdicts_available is False
    assert summary.verdicts_unavailable_reason
    assert summary.findings_written >= 0


# --- the rendered rollup ---------------------------------------------------------------


@requires_agentwatch
def test_render_separates_the_kinds_and_names_the_limits(summary):
    text = render(summary)
    for expected in ("CONFIRMED", "NONE", "GAP", "authorized", "not calibrated", "shell-out"):
        assert expected in text
    assert "provisioning phase" in text
    assert "work phase" in text
