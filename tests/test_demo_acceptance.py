"""DEMO-SPEC §8 acceptance, at the level this machine can honestly prove it.

**What this is and is not.** §8 asks for the five-command loop on a fresh real host. This file
proves the same criteria against `FakeIncusClient` plus the checked-in synthetic planes — the same
arrangement `test_acceptance.py` uses for the wizard's own §4, and for the same reason. Two things
are therefore NOT proven here and are not claimed to be:

  * that the Gemini CLI, driven with `--skip-trust -p`, actually runs to completion hands-off and
    writes the telemetry file the adapter expects;
  * that a real auditd rule captures that run's execs at the derived range.

Both need a real host and a key. Until they run, the honest statement is "logic validated on
fixtures, one real run pending" — see NEEDS-HUMAN.md. The two planes here are substituted with the
synthetic fixtures rather than pretended into existence by the fake, so it is visible in the code
which half is modelled.

Criterion §8.4 (schema-valid, SHACL `well_formed`, tiers not inflated, calibration absent) IS
proven for real against canon's own API wherever canon is importable — that check is not modelled.
"""

from __future__ import annotations

import json
import tarfile
from pathlib import Path

import pytest

from tests.conftest import canon_available, requires_agentwatch
from tests.fakes import (
    FakeAuditRuleInstaller,
    FakeEventSource,
    FakeIncusClient,
    FakeProxyAllowlistController,
)
from tests.test_report import (
    AGENT_UID,
    AUDIT_FIXTURE,
    RANGE_SIZE,
    TELEMETRY_FIXTURE,
    StubCollector,
)
from warden.app import WardenApp
from warden.config import build_config
from warden.example_prompt import EXAMPLE_PROMPT
from warden.export import CONTENTS_NAME, GIT_LOG_NAME, READ_ME, WORKREPO_TAR, Exporter
from warden.incus import ExecResult
from warden.report import (
    AUDIT_CAPTURE_NAME,
    FINDINGS_NAME,
    PHASE_PROVISIONING,
    PHASE_WORK,
    REPORT_NAME,
    TRANSCRIPT_NAME,
    VERDICTS_NAME,
    Reporter,
)
from warden.workload import MANIFEST_NAME, WorkloadRunner, run_dir_for

PROJECT = "wardendemo"  # never `warden` — the demo runs in its own isolated project
INSTANCE = "wd-demo"
TRANSCRIPT_IN_GUEST = "/root/.warden-run/telemetry.txt"

# The fixture's clock. The loop's manifest is rewritten to these so the phase split has the
# fixture's own boundary rather than wall-clock noise.
T0 = 1785632030.0
T_END = 1785632080.0


def _cfg(secret_file: Path | None = None):
    return build_config(
        instance=INSTANCE, flavor="builder", llm="gemini", project=PROJECT, audit=True,
        secret_file=secret_file,
    )


class DemoLoop:
    """up → run → report → export → down, on one fake client. Each step is one call, which is
    §8.1's actual claim: the loop is five commands, not five commands plus glue."""

    def __init__(self, tmp_path: Path):
        self.tmp = tmp_path
        # A synthetic key file. `up` and `run` both refuse a gemini instance without one — the
        # wizard's "stops before a real run without it" rule — so the loop needs a path to point
        # at. The bytes are nonsense and no real endpoint is ever contacted.
        self.secret_file = tmp_path / "synthetic.key"
        self.secret_file.write_text("SYNTHETIC-NOT-A-KEY")
        self.cfg = _cfg(secret_file=self.secret_file)
        self.client = FakeIncusClient(first_host_uid=AGENT_UID, range_size=RANGE_SIZE)
        self.installer = FakeAuditRuleInstaller()
        self.proxy = FakeProxyAllowlistController()
        self.run_dir = run_dir_for(tmp_path / "runs", PROJECT, INSTANCE)

    def up(self):
        app = WardenApp(
            self.client,
            audit_installer=self.installer,
            event_source_factory=lambda _i: FakeEventSource(self.client),
            proxy_controller=self.proxy,
        )
        self.up_result = app.up(self.cfg)
        return self.up_result

    def run(self):
        runner = WorkloadRunner(self.client, proxy_controller=self.proxy)
        manifest = runner.run(
            self.cfg, EXAMPLE_PROMPT, prompt_source="example", secret_file=self.secret_file
        )
        # --- the modelled half, marked as such -------------------------------
        # A real Gemini CLI writes its OTel telemetry here and leaves a git history in the
        # workdir. The fake runs no agent, so both planes are substituted from the fixtures, and
        # the manifest's clock is set to the fixture's window.
        self.client.file_push(
            self.cfg.instance, TELEMETRY_FIXTURE.read_bytes(), TRANSCRIPT_IN_GUEST,
            project=self.cfg.project,
        )
        self.client.file_push(
            self.cfg.instance, b"SYNTHETIC-REPO-TARBALL", "/root/.warden-run/workrepo.tar.gz",
            project=self.cfg.project,
        )
        self.client.exec_results["git -C"] = ExecResult(
            0, "commit deadbeef\nAuthor: agent <agent@example>\n\n    add slugify + tests\n", ""
        )
        from dataclasses import replace

        self.manifest = replace(manifest, started_at=T0, ended_at=T_END)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        (self.run_dir / MANIFEST_NAME).write_text(self.manifest.to_json())
        return self.manifest

    def report(self):
        reporter = Reporter(
            self.client,
            collector=StubCollector(AUDIT_FIXTURE),
            event_source_factory=lambda _i: FakeEventSource(self.client),
        )
        self.summary = reporter.report(self.cfg, self.manifest, self.run_dir)
        (self.run_dir / REPORT_NAME).write_text(self.summary.to_json())
        return self.summary

    def export(self):
        self.export_result = Exporter(self.client).export(
            self.cfg, self.manifest, self.run_dir, self.tmp / "out"
        )
        return self.export_result

    def down(self):
        app = WardenApp(self.client, audit_installer=self.installer)
        return app.down(self.cfg.instance, self.cfg.project)


@pytest.fixture
def loop(tmp_path):
    demo = DemoLoop(tmp_path)
    demo.up()
    demo.run()
    demo.report()
    demo.export()
    return demo


# --- §8.1 the five-command loop ------------------------------------------------------


@requires_agentwatch
def test_8_1_the_five_command_loop_runs_end_to_end(loop):
    assert loop.up_result.instance == INSTANCE
    assert loop.manifest.prompt_source == "example"
    assert loop.summary.capture_proven is True
    assert loop.export_result.archive.exists()
    assert loop.down() is True


@requires_agentwatch
def test_8_1_the_demo_runs_in_its_own_project_not_the_capsules(loop):
    """The demo must never share a project with a co-located capsule build."""
    assert loop.cfg.project == "wardendemo"
    assert loop.client.list_instances("warden") == []


# --- §8.2 the example run produces a work product -------------------------------------


@requires_agentwatch
def test_8_2_the_example_prompt_asks_for_a_real_build(loop):
    """Not rigged (§6/§7): no fork-gap staging, no planted orphan, no egress probe. Asserted on
    the shipped text so a later "improvement" that adds a gotcha fails here."""
    prompt = EXAMPLE_PROMPT.lower()
    assert "git init" in prompt and "unittest" in prompt and "commit" in prompt
    for staged in ("&", "nohup", "background", "curl", "wget", "fork"):
        assert staged not in prompt
    assert loop.manifest.prompt == EXAMPLE_PROMPT


@requires_agentwatch
def test_8_2_a_transcript_and_a_git_history_result(loop):
    assert (loop.run_dir / TRANSCRIPT_NAME).exists()
    assert (loop.run_dir / GIT_LOG_NAME).exists()
    assert "commit" in (loop.run_dir / GIT_LOG_NAME).read_text()


# --- §8.3 findings + verdicts + a summary that segments and breaks out ----------------


@requires_agentwatch
def test_8_3a_the_summary_segments_provisioning_from_work(loop):
    phases = loop.summary.phases
    assert phases[PHASE_PROVISIONING]["execs"] > 0
    assert phases[PHASE_WORK]["execs"] > 0
    # provisioning is out of the agent's session subtree, so it cannot drown the work signal
    assert phases[PHASE_PROVISIONING]["evaluated"] == 0


@requires_agentwatch
def test_8_3b_the_summary_breaks_out_the_verdict_kinds_separately(loop):
    work = loop.summary.phases[PHASE_WORK]
    for kind in ("authorized", "confirmed", "none", "gap"):
        assert kind in work
    # all four are genuinely distinguished on this run, not just present as keys
    assert work["authorized"] > 0
    assert work["confirmed"] > 0
    assert work["none"] > 0
    assert work["none_reasons"]


@requires_agentwatch
def test_8_3_findings_jsonl_exists_even_for_a_clean_run(loop):
    assert (loop.run_dir / FINDINGS_NAME).exists()


# --- §8.4 the honesty assertion, against canon's real API -----------------------------


@requires_agentwatch
@pytest.mark.skipif(not canon_available(), reason="canon not importable")
def test_8_4_every_verdict_is_schema_valid_and_shacl_well_formed(loop):
    """The §8.4 criterion, proven for real: schema, SHACL `well_formed`, and the provenance DAG.

    Not modelled — this is canon's own validator over the verdicts warden actually wrote."""
    import detection
    import jsonschema
    from provenance import to_prov, validate_graph, well_formed_shapes

    canon_root = Path(detection.__file__).resolve().parents[4]
    contracts = canon_root / "contracts"
    schema = json.loads((contracts / "detection_verdict.schema.json").read_text())

    shapes = well_formed_shapes()
    for shape in ("detection.shapes.ttl", "cross_model.shapes.ttl"):
        path = contracts / "shapes" / shape
        if path.exists():
            shapes.parse(path, format="turtle")

    verdicts = [
        json.loads(line)
        for line in (loop.run_dir / VERDICTS_NAME).read_text().splitlines()
        if line.strip()
    ]
    assert verdicts, "the run produced no verdicts to validate"
    for verdict in verdicts:
        jsonschema.validate(verdict, schema)

    # …and the provenance cid each verdict carries resolves to a well-formed PROV-O DAG.
    from agentwatch import canon_emit, runtimes
    from agentwatch.groundtruth import audit_log
    from agentwatch.reconciler.orphan import DEFAULT_WINDOW_SECONDS, reconcile_orphans_scoped
    from agentwatch.reconciler.verdict import Verdict

    profile = runtimes.resolve(loop.manifest.agentwatch_runtime)
    with (loop.run_dir / AUDIT_CAPTURE_NAME).open(encoding="utf-8") as fh:
        gt_events, _ = audit_log.parse_lines(fh)
    transcript = list(profile.adapter_factory().parse_file(loop.run_dir / TRANSCRIPT_NAME))
    confirmed = [
        c for c in reconcile_orphans_scoped(
            gt_events, transcript, agent_uid=loop.summary.agent_uid,
            scope_tuning=profile.scope_tuning,
        )
        if c.verdict == Verdict.CONFIRMED
    ]
    assert confirmed
    emitted_cids = {v["provenance"] for v in verdicts}
    for candidate in confirmed:
        root = canon_emit.orphan_provenance_root(
            candidate, host=loop.summary.host, agent_uid=loop.summary.agent_uid,
            window_seconds=DEFAULT_WINDOW_SECONDS,
        )
        assert root.id in emitted_cids, "verdict provenance does not resolve to its root"
        report = validate_graph(to_prov(root), shapes)
        assert report.conforms, report.text


@requires_agentwatch
@pytest.mark.skipif(not canon_available(), reason="canon not importable")
def test_8_4_tiers_are_not_inflated_and_calibration_is_absent(loop):
    """The anti-theatre gate. `bounded`/`machine_checked` would claim a calibration agentwatch
    does not have, and a present `calibration` block would claim a bound nobody computed."""
    verdicts = [
        json.loads(line)
        for line in (loop.run_dir / VERDICTS_NAME).read_text().splitlines()
        if line.strip()
    ]
    for verdict in verdicts:
        assert verdict.get("guarantee", {}).get("tier") in {"absent", "well_formed"}
        assert verdict.get("calibration") in (None, {}, [])
    assert loop.summary.honesty["calibrated"] is False
    assert loop.summary.honesty["guarantee_tier_max"] == "well_formed"


# --- §8.5 the tarball ------------------------------------------------------------------


@requires_agentwatch
def test_8_5_the_tarball_contains_everything_asked_for(loop):
    with tarfile.open(loop.export_result.archive) as tar:
        names = {Path(m.name).name for m in tar.getmembers()}
    for expected in (
        TRANSCRIPT_NAME, FINDINGS_NAME, WORKREPO_TAR, GIT_LOG_NAME,
        AUDIT_CAPTURE_NAME, MANIFEST_NAME, REPORT_NAME, CONTENTS_NAME, READ_ME,
    ):
        assert expected in names, expected
    if canon_available():
        assert VERDICTS_NAME in names


# --- §8.6 reversibility ----------------------------------------------------------------


@requires_agentwatch
def test_8_6_down_removes_the_instance_and_takes_its_audit_rule(loop):
    substrate_before = (
        set(loop.client.projects), set(loop.client.networks),
        set(loop.client.profiles), set(loop.client.storage_pools),
    )
    assert loop.down() is True
    assert not loop.client.instance_exists(INSTANCE, PROJECT)
    # the rule goes with it — a dead instance's rule shadowing a live one's range is D14
    assert INSTANCE not in loop.installer.installed
    # …and nothing else moved: the shared substrate is left as it was
    assert substrate_before == (
        set(loop.client.projects), set(loop.client.networks),
        set(loop.client.profiles), set(loop.client.storage_pools),
    )


# --- §8.7 derived scope, marker proven before the plane is trusted ----------------------


@requires_agentwatch
def test_8_7_scope_is_derived_and_capture_is_proven_before_reporting(loop):
    assert loop.summary.agent_uid == AGENT_UID
    assert loop.summary.capture_proven is True
    # the rule was installed against the DERIVED range, not a constant
    assert loop.installer.installed[INSTANCE].host_start == AGENT_UID


@requires_agentwatch
def test_8_7_the_manifest_range_is_a_record_not_the_scope(loop):
    """`report` re-derives and compares; it never reads the manifest's range as its scope. The
    frozen-idmap bug has bitten three times, and a manifest is the most plausible cache yet."""
    assert loop.manifest.idmap_uid_start == loop.summary.agent_uid  # they agree here…
    # …and when they cannot, report refuses rather than picking one (see test_report.py)
