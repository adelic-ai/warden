"""P4 — warden's live eBPF reconcile (decision B).

Pins the warden->agentwatch wiring: warden invokes agentwatch's OWN probe loader (with an elevation
prefix — privilege is warden's job) and the captured events reconcile through the SAME run_once the
auditd path uses. bpftrace itself is mocked here via the `_capture` seam; the real spawn is validated
on gembox (P5). What's asserted is the wiring and the honesty rules, not the kernel probe.
"""
from __future__ import annotations

import pytest

from tests.conftest import requires_agentwatch
from warden.report import EbpfLiveResult, Reporter

AGENT_UID = 1000
RUNTIME_EXE = "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"
CG = "225062"


def _forkgap_events():
    """A live agent session + a host-root-injected exec (parent 4999 has no exec record — the fork
    gap), both carrying the container cgroup, exactly as the eBPF probe would emit them."""
    from agentwatch.events import EXEC, GroundTruthEvent

    runtime = GroundTruthEvent(
        ts=100.0, kind=EXEC, pid=1000, ppid=1, uid=AGENT_UID, exe=RUNTIME_EXE, comm="node", cgroup=CG
    )
    injected = GroundTruthEvent(
        ts=200.0, kind=EXEC, pid=5000, ppid=4999, uid=AGENT_UID,
        exe="/tmp/EXP_EXT", comm="EXP_EXT", cgroup=CG,
    )
    return [runtime, injected]


@requires_agentwatch
def test_live_ebpf_surfaces_forkgap_injection_via_run_once(tmp_path):
    from agentwatch.events import ParseStats

    seen = {}

    def cap(*, duration_s, elevation_prefix):
        seen["duration_s"] = duration_s
        seen["elevation_prefix"] = elevation_prefix
        return _forkgap_events(), ParseStats()

    result = Reporter(client=None).reconcile_ebpf_live(
        tmp_path, agent_uid=AGENT_UID, duration_s=7, _capture=cap
    )
    assert isinstance(result, EbpfLiveResult)
    assert result.ground_truth_execs == 2
    # The in-cgroup injected exec with no authorizing tool_use is CONFIRMED -> one orphan finding.
    assert result.findings_written >= 1
    assert result.capture_window_s == 7
    # warden supplies BOTH the window and an elevation prefix — privilege is warden's decision, not
    # agentwatch's (the loader never self-elevates).
    assert seen["duration_s"] == 7
    assert seen["elevation_prefix"] is not None


def test_cli_ebpf_requires_live(capsys):
    # --ebpf is live-only (ephemeral ring buffer); using it after-the-fact must refuse, not silently
    # fall back to auditd. Pure argument handling — no incus, no agentwatch needed.
    import warden.cli as cli

    args = cli.build_parser().parse_args(["report", "--llm", "claude", "--ebpf"])
    rc = cli._report(args)
    assert rc == 1
    assert "live-only" in capsys.readouterr().err


@requires_agentwatch
def test_clean_window_writes_empty_findings_not_absent(tmp_path):
    from agentwatch.events import ParseStats

    def cap(*, duration_s, elevation_prefix):
        return [], ParseStats()  # a quiet window: nothing exec'd

    result = Reporter(client=None).reconcile_ebpf_live(tmp_path, agent_uid=AGENT_UID, _capture=cap)
    assert result.findings_written == 0
    # clean != never-ran: the file must exist so `export` can tell "looked, found nothing" from
    # "never ran" (same rule report() enforces).
    assert (tmp_path / "findings.jsonl").exists()
