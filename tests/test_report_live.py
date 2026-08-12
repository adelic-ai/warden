"""`warden report --live` — reconciling a persistent `dev` home that has no run manifest.

The point of these: the free-form home goes through the SAME reconciliation engine a workload does
(no second reconciler, no lowered honesty bar). warden's only new job is to synthesize the manifest
`report` needs from the live instance + a `--since` boundary."""
import time

import pytest

import pytest as _pytest

from warden.app import WardenApp
from warden.cli import _resolve_live_since
from warden.config import build_config
from warden.report import (
    PROVISIONED_AT_KEY,
    SESSION_STARTED_KEY,
    ReportError,
    live_manifest,
    parse_since,
)
from tests.fakes import (
    FakeAuditRuleInstaller,
    FakeEventSource,
    FakeIncusClient,
    FakeProxyAllowlistController,
)


def _app(client):
    return WardenApp(
        client,
        audit_installer=FakeAuditRuleInstaller(),
        event_source_factory=lambda instance: FakeEventSource(client),
        proxy_controller=FakeProxyAllowlistController(),
    )


def test_parse_since_windows():
    assert parse_since("45m") == 45 * 60
    assert parse_since("2h") == 2 * 3600
    assert parse_since("3d") == 3 * 86400
    assert parse_since("30s") == 30
    # not a window — the caller falls back to treating it as an absolute epoch.
    assert parse_since("1700000000") is None
    assert parse_since("nonsense") is None


def test_dev_up_stamps_the_provisioning_boundary():
    # A live reconcile needs the furnishing->interactive split a workload gets from its manifest.
    client = FakeIncusClient()
    cfg = build_config(instance="warden-dev", flavor="dev", llm="claude", project="warden")
    _app(client).up(cfg)
    stamped = client.config_get("warden-dev", PROVISIONED_AT_KEY, project="warden")
    assert stamped and float(stamped) > 0


def test_dev_reentry_does_not_move_the_boundary():
    # Re-entering an existing home (created=False) must NOT re-stamp, or every reconcile would
    # re-label the whole accumulated session as fresh setup.
    client = FakeIncusClient()
    cfg = build_config(instance="warden-dev", flavor="dev", llm="claude", project="warden")
    app = _app(client)
    app.up(cfg)
    first = client.config_get("warden-dev", PROVISIONED_AT_KEY, project="warden")
    app.up(cfg)  # re-entry
    assert client.config_get("warden-dev", PROVISIONED_AT_KEY, project="warden") == first


def test_live_since_defaults_to_the_session_boundary():
    # The zero-config common case: `warden dev` stamped the session, so `report --live` needs no
    # --since. Session wins over the older furnishing boundary.
    client = FakeIncusClient()
    cfg = build_config(instance="warden-dev", flavor="dev", llm="claude", project="warden")
    _app(client).up(cfg)  # stamps provisioning boundary
    client.config_set("warden-dev", SESSION_STARTED_KEY, "9999.0", project="warden")
    assert _resolve_live_since(client, cfg, None) == 9999.0


def test_live_since_explicit_arg_overrides_the_session():
    client = FakeIncusClient()
    cfg = build_config(instance="warden-dev", flavor="dev", llm="claude", project="warden")
    _app(client).up(cfg)
    client.config_set("warden-dev", SESSION_STARTED_KEY, "9999.0", project="warden")
    # an absolute epoch is taken literally; a relative window is now-anchored (not the session value).
    assert _resolve_live_since(client, cfg, "123.0") == 123.0
    assert abs(_resolve_live_since(client, cfg, "1h") - (time.time() - 3600)) < 5


def test_live_since_refuses_when_no_boundary_and_no_arg():
    client = FakeIncusClient()
    client.launch("images:debian/12", "bare", "warden", "prof")  # no boundary stamped
    cfg = build_config(instance="bare", flavor="dev", llm="claude", project="warden")
    with _pytest.raises(ReportError):
        _resolve_live_since(client, cfg, None)


def test_live_manifest_synthesizes_a_reconcilable_manifest():
    client = FakeIncusClient()
    cfg = build_config(instance="warden-claude", flavor="dev", llm="claude", project="warden")
    _app(client).up(cfg)

    since = time.time() - 3600
    manifest = live_manifest(client, cfg, since=since, out_dir="/tmp/x")

    assert manifest.flavor == "dev"
    assert manifest.auditd_wired is True                    # report refuses without the plane
    assert manifest.started_at == since                     # the --since boundary is the work_from
    assert manifest.ended_at >= since
    assert manifest.llm == "claude"
    assert manifest.agentwatch_runtime == "claude"
    # Claude Code writes here interactively too, so the workload glob is correct for the dev home.
    assert manifest.transcript_glob == "/root/.claude/projects/*/*.jsonl"
    # idmap is DERIVED from the live instance, never invented.
    assert manifest.idmap_uid_start > 0
    assert manifest.idmap_uid_end > manifest.idmap_uid_start
