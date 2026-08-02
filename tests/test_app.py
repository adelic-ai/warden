import pytest

from warden.app import WardenApp
from warden.auditd import CaptureNotProvenError
from warden.config import build_config
from tests.fakes import FakeAuditRuleInstaller, FakeEventSource, FakeIncusClient, FakeProxyAllowlistController


def _app(client):
    installer = FakeAuditRuleInstaller()
    proxy = FakeProxyAllowlistController()
    return WardenApp(
        client,
        audit_installer=installer,
        event_source_factory=lambda instance: FakeEventSource(client),
        proxy_controller=proxy,
    ), installer, proxy


def test_up_creates_substrate_and_instance():
    client = FakeIncusClient()
    app, installer, proxy = _app(client)
    cfg = build_config(instance="cap-1", flavor="monitored", llm="claude", project="warden")

    result = app.up(cfg)

    assert result.created is True
    assert client.project_exists("warden")
    assert client.network_exists("wardenbr0")
    assert client.instance_exists("cap-1", "warden")
    assert result.capture_proof is not None
    assert "cap-1" in installer.installed
    assert proxy.current == cfg.spec.runtime_allowlist


def test_up_is_idempotent():
    client = FakeIncusClient()
    app, _, _ = _app(client)
    cfg = build_config(instance="cap-1", flavor="builder", llm="claude", project="warden")

    first = app.up(cfg)
    second = app.up(cfg)

    assert first.created is True
    assert second.created is False  # no-op re-run, not a duplicate launch


def test_builder_has_no_audit_installed():
    client = FakeIncusClient()
    app, installer, _ = _app(client)
    cfg = build_config(instance="cap-b", flavor="builder", llm="claude", project="warden")

    result = app.up(cfg)

    assert result.capture_proof is None
    assert "cap-b" not in installer.installed


def test_down_removes_instance_leaves_substrate():
    client = FakeIncusClient()
    app, _, _ = _app(client)
    cfg = build_config(instance="cap-1", flavor="builder", llm="claude", project="warden")
    app.up(cfg)

    removed = app.down("cap-1", "warden")

    assert removed is True
    assert not client.instance_exists("cap-1", "warden")
    assert client.project_exists("warden")  # host substrate unchanged
    assert client.network_exists("wardenbr0")


def test_down_is_idempotent_when_already_gone():
    client = FakeIncusClient()
    app, _, _ = _app(client)
    assert app.down("nope", "warden") is False


def test_up_refuses_gemini_without_key(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    client = FakeIncusClient()
    app, _, _ = _app(client)
    cfg = build_config(instance="cap-1", flavor="monitored", llm="gemini", project="warden")

    with pytest.raises(Exception):
        app.up(cfg)
    # and nothing got created as a side effect of the aborted attempt
    assert not client.instance_exists("cap-1", "warden")


def test_restore_and_reprove_rewires_after_reallocation():
    client = FakeIncusClient()
    app, installer, _ = _app(client)
    cfg = build_config(instance="cap-1", flavor="monitored", llm="claude", project="warden")
    app.up(cfg)
    pre_restore_range = installer.installed["cap-1"]

    event = app.restore_and_reprove(cfg)

    assert event is not None
    post_restore_range = installer.installed["cap-1"]
    assert post_restore_range != pre_restore_range
    assert post_restore_range.contains(event.uid)
