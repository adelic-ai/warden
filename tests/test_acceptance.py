"""§4's acceptance tests, proven against `FakeIncusClient`.

This is the honest version of §4: the wizard is done when each of these
is one command and each invariant is *proven*, not assumed — but proven
against a real nested Incus, which this build VM cannot run (no root;
see NEEDS-HUMAN.md). What follows proves the same invariants against a
model of Incus's behavior instead. `scripts/run-acceptance-nested.sh` is
the same shape of check, written to run for real once root is available.
"""

from __future__ import annotations

from warden.app import WardenApp
from warden.config import build_config
from tests.fakes import FakeAuditRuleInstaller, FakeEventSource, FakeIncusClient, FakeProxyAllowlistController

PROJECT = "warden"


def _monitored_app(client):
    installer = FakeAuditRuleInstaller()
    proxy = FakeProxyAllowlistController()
    app = WardenApp(
        client,
        audit_installer=installer,
        event_source_factory=lambda instance: FakeEventSource(client),
        proxy_controller=proxy,
    )
    return app, installer, proxy


def _builder_app(client):
    # deliberately NOT wired with an audit_installer/event_source_factory —
    # test 2 requires proving auditd is not needed for this flavor at all.
    proxy = FakeProxyAllowlistController()
    return WardenApp(client, proxy_controller=proxy), proxy


# ---------------------------------------------------------------------------
# Test 1 — `warden up --flavor monitored`
# ---------------------------------------------------------------------------

def test_1_monitored_invariants():
    client = FakeIncusClient()
    app, installer, proxy = _monitored_app(client)
    cfg = build_config(instance="cap-mon", flavor="monitored", llm="claude", project=PROJECT)

    result = app.up(cfg)

    # unprivileged: init at a high subuid, not 0
    assert result.idmap.uid.host_start > 0

    # no host disk device on the profile this instance actually launched with
    from warden.profiles import build_profile
    spec = build_profile("monitored")
    assert "source" not in spec.devices["root"]

    # egress reaches the allowlisted LLM host, and *only* that — not a LAN
    # IP, not some other non-allowlisted domain (proxy.py's is_allowed
    # logic is proven for real, over live traffic, in test_proxy.py; here
    # we prove the monitored flavor hands it exactly the LLM-only list)
    assert proxy.current == ("api.anthropic.com",)
    assert "github.com" not in proxy.current

    # auditd captures a marker exec at the derived uid range
    assert result.capture_proof is not None
    assert result.idmap.uid.contains(result.capture_proof.uid)

    # clean snapshot exists
    assert client.snapshot_exists("cap-mon", "clean", PROJECT)

    # restore re-derives the audit rule and re-proves capture (I6->I5)
    pre_range = installer.installed["cap-mon"]
    reproof = app.restore_and_reprove(cfg)
    post_range = installer.installed["cap-mon"]
    assert post_range != pre_range
    assert reproof is not None
    assert post_range.contains(reproof.uid)
    assert not pre_range.contains(reproof.uid)


# ---------------------------------------------------------------------------
# Test 2 — `warden up --flavor builder`
# ---------------------------------------------------------------------------

def test_2_builder_invariants():
    client = FakeIncusClient()
    app, proxy = _builder_app(client)
    cfg = build_config(
        instance="cap-build", flavor="builder", llm="claude", project=PROJECT,
        repo_url="https://github.com/example/public-repo.git",
    )

    result = app.up(cfg)

    # can git clone a public repo. The image has no git, so provisioning
    # has to install it first — the first real-Incus run skipped that and
    # the clone failed silently (finding 6).
    execs = [" ".join(argv) for (inst, argv) in client.exec_calls if inst == "cap-build"]
    assert any("apt-get install" in e and "git" in e for e in execs), \
        "expected git to be installed before cloning — images:debian/12 has none"
    clone_calls = [e for e in execs if "git clone" in e]
    assert clone_calls, "expected a git clone exec against the instance"
    assert cfg.repo_url in clone_calls[0]
    # and the result is verified, not assumed
    assert any(argv == ["test", "-d", "/root/repo/.git"] for (_, argv) in client.exec_calls)

    # hands-off: skip-permissions
    assert cfg.spec.permission_mode == "skip-permissions"

    # egress reaches GitHub/npm but not the LAN (again: is_allowed's real
    # enforcement is proven live in test_proxy.py; here we check builder
    # gets the wider registries list, not the monitored LLM-only one)
    assert "github.com" in proxy.current
    assert "registry.npmjs.org" in proxy.current

    # no auditd required — note this WardenApp has no audit_installer at
    # all, so if the code path tried to wire it, this would already have
    # raised. Belt and suspenders:
    assert result.capture_proof is None


# ---------------------------------------------------------------------------
# Test 3 — idempotent and reversible
# ---------------------------------------------------------------------------

def test_3_idempotent_and_reversible():
    client = FakeIncusClient()
    app, _, _ = _monitored_app(client)
    cfg = build_config(instance="cap-idem", flavor="monitored", llm="claude", project=PROJECT)

    first = app.up(cfg)
    second = app.up(cfg)  # re-run: no-op, not a duplicate launch (would raise in the fake otherwise)

    assert first.created is True
    assert second.created is False

    removed = app.down("cap-idem", PROJECT)
    assert removed is True
    assert not client.instance_exists("cap-idem", PROJECT)
    # the host is unchanged
    assert client.project_exists(PROJECT)
    assert client.network_exists("wardenbr0")
    assert client.profile_exists("warden-monitored", PROJECT)


# ---------------------------------------------------------------------------
# Test 4 — a monitored capsule and a builder side by side
# ---------------------------------------------------------------------------

def test_4_monitored_and_builder_coexist_with_distinct_idmaps_and_audit_scoping():
    client = FakeIncusClient()
    installer = FakeAuditRuleInstaller()
    monitored_proxy = FakeProxyAllowlistController()
    builder_proxy = FakeProxyAllowlistController()

    monitored_app = WardenApp(
        client,
        audit_installer=installer,
        event_source_factory=lambda instance: FakeEventSource(client),
        proxy_controller=monitored_proxy,
    )
    builder_app = WardenApp(client, proxy_controller=builder_proxy)

    mon_cfg = build_config(instance="cap-mon", flavor="monitored", llm="claude", project=PROJECT)
    build_cfg = build_config(instance="cap-build", flavor="builder", llm="claude", project=PROJECT)

    mon_result = monitored_app.up(mon_cfg)
    build_result = builder_app.up(build_cfg)

    # 1 -> N on one host: both exist, sharing the project/host
    assert client.instance_exists("cap-mon", PROJECT)
    assert client.instance_exists("cap-build", PROJECT)

    # distinct idmaps (security.idmap.isolated=true makes this true by
    # construction — see DECISIONS.md)
    assert mon_result.idmap.uid.host_start != build_result.idmap.uid.host_start
    assert not mon_result.idmap.uid.contains(build_result.idmap.uid.host_start)

    # distinct audit scoping: only the monitored instance has a rule
    assert "cap-mon" in installer.installed
    assert "cap-build" not in installer.installed
    assert mon_result.capture_proof is not None
    assert build_result.capture_proof is None
