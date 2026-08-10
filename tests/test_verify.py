"""`warden verify` — the runtime prover. These pin the measurement logic that makes a `verify` green
*measured*, not assumed: an unmeasured/blocked probe must never read as a pass (the D17/D18 rule)."""
import pytest

from warden.app import (
    WardenApp,
    _http_code,
    interpret_egress,
)
from warden.config import build_config
from warden.incus import ExecResult, IncusTimeoutError
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


# ---- pure: _http_code — a missing/garbage code is '' (never a code, so never a pass) ----
@pytest.mark.parametrize("stdout,expected", [
    ("200", "200"), (" 403 ", "403"), ("000", "000"),
    ("", ""), ("20", ""), ("2000", ""), ("abc", ""), ("2x0", ""),
])
def test_http_code_extracts_three_digits_or_empties(stdout, expected):
    assert _http_code(ExecResult(0, stdout, "")) == expected


# ---- pure: interpret_egress ----
def test_egress_all_good_is_pass():
    assert interpret_egress("200", "403", "000").status == "pass"


@pytest.mark.parametrize("allow,deny_proxy,deny_direct,why", [
    ("000", "403", "000", "allow host blocked -> allowlist broke the allow path"),
    ("403", "403", "000", "allow host refused by proxy -> allowlist broke the allow path"),
    ("200", "200", "000", "non-allowlisted host SERVED via proxy -> allowlist not enforced"),
    ("200", "403", "200", "non-allowlisted host reachable DIRECT -> network default-drop off"),
    ("", "403", "000", "allow probe produced no code -> not measured"),
    ("200", "", "000", "deny-proxy probe produced no code -> not measured"),
    ("200", "403", "", "deny-direct probe produced no code -> not measured"),
])
def test_egress_failures_are_failures_not_silent_passes(allow, deny_proxy, deny_direct, why):
    assert interpret_egress(allow, deny_proxy, deny_direct).status == "fail", why


def test_egress_lan_reachable_is_fail():
    assert interpret_egress("200", "403", "000", lan_direct_code="200").status == "fail"


def test_egress_lan_blocked_is_pass():
    assert interpret_egress("200", "403", "000", lan_direct_code="000").status == "pass"


# ---- integration: verify() against the fake substrate ----
def _up_then_probe(client, cfg, codes):
    """Bring the instance up, then register canned curl responses so verify's egress probes read
    them. codes = (allow, deny_proxy, deny_direct). The `--noproxy` needle is the direct probe;
    the per-host `-m 20` needles are the proxy probes (allow host vs the non-allowlisted example.com)."""
    app = _app(client)
    app.up(cfg)
    allow_code, deny_proxy_code, deny_direct_code = codes
    allow_host = cfg.spec.runtime_allowlist[0]
    client.exec_results["--noproxy"] = ExecResult(0, deny_direct_code, "")
    client.exec_results[f"-m 20 https://{allow_host}"] = ExecResult(0, allow_code, "")
    client.exec_results["-m 20 https://example.com"] = ExecResult(0, deny_proxy_code, "")
    return app.verify(cfg)


def test_verify_all_rings_pass_on_a_sound_cage():
    client = FakeIncusClient()
    cfg = build_config(instance="cap-1", flavor="monitored", llm="claude", project="warden")
    result = _up_then_probe(client, cfg, ("200", "403", "000"))
    by = {r.ring: r.status for r in result.rings}
    assert by == {"instance": "pass", "unprivileged": "pass", "egress": "pass", "audit-capture": "pass"}
    assert result.ok


def test_verify_catches_a_direct_egress_leak():
    client = FakeIncusClient()
    cfg = build_config(instance="cap-1", flavor="monitored", llm="claude", project="warden")
    result = _up_then_probe(client, cfg, ("200", "403", "200"))  # example.com reachable DIRECT
    by = {r.ring: r for r in result.rings}
    assert by["egress"].status == "fail"
    assert "default-drop" in by["egress"].detail
    assert not result.ok


def test_verify_instance_not_found_is_a_single_fail():
    client = FakeIncusClient()
    cfg = build_config(instance="ghost", flavor="monitored", llm="claude", project="warden")
    result = _app(client).verify(cfg)
    assert [r.ring for r in result.rings] == ["instance"]
    assert result.rings[0].status == "fail"
    assert not result.ok


def test_verify_skips_audit_capture_for_a_flavor_without_auditd():
    client = FakeIncusClient()
    cfg = build_config(instance="cap-b", flavor="builder", llm="claude", project="warden")
    result = _up_then_probe(client, cfg, ("200", "403", "000"))
    by = {r.ring: r.status for r in result.rings}
    assert by["audit-capture"] == "skip"   # builder flavor: auditd not wired
    assert result.ok                       # skip is not a fail


class _ExecAlwaysTimesOut:
    """A client whose every exec raises — stands in for a wedged daemon / a hung probe."""

    def exec(self, name, argv, project="default", **kwargs):
        raise IncusTimeoutError(argv, 6.0)


def test_egress_probe_survives_an_exec_timeout_as_empty_not_a_crash():
    # A slow/hung probe must fail the ring (empty code -> interpret_egress fails), never escape as
    # a raw traceback. This is the error-handling gap the verify feature would otherwise introduce.
    app = WardenApp(_ExecAlwaysTimesOut())
    cfg = build_config(instance="cap-1", flavor="monitored", llm="claude", project="warden")
    assert app._egress_probe(cfg, "https://anything/", direct=False) == ""
    assert app._egress_probe(cfg, "https://anything/", direct=True) == ""
