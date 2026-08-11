"""`warden dev` — the persistent, key-free free-form home (ROADMAP step 1). These pin the two
load-bearing properties: it stands up WITHOUT a key, and its home is protected from a stray `down`."""
import pytest

from warden.app import PERSISTENT_KEY, PersistentInstanceError, WardenApp
from warden.config import build_config
from warden.flavors import Flavor, resolve
from warden.standing_rules import render_standing_rules
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


# ---- the flavor ----
def test_dev_flavor_is_keyfree_persistent_audited_and_egress_locked():
    spec = resolve(Flavor.DEV, "claude")
    assert spec.needs_secret is False          # operator brings their own auth interactively
    assert spec.persistent is True             # the daily home
    assert spec.auditd_wired is True           # agentwatch's unforgeable plane
    assert spec.provision_agent_cli is True    # the home comes furnished (CLI installed at up)
    # runtime egress reaches the LLM + dev registries, but NOT the node/npm *install* sources —
    # those are provisioning-only (installed once, then narrowed away).
    assert "api.anthropic.com" in spec.runtime_allowlist
    assert "deb.nodesource.com" not in spec.runtime_allowlist
    assert "deb.nodesource.com" in spec.provisioning_allowlist


def test_dev_egress_reaches_interactive_login_hosts():
    # The operator logs in with their OWN account (no injected key), so the OAuth login + token
    # hosts must be reachable at RUNTIME — a bare LLM-API allowlist would block the login itself.
    gemini = resolve(Flavor.DEV, "gemini")
    assert "accounts.google.com" in gemini.runtime_allowlist       # Google OAuth login
    assert "cloudcode-pa.googleapis.com" in gemini.runtime_allowlist  # free-tier Code Assist API
    claude = resolve(Flavor.DEV, "claude")
    assert "claude.ai" in claude.runtime_allowlist                 # subscription login
    assert "platform.claude.com" in claude.runtime_allowlist       # Claude Code's unified API/auth host
    # workloads authenticate with an injected key, so they must NOT carry the login hosts.
    assert "accounts.google.com" not in resolve(Flavor.MONITORED, "gemini").runtime_allowlist


def test_dev_standing_rules_describe_an_interactive_home_not_a_builder_workload():
    # The bug that shipped: dev fell through to the builder body and told the agent it was a builder
    # with git-push/branch/DECISIONS.md workload discipline. dev is the operator's interactive home.
    rules = render_standing_rules(resolve(Flavor.DEV, "claude"))
    assert "builder" not in rules
    assert "DECISIONS.md" not in rules and "NEEDS-HUMAN" not in rules   # workload discipline, not dev
    assert "interactive" in rules and "persist" in rules
    # the containment facts still belong here — the agent must know egress/audit are expected.
    assert "egress" in rules and "auditd" in rules
    # builder still gets its own body (no regression).
    assert "builder" in render_standing_rules(resolve(Flavor.BUILDER, "claude"))


def test_non_dev_flavors_still_need_a_key_and_are_not_persistent():
    for flavor in (Flavor.MONITORED, Flavor.BUILDER):
        spec = resolve(flavor, "gemini")
        assert spec.needs_secret is True
        assert spec.persistent is False


# ---- key-free up ----
def test_dev_up_needs_no_key():
    # monitored/builder up() would raise NeedsHumanError with no key anywhere; dev must not.
    client = FakeIncusClient()
    cfg = build_config(instance="warden-dev", flavor="dev", llm="claude", project="warden")
    result = _app(client).up(cfg)
    assert result.instance == "warden-dev"
    assert client.instance_exists("warden-dev", "warden")


def test_dev_up_installs_the_agent_cli_at_provisioning():
    # dev has no run step, so the CLI must be installed during up — assert the install script
    # (node + `npm install -g` the CLI) actually ran in the instance.
    client = FakeIncusClient()
    cfg = build_config(instance="warden-dev", flavor="dev", llm="gemini", project="warden")
    _app(client).up(cfg)
    ran = " ".join(cmd for _, argv in client.exec_calls for cmd in argv)
    assert "npm install -g" in ran and "@google/gemini-cli" in ran
    assert "deb.nodesource.com" in ran        # node itself, from the provisioning-only source


def test_dev_instance_is_marked_persistent_on_the_instance():
    client = FakeIncusClient()
    cfg = build_config(instance="warden-dev", flavor="dev", llm="gemini", project="warden")
    _app(client).up(cfg)
    assert client.config_get("warden-dev", PERSISTENT_KEY, project="warden") == "true"


# ---- the home is protected from a stray down (Fork P) ----
def test_down_refuses_a_persistent_home_without_force():
    client = FakeIncusClient()
    cfg = build_config(instance="warden-dev", flavor="dev", llm="claude", project="warden")
    app = _app(client)
    app.up(cfg)

    with pytest.raises(PersistentInstanceError):
        app.down("warden-dev", "warden")
    assert client.instance_exists("warden-dev", "warden")   # NOT deleted

    assert app.down("warden-dev", "warden", force=True) is True
    assert not client.instance_exists("warden-dev", "warden")   # force deletes


def test_down_of_a_non_persistent_instance_is_unaffected():
    client = FakeIncusClient()
    client.launch("images:debian/12", "cap-1", "warden", "prof")   # no persistent marker
    assert _app(client).down("cap-1", "warden") is True
    assert not client.instance_exists("cap-1", "warden")
