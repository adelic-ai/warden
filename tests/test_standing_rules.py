from warden.flavors import Flavor, resolve
from warden.standing_rules import render_standing_rules, standing_rules_filename


def test_filename_matches_llm():
    assert standing_rules_filename("gemini") == "GEMINI.md"
    assert standing_rules_filename("claude") == "CLAUDE.md"


def test_monitored_rules_mention_gated_and_auditd():
    spec = resolve(Flavor.MONITORED, "gemini")
    text = render_standing_rules(spec)
    assert "gated" in text.lower()
    assert "auditd" in text.lower()


def test_builder_rules_mention_skip_permissions():
    spec = resolve(Flavor.BUILDER, "claude")
    text = render_standing_rules(spec)
    assert "skip-permissions" in text.lower()


def test_both_forbid_self_modification():
    for flavor in (Flavor.MONITORED, Flavor.BUILDER):
        text = render_standing_rules(resolve(flavor, "claude"))
        assert "never modify your own" in text.lower()
