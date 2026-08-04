from warden.flavors import Flavor, resolve


def test_monitored_runtime_allowlist_is_llm_only():
    spec = resolve(Flavor.MONITORED, "gemini")
    assert spec.runtime_allowlist == ("generativelanguage.googleapis.com",)
    assert spec.auditd_wired is True
    assert spec.repo_git is False
    assert spec.permission_mode == "gated"


def test_monitored_provisioning_is_wider_than_runtime():
    spec = resolve(Flavor.MONITORED, "claude")
    assert set(spec.runtime_allowlist) < set(spec.provisioning_allowlist)
    assert "deb.debian.org" in spec.provisioning_allowlist
    assert "deb.debian.org" not in spec.runtime_allowlist


def test_builder_runtime_keeps_registries_not_just_llm():
    spec = resolve(Flavor.BUILDER, "claude")
    assert "github.com" in spec.runtime_allowlist
    assert "registry.npmjs.org" in spec.runtime_allowlist
    assert spec.repo_git is True
    assert spec.auditd_wired is False
    assert spec.permission_mode == "skip-permissions"


def test_builder_provisioning_wider_still_includes_node_setup():
    spec = resolve(Flavor.BUILDER, "gemini")
    assert "deb.nodesource.com" in spec.provisioning_allowlist
    assert "deb.nodesource.com" not in spec.runtime_allowlist


def test_extra_allow_domains_land_in_both_lists():
    spec = resolve(Flavor.MONITORED, "claude", extra_allow=["extra.example.com"])
    assert "extra.example.com" in spec.runtime_allowlist
    assert "extra.example.com" in spec.provisioning_allowlist


def test_both_flavors_always_snapshot():
    assert resolve(Flavor.MONITORED, "claude").snapshot is True
    assert resolve(Flavor.BUILDER, "claude").snapshot is True


# --- the `--audit` toggle (DEMO-SPEC §11.1) ----------------------------------
# A config toggle, not a third flavor: reconciliation needs both planes, and
# `builder` — the flavor with a repo and a git history worth reconciling —
# shipped with only the self-report one.


def test_builder_audit_toggle_wires_the_ground_truth_plane():
    spec = resolve(Flavor.BUILDER, "gemini", audit=True)
    assert spec.auditd_wired is True
    # and nothing else moves — this is data, not a new codepath
    plain = resolve(Flavor.BUILDER, "gemini")
    assert spec.name == plain.name
    assert spec.repo_git == plain.repo_git
    assert spec.permission_mode == plain.permission_mode
    assert spec.runtime_allowlist == plain.runtime_allowlist
    assert spec.provisioning_allowlist == plain.provisioning_allowlist


def test_builder_audit_defaults_off():
    assert resolve(Flavor.BUILDER, "claude").auditd_wired is False


def test_monitored_is_already_audited_and_the_flag_is_a_no_op():
    """"Make sure this is audited" is a reasonable thing to say about an
    instance that already is — not an error."""
    assert resolve(Flavor.MONITORED, "claude", audit=True).auditd_wired is True
    assert resolve(Flavor.MONITORED, "claude", audit=False).auditd_wired is True
