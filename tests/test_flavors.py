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
