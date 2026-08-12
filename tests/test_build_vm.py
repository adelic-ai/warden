import pytest

from warden.build_vm import build_vm_profile, resolve
from warden.egress import ACL_NAME
from warden.profiles import BRIDGE_NAME, validate_no_host_mounts


def test_resolve_unknown_llm_raises():
    with pytest.raises(ValueError):
        resolve("not-a-real-llm")


def test_resolve_runtime_keeps_registries_like_a_container_builder():
    # A build needs the same registries a container builder does — the
    # difference from `flavors.resolve` is everything after provisioning
    # (no idmap/auditd/snapshot), not the allowlist shape.
    spec = resolve("claude")
    assert "github.com" in spec.runtime_allowlist
    assert "registry.npmjs.org" in spec.runtime_allowlist
    assert "api.anthropic.com" in spec.runtime_allowlist


def test_resolve_provisioning_wider_than_runtime():
    spec = resolve("gemini")
    assert "deb.nodesource.com" in spec.provisioning_allowlist
    assert "deb.nodesource.com" not in spec.runtime_allowlist


def test_resolve_extra_allow_lands_in_both_lists():
    spec = resolve("claude", extra_allow=["extra.example.com"])
    assert "extra.example.com" in spec.runtime_allowlist
    assert "extra.example.com" in spec.provisioning_allowlist


def test_build_vm_profile_has_no_container_only_security_keys():
    # security.privileged / security.nesting / security.idmap.isolated are
    # container idmap/nesting knobs — meaningless for a VM, which owns its
    # own kernel. Their absence here is the structural marker that this
    # profile was never meant to go through the container trust model.
    spec = build_vm_profile()
    assert "security.privileged" not in spec.config
    assert "security.nesting" not in spec.config
    assert "security.idmap.isolated" not in spec.config


def test_build_vm_profile_shares_the_same_bridge_and_acl():
    # The one unforgeable signal a VM-root build keeps: its NIC rides the
    # same bridge, under the same egress ACL, as every container — enforced
    # outside the guest kernel, so this must not be a separate ACL/bridge.
    spec = build_vm_profile()
    assert spec.devices["eth0"]["network"] == BRIDGE_NAME
    assert spec.devices["eth0"]["security.acls"] == ACL_NAME


def test_build_vm_profile_root_disk_has_no_host_source():
    spec = build_vm_profile()
    assert spec.devices["root"]["type"] == "disk"
    assert "source" not in spec.devices["root"]


def test_build_vm_profile_devices_pass_no_host_mounts_validation():
    spec = build_vm_profile()
    validate_no_host_mounts(spec.devices)  # must not raise


def test_build_vm_profile_respects_mem_cpu_overrides():
    spec = build_vm_profile(mem="8GiB", cpu="4")
    assert spec.config["limits.memory"] == "8GiB"
    assert spec.config["limits.cpu"] == "4"
