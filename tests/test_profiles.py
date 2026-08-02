import pytest

from warden.profiles import (
    ProfileValidationError,
    build_profile,
    project_config,
    validate_no_host_mounts,
)


def test_project_config_requires_features_profiles_with_restricted():
    cfg = project_config()
    assert cfg["restricted"] == "true"
    assert cfg["features.profiles"] == "true"


def test_project_config_pins_bridge_not_auto():
    cfg = project_config()
    assert "auto" not in cfg["restricted.networks.subnets"]


def test_build_profile_no_privileged_no_nesting():
    spec = build_profile("monitored")
    assert spec.config["security.privileged"] == "false"
    assert spec.config["security.nesting"] == "false"


def test_build_profile_idmap_isolated_for_distinct_ranges():
    # this is what makes §4 test 4 ("distinct idmaps") true by construction
    spec = build_profile("monitored")
    assert spec.config["security.idmap.isolated"] == "true"


def test_build_profile_root_disk_has_no_host_source():
    spec = build_profile("builder")
    assert spec.devices["root"]["type"] == "disk"
    assert "source" not in spec.devices["root"]


def test_validate_no_host_mounts_rejects_bind_mount():
    with pytest.raises(ProfileValidationError):
        validate_no_host_mounts({"evil": {"type": "disk", "source": "/home/agent"}})


def test_validate_no_host_mounts_accepts_pool_backed_root():
    validate_no_host_mounts({"root": {"type": "disk", "pool": "wardenpool", "path": "/"}})
