import pytest

from warden.profiles import (
    BRIDGE_GATEWAY,
    BRIDGE_SUBNET,
    CGNAT_RANGE,
    BridgeSubnetError,
    ProfileValidationError,
    assert_subnet_sane,
    build_profile,
    network_config,
    project_config,
    validate_no_host_mounts,
)


def test_project_config_requires_features_profiles_with_restricted():
    cfg = project_config()
    assert cfg["restricted"] == "true"
    assert cfg["features.profiles"] == "true"


def test_project_config_confines_the_project_to_wardens_bridge():
    cfg = project_config()
    assert cfg["restricted.networks.access"] == "wardenbr0"
    # `restricted.networks.subnets` takes <uplink>:<subnet> pairs, not a
    # bare network name; setting it to one is rejected by Incus. The first
    # real run's project had it silently absent as a result.
    assert "restricted.networks.subnets" not in cfg


def test_project_config_allows_snapshots():
    """`restricted=true` blocks snapshot creation by default, and the clean
    snapshot + restore is load-bearing for I6."""
    assert project_config()["restricted.snapshots"] == "allow"


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


def test_bridge_subnet_is_outside_cgnat():
    """The Tailscale finding. 100.64.0.0/10 is the range Tailscale allocates
    every node from and routes as a whole; a managed bridge with a /24 inside
    it is more specific and wins, so the tailnet loses those addresses — and
    an operator driving warden over the tailnet can lose the host itself."""
    from ipaddress import ip_interface

    assert not ip_interface(BRIDGE_SUBNET).network.subnet_of(CGNAT_RANGE)


def test_bridge_subnet_is_private():
    from ipaddress import ip_interface

    assert ip_interface(BRIDGE_SUBNET).network.is_private


def test_assert_subnet_sane_rejects_a_cgnat_subnet():
    """The old default, pinned as a rejection so it cannot come back."""
    with pytest.raises(BridgeSubnetError):
        assert_subnet_sane("100.89.0.1/24")


def test_network_config_refuses_to_build_a_cgnat_bridge():
    """The guard is on the constructor, not only on the constant — a caller
    passing an explicit subnet is checked too."""
    with pytest.raises(BridgeSubnetError):
        network_config("100.100.5.1/24")


def test_gateway_matches_the_subnet():
    assert BRIDGE_GATEWAY == BRIDGE_SUBNET.split("/")[0]
