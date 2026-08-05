import pytest

from warden.egress import (
    ACL_NAME,
    PRIVATE_RANGES,
    EgressPolicyError,
    assert_enforceable,
    build_acl_document,
    lan_drops,
)
from warden.profiles import BRIDGE_GATEWAY, BRIDGE_SUBNET

GW = "203.0.113.1"  # outside every private range — exercises the no-carve-out path
PORT = 3128


def test_acl_uses_drop_not_reject():
    doc = build_acl_document(GW, PORT)
    actions = {r["action"] for r in doc["egress"] + doc["ingress"]}
    assert "reject" not in actions
    assert "drop" in actions


def test_acl_allows_only_the_proxy_port_outbound_to_the_gateway():
    doc = build_acl_document(GW, PORT)
    allowed = {
        (r.get("protocol"), r.get("destination"), r.get("destination_port"))
        for r in doc["egress"]
        if r["action"] == "allow"
    }
    assert ("tcp", f"{GW}/32", str(PORT)) in allowed
    # DNS and DHCP to the bridge only; nothing else, and nothing to anywhere else.
    assert all(dest == f"{GW}/32" for _, dest, _ in allowed)
    assert {port for _, _, port in allowed} == {str(PORT), "53", "67"}


def test_acl_drops_the_lan():
    doc = build_acl_document(GW, PORT)
    dropped = {r["destination"] for r in doc["egress"] if r["action"] == "drop"}
    assert "192.168.0.0/16" in dropped


def test_acl_never_drops_the_bridge_itself():
    """A drop covering the gateway would shadow the proxy allow, and the
    capsule build measured that drops outrank allows on this Incus."""
    doc = build_acl_document(GW, PORT)
    for rule in doc["egress"]:
        if rule["action"] == "drop":
            assert not rule["destination"].startswith("203.0.113.")


def test_generated_document_passes_the_guard():
    assert_enforceable(build_acl_document(GW, PORT), GW, PORT)


def test_guard_catches_reject():
    doc = build_acl_document(GW, PORT)
    doc["egress"].append({"action": "reject", "destination": "203.0.113.0/24", "state": "enabled"})
    with pytest.raises(EgressPolicyError):
        assert_enforceable(doc, GW, PORT)


def test_guard_catches_a_missing_proxy_allow():
    doc = build_acl_document(GW, PORT)
    doc["egress"] = [r for r in doc["egress"] if r.get("destination_port") != str(PORT)]
    with pytest.raises(EgressPolicyError):
        assert_enforceable(doc, GW, PORT)


def test_guard_catches_a_drop_that_shadows_the_proxy_allow():
    doc = build_acl_document(GW, PORT)
    doc["egress"].append({"action": "drop", "destination": "203.0.113.0/24", "state": "enabled"})
    with pytest.raises(EgressPolicyError):
        assert_enforceable(doc, GW, PORT)


def test_acl_name_is_stable():
    # profiles.build_profile bakes this into the NIC device.
    assert ACL_NAME == "warden-egress"


# --- the real bridge, which now lives inside one of the LAN drop ranges -------
# Before the Tailscale fix the bridge was in CG-NAT, so "the bridge's own
# subnet is not dropped" was true by accident. It is now enforced.


def test_the_real_bridge_document_passes_the_guard():
    """The regression that actually fired: moving the bridge to 172.29.0.1/24
    put it inside the 172.16.0.0/12 drop, which would have shadowed the proxy
    allow and left the container with no egress at all."""
    doc = build_acl_document(BRIDGE_GATEWAY, PORT, BRIDGE_SUBNET)
    assert_enforceable(doc, BRIDGE_GATEWAY, PORT)


def test_carve_out_still_drops_the_rest_of_the_containing_range():
    """The bridge /24 is subtracted, not the whole /12 — dropping RFC 1918 is
    the point of the rule, and discarding it to make one /24 reachable would
    trade a broken container for a quiet hole."""
    from ipaddress import ip_address, ip_network

    drops = [ip_network(c) for c in lan_drops(BRIDGE_SUBNET)]
    assert not any(ip_address(BRIDGE_GATEWAY) in n for n in drops)
    # a neighbouring address in the same /12 is still dropped
    assert any(ip_address("172.20.5.9") in n for n in drops)
    # and the other two ranges are untouched
    assert any(ip_address("192.168.1.20") in n for n in drops)
    assert any(ip_address("10.234.56.1") in n for n in drops)


def test_no_carve_out_when_the_bridge_is_outside_every_private_range():
    assert lan_drops(None) == PRIVATE_RANGES
    # same ranges, canonically ordered (the carve-out path always sorts)
    assert set(lan_drops("203.0.113.1/24")) == set(PRIVATE_RANGES)


def test_lan_drops_are_stable_across_calls():
    """`ensure_substrate` only pushes the ACL when it differs from what Incus
    already has, so an unstably-ordered document would rewrite it every run."""
    assert lan_drops(BRIDGE_SUBNET) == lan_drops(BRIDGE_SUBNET)
