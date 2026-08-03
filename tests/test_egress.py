import pytest

from warden.egress import (
    ACL_NAME,
    EgressPolicyError,
    assert_enforceable,
    build_acl_document,
)

GW = "100.89.0.1"
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
            assert not rule["destination"].startswith("100.")


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
    doc["egress"].append({"action": "drop", "destination": "100.64.0.0/10", "state": "enabled"})
    with pytest.raises(EgressPolicyError):
        assert_enforceable(doc, GW, PORT)


def test_acl_name_is_stable():
    # profiles.build_profile bakes this into the NIC device.
    assert ACL_NAME == "warden-egress"
