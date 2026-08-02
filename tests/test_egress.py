import pytest

from warden.egress import assert_no_reject_and_correct_ordering, generate_nft_ruleset


def test_ruleset_uses_drop_not_reject():
    ruleset = generate_nft_ruleset("wardenbr0", 8443)
    assert "reject" not in ruleset
    assert "policy drop" in ruleset


def test_ruleset_has_no_broad_cidr_rule():
    ruleset = generate_nft_ruleset("wardenbr0", 8443)
    assert "10.0.0.0/8" not in ruleset


def test_ruleset_passes_ordering_guard():
    ruleset = generate_nft_ruleset("wardenbr0", 8443)
    assert_no_reject_and_correct_ordering(ruleset, "wardenbr0", 8443)


def test_ordering_guard_catches_reject():
    bad = 'table inet warden { chain forward { iifname "br0" reject } }'
    with pytest.raises(ValueError):
        assert_no_reject_and_correct_ordering(bad, "br0", 8443)


def test_ordering_guard_catches_shadowing_drop():
    bad = (
        'chain input {\n'
        '    iifname "br0" drop\n'
        '    iifname "br0" tcp dport 8443 accept\n'
        '}\n'
    )
    with pytest.raises(ValueError):
        assert_no_reject_and_correct_ordering(bad, "br0", 8443)
