from warden.security_verify import THREATFOREST_AVAILABLE, verify_security


def test_threatforest_is_unconditionally_unavailable_today():
    # Pinned so this cannot silently start reading as "checked and passed" — flipping it is a
    # deliberate act (a real canon-ThreatForest integration landing), never a side effect.
    assert THREATFOREST_AVAILABLE is False


def test_verify_security_states_absence_rather_than_faking_a_clean_pass():
    verdict = verify_security("deadbeef" * 8)

    assert verdict.available is False
    assert verdict.findings is None  # never `()` — that would read as "checked, found nothing"
    assert verdict.guarantee_tier is None
    assert "not built" in verdict.reason
    assert "ROADMAP step 4" in verdict.reason


def test_verify_security_reason_is_stable_regardless_of_which_artifact():
    a = verify_security("aaaa")
    b = verify_security(None)
    assert a.reason == b.reason
