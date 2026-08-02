from warden.incus import IncusNotFoundError, RealIncusClient


def test_missing_binary_raises_clean_error_not_raw_traceback():
    client = RealIncusClient(binary="definitely-not-a-real-binary-xyz")
    try:
        client.project_exists("warden")
    except IncusNotFoundError as exc:
        assert "not found on PATH" in str(exc)
        assert "NEEDS-HUMAN" in str(exc)
    else:
        raise AssertionError("expected IncusNotFoundError")
