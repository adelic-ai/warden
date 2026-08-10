import subprocess

import pytest

from warden.incus import (
    EXEC_TIMEOUT,
    LAUNCH_TIMEOUT,
    QUERY_TIMEOUT,
    IncusCommandError,
    IncusNotFoundError,
    IncusTimeoutError,
    RealIncusClient,
)


@pytest.fixture
def incus_on_path(monkeypatch):
    """Make the `incus` binary resolvable without a real install.

    These tests assert behaviour *given the binary is present* (per-operation timeouts, hang
    handling). `_run` does an intentional pre-flight `shutil.which` check before the elevation
    prefix (see incus.py and test_missing_binary_is_detected_before_the_elevation_prefix), so on a
    machine with no `incus` on PATH that check fires first and the mocked `subprocess.run` is never
    reached. Stubbing `which` here keeps these tests hermetic — green on any dev machine, not just a
    provisioned Incus host. The missing-binary tests deliberately do NOT use this fixture."""
    monkeypatch.setattr("warden.incus.shutil.which", lambda _bin: "/usr/bin/incus")


def test_missing_binary_raises_clean_error_not_raw_traceback():
    client = RealIncusClient(binary="definitely-not-a-real-binary-xyz")
    try:
        client.project_exists("warden")
    except IncusNotFoundError as exc:
        assert "not found on PATH" in str(exc)
        assert "NEEDS-HUMAN" in str(exc)
    else:
        raise AssertionError("expected IncusNotFoundError")


class _Recorder:
    """Stands in for subprocess.run: records the timeout it was handed, and
    optionally hangs (i.e. raises TimeoutExpired, as subprocess.run does once
    it has killed and reaped the child)."""

    def __init__(self, hang: bool = False):
        self.hang = hang
        self.timeouts: list[float | None] = []
        self.argvs: list[list[str]] = []

    def __call__(self, argv, **kwargs):
        self.timeouts.append(kwargs.get("timeout"))
        self.argvs.append(list(argv))
        if self.hang:
            raise subprocess.TimeoutExpired(argv, kwargs.get("timeout"))
        return subprocess.CompletedProcess(argv, 0, "", "")


def test_every_invocation_is_bounded(monkeypatch, incus_on_path):
    """No `incus` call may be unbounded — an unbounded subprocess has no
    failure mode, only an absence of progress."""
    rec = _Recorder()
    monkeypatch.setattr(subprocess, "run", rec)
    client = RealIncusClient()

    client.project_exists("warden")
    client.config_get("cap-mon", "volatile.idmap.current", project="warden")
    client.launch("images:debian/12", "cap-mon", "warden", "warden-monitored")
    client.exec("cap-mon", ["/bin/true"], project="warden")
    client.snapshot("cap-mon", "clean", project="warden")
    client.file_push("cap-mon", b"x", "/root/x", project="warden")

    assert rec.timeouts, "expected calls to have been recorded"
    assert all(t is not None and t > 0 for t in rec.timeouts), rec.timeouts


def test_timeouts_are_sized_per_operation(monkeypatch, incus_on_path):
    """A metadata read that takes a minute is broken; `apt-get install`
    through the proxy legitimately takes several. One global bound would have
    to be the larger, which would leave metadata hangs effectively unbounded."""
    rec = _Recorder()
    monkeypatch.setattr(subprocess, "run", rec)
    client = RealIncusClient()

    client.project_exists("warden")
    client.launch("images:debian/12", "cap-mon", "warden", "warden-monitored")
    client.exec("cap-mon", ["apt-get", "install", "git"], project="warden")

    query_t, launch_t, exec_t = rec.timeouts
    assert query_t == QUERY_TIMEOUT
    assert launch_t == LAUNCH_TIMEOUT
    assert exec_t == EXEC_TIMEOUT
    assert query_t < launch_t <= exec_t


def test_exec_timeout_is_overridable_for_probes(monkeypatch, incus_on_path):
    rec = _Recorder()
    monkeypatch.setattr(subprocess, "run", rec)
    RealIncusClient().exec("cap-mon", ["/bin/true"], project="warden", timeout=5.0)
    assert rec.timeouts == [5.0]


def test_a_hang_raises_rather_than_reading_as_absent(monkeypatch, incus_on_path):
    """The load-bearing half. Existence checks read `.returncode`, so a
    timeout that *returned* would silently become "doesn't exist" and send
    warden off to recreate something that already exists."""
    monkeypatch.setattr(subprocess, "run", _Recorder(hang=True))
    client = RealIncusClient()

    with pytest.raises(IncusTimeoutError) as caught:
        client.project_exists("warden")

    # Subclassing IncusCommandError is what lets every existing handler —
    # `warden up`'s error path, `_wait_ready`'s retry loop — treat a hang as
    # the failure it is, with no new call sites.
    assert isinstance(caught.value, IncusCommandError)
    assert caught.value.timeout == QUERY_TIMEOUT


def test_timeout_message_does_not_claim_the_operation_failed(monkeypatch, incus_on_path):
    """Killing the client does not cancel the operation on the daemon: the run
    that motivated this bound had the instance created, started and running
    while its client hung. The error must not assert otherwise."""
    monkeypatch.setattr(subprocess, "run", _Recorder(hang=True))

    with pytest.raises(IncusTimeoutError) as caught:
        RealIncusClient().launch("images:debian/12", "cap-mon", "warden", "warden-monitored")

    message = str(caught.value)
    assert "may still have completed" in message
    assert "re-run" in message


def test_missing_binary_is_detected_before_the_elevation_prefix():
    """With `sudo -n incus …` the process that launches is `sudo`, which exists — so a missing
    `incus` returns sudo's rc=1 'command not found' instead of a FileNotFoundError. The clear
    install message must survive elevation."""
    client = RealIncusClient(binary="definitely-not-a-real-binary-xyz")
    for call in (
        lambda: client.project_exists("warden"),
        lambda: client.file_pull("i", "/tmp/x"),
    ):
        try:
            call()
        except IncusNotFoundError as exc:
            assert "not found on PATH" in str(exc)
        else:
            raise AssertionError("expected IncusNotFoundError")
