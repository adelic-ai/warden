"""LimaIncusClient — a full IncusClient Protocol backed by an Incus daemon inside a Lima VM. Same
testing shape test_incus_client.py already uses for RealIncusClient: subprocess.run monkeypatched
directly, since this class IS the subprocess-wrapping boundary, nothing lower to inject at. Actually
reaching a real Lima VM's real Incus daemon is validated for real, separately (this session, against
warden-lima-fresh-test-2).
"""
from __future__ import annotations

import subprocess

import pytest

from warden.incus import IncusCommandError, IncusNotFoundError, IncusTimeoutError, QUERY_TIMEOUT
from warden.lima import LIMACTL_BIN
from warden.lima_client import LimaIncusClient
from warden.privilege import SUDO


@pytest.fixture
def limactl_on_path(monkeypatch):
    monkeypatch.setattr("warden.lima_client.shutil.which", lambda _bin: "/opt/homebrew/bin/limactl")


class _Recorder:
    def __init__(self, hang: bool = False):
        self.hang = hang
        self.argvs: list[list[str]] = []
        self.timeouts: list[float] = []

    def __call__(self, argv, **kwargs):
        self.argvs.append(list(argv))
        self.timeouts.append(kwargs.get("timeout"))
        if self.hang:
            raise subprocess.TimeoutExpired(argv, kwargs.get("timeout"))
        return subprocess.CompletedProcess(argv, 0, "", "")


def test_exec_routes_through_limactl_shell_sudo_not_local_incus(monkeypatch, limactl_on_path):
    rec = _Recorder()
    monkeypatch.setattr(subprocess, "run", rec)
    client = LimaIncusClient("warden-lima")

    client.exec("warden-dev", ["/bin/true"], project="warden")

    argv = rec.argvs[0]
    assert argv[:3] == [LIMACTL_BIN, "shell", "warden-lima"]
    assert argv[3] == "--"
    assert list(SUDO) == argv[4:4 + len(SUDO)]
    assert "incus" in argv
    assert "exec" in argv and "warden-dev" in argv


def test_project_create_and_launch_and_snapshot_all_inherit_unmodified(monkeypatch, limactl_on_path):
    # Spot-check a few of the ~26 inherited methods — they're all mechanically identical (built on
    # _run/_run_ok), so this is proportionate coverage, not an attempt at exhaustiveness.
    rec = _Recorder()
    monkeypatch.setattr(subprocess, "run", rec)
    client = LimaIncusClient("warden-lima")

    client.project_create("warden", {})
    client.launch("images:debian/12", "warden-dev", "warden", "warden-dev-profile")
    client.snapshot("warden-dev", "clean", project="warden")

    for argv in rec.argvs:
        assert argv[:3] == [LIMACTL_BIN, "shell", "warden-lima"]


def test_missing_limactl_raises_incus_not_found_error(monkeypatch):
    monkeypatch.setattr("warden.lima_client.shutil.which", lambda _bin: None)
    client = LimaIncusClient("warden-lima")
    with pytest.raises(IncusNotFoundError, match="not found on PATH"):
        client.project_exists("warden")


def test_a_hang_raises_incus_timeout_error(monkeypatch, limactl_on_path):
    monkeypatch.setattr(subprocess, "run", _Recorder(hang=True))
    client = LimaIncusClient("warden-lima")

    with pytest.raises(IncusTimeoutError) as caught:
        client.project_exists("warden")

    assert caught.value.timeout == QUERY_TIMEOUT


def test_run_ok_error_message_shows_the_real_limactl_argv_not_a_local_one(monkeypatch, limactl_on_path):
    def fake_run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 1, "", "Error: not found")
    monkeypatch.setattr(subprocess, "run", fake_run)
    client = LimaIncusClient("warden-lima")

    with pytest.raises(IncusCommandError) as caught:
        client._run_ok(["config", "show", "warden-dev"])

    assert LIMACTL_BIN in caught.value.argv[0]
    assert "warden-lima" in caught.value.argv


def test_file_pull_routes_through_limactl_shell_too(monkeypatch, limactl_on_path):
    rec_holder = {}

    def fake_run(argv, **kwargs):
        rec_holder["argv"] = list(argv)
        return subprocess.CompletedProcess(argv, 0, b"file contents", b"")
    monkeypatch.setattr(subprocess, "run", fake_run)
    client = LimaIncusClient("warden-lima")

    content = client.file_pull("warden-dev", "/root/report.json", project="warden")

    assert content == b"file contents"
    argv = rec_holder["argv"]
    assert argv[:3] == [LIMACTL_BIN, "shell", "warden-lima"]
    assert "pull" in argv


def test_file_pull_missing_file_raises_file_not_found(monkeypatch, limactl_on_path):
    def fake_run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 1, b"", b"Error: not found")
    monkeypatch.setattr(subprocess, "run", fake_run)
    client = LimaIncusClient("warden-lima")

    with pytest.raises(FileNotFoundError):
        client.file_pull("warden-dev", "/root/missing.json")


def test_sudo_is_non_prompting():
    # -n is load-bearing: a hands-off run blocking on a password reads as a silent hang.
    assert SUDO == ("sudo", "-n")
