"""LimaProxyAllowlistController / ensure_running_lima — the allowlist proxy has to run *inside* the
Lima VM (BRIDGE_GATEWAY doesn't exist on the Mac), unlike Incus commands which LimaIncusClient
already routes through `limactl shell`. Same subprocess-monkeypatching shape test_incus_client.py
and test_lima_client.py already use — this is the boundary layer, nothing lower to inject at.
Actually spawning a detached proxy inside a real Lima VM and confirming it survives session close
is validated for real, separately (this session, against warden-lima-fresh-test-2).
"""
from __future__ import annotations

import subprocess

import pytest

from warden.lima import LIMACTL_BIN
from warden.proxy import LimaProxyAllowlistController, ensure_running_lima


class _Recorder:
    def __init__(self, listening_after: int = 0):
        # first `listening_after` "is it listening" checks say no, then yes — models a proxy that
        # takes a moment to come up rather than being instantly ready.
        self.calls: list[list[str]] = []
        self._checks = 0
        self._listening_after = listening_after

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        if "-c" in argv and "socket" in argv[-1]:
            self._checks += 1
            ok = self._checks > self._listening_after
            return subprocess.CompletedProcess(argv, 0 if ok else 1, b"", b"")
        return subprocess.CompletedProcess(argv, 0, b"", b"")


def test_ensure_running_lima_skips_spawn_if_already_listening(monkeypatch, tmp_path):
    monkeypatch.setattr(subprocess, "run", _Recorder(listening_after=0))
    started = ensure_running_lima(
        "warden-lima", tmp_path / "allowlist.txt", "172.29.0.1", 3128,
    )
    assert started is False


def test_ensure_running_lima_spawns_via_limactl_shell_nohup_backgrounded(monkeypatch, tmp_path):
    rec = _Recorder(listening_after=1)  # not listening yet, then comes up after the spawn
    monkeypatch.setattr(subprocess, "run", rec)

    started = ensure_running_lima(
        "warden-lima", tmp_path / "allowlist.txt", "172.29.0.1", 3128,
        pythonpath="/Users/maude/dev/warden",
    )

    assert started is True
    spawn_calls = [c for c in rec.calls if "nohup" in " ".join(c)]
    assert len(spawn_calls) == 1
    argv = spawn_calls[0]
    assert argv[:3] == [LIMACTL_BIN, "shell", "warden-lima"]
    joined = " ".join(argv)
    assert "nohup" in joined and joined.rstrip().endswith("&")
    assert "warden.cli proxy" in joined
    assert "--bind 172.29.0.1" in joined
    assert "--port 3128" in joined
    assert "PYTHONPATH=/Users/maude/dev/warden" in joined
    assert "< /dev/null" in joined  # stdin closed, same reason RealIncusClient's own calls do this


def test_ensure_running_lima_includes_upstream_proxy_when_set(monkeypatch, tmp_path):
    rec = _Recorder(listening_after=1)
    monkeypatch.setattr(subprocess, "run", rec)

    ensure_running_lima(
        "warden-lima", tmp_path / "allowlist.txt", "172.29.0.1", 3128,
        upstream_proxy="10.0.0.1:8080",
    )

    spawn = next(c for c in rec.calls if "nohup" in " ".join(c))
    assert "--upstream-proxy 10.0.0.1:8080" in " ".join(spawn)


def test_ensure_running_lima_raises_if_never_comes_up(monkeypatch, tmp_path):
    monkeypatch.setattr(subprocess, "run", _Recorder(listening_after=999))
    with pytest.raises(RuntimeError, match="did not come up"):
        ensure_running_lima(
            "warden-lima", tmp_path / "allowlist.txt", "172.29.0.1", 3128, timeout=0.5,
        )


def test_controller_writes_empty_allowlist_before_first_run(monkeypatch, tmp_path):
    monkeypatch.setattr(subprocess, "run", _Recorder(listening_after=0))
    allowlist = tmp_path / "sub" / "allowlist.txt"
    controller = LimaProxyAllowlistController("warden-lima", allowlist, bind="172.29.0.1", port=3128)

    controller.ensure_running()

    assert allowlist.exists()
    assert allowlist.read_text().strip() == ""


def test_controller_set_allowlist_writes_the_shared_file_directly(tmp_path):
    allowlist = tmp_path / "allowlist.txt"
    controller = LimaProxyAllowlistController("warden-lima", allowlist, bind="172.29.0.1", port=3128)

    controller.set_allowlist(("github.com", "api.anthropic.com"))

    assert "github.com" in allowlist.read_text()
    assert "api.anthropic.com" in allowlist.read_text()
