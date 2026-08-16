"""LimaAuditRuleInstaller / LimaEventSource — auditd runs inside the Lima VM, not on the Mac, same
shape as the proxy and the Incus client. Same subprocess-monkeypatching pattern the other Lima test
files use — this is the boundary layer. Real-host validation (a real auditctl rule actually loading
inside a Lima VM) is the next real-host check, separate from these.
"""
from __future__ import annotations

import subprocess

import pytest

from warden.auditd import AuditRuleLoadError, generate_rule, rule_key
from warden.idmap import IdRange
from warden.lima import LIMACTL_BIN
from warden.lima_auditd import LimaAuditRuleInstaller, LimaEventSource


def _proc(returncode, stdout="", stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class _Recorder:
    def __init__(self):
        self.calls: list[list[str]] = []
        self.results: dict[str, subprocess.CompletedProcess] = {}
        self.default = _proc(0)

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        joined = " ".join(argv)
        for needle, canned in self.results.items():
            if needle in joined:
                return canned
        return self.default


def test_install_loads_via_limactl_shell_sudo_and_verifies_loaded(monkeypatch):
    rec = _Recorder()
    key = rule_key("warden-dev")
    rec.results["auditctl -l"] = _proc(0, stdout=f"-a always,exit -F arch=b64 key={key}\n")
    monkeypatch.setattr(subprocess, "run", rec)
    installer = LimaAuditRuleInstaller("warden-lima")

    installer.install("warden-dev", IdRange(1_000_000, 65536))

    load_calls = [c for c in rec.calls if "auditctl" in c and "-a" in c]
    assert load_calls, "expected at least one `auditctl -a` load call"
    for c in load_calls:
        assert c[:3] == [LIMACTL_BIN, "shell", "warden-lima"]
        assert "sudo" in c


def test_install_raises_if_key_not_actually_loaded_after(monkeypatch):
    rec = _Recorder()
    rec.results["auditctl -l"] = _proc(0, stdout="")  # never shows the key as loaded
    monkeypatch.setattr(subprocess, "run", rec)
    installer = LimaAuditRuleInstaller("warden-lima")

    with pytest.raises(AuditRuleLoadError, match="not present"):
        installer.install("warden-dev", IdRange(1_000_000, 65536))


def test_install_raises_on_auditctl_load_failure(monkeypatch):
    rec = _Recorder()
    rec.results["auditctl -a"] = _proc(1, stderr="Error sending add rule")
    monkeypatch.setattr(subprocess, "run", rec)
    installer = LimaAuditRuleInstaller("warden-lima")

    with pytest.raises(AuditRuleLoadError, match="auditctl -a"):
        installer.install("warden-dev", IdRange(1_000_000, 65536))


def test_write_rule_file_writes_inside_the_guest_via_stdin(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(subprocess, "run", rec)
    installer = LimaAuditRuleInstaller("warden-lima")

    ok = installer._write_rule_file(
        "/etc/audit/rules.d/60-warden-dev.rules", generate_rule(IdRange(1_000_000, 65536), "dev")
    )

    assert ok is True
    write_call = next(c for c in rec.calls if "cat >" in " ".join(c))
    assert write_call[:3] == [LIMACTL_BIN, "shell", "warden-lima"]


def test_uninstall_deletes_loaded_rule_and_removes_file(monkeypatch):
    rec = _Recorder()
    key = rule_key("warden-dev")
    rec.results["auditctl -l"] = _proc(0, stdout=f"-a always,exit -F arch=b64 key={key}\n")
    monkeypatch.setattr(subprocess, "run", rec)
    installer = LimaAuditRuleInstaller("warden-lima")

    installer.uninstall("warden-dev")

    rm_calls = [c for c in rec.calls if "rm" in c and "-f" in c]
    assert rm_calls, "expected the rules.d file to be removed inside the guest"


def test_event_source_poll_routes_through_limactl_and_parses_raw_output(monkeypatch):
    key = rule_key("warden-dev")
    raw = (
        f'type=SYSCALL msg=audit(1700000000.000:1): '
        f'uid=1000000 exe="/bin/true" key="{key}"\n'
    )
    rec = _Recorder()
    rec.results["ausearch"] = _proc(0, stdout=raw)
    monkeypatch.setattr(subprocess, "run", rec)
    source = LimaEventSource("warden-lima", "warden-dev")

    events = source.poll()

    assert len(events) == 1
    assert events[0].uid == 1000000
    search_call = rec.calls[0]
    assert search_call[:3] == [LIMACTL_BIN, "shell", "warden-lima"]
    assert "ausearch" in search_call


def test_event_source_poll_returns_empty_on_failure_not_a_crash(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _proc(1, stderr="not found"))
    source = LimaEventSource("warden-lima", "warden-dev")

    assert source.poll() == []
