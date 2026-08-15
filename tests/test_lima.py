"""Lima VM lifecycle — the Mac-native, no-nesting analog of vantage.py's ensure_vantage_vm. Pins the
argv construction and control flow against a fake `run` callable; actually creating a Lima VM and
bootstrapping Incus inside it needs a real Mac with Lima installed, validated separately.
"""
from __future__ import annotations

import subprocess

import pytest

from warden.lima import (
    DEFAULT_NAME,
    LIMA_TEMPLATE,
    LIMACTL_BIN,
    LimaError,
    bootstrap_incus,
    ensure_lima_vm,
    instance_exists,
)


def _proc(returncode: int, stdout: bytes = b"", stderr: bytes = b"") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


class _FakeRunner:
    """Records every call; returns canned results keyed by a substring of the joined argv, same
    dialect FakeIncusClient's exec_results/exec_failures already use elsewhere in this repo."""

    def __init__(self):
        self.calls: list[list[str]] = []
        self.results: dict[str, subprocess.CompletedProcess] = {}
        self.default = _proc(0)

    def __call__(self, argv, *, timeout, input_bytes=None):
        self.calls.append(list(argv))
        joined = " ".join(argv)
        for needle, canned in self.results.items():
            if needle in joined:
                return canned
        return self.default


def test_instance_exists_false_when_list_is_empty():
    runner = _FakeRunner()
    runner.results["list --json"] = _proc(0, stdout=b"")

    assert instance_exists("warden-lima", run=runner) is False


def test_instance_exists_true_when_present_in_list_json():
    runner = _FakeRunner()
    runner.results["list --json"] = _proc(
        0, stdout=b'{"name":"warden-lima","status":"Running"}\n{"name":"other","status":"Stopped"}\n'
    )

    assert instance_exists("warden-lima", run=runner) is True
    assert instance_exists("nonexistent", run=runner) is False


def test_ensure_lima_vm_creates_when_absent():
    runner = _FakeRunner()
    runner.results["list --json"] = _proc(0, stdout=b"")

    info = ensure_lima_vm(run=runner)

    assert info.created is True
    assert info.name == DEFAULT_NAME
    start_calls = [c for c in runner.calls if "start" in c]
    assert len(start_calls) == 1
    argv = start_calls[0]
    assert LIMACTL_BIN in argv[0]
    assert f"--name={DEFAULT_NAME}" in argv
    assert LIMA_TEMPLATE in argv
    assert "-y" in argv  # never interactive


def test_ensure_lima_vm_is_noop_when_already_running():
    runner = _FakeRunner()
    runner.results["list --json"] = _proc(
        0, stdout=f'{{"name":"{DEFAULT_NAME}","status":"Running"}}\n'.encode()
    )

    info = ensure_lima_vm(run=runner)

    assert info.created is False
    start_calls = [c for c in runner.calls if "start" in c]
    assert start_calls == []  # never even tried to start an already-running VM


def test_ensure_lima_vm_restarts_when_present_but_stopped():
    runner = _FakeRunner()
    runner.results["list --json"] = _proc(
        0, stdout=f'{{"name":"{DEFAULT_NAME}","status":"Stopped"}}\n'.encode()
    )

    info = ensure_lima_vm(run=runner)

    assert info.created is False
    start_calls = [c for c in runner.calls if "start" in c]
    assert len(start_calls) == 1
    assert start_calls[0][-1] == DEFAULT_NAME  # `limactl start <name>`, not the create form
    assert "--name=" not in " ".join(start_calls[0])


def test_ensure_lima_vm_raises_lima_error_on_create_failure():
    runner = _FakeRunner()
    runner.results["list --json"] = _proc(0, stdout=b"")
    runner.results["start"] = _proc(1, stderr=b"qemu: could not find template")

    with pytest.raises(LimaError, match="failed to create"):
        ensure_lima_vm(run=runner)


def test_bootstrap_incus_installs_prereqs_pushes_and_runs_script():
    runner = _FakeRunner()

    bootstrap_incus(
        DEFAULT_NAME, "#!/bin/bash\necho pretending to install incus\n",
        prereq_packages=("curl", "ca-certificates", "git", "auditd", "bpftrace"), run=runner,
    )

    joined_calls = [" ".join(c) for c in runner.calls]
    prereq_call = next(c for c in joined_calls if "apt-get install" in c)
    assert "bpftrace" in prereq_call and "auditd" in prereq_call
    assert any("cat > /tmp/install-incus-nested.sh" in c for c in joined_calls)
    assert any("bash /tmp/install-incus-nested.sh" in c for c in joined_calls)
    # order: prereqs before the install script actually runs
    prereq_idx = joined_calls.index(prereq_call)
    run_idx = next(i for i, c in enumerate(joined_calls) if "bash /tmp/install-incus-nested.sh" in c)
    assert prereq_idx < run_idx


def test_bootstrap_incus_prereq_failure_raises_before_pushing_script():
    runner = _FakeRunner()
    runner.results["apt-get install"] = _proc(1, stderr=b"E: Unable to locate package bpftrace")

    with pytest.raises(LimaError, match="prereq install failed"):
        bootstrap_incus(
            DEFAULT_NAME, "#!/bin/bash\n", prereq_packages=("bpftrace",), run=runner,
        )

    assert not any("install-incus-nested.sh" in " ".join(c) for c in runner.calls)


def test_bootstrap_incus_install_script_failure_raises():
    runner = _FakeRunner()
    runner.results["bash /tmp/install-incus-nested.sh"] = _proc(1, stderr=b"Network is unreachable")

    with pytest.raises(LimaError, match="install-incus-nested.sh failed"):
        bootstrap_incus(DEFAULT_NAME, "#!/bin/bash\n", prereq_packages=("curl",), run=runner)
