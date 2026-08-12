from __future__ import annotations

import pytest

from tests.fakes import FakeIncusClient, FakeProxyAllowlistController
from warden.app import WardenApp
from warden.build_vm import (
    ARTIFACT_TAR_PATH,
    BUILD_SCRIPT_PATH,
    BUILD_SECRET_PATH,
    BuildVmError,
    BuildVmRunner,
    build_vm_profile,
    resolve,
)
from warden.incus import ExecResult, IncusTimeoutError


def _runner(client):
    proxy = FakeProxyAllowlistController()
    app = WardenApp(client, proxy_controller=proxy)
    return BuildVmRunner(app), proxy


def test_submit_build_happy_path_launches_provisions_and_tears_down():
    client = FakeIncusClient()
    runner, proxy = _runner(client)
    spec = resolve("claude")
    client.exec_results[f"sh -c {BUILD_SCRIPT_PATH}"] = ExecResult(0, "build ok", "")

    result = runner.submit_build(
        spec=spec, instance="build-1", project="warden", build_script="#!/bin/sh\necho hi\n"
    )

    assert result.ok is True
    assert result.returncode == 0
    assert result.timed_out is False
    # torn down by default — a VM-root build is throwaway, never left behind
    assert client.instance_exists("build-1", "warden") is False
    # substrate was ensured along the way
    assert client.project_exists("warden")
    assert client.network_exists("wardenbr0")


def test_submit_build_narrows_provisioning_allowlist_to_runtime():
    client = FakeIncusClient()
    runner, proxy = _runner(client)
    spec = resolve("claude")

    runner.submit_build(spec=spec, instance="build-1", project="warden", build_script="true")

    assert proxy.history == [spec.provisioning_allowlist, spec.runtime_allowlist]


def test_submit_build_captures_nonzero_build_exit_without_raising():
    client = FakeIncusClient()
    runner, _ = _runner(client)
    spec = resolve("claude")
    client.exec_results[f"sh -c {BUILD_SCRIPT_PATH}"] = ExecResult(3, "", "build step failed")

    result = runner.submit_build(spec=spec, instance="build-1", project="warden", build_script="false")

    assert result.ok is False
    assert result.returncode == 3
    # still torn down — a failed build is a normal, reportable outcome, not a warden error
    assert client.instance_exists("build-1", "warden") is False


def test_submit_build_injects_secret_via_file_never_the_build_argv(tmp_path):
    client = FakeIncusClient()
    runner, _ = _runner(client)
    spec = resolve("gemini")
    key_file = tmp_path / "gemini.key"
    key_file.write_text("super-secret-value")

    result = runner.submit_build(
        spec=spec, instance="build-1", project="warden", build_script="true", secret_file=key_file
    )

    assert result.secret_source == f"secret-file:{key_file}"
    # the build's own exec never carries the secret in argv
    build_calls = [argv for (name, argv) in client.exec_calls if argv == ["sh", "-c", BUILD_SCRIPT_PATH]]
    assert build_calls
    for argv in client.exec_calls:
        assert "super-secret-value" not in " ".join(argv[1])


def test_submit_build_records_a_wall_clock_timeout_without_raising():
    client = FakeIncusClient()
    runner, _ = _runner(client)
    spec = resolve("claude")

    real_exec = client.exec

    def hang_on_build_script(name, argv, project="default", env=None, timeout=None):
        if argv == ["sh", "-c", BUILD_SCRIPT_PATH]:
            raise IncusTimeoutError(argv, timeout or 0.0)
        return real_exec(name, argv, project=project, env=env, timeout=timeout)

    client.exec = hang_on_build_script  # type: ignore[method-assign]

    result = runner.submit_build(
        spec=spec, instance="build-1", project="warden", build_script="sleep 999999",
        wall_clock_seconds=1.0,
    )

    assert result.timed_out is True
    assert result.returncode == 124
    assert client.instance_exists("build-1", "warden") is False


def test_submit_build_refuses_when_instance_already_exists_and_leaves_it_untouched():
    client = FakeIncusClient()
    runner, _ = _runner(client)
    spec = resolve("claude")
    runner.app.ensure_build_vm_substrate("warden", build_vm_profile())
    client.launch("images:debian/12", "build-1", "warden", "warden-build-vm")

    with pytest.raises(BuildVmError):
        runner.submit_build(spec=spec, instance="build-1", project="warden", build_script="true")

    assert client.instance_exists("build-1", "warden") is True


def test_submit_build_teardown_false_keeps_the_vm_for_debugging():
    client = FakeIncusClient()
    runner, _ = _runner(client)
    spec = resolve("claude")
    client.exec_results[f"sh -c {BUILD_SCRIPT_PATH}"] = ExecResult(1, "", "boom")

    runner.submit_build(
        spec=spec, instance="build-1", project="warden", build_script="false", teardown=False
    )

    assert client.instance_exists("build-1", "warden") is True


def test_collect_artifacts_returns_none_for_an_empty_output_dir():
    client = FakeIncusClient()
    runner, _ = _runner(client)
    client.launch("images:debian/12", "build-1", "warden", "warden-build-vm")
    client.exec_results["ls -A"] = ExecResult(1, "", "")  # empty dir -> test expression is false

    assert runner._collect_artifacts("build-1", "warden") is None


def test_collect_artifacts_returns_the_staged_tarball_bytes():
    client = FakeIncusClient()
    runner, _ = _runner(client)
    client.launch("images:debian/12", "build-1", "warden", "warden-build-vm")
    # the fake stages whatever `tar -czf ARTIFACT_TAR_PATH` would have produced — same pattern
    # test_export.py uses for workrepo.tar.gz.
    client.file_push("build-1", b"FAKE-TAR-BYTES", ARTIFACT_TAR_PATH, project="warden")

    artifacts = runner._collect_artifacts("build-1", "warden")

    assert artifacts == b"FAKE-TAR-BYTES"
