"""Closes VANTAGE-PLAN.md's stated gap: `report --live` taught the double hop. Pins the wiring —
the remote argv, the relay of report's own exit code/stdout verbatim, and the pull-back landing on
the base host — against FakeIncusClient; an actual nested `warden report --live` reconciling for
real needs pop-os, same as every other real-host claim in this repo.
"""
from __future__ import annotations

import io
import tarfile

import pytest

from tests.fakes import FakeIncusClient, FakeProxyAllowlistController
from warden.app import WardenApp
from warden.incus import ExecResult
from warden.remote_report import REMOTE_OUT_ROOT, report_nested_live
from warden.transfer import VM_STAGING_PATH
from warden.vantage import DEFAULT_PROJECT

VANTAGE_INSTANCE = "warden-vantage"
CONTAINER = "warden-dev"


def _app(client):
    return WardenApp(client, proxy_controller=FakeProxyAllowlistController())


def _launched_vantage(client):
    client.project_create(DEFAULT_PROJECT, {})
    client.launch(
        "warden-vantage-golden", VANTAGE_INSTANCE, DEFAULT_PROJECT, "p", instance_type="virtual-machine"
    )


def _make_tar(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _seed_pullable_artifacts(client, files: dict[str, str]):
    # Models what the remote `warden report --live` call would have written to the VM's own disk —
    # the fake can't run that inner CLI invocation for real, so the tar it would produce is pre-seeded.
    client.instances[(DEFAULT_PROJECT, VANTAGE_INSTANCE)].files[VM_STAGING_PATH] = _make_tar(files)


def test_report_nested_live_builds_the_remote_argv_and_pulls_artifacts_back(tmp_path):
    client = FakeIncusClient()
    app = _app(client)
    _launched_vantage(client)
    _seed_pullable_artifacts(client, {"report.json": "{}"})
    out = tmp_path / "out"

    result = report_nested_live(
        app, vantage_instance=VANTAGE_INSTANCE, container_name=CONTAINER, llm="claude",
        local_out_dir=out, nested_project="warden",
    )

    assert result.returncode == 0
    assert result.artifacts_pulled
    assert result.pull_error is None
    assert (out / "report.json").read_text() == "{}"

    report_calls = [argv for n, argv in client.exec_calls if n == VANTAGE_INSTANCE and "warden.cli" in " ".join(argv)]
    assert len(report_calls) == 1
    argv = report_calls[0]
    assert argv[:6] == ["python3", "-m", "warden.cli", "report", "--live", "--llm"]
    assert "--instance" in argv and CONTAINER in argv
    assert "--project" in argv and "warden" in argv
    assert "--out" in argv and REMOTE_OUT_ROOT in argv
    assert "--ebpf" not in argv


def test_report_nested_live_passes_since_host_and_ebpf_flags(tmp_path):
    client = FakeIncusClient()
    app = _app(client)
    _launched_vantage(client)
    _seed_pullable_artifacts(client, {"report.json": "{}"})

    report_nested_live(
        app, vantage_instance=VANTAGE_INSTANCE, container_name=CONTAINER, llm="claude",
        local_out_dir=tmp_path / "out", since="45m", host="pop-os",
        ebpf=True, capture_seconds=15,
    )

    report_calls = [argv for n, argv in client.exec_calls if n == VANTAGE_INSTANCE and "warden.cli" in " ".join(argv)]
    argv = report_calls[0]
    assert "--since" in argv and "45m" in argv
    assert "--host" in argv and "pop-os" in argv
    assert "--ebpf" in argv
    assert "--capture-seconds" in argv and "15" in argv


def test_report_nested_live_relays_a_nonzero_remote_exit_without_raising(tmp_path):
    client = FakeIncusClient()
    app = _app(client)
    _launched_vantage(client)
    client.exec_failures["warden.cli report"] = ExecResult(1, "", "DISAGREEMENT: ...")
    _seed_pullable_artifacts(client, {"report.json": "{}"})

    result = report_nested_live(
        app, vantage_instance=VANTAGE_INSTANCE, container_name=CONTAINER, llm="claude",
        local_out_dir=tmp_path / "out",
    )

    assert result.returncode == 1
    assert result.stderr == "DISAGREEMENT: ..."


def test_report_nested_live_records_pull_failure_without_raising(tmp_path):
    client = FakeIncusClient()
    app = _app(client)
    _launched_vantage(client)
    client.exec_failures["tar cf"] = ExecResult(1, "", "tar: /root/.warden: No such file or directory")

    result = report_nested_live(
        app, vantage_instance=VANTAGE_INSTANCE, container_name=CONTAINER, llm="claude",
        local_out_dir=tmp_path / "out",
    )

    # The remote report's own exit code/output are still relayed even though nothing was pulled.
    assert result.returncode == 0
    assert not result.artifacts_pulled
    assert result.pull_error is not None
