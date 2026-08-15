"""VANTAGE-PLAN.md phase 6 — file transfer, the two-hop path (base host -> vantage VM -> container).
Pins the wiring and the local tar/untar (real, not faked - tarfile itself needs no Incus) against
FakeIncusClient for the Incus-side hops; the nested incus file push/pull actually reaching a real
container needs pop-os, same as every other real-host claim in this repo.
"""
from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest

from tests.fakes import FakeIncusClient, FakeProxyAllowlistController
from warden.app import WardenApp
from warden.incus import ExecResult
from warden.transfer import (
    CONTAINER_STAGING_PATH,
    VM_STAGING_PATH,
    TransferError,
    pull_path,
    push_path,
)
from warden.vantage import DEFAULT_PROJECT

VANTAGE_INSTANCE = "warden-vantage"
CONTAINER = "warden-dev"


def _app(client):
    return WardenApp(client, proxy_controller=FakeProxyAllowlistController())


def _launched_vantage(client):
    client.project_create(DEFAULT_PROJECT, {})
    client.launch("warden-vantage-golden", VANTAGE_INSTANCE, DEFAULT_PROJECT, "p", instance_type="virtual-machine")


def _make_tar(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_push_path_tars_locally_and_stages_through_both_hops(tmp_path):
    client = FakeIncusClient()
    app = _app(client)
    _launched_vantage(client)
    local_dir = tmp_path / "work"
    local_dir.mkdir()
    (local_dir / "hello.txt").write_text("hi")

    result = push_path(
        app, vantage_instance=VANTAGE_INSTANCE, container_name=CONTAINER,
        local_path=local_dir, remote_path="/root/work",
    )

    assert result.remote_path == "/root/work"
    assert result.tar_bytes > 0
    # the tar actually landed on the VM with real, extractable content
    staged = client.instances[(DEFAULT_PROJECT, VANTAGE_INSTANCE)].files[VM_STAGING_PATH]
    with tarfile.open(fileobj=io.BytesIO(staged)) as tar:
        names = tar.getnames()
    assert "./hello.txt" in names
    # both hops happened, in order: stage onto container, then extract
    calls = [argv for n, argv in client.exec_calls if n == VANTAGE_INSTANCE]
    stage_call = next(i for i, c in enumerate(calls) if "file" in c and "push" in c)
    extract_call = next(i for i, c in enumerate(calls) if "tar xf" in " ".join(c))
    assert stage_call < extract_call


def test_push_path_missing_local_path_raises_before_touching_anything(tmp_path):
    client = FakeIncusClient()
    app = _app(client)
    _launched_vantage(client)

    with pytest.raises(TransferError, match="does not exist"):
        push_path(
            app, vantage_instance=VANTAGE_INSTANCE, container_name=CONTAINER,
            local_path=tmp_path / "nonexistent", remote_path="/root/work",
        )
    assert client.exec_calls == []


def test_push_path_extract_failure_raises_transfer_error():
    client = FakeIncusClient()
    app = _app(client)
    _launched_vantage(client)
    client.exec_failures["tar xf"] = ExecResult(1, "", "tar: unexpected end of file")

    with pytest.raises(TransferError, match="extract into the container"):
        push_path(
            app, vantage_instance=VANTAGE_INSTANCE, container_name=CONTAINER,
            local_path=Path(__file__), remote_path="/root/work",
        )


def test_pull_path_untars_locally_after_both_hops(tmp_path):
    client = FakeIncusClient()
    app = _app(client)
    _launched_vantage(client)
    # simulate what the nested `incus exec ... incus file pull` hop would have staged onto the VM -
    # the fake can't model the nested container's own filesystem, so this is pre-seeded directly.
    client.instances[(DEFAULT_PROJECT, VANTAGE_INSTANCE)].files[VM_STAGING_PATH] = _make_tar(
        {"result.txt": "output"}
    )
    dest = tmp_path / "results"

    result = pull_path(
        app, vantage_instance=VANTAGE_INSTANCE, container_name=CONTAINER,
        remote_path="/root/work", local_path=dest,
    )

    assert result.tar_bytes > 0
    assert (dest / "result.txt").read_text() == "output"
    # both hops happened, in order: tar inside the container, then pull it onto the VM
    calls = [argv for n, argv in client.exec_calls if n == VANTAGE_INSTANCE]
    tar_call = next(i for i, c in enumerate(calls) if "tar" in c and "cf" in c)
    pull_call = next(i for i, c in enumerate(calls) if "file" in c and "pull" in c)
    assert tar_call < pull_call


def test_pull_path_tar_failure_raises_transfer_error(tmp_path):
    client = FakeIncusClient()
    app = _app(client)
    _launched_vantage(client)
    client.exec_failures["tar cf"] = ExecResult(1, "", "tar: /root/work: No such file or directory")

    with pytest.raises(TransferError, match="tar the container's directory"):
        pull_path(
            app, vantage_instance=VANTAGE_INSTANCE, container_name=CONTAINER,
            remote_path="/root/work", local_path=tmp_path / "results",
        )
