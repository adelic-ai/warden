"""VANTAGE-PLAN.md phase 6 — file transfer: get local work into the nested container, and results
back out, through the two-hop path (base host -> vantage VM -> container) that nothing before this
phase ever needed to cover.

`IncusClient.file_push`/`file_pull` only reach instances the OUTER Incus manages — the container is
one level deeper, reachable only via the VM's OWN `incus`, invoked through `exec`. So every transfer
here is really two transfers: base host <-> VM (via the outer client's `file_push`/`file_pull`,
already proven binary-safe — see `build_vm.py`'s artifact collection) staged through the VM's own
filesystem, then VM <-> container (via `incus exec <vantage> -- incus file push/pull`, itself
file-to-file, not through captured stdout, for the same binary-safety reason: `exec()`'s stdout
capture is not proven binary-safe, and nothing here should be the first thing to find that out).

One tar per push/pull, not a file-by-file walk — each hop is a real network round trip, and
iterating per file across two of them for a whole directory would be needlessly slow.
"""
from __future__ import annotations

import io
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from warden.vantage import DEFAULT_PROJECT

if TYPE_CHECKING:
    from warden.app import WardenApp

VM_STAGING_PATH = "/tmp/warden-transfer.tar"
CONTAINER_STAGING_PATH = "/tmp/warden-transfer.tar"
EXEC_TIMEOUT = 120.0


class TransferError(RuntimeError):
    """A step of push_path/pull_path failed — local tar, either network hop, or remote
    tar/untar. Staging files on the VM and in the container are best-effort cleaned up on the way
    out; a failure partway through does not leave the transfer looking like it succeeded."""


@dataclass(frozen=True)
class TransferResult:
    remote_path: str
    #: Size of the tar actually moved, for a caller that wants to sanity-check "did anything
    #: happen" beyond just "did this not raise."
    tar_bytes: int


def _exec_ok(client, instance: str, project: str, argv: list[str], what: str):
    result = client.exec(instance, argv, project=project, timeout=EXEC_TIMEOUT)
    if not result.ok:
        raise TransferError(
            f"{instance}: {what} failed (rc={result.returncode}): "
            f"{(result.stderr or result.stdout).strip()[:2000]}"
        )
    return result


def _cleanup(client, instance: str, project: str, container_name: str, nested_project: str) -> None:
    # Best-effort: a failed cleanup shouldn't mask the real error, and a successful transfer
    # shouldn't fail overall just because a stale staging file couldn't be removed.
    client.exec(instance, ["rm", "-f", VM_STAGING_PATH], project=project, timeout=EXEC_TIMEOUT)
    client.exec(
        instance,
        ["incus", "exec", container_name, "--project", nested_project, "--",
         "rm", "-f", CONTAINER_STAGING_PATH],
        project=project, timeout=EXEC_TIMEOUT,
    )


def push_path(
    app: "WardenApp",
    *,
    vantage_instance: str,
    container_name: str,
    local_path: Path,
    remote_path: str,
    vantage_project: str = DEFAULT_PROJECT,
    nested_project: str = "warden",
) -> TransferResult:
    """Tar `local_path` (file or directory) on the base host, stage it onto the vantage VM, then
    onto the container, then untar it at `remote_path` inside the container — creating
    `remote_path` first if it doesn't exist."""
    client = app.client
    local_path = Path(local_path)
    if not local_path.exists():
        raise TransferError(f"{local_path}: does not exist locally, nothing to push")

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        tar.add(local_path, arcname=".")
    tar_bytes = buf.getvalue()

    client.file_push(vantage_instance, tar_bytes, VM_STAGING_PATH, project=vantage_project)
    _exec_ok(
        client, vantage_instance, vantage_project,
        ["incus", "file", "push", VM_STAGING_PATH,
         f"{container_name}{CONTAINER_STAGING_PATH}", "--project", nested_project],
        "stage tar onto the container",
    )
    _exec_ok(
        client, vantage_instance, vantage_project,
        ["incus", "exec", container_name, "--project", nested_project, "--",
         "sh", "-c", f"mkdir -p {remote_path} && tar xf {CONTAINER_STAGING_PATH} -C {remote_path}"],
        "extract into the container",
    )
    _cleanup(client, vantage_instance, vantage_project, container_name, nested_project)
    return TransferResult(remote_path=remote_path, tar_bytes=len(tar_bytes))


def pull_path(
    app: "WardenApp",
    *,
    vantage_instance: str,
    container_name: str,
    remote_path: str,
    local_path: Path,
    vantage_project: str = DEFAULT_PROJECT,
    nested_project: str = "warden",
) -> TransferResult:
    """Tar `remote_path` inside the container, stage it back through the VM, pull it to the base
    host, and untar into `local_path` (created if it doesn't exist)."""
    client = app.client
    local_path = Path(local_path)

    _exec_ok(
        client, vantage_instance, vantage_project,
        ["incus", "exec", container_name, "--project", nested_project, "--",
         "tar", "cf", CONTAINER_STAGING_PATH, "-C", remote_path, "."],
        "tar the container's directory",
    )
    _exec_ok(
        client, vantage_instance, vantage_project,
        ["incus", "file", "pull", f"{container_name}{CONTAINER_STAGING_PATH}",
         VM_STAGING_PATH, "--project", nested_project],
        "pull tar off the container onto the VM",
    )
    tar_bytes = client.file_pull(vantage_instance, VM_STAGING_PATH, project=vantage_project)

    local_path.mkdir(parents=True, exist_ok=True)
    # filter="data" (PEP 706) only exists on Python 3.12+; this runs wherever warden itself runs,
    # not just wherever this was developed, so it's conditional rather than assumed.
    extract_kwargs = {"filter": "data"} if hasattr(tarfile, "data_filter") else {}
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r") as tar:
        tar.extractall(local_path, **extract_kwargs)

    _cleanup(client, vantage_instance, vantage_project, container_name, nested_project)
    return TransferResult(remote_path=remote_path, tar_bytes=len(tar_bytes))
