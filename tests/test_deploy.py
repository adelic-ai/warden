"""VANTAGE-PLAN.md phase 4 — code deploy. Bundling exercises real `git` against this actual repo
checkout (cheap, deterministic, worth doing for real rather than mocking away); the Incus-side
wiring (push/clone/verify calls happening in the right order) is pinned against FakeIncusClient.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tests.fakes import FakeIncusClient, FakeProxyAllowlistController
from warden.app import WardenApp
from warden.deploy import (
    AGENTWATCH_BUNDLE_REMOTE,
    VERIFY_SCRIPT_REMOTE,
    WARDEN_BUNDLE_REMOTE,
    DeployError,
    deploy_code,
)
from warden.incus import ExecResult
from warden.vantage import DEFAULT_PROJECT

THIS_REPO = Path(__file__).resolve().parent.parent
AGENTWATCH_SIBLING = THIS_REPO.parent / "agentwatch"

requires_agentwatch_checkout = pytest.mark.skipif(
    not (AGENTWATCH_SIBLING / "agentwatch" / "run.py").exists(),
    reason="no sibling agentwatch checkout on this machine",
)


def _app(client):
    return WardenApp(client, proxy_controller=FakeProxyAllowlistController())


def _launched(client, name=DEFAULT_PROJECT + "-vm"):
    """A minimal already-launched instance — deploy_code doesn't launch anything itself, it targets
    an existing VM (phase 1/3's job)."""
    client.project_create(DEFAULT_PROJECT, {})
    client.profile_create(DEFAULT_PROJECT, DEFAULT_PROJECT, {}, {})
    client.launch("some-image", name, DEFAULT_PROJECT, DEFAULT_PROJECT, instance_type="virtual-machine")
    return name


@requires_agentwatch_checkout
def test_deploy_code_happy_path_pushes_bundles_clones_and_verifies():
    client = FakeIncusClient()
    app = _app(client)
    instance = _launched(client)

    result = deploy_code(app, instance=instance, warden_path=THIS_REPO, agentwatch_path=AGENTWATCH_SIBLING)

    assert result.warden_commit  # non-empty short hash
    assert result.agentwatch_commit
    inst = client.instances[(DEFAULT_PROJECT, instance)]
    assert inst.files[WARDEN_BUNDLE_REMOTE].startswith(b"# v")  # real git bundle header
    assert inst.files[AGENTWATCH_BUNDLE_REMOTE].startswith(b"# v")
    assert VERIFY_SCRIPT_REMOTE in inst.files
    # the clone command actually ran (not just the file pushes)
    clone_calls = [argv for n, argv in client.exec_calls if n == instance and "git clone" in " ".join(argv)]
    assert len(clone_calls) == 1


def test_deploy_code_include_agentwatch_false_skips_it_entirely():
    client = FakeIncusClient()
    app = _app(client)
    instance = _launched(client)

    result = deploy_code(
        app, instance=instance, warden_path=THIS_REPO, include_agentwatch=False,
    )

    assert result.warden_commit
    assert result.agentwatch_commit is None
    inst = client.instances[(DEFAULT_PROJECT, instance)]
    assert AGENTWATCH_BUNDLE_REMOTE not in inst.files
    clone_calls = [argv for n, argv in client.exec_calls if n == instance and "git clone" in " ".join(argv)]
    assert len(clone_calls) == 1
    joined = " ".join(clone_calls[0])
    assert joined.count("git clone") == 1  # only warden's, not a second one for agentwatch
    assert "rm -rf warden agentwatch" in joined  # still cleans up any stale agentwatch from before
    # the verify script gets told not to expect agentwatch
    verify_calls = [argv for n, argv in client.exec_calls if "verify-vantage-vm.py" in " ".join(argv)]
    assert "--no-agentwatch" in verify_calls[0]


@requires_agentwatch_checkout
def test_clone_failure_raises_deploy_error():
    client = FakeIncusClient()
    app = _app(client)
    instance = _launched(client)
    client.exec_failures["git clone"] = ExecResult(1, "", "fatal: repository not found")

    with pytest.raises(DeployError, match="clone failed"):
        deploy_code(app, instance=instance, warden_path=THIS_REPO, agentwatch_path=AGENTWATCH_SIBLING)


@requires_agentwatch_checkout
def test_verify_failure_raises_deploy_error():
    client = FakeIncusClient()
    app = _app(client)
    instance = _launched(client)
    client.exec_failures["verify-vantage-vm.py"] = ExecResult(1, "FAIL: warden importable", "")

    with pytest.raises(DeployError, match="verification failed"):
        deploy_code(app, instance=instance, warden_path=THIS_REPO, agentwatch_path=AGENTWATCH_SIBLING)


def test_invalid_repo_path_raises_deploy_error_not_a_crash():
    client = FakeIncusClient()
    app = _app(client)
    instance = _launched(client)

    with pytest.raises(DeployError, match="not a git repo"):
        deploy_code(
            app, instance=instance, warden_path=THIS_REPO,
            agentwatch_path=Path("/nonexistent/agentwatch"),
        )


def test_discover_agentwatch_path_raises_deploy_error_when_not_found(monkeypatch):
    from warden.deploy import _discover_agentwatch_path

    monkeypatch.delenv("WARDEN_AGENTWATCH_PATH", raising=False)
    monkeypatch.setattr(
        "warden.deploy.Path.exists", lambda self: False
    )  # simulate no sibling checkout either

    with pytest.raises(DeployError, match="agentwatch not found"):
        _discover_agentwatch_path()
