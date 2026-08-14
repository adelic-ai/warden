"""VANTAGE-PLAN.md phase 2 — the mold. Pins the wiring (egress check -> prereqs -> install script ->
dependency verify -> stop -> publish -> teardown) against FakeIncusClient; real apt/zabbly/admin-init
behavior needs pop-os, same as every other real-host claim in this repo.
"""
from __future__ import annotations

import pytest

from tests.fakes import FakeIncusClient, FakeProxyAllowlistController
from warden.app import WardenApp
from warden.incus import ExecResult
from warden.mold import GOLDEN_ALIAS, MOLD_ALLOWLIST, MOLD_INSTANCE_NAME, MoldError, build_vantage_mold
from warden.vantage import DEFAULT_PROJECT, VantageProjectConflict

FAKE_SCRIPT = "#!/bin/bash\necho pretending to install incus\n"


def _app(client):
    return WardenApp(client, proxy_controller=FakeProxyAllowlistController())


def test_build_vantage_mold_happy_path_publishes_and_tears_down():
    client = FakeIncusClient()
    app = _app(client)

    result = build_vantage_mold(app, FAKE_SCRIPT)

    assert result.alias == GOLDEN_ALIAS
    assert result.fingerprint  # non-empty
    assert client.image_exists(GOLDEN_ALIAS, project=DEFAULT_PROJECT)
    # the build instance is torn down - the image is the durable artifact, not the VM
    assert client.instance_exists(MOLD_INSTANCE_NAME, DEFAULT_PROJECT) is False
    # the install script actually got pushed before being run
    assert MOLD_INSTANCE_NAME in [n for n, _ in client.exec_calls]


def test_wires_proxy_env_and_allowlist_before_touching_the_network():
    # Real pop-os lesson: without this, apt gets "Network is unreachable" — not transient, the
    # bridge ACL default-drops direct egress and the proxy allowlist was simply never set.
    client = FakeIncusClient()
    proxy = FakeProxyAllowlistController()
    app = WardenApp(client, proxy_controller=proxy)

    build_vantage_mold(app, FAKE_SCRIPT)

    assert "deb.debian.org" in MOLD_ALLOWLIST
    assert "pkgs.zabbly.com" in MOLD_ALLOWLIST
    # set before any apt call, not after - a late-set allowlist wouldn't have caught the real bug
    assert proxy.history[0] == MOLD_ALLOWLIST


def test_egress_check_failure_raises_mold_error_and_leaves_instance_for_debugging():
    client = FakeIncusClient()
    app = _app(client)
    client.exec_failures["apt-get update"] = ExecResult(1, "", "Could not resolve deb.debian.org")

    with pytest.raises(MoldError, match="egress check"):
        build_vantage_mold(app, FAKE_SCRIPT)

    # left running, not torn down - a human debugging this needs to see the state it died in
    assert client.instance_exists(MOLD_INSTANCE_NAME, DEFAULT_PROJECT) is True


def test_install_script_failure_raises_mold_error_with_stderr():
    client = FakeIncusClient()
    app = _app(client)
    client.exec_failures[f"bash /root/install-incus-nested.sh"] = ExecResult(
        1, "", "Only allowed source path ..."
    )

    with pytest.raises(MoldError, match="install-incus-nested.sh"):
        build_vantage_mold(app, FAKE_SCRIPT)


def test_refuses_a_foreign_project_before_touching_anything():
    client = FakeIncusClient()
    app = _app(client)
    client.project_create("shared", {})
    client.launch("images:debian/12", "someone-elses-vm", "shared", "default")

    with pytest.raises(VantageProjectConflict):
        build_vantage_mold(app, FAKE_SCRIPT, project="shared")

    assert client.projects["shared"] == {}
    assert client.instance_exists(MOLD_INSTANCE_NAME, "shared") is False
