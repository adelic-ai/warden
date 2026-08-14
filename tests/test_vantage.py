"""VANTAGE-PLAN.md phase 1 — persistent vantage-VM lifecycle (create-if-absent, not
create-and-destroy). Pins the wiring against FakeIncusClient; the mold, unattended Incus bootstrap,
and real cold-boot timing (phase 2+) need pop-os, same as every other real-host claim in this repo.
"""
from __future__ import annotations

import pytest

from tests.fakes import FakeIncusClient, FakeProxyAllowlistController
from warden.app import WardenApp
from warden.vantage import (
    DEFAULT_NAME,
    DEFAULT_PROJECT,
    PROFILE_NAME,
    VantageError,
    VantageProjectConflict,
    ensure_vantage_vm,
)


def _app(client):
    return WardenApp(client, proxy_controller=FakeProxyAllowlistController())


def test_ensure_vantage_vm_creates_when_absent():
    client = FakeIncusClient()
    app = _app(client)

    info = ensure_vantage_vm(app)

    assert info.created is True
    assert info.name == DEFAULT_NAME
    assert info.project == DEFAULT_PROJECT
    assert client.instance_exists(DEFAULT_NAME, DEFAULT_PROJECT)
    assert client.profile_exists(PROFILE_NAME, DEFAULT_PROJECT)
    # substrate (pool/project/network) was ensured along the way, same as the container path
    assert client.project_exists(DEFAULT_PROJECT)
    assert client.network_exists("wardenbr0")


def test_ensure_vantage_vm_is_noop_when_already_running():
    client = FakeIncusClient()
    app = _app(client)
    first = ensure_vantage_vm(app)
    assert first.created is True

    second = ensure_vantage_vm(app)

    assert second.created is False
    assert second.name == first.name
    # only one instance ever got launched
    assert len([k for k in client.instances if k[1] == DEFAULT_NAME]) == 1


def test_ensure_vantage_vm_launches_as_virtual_machine_not_container():
    client = FakeIncusClient()
    app = _app(client)

    ensure_vantage_vm(app)

    inst = client.instances[(DEFAULT_PROJECT, DEFAULT_NAME)]
    assert inst.instance_type == "virtual-machine"


def test_refuses_to_converge_a_project_with_other_tenants_in_it():
    # Reproduces the real pop-os incident: default already existed and already hosted cta-dev-vm.
    # ensure_build_vm_substrate's network-policy convergence collided with it. This must now refuse
    # before ever attempting that convergence, not partially apply it and fail midway.
    client = FakeIncusClient()
    app = _app(client)
    client.project_create("shared", {})
    client.launch("images:debian/12", "someone-elses-vm", "shared", "default")

    with pytest.raises(VantageProjectConflict, match="someone-elses-vm"):
        ensure_vantage_vm(app, project="shared")

    # and it must not have touched the project at all
    assert client.projects["shared"] == {}


def test_converges_a_project_that_already_exists_but_only_has_our_own_vm():
    # The normal repeat-call case: warden already stood this up once. Existing + only our own
    # instance in it must NOT be treated as foreign.
    client = FakeIncusClient()
    app = _app(client)
    first = ensure_vantage_vm(app, name="warden-vantage-2")
    assert first.created is True

    # simulate a fresh process re-running against the now-existing project + VM
    second = ensure_vantage_vm(app, name="warden-vantage-2")
    assert second.created is False


def test_empty_preexisting_project_is_not_foreign():
    client = FakeIncusClient()
    app = _app(client)
    client.project_create(DEFAULT_PROJECT, {})  # exists, but empty - nothing to collide with

    info = ensure_vantage_vm(app)

    assert info.created is True


def test_wait_ready_raises_vantage_error_not_silent_timeout_on_a_wedged_boot():
    # A VM whose guest agent never comes up must fail loudly, not hang or silently give up —
    # VANTAGE-PLAN.md's failure-handling section: first boot is not recover.py's problem, but it
    # still must not be silence. Calls _wait_ready directly with a small timeout rather than going
    # through ensure_vantage_vm, which hardcodes the real 120s bound - not something a unit test
    # should actually wait out.
    from warden.vantage import _wait_ready

    client = FakeIncusClient()
    app = _app(client)
    ensure_vantage_vm(app, name="warden-vantage-stuck")
    # reused L2 hang simulation (recover.py) for "never finishes booting", not "was working, then
    # wedged" — same underlying signal (exec never answers), different meaning at this layer.
    client._hung.add("warden-vantage-stuck")

    with pytest.raises(VantageError, match="not ready within"):
        _wait_ready(client, "warden-vantage-stuck", DEFAULT_PROJECT, timeout=0.2)
