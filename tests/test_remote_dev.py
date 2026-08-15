"""VANTAGE-PLAN.md phase 5 — remote-drive container creation. Pins the wiring (the exec argv, the
PYTHONPATH env, and — the important one — never trusting a zero exit code alone) against
FakeIncusClient; the actual nested `warden dev` provisioning needs pop-os.
"""
from __future__ import annotations

import pytest

from tests.fakes import FakeIncusClient, FakeProxyAllowlistController
from warden.app import WardenApp
from warden.incus import ExecResult
from warden.profiles import NESTED_BRIDGE_SUBNET_ENV_VAR
from warden.flavors import Flavor, resolve as resolve_flavor
from warden.remote_dev import DEFAULT_DEV_NAME, NESTED_IMAGE_HOST, RemoteDevError, create_nested_dev
from warden.vantage import DEFAULT_PROJECT, NESTED_BRIDGE_SUBNET

VANTAGE_INSTANCE = "warden-vantage"


def _app(client):
    return WardenApp(client, proxy_controller=FakeProxyAllowlistController())


def _launched_vantage(client):
    client.project_create(DEFAULT_PROJECT, {})
    client.profile_create(DEFAULT_PROJECT, DEFAULT_PROJECT, {}, {})
    client.launch(
        "warden-vantage-golden", VANTAGE_INSTANCE, DEFAULT_PROJECT, DEFAULT_PROJECT,
        instance_type="virtual-machine",
    )


def test_create_nested_dev_happy_path_verifies_against_nested_incus():
    client = FakeIncusClient()
    app = _app(client)
    _launched_vantage(client)
    # the fake's default exec() returns empty stdout - simulate the nested `incus list` actually
    # showing the container, which is what verification checks for
    client.exec_results["incus list"] = ExecResult(0, f"{DEFAULT_DEV_NAME}\n", "")

    result = create_nested_dev(app, vantage_instance=VANTAGE_INSTANCE, llm="claude")

    assert result.name == DEFAULT_DEV_NAME
    assert result.nested_project == "warden"
    dev_calls = [argv for n, argv in client.exec_calls if "warden.cli" in " ".join(argv)]
    assert len(dev_calls) == 1
    assert "--no-shell" in dev_calls[0]
    assert "--llm" in dev_calls[0] and "claude" in dev_calls[0]
    # nested incusd's own proxy config gets set before dev runs, not skipped
    proxy_calls = [argv for n, argv in client.exec_calls if "core.proxy_https" in " ".join(argv)]
    assert len(proxy_calls) == 1
    proxy_call_index = client.exec_calls.index((VANTAGE_INSTANCE, proxy_calls[0]))
    dev_call_index = client.exec_calls.index((VANTAGE_INSTANCE, dev_calls[0]))
    assert proxy_call_index < dev_call_index
    # the outer allowlist was opened to the nested image host PLUS whatever the container's own
    # provisioning needs — reused from flavors.resolve, not a second hand-maintained list (real-
    # host lesson: narrowing this to just the image host produced a fast 403 once proxy chaining
    # started actually reaching this far).
    expected = (NESTED_IMAGE_HOST, *resolve_flavor(Flavor.DEV, "claude").provisioning_allowlist)
    assert app.proxy_controller.current == expected
    # real-host incident: without this env var, the deployed code's own ensure_substrate() would
    # converge the nested wardenbr0 back to the (colliding) outer default
    assert client.exec_envs[dev_call_index][NESTED_BRIDGE_SUBNET_ENV_VAR] == NESTED_BRIDGE_SUBNET


def test_nested_proxy_config_failure_raises_before_attempting_dev():
    client = FakeIncusClient()
    app = _app(client)
    _launched_vantage(client)
    client.exec_failures["core.proxy_https"] = ExecResult(1, "", "Error: not a server-level key")

    with pytest.raises(RemoteDevError, match="proxy"):
        create_nested_dev(app, vantage_instance=VANTAGE_INSTANCE, llm="claude")

    dev_calls = [argv for n, argv in client.exec_calls if "warden.cli" in " ".join(argv)]
    assert dev_calls == []  # never got that far


def test_dev_command_failure_raises_remote_dev_error():
    client = FakeIncusClient()
    app = _app(client)
    _launched_vantage(client)
    client.exec_failures["warden.cli dev"] = ExecResult(1, "", "NEEDS-HUMAN: no API key")

    with pytest.raises(RemoteDevError, match="remote `warden dev` failed"):
        create_nested_dev(app, vantage_instance=VANTAGE_INSTANCE, llm="claude")


def test_zero_exit_but_no_container_is_not_trusted():
    # The core principle this module exists to enforce: a clean exit code alone doesn't mean the
    # container is actually there. Fake's default exec() returns empty stdout for the verify call
    # (no exec_results override), simulating exactly that gap.
    client = FakeIncusClient()
    app = _app(client)
    _launched_vantage(client)

    with pytest.raises(RemoteDevError, match="not trusting the exit code alone"):
        create_nested_dev(app, vantage_instance=VANTAGE_INSTANCE, llm="claude")
