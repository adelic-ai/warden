"""Operational recovery (warden/recover.py) — tiered diagnose->heal, L3-first, honest about the
one tier warden is not privileged for."""
from datetime import datetime, timedelta, timezone

import pytest

from warden.incus import IncusTimeoutError
from warden.recover import (
    TIER_DAEMON_WEDGED,
    TIER_HEALTHY,
    TIER_HUNG_INSTANCE,
    TIER_STUCK_OPERATION,
    SubstrateUnrecovered,
    diagnose,
    diagnose_and_recover,
    recover,
    run_with_recovery,
)
from tests.fakes import FakeIncusClient

NOW = datetime(2026, 8, 10, 12, 0, 0, tzinfo=timezone.utc)


def _running_instance(client, name="cap-1", project="warden"):
    client.launch("images:debian/12", name, project, "prof")
    return name


def _op(op_id, status="Running", age_seconds=999):
    created = (NOW - timedelta(seconds=age_seconds)).isoformat()
    return {"id": op_id, "status": status, "created_at": created}


# ---- diagnosis, L3-first ----
def test_wedged_daemon_is_diagnosed_before_anything_else():
    client = FakeIncusClient()
    client._responsive = False
    # even with a stuck operation present, a dead daemon must win — L1/L2 would hang against it
    client._operations = [_op("op-1")]
    d = diagnose(client, now=NOW)
    assert d.tier == TIER_DAEMON_WEDGED


def test_stuck_operation_detected_when_daemon_is_up():
    client = FakeIncusClient()
    client._operations = [_op("op-old", age_seconds=999), _op("op-fresh", age_seconds=5)]
    d = diagnose(client, now=NOW)
    assert d.tier == TIER_STUCK_OPERATION
    assert d.stuck_operations == ["op-old"]   # the fresh one is NOT swept up


def test_a_running_but_fresh_operation_is_not_stuck():
    client = FakeIncusClient()
    client._operations = [_op("op-fresh", age_seconds=10)]
    assert diagnose(client, now=NOW).tier == TIER_HEALTHY


def test_an_operation_with_no_parseable_age_is_not_treated_as_stuck():
    client = FakeIncusClient()
    client._operations = [{"id": "op-x", "status": "Running", "created_at": "not-a-date"}]
    assert diagnose(client, now=NOW).tier == TIER_HEALTHY  # conservative: never delete what we can't age


def test_hung_instance_detected_via_bounded_exec():
    client = FakeIncusClient()
    name = _running_instance(client)
    client._hung.add(name)  # its exec now times out
    d = diagnose(client, instance=name, project="warden", now=NOW)
    assert d.tier == TIER_HUNG_INSTANCE
    assert d.hung_instance == name


def test_healthy_when_daemon_up_no_ops_and_instance_responds():
    client = FakeIncusClient()
    name = _running_instance(client)
    assert diagnose(client, instance=name, project="warden", now=NOW).tier == TIER_HEALTHY


# ---- recovery actions ----
def test_recover_deletes_stuck_operations():
    client = FakeIncusClient()
    client._operations = [_op("op-old", age_seconds=999)]
    result = diagnose_and_recover(client)   # now=real, op is 999s in the past relative to real now too
    assert result.recovered
    assert "deleted 1 stuck operation" in result.action
    assert client._operations == []          # actually gone


def test_recover_force_restarts_a_hung_instance():
    client = FakeIncusClient()
    name = _running_instance(client)
    client._hung.add(name)
    result = diagnose_and_recover(client, instance=name, project="warden")
    assert result.recovered
    assert (name, True) in client.restarts   # force-restarted
    # and after recovery the instance answers again (idempotent re-converge)
    assert diagnose(client, instance=name, project="warden").tier == TIER_HEALTHY


def test_recover_surfaces_daemon_wedge_never_fakes_or_escalates():
    client = FakeIncusClient()
    client._responsive = False
    result = diagnose_and_recover(client)
    assert result.recovered is False              # NOT reported as recovered
    assert result.needs_human is not None
    assert "systemctl restart incus" in result.needs_human
    assert client.restarts == []                  # did NOT attempt an L2 action against a wedged daemon


def test_recover_healthy_is_a_noop():
    client = FakeIncusClient()
    result = recover(client, diagnose(client, now=NOW))
    assert result.recovered
    assert result.action == "nothing to recover"


# ---- auto-recover wrapper (run_with_recovery) ----
def test_auto_recover_passes_a_success_straight_through():
    client = FakeIncusClient()
    assert run_with_recovery(client, lambda: "done") == "done"


def test_auto_recover_heals_a_hung_instance_then_retries_and_succeeds():
    client = FakeIncusClient()
    name = _running_instance(client)
    client._hung.add(name)  # the operation's first attempt will time out; diagnosis sees the hang
    calls = []

    def op():
        calls.append(1)
        if len(calls) == 1:
            raise IncusTimeoutError(["up"], 60.0)   # first attempt hangs
        return "up-ok"                               # retry (post force-restart) succeeds

    result = run_with_recovery(client, op, instance=name, project="warden")
    assert result == "up-ok"
    assert len(calls) == 2                       # retried exactly once
    assert (name, True) in client.restarts       # L2 recovery actually happened


def test_auto_recover_surfaces_a_daemon_wedge_without_retrying():
    client = FakeIncusClient()
    client._responsive = False
    calls = []

    def op():
        calls.append(1)
        raise IncusTimeoutError(["up"], 60.0)

    with pytest.raises(SubstrateUnrecovered) as caught:
        run_with_recovery(client, op)
    assert "systemctl restart incus" in str(caught.value)
    assert len(calls) == 1                        # did NOT retry into a wedged daemon


def test_auto_recover_gives_up_after_a_second_timeout_never_loops():
    client = FakeIncusClient()
    name = _running_instance(client)
    client._hung.add(name)

    def op():  # always times out, even after the heal
        raise IncusTimeoutError(["up"], 60.0)

    with pytest.raises(SubstrateUnrecovered) as caught:
        run_with_recovery(client, op, instance=name, project="warden")
    assert "still timed out after recovery" in str(caught.value)
