"""Operational recovery — tiered self-heal for a wedged Incus substrate (warden hardening #1).

Every warden operation is already bounded: `incus.py` raises `IncusTimeoutError` rather than hanging.
This module is what to DO with that — diagnose *which layer* wedged, recover the layers warden is
privileged for, and SURFACE (never silently swallow, never fake) the one layer it is not.

Three tiers, ordered by the privilege they need:

  L1  stuck operation  -> `incus operation delete`   (incus grant — warden self-heals)
  L2  hung instance    -> `incus restart --force`     (incus grant — warden self-heals)
  L3  wedged daemon    -> `systemctl restart incus`   (root warden lacks) -> NEEDS-HUMAN, surfaced

Diagnosis is L3-FIRST on purpose: an unresponsive daemon makes every L1/L2 action hang too — a
force-restart issued against a wedged daemon is exactly what hung for 150s and had to be SIGKILL'd
in the session that motivated this. So warden must never attempt L1/L2 when the daemon itself is the
problem. It probes daemon health first and, if that fails, does the honest thing: reports the exact
human command instead of trying to escalate to a privilege it does not have.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from warden.incus import IncusClient, IncusTimeoutError

STUCK_OPERATION_SECONDS = 120.0  # a still-Running operation older than this is treated as stuck
LIVENESS_PROBE_TIMEOUT = 15.0    # bounding the per-instance liveness exec

TIER_HEALTHY = "healthy"
TIER_STUCK_OPERATION = "stuck_operation"
TIER_HUNG_INSTANCE = "hung_instance"
TIER_DAEMON_WEDGED = "daemon_wedged"

# Surfaced verbatim for L3. Kept honest: names the privilege warden lacks and the exact command,
# and warns against rebooting instead — an operator who does not know instances survive a daemon
# restart might reboot the whole host, which risks stranding it on any box that needs a manual step
# to come back up (disk decryption, a console session that isn't there). Host-agnostic on purpose:
# no hardcoded hostname/user — warden doesn't know how *this* operator reaches *this* host (local
# shell, SSH, something else), so it names the command, not a way to run it.
DAEMON_RECOVERY_HINT = (
    "incus daemon is wedged — warden cannot restart it (needs root it does not have). "
    "As a user with sudo on this host, run: sudo systemctl restart incus "
    "(running instances survive a daemon restart — do NOT reboot instead; a reboot risks any "
    "manual step this host needs to come back up that this session cannot perform)."
)


@dataclass
class Diagnosis:
    tier: str
    detail: str
    stuck_operations: list[str] = field(default_factory=list)
    hung_instance: Optional[str] = None


@dataclass
class RecoveryResult:
    diagnosis: Diagnosis
    recovered: bool
    action: str
    needs_human: Optional[str] = None


def _operation_age_seconds(op: dict, now: datetime) -> Optional[float]:
    created = op.get("created_at") or op.get("created")
    if not isinstance(created, str) or not created:
        return None
    try:
        ts = datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return (now - ts).total_seconds()


def _is_stuck(op: dict, now: datetime) -> bool:
    status = str(op.get("status") or op.get("state") or "").lower()
    if status not in ("running", "pending"):
        return False
    age = _operation_age_seconds(op, now)
    # Unknown age is NOT treated as stuck: deleting an operation we cannot age could kill a genuinely
    # in-flight one. Conservative on the destructive side, by design.
    return age is not None and age >= STUCK_OPERATION_SECONDS


def diagnose(
    client: IncusClient,
    *,
    instance: Optional[str] = None,
    project: str = "default",
    now: Optional[datetime] = None,
) -> Diagnosis:
    """Classify the wedge. L3-first (see module docstring): never probe L1/L2 past an unresponsive
    daemon. `instance` is optional — L2 is only checkable when the caller says which instance."""
    now = now or datetime.now(timezone.utc)

    if not client.responsive():
        return Diagnosis(TIER_DAEMON_WEDGED, "incus daemon did not answer a bounded query")

    stuck = [op for op in client.operations() if _is_stuck(op, now)]
    if stuck:
        ids = [str(op.get("id", "?")) for op in stuck]
        return Diagnosis(
            TIER_STUCK_OPERATION, f"{len(ids)} stuck operation(s): {', '.join(ids)}",
            stuck_operations=ids,
        )

    if instance is not None:
        try:
            alive = client.exec(instance, ["/bin/true"], project=project, timeout=LIVENESS_PROBE_TIMEOUT).ok
        except IncusTimeoutError:
            return Diagnosis(TIER_HUNG_INSTANCE, f"{instance} did not answer a bounded exec",
                             hung_instance=instance)
        if not alive:
            return Diagnosis(TIER_HUNG_INSTANCE, f"{instance} exec returned non-zero to a liveness probe",
                             hung_instance=instance)

    detail = "daemon responsive; no stuck operations"
    if instance is not None:
        detail += f"; {instance} responds to exec"
    return Diagnosis(TIER_HEALTHY, detail)


def recover(client: IncusClient, diagnosis: Diagnosis, *, project: str = "default") -> RecoveryResult:
    """Execute the recovery warden is privileged for; SURFACE L3. Idempotent — safe to re-run: a
    re-diagnose after a successful recovery returns healthy, and a re-run of L1/L2 is a no-op."""
    if diagnosis.tier == TIER_HEALTHY:
        return RecoveryResult(diagnosis, recovered=True, action="nothing to recover")

    if diagnosis.tier == TIER_STUCK_OPERATION:
        for op_id in diagnosis.stuck_operations:
            client.operation_delete(op_id)
        return RecoveryResult(diagnosis, recovered=True,
                              action=f"deleted {len(diagnosis.stuck_operations)} stuck operation(s)")

    if diagnosis.tier == TIER_HUNG_INSTANCE:
        assert diagnosis.hung_instance is not None
        client.restart(diagnosis.hung_instance, project=project, force=True)
        return RecoveryResult(diagnosis, recovered=True,
                              action=f"force-restarted instance {diagnosis.hung_instance}")

    # TIER_DAEMON_WEDGED — warden lacks the privilege. Surface the exact command; do NOT escalate,
    # do NOT attempt an L1/L2 action (they would hang against the wedged daemon), do NOT report success.
    return RecoveryResult(diagnosis, recovered=False, action="surfaced to human",
                          needs_human=DAEMON_RECOVERY_HINT)


def diagnose_and_recover(
    client: IncusClient, *, instance: Optional[str] = None, project: str = "default"
) -> RecoveryResult:
    return recover(client, diagnose(client, instance=instance, project=project), project=project)


class SubstrateUnrecovered(RuntimeError):
    """A warden operation timed out and auto-recovery could not make it succeed — an L3 daemon wedge
    warden can't fix, or a hang that persisted after an L1/L2 heal. Carries the human-facing hint so
    the CLI can surface it and exit NEEDS-HUMAN, never a false success."""

    def __init__(self, message: str, result: Optional[RecoveryResult] = None):
        self.result = result
        super().__init__(message)


def _noop(_msg: str) -> None:
    pass


def run_with_recovery(
    client: IncusClient,
    operation,
    *,
    instance: Optional[str] = None,
    project: str = "default",
    log=_noop,
):
    """Run `operation()`; on an `IncusTimeoutError`, diagnose + recover the substrate and retry it
    ONCE. Recovery is logged (never silent). Only retries when recovery actually healed (L1/L2) — an
    L3 daemon wedge (or a hang that survives one heal) raises `SubstrateUnrecovered` instead of
    retrying, because retrying against a wedged daemon would just hang again.

    `operation` MUST be idempotent — warden's up/run/restore are (re-run converges), which is what
    makes the single retry safe."""
    try:
        return operation()
    except IncusTimeoutError as first:
        log("warden: operation timed out — diagnosing the substrate before assuming failure...")
        result = diagnose_and_recover(client, instance=instance, project=project)
        log(f"warden: {result.diagnosis.tier} — {result.diagnosis.detail}")
        if not result.recovered:
            raise SubstrateUnrecovered(result.needs_human or result.diagnosis.detail, result) from first
        log(f"warden: recovered ({result.action}); retrying the operation once...")
        try:
            return operation()
        except IncusTimeoutError as second:
            # Healed once but it still timed out — do NOT loop. Surface with the action we took.
            raise SubstrateUnrecovered(
                f"operation still timed out after recovery ({result.action})", result
            ) from second
