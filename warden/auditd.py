"""auditd wiring for the `monitored` flavor (§1, §4 test 1).

Three things live here, deliberately kept independent of each other:

1. `generate_rule` / `RULE_KEY_PREFIX` — render the persistent
   `/etc/audit/rules.d/*.rules` content, scoped to a *derived* (never
   frozen) host-uid range.
2. A dialect-tolerant/raw event parser — this host "interpolates
   `ausearch -i` fields and uses local-time headers" per the spec; the
   parser accepts either that or raw epoch-keyed output, preferring raw
   because it's unambiguous.
3. `prove_capture` — the actual regression test for the I6-breaks-I5
   gotcha: after wiring (or re-wiring, post-restore) a rule, exec a
   uniquely-tokened marker command and confirm the audit trail actually
   captured it at the expected uid range. `auditctl -l` only proves a rule
   is *loaded*, not that it's matching real syscalls (ordering, an
   earlier catch-all, backlog limits, or a stale range can all make a
   "loaded" rule capture nothing) — so this never substitutes for the
   real thing.
"""

from __future__ import annotations

import re
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from warden.idmap import IdRange
    from warden.incus import IncusClient

RULE_KEY_PREFIX = "warden"
MARKER_PREFIX = "WARDEN_MARKER_"
_MARKER_RE = re.compile(rf"{MARKER_PREFIX}[0-9a-f]{{32}}")


class CaptureNotProvenError(RuntimeError):
    """The marker exec didn't show up in the audit trail in time.

    This is the failure mode the spec calls out explicitly: never trust
    `auditctl -l` for this — it only proves the rule is loaded text, not
    that it's capturing.
    """


@dataclass(frozen=True)
class AuditEvent:
    ts: float | None  # epoch seconds; None if the dialect couldn't be parsed
    uid: int | None
    key: str | None
    marker: str | None
    raw: str


class EventSource(Protocol):
    """Something `prove_capture` can poll for freshly-captured events."""

    def poll(self) -> list[AuditEvent]: ...


class AuditRuleInstaller(Protocol):
    """Writes the persistent rule and reloads it. Needs root for real —
    see `RealAuditRuleInstaller` and NEEDS-HUMAN.md."""

    def install(self, instance: str, uid_range: "IdRange") -> None: ...


def rule_key(instance: str) -> str:
    return f"{RULE_KEY_PREFIX}-{instance}"


def rule_file_path(instance: str) -> str:
    return f"/etc/audit/rules.d/60-{rule_key(instance)}.rules"


def generate_rule(uid_range: "IdRange", instance: str) -> str:
    """Persistent rule text, scoped to the *derived* host-uid range.

    Scoped on `uid` (the actual running uid), not `auid` (login uid) —
    unprivileged containers have no PAM session, so `auid` is unset for
    everything inside them and wouldn't distinguish containers at all.
    See DECISIONS.md.
    """
    key = rule_key(instance)
    lo, hi = uid_range.host_start, uid_range.host_end
    return (
        f"-a always,exit -F arch=b64 -S execve -F uid>={lo} -F uid<={hi} -k {key}\n"
        f"-a always,exit -F arch=b32 -S execve -F uid>={lo} -F uid<={hi} -k {key}\n"
    )


def extract_marker(text: str) -> str | None:
    m = _MARKER_RE.search(text)
    return m.group(0) if m else None


def marker_argv() -> tuple[list[str], str]:
    """A command whose *argv* (not environment — audit captures syscall
    arguments, not env) contains a unique, greppable token."""
    token = f"{MARKER_PREFIX}{uuid.uuid4().hex}"
    return ["/bin/echo", token], token


# ---------------------------------------------------------------------------
# dialect-tolerant / raw parsing
# ---------------------------------------------------------------------------

_AUDIT_MSG_RE = re.compile(r"msg=audit\(([^)]*)\)")
_UID_RE = re.compile(r"\buid=(\d+)")
_KEY_RE = re.compile(r'\bkey="?([\w-]+)"?')


def _split_ts_serial(inner: str) -> tuple[str, str]:
    # Both raw ("1690000000.123:456") and ausearch -i interpolated
    # ("08/02/2026 19:40:00.123:456") end in ":<serial>"; the timestamp
    # portion itself may contain colons (HH:MM:SS), so split on the last one.
    ts_part, _, serial = inner.rpartition(":")
    return ts_part, serial


def _parse_ts(ts_part: str) -> float | None:
    if re.fullmatch(r"\d+\.\d+", ts_part):
        return float(ts_part)  # raw epoch — unambiguous, preferred
    for fmt in ("%m/%d/%Y %H:%M:%S.%f",):
        try:
            struct = time.strptime(ts_part, fmt)
            return time.mktime(struct)
        except ValueError:
            continue
    return None  # unrecognized dialect — still usable for uid/marker matching


def parse_events(text: str) -> list[AuditEvent]:
    """Parse either raw `audit.log`/`ausearch --raw` text or this host's
    interpolated `ausearch -i` dialect (local-time headers). Lines sharing
    an `audit(ts:serial)` id (SYSCALL carries uid, EXECVE carries argv) are
    merged into one event.
    """
    by_serial: dict[str, dict] = {}
    for line in text.splitlines():
        m = _AUDIT_MSG_RE.search(line)
        if not m:
            continue
        ts_part, serial = _split_ts_serial(m.group(1))
        rec = by_serial.setdefault(
            serial, {"ts": _parse_ts(ts_part), "uid": None, "key": None, "marker": None, "raw": []}
        )
        rec["raw"].append(line)
        uid_m = _UID_RE.search(line)
        if uid_m and rec["uid"] is None:
            rec["uid"] = int(uid_m.group(1))
        key_m = _KEY_RE.search(line)
        if key_m and rec["key"] is None:
            rec["key"] = key_m.group(1)
        marker = extract_marker(line)
        if marker and rec["marker"] is None:
            rec["marker"] = marker

    return [
        AuditEvent(ts=r["ts"], uid=r["uid"], key=r["key"], marker=r["marker"], raw="\n".join(r["raw"]))
        for r in by_serial.values()
    ]


# ---------------------------------------------------------------------------
# marker-exec capture proof
# ---------------------------------------------------------------------------

def prove_capture(
    client: "IncusClient",
    source: EventSource,
    instance: str,
    uid_range: "IdRange",
    project: str = "default",
    timeout: float = 5.0,
    poll_interval: float = 0.2,
    _sleep=time.sleep,
    _now=time.monotonic,
) -> AuditEvent:
    """Exec a marker inside `instance` and confirm the audit trail actually
    captured it at `uid_range`. Raises `CaptureNotProvenError` on timeout —
    that failure is the whole point of this function existing instead of
    just checking `auditctl -l`.
    """
    argv, token = marker_argv()
    result = client.exec(instance, argv, project=project)
    if not result.ok:
        raise CaptureNotProvenError(
            f"{instance}: marker exec itself failed (rc={result.returncode}): {result.stderr}"
        )

    deadline = _now() + timeout
    while True:
        for event in source.poll():
            if event.marker == token and event.uid is not None and uid_range.contains(event.uid):
                return event
        if _now() >= deadline:
            break
        _sleep(poll_interval)

    raise CaptureNotProvenError(
        f"{instance}: marker {token!r} not observed in the audit trail for uid range "
        f"{uid_range} within {timeout}s. Do not trust `auditctl -l` here — capture is "
        "unproven, whatever the rule listing says."
    )


# ---------------------------------------------------------------------------
# real (root-requiring) adapters — see NEEDS-HUMAN.md
# ---------------------------------------------------------------------------

class RealAuditRuleInstaller:
    """Writes `/etc/audit/rules.d/60-warden-<instance>.rules` and reloads
    via `augenrules --load`. Requires root; not exercised in this build
    (see NEEDS-HUMAN.md) but written to be run by
    `scripts/run-acceptance-nested.sh` once root is available."""

    def install(self, instance: str, uid_range: "IdRange") -> None:
        path = Path(rule_file_path(instance))
        path.write_text(generate_rule(uid_range, instance))
        subprocess.run(["augenrules", "--load"], check=True)


class RealEventSource:
    """Prefers raw, unambiguous-epoch `ausearch --raw`; falls back to
    reading the raw log file directly if `ausearch` isn't on PATH or the
    caller lacks permission to invoke it. Both paths go through the same
    dialect-tolerant `parse_events`, so this host's ausearch -i/local-time
    quirks don't need special-casing here."""

    def __init__(self, instance: str, raw_log_path: str = "/var/log/audit/audit.log"):
        self.key = rule_key(instance)
        self.raw_log_path = raw_log_path

    def poll(self) -> list[AuditEvent]:
        try:
            proc = subprocess.run(
                ["ausearch", "-k", self.key, "--raw"], capture_output=True, text=True
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return parse_events(proc.stdout)
        except FileNotFoundError:
            pass
        try:
            text = Path(self.raw_log_path).read_text()
        except (FileNotFoundError, PermissionError):
            return []
        return [e for e in parse_events(text) if e.key == self.key]
