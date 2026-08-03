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
    def uninstall(self, instance: str) -> None: ...
    def prune(self, live_instances: set[str]) -> None: ...


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
    return "".join(f"-a {' '.join(frag)}\n" for frag in rule_fragments(uid_range, instance))


def rule_fragments(uid_range: "IdRange", instance: str) -> list[list[str]]:
    """The same rules as `generate_rule`, as `auditctl` argv fragments.

    Used to load and unload rules *individually, by key*. `augenrules
    --load` is not used for the live load: it compiles every file in
    `rules.d` and its output starts with `-D`, which would momentarily
    wipe every audit rule on the host — including the unrelated
    gemini-capsule build's ground-truth plane. The file in `rules.d` is
    still written, so the rule survives a reboot; only the live load is
    surgical. See DECISIONS.md "D15".
    """
    key = rule_key(instance)
    lo, hi = uid_range.host_start, uid_range.host_end
    return [
        ["always,exit", "-F", f"arch={arch}", "-S", "execve",
         "-F", f"uid>={lo}", "-F", f"uid<={hi}", "-k", key]
        for arch in ("b64", "b32")
    ]


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

    The merge key is the **whole `ts:serial` id, never the serial alone**.
    The kernel's serial counter restarts from zero at every boot while
    `/var/log/audit/audit.log` persists across boots, so a serial is only
    unique *within* a boot. Measured on this host: 27 counter resets and
    two serials living under two timestamps ~28h apart in the current log.

    Merging on the serial alone silently fuses those unrelated events into
    one, and since each field is taken from the first record that carries
    it, the fused event can pair a real marker with a `uid` and `key`
    lifted from a different event entirely — i.e. report capture proven
    for a rule that captured nothing. That is the exact failure shape this
    module exists to catch, so it must not be the way it fails.
    """
    by_event: dict[str, dict] = {}
    for line in text.splitlines():
        m = _AUDIT_MSG_RE.search(line)
        if not m:
            continue
        ts_part, serial = _split_ts_serial(m.group(1))
        rec = by_event.setdefault(
            f"{ts_part}:{serial}",
            {"ts": _parse_ts(ts_part), "uid": None, "key": None, "marker": None, "raw": []},
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
        for r in by_event.values()
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
    timeout: float = 20.0,
    poll_interval: float = 0.2,
    _sleep=time.sleep,
    _now=time.monotonic,
) -> AuditEvent:
    """Exec a marker inside `instance` and confirm the audit trail actually
    captured it at `uid_range`, **under this instance's own rule key**.
    Raises `CaptureNotProvenError` on timeout — that failure is the whole
    point of this function existing instead of just checking `auditctl -l`.

    The key check is not decoration. The first real-Incus run had a
    deleted instance's rule still loaded with an identical uid range;
    the kernel's exit filter stops at the first matching rule, so the new
    instance's execs were tagged with the *dead* instance's key. Matching
    on uid alone called that a pass while `ausearch -k <this instance>`
    found nothing — a confident wrong answer, which is this build's
    recurring failure shape. See DECISIONS.md "D14".

    The timeout is generous because auditd's flush is not synchronous with
    the exec: the capsule build twice diagnosed a working plane as broken
    on a 2-3s wait.
    """
    argv, token = marker_argv()
    expected_key = rule_key(instance)
    result = client.exec(instance, argv, project=project)
    if not result.ok:
        raise CaptureNotProvenError(
            f"{instance}: marker exec itself failed (rc={result.returncode}): {result.stderr}"
        )

    near_miss: AuditEvent | None = None
    deadline = _now() + timeout
    while True:
        for event in source.poll():
            if event.marker != token:
                continue
            if event.uid is None or not uid_range.contains(event.uid):
                near_miss = event
                continue
            if event.key != expected_key:
                near_miss = event
                continue
            return event
        if _now() >= deadline:
            break
        _sleep(poll_interval)

    detail = ""
    if near_miss is not None:
        detail = (
            f" The marker WAS captured (uid={near_miss.uid}, key={near_miss.key!r}) but did not "
            f"match this instance's rule (expected key {expected_key!r} in uid range {uid_range}). "
            "A stale rule from a deleted instance with an overlapping uid range will do exactly "
            "this — the kernel tags the exec with whichever matching rule it reaches first."
        )
    raise CaptureNotProvenError(
        f"{instance}: marker {token!r} not observed in the audit trail for uid range "
        f"{uid_range} under key {expected_key!r} within {timeout}s. Do not trust `auditctl -l` "
        f"here — capture is unproven, whatever the rule listing says.{detail}"
    )


# ---------------------------------------------------------------------------
# real (root-requiring) adapters — see NEEDS-HUMAN.md
# ---------------------------------------------------------------------------

class AuditRuleLoadError(RuntimeError):
    """A rule was written but the kernel does not have it loaded."""


class RealAuditRuleInstaller:
    """Writes `/etc/audit/rules.d/60-warden-<instance>.rules` for
    persistence and loads/unloads that instance's rules **by key** with
    `auditctl`. Requires root.

    Two failures from the first real-Incus run shaped this:

    - `augenrules --load` is a no-op when the compiled ruleset is
      byte-identical ("No change"), so a rule that is on disk but not in
      the kernel stays that way. Nothing checked. Now the load is direct
      and the result is verified against `auditctl -l`.
    - `warden down` removed the instance but left its rule file behind.
      The next instance to be allocated that freed uid range was captured
      under the *dead* instance's key. `prune()` is the fix, and
      `uninstall()` stops it happening in the first place.
    """

    RULE_FILE_GLOB = f"60-{RULE_KEY_PREFIX}-*.rules"

    def __init__(self, rules_dir: str = "/etc/audit/rules.d"):
        self.rules_dir = Path(rules_dir)

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _loaded_lines() -> list[str]:
        proc = subprocess.run(["auditctl", "-l"], capture_output=True, text=True)
        if proc.returncode != 0:
            return []
        return [line.strip() for line in proc.stdout.splitlines() if line.strip()]

    @classmethod
    def _delete_loaded(cls, key: str) -> None:
        """Delete only the rules carrying `key`, converting each listed
        rule back into a `-d` spec. Never `auditctl -D`: this host also
        carries the gemini-capsule build's rule, and wiping it would blind
        an unrelated system's ground-truth plane."""
        for line in cls._loaded_lines():
            tokens = line.split()
            if not any(t in (f"key={key}", key) for t in tokens):
                continue
            args, i = [], 0
            while i < len(tokens):
                tok = tokens[i]
                if tok == "-a":
                    args.append("-d")
                elif tok == "-F" and i + 1 < len(tokens) and tokens[i + 1].startswith("key="):
                    args += ["-k", tokens[i + 1][len("key="):]]
                    i += 1
                else:
                    args.append(tok)
                i += 1
            subprocess.run(["auditctl", *args], capture_output=True, text=True)

    @classmethod
    def _is_loaded(cls, key: str) -> bool:
        return any(
            any(t in (f"key={key}", key) for t in line.split()) for line in cls._loaded_lines()
        )

    # -- protocol ----------------------------------------------------------
    def install(self, instance: str, uid_range: "IdRange") -> None:
        key = rule_key(instance)
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        # persistence across reboot
        Path(rule_file_path(instance)).write_text(generate_rule(uid_range, instance))
        # live load: replace whatever is currently loaded under this key,
        # so a re-derived range after a restore actually takes effect
        self._delete_loaded(key)
        for fragment in rule_fragments(uid_range, instance):
            proc = subprocess.run(["auditctl", "-a", *fragment], capture_output=True, text=True)
            if proc.returncode != 0:
                raise AuditRuleLoadError(
                    f"auditctl -a for {instance} failed (rc={proc.returncode}): {proc.stderr.strip()}"
                )
        if not self._is_loaded(key):
            raise AuditRuleLoadError(
                f"{instance}: rule written to {rule_file_path(instance)} but key {key!r} is "
                "not present in `auditctl -l` — the kernel does not have it"
            )

    def uninstall(self, instance: str) -> None:
        self._delete_loaded(rule_key(instance))
        Path(rule_file_path(instance)).unlink(missing_ok=True)

    def prune(self, live_instances: set[str]) -> None:
        """Drop rules for warden instances that no longer exist.

        Covers the crash case as well as the clean one: a run that dies
        between `incus delete` and `uninstall` leaves a rule file behind,
        and the next `up` would otherwise inherit the shadowing bug."""
        for path in self.rules_dir.glob(self.RULE_FILE_GLOB):
            instance = path.name[len(f"60-{RULE_KEY_PREFIX}-"):-len(".rules")]
            if instance and instance not in live_instances:
                self.uninstall(instance)


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
