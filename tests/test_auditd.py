import pytest

from warden.auditd import (
    CaptureNotProvenError,
    generate_rule,
    parse_events,
    prove_capture,
)
from warden.idmap import IdRange
from tests.fakes import FakeEventSource, FakeIncusClient


def test_generate_rule_scopes_by_uid_not_auid():
    rng = IdRange(1_000_000, 65536)
    rule = generate_rule(rng, "cap-1")
    assert "-F uid>=1000000" in rule
    assert "-F uid<=1065535" in rule
    assert "auid" not in rule
    assert "-k warden-cap-1" in rule


def test_rule_captures_action_and_ancestry_arms():
    # execve is the action arm (what verdicts reconcile against); clone is the
    # ancestry arm — captured so a forked-but-never-execve'd bridge process
    # doesn't orphan its execve'd subtree (the fork gap).
    rng = IdRange(1_000_000, 65536)
    rule = generate_rule(rng, "cap-1")
    assert "-S execve" in rule
    assert "-S clone" in rule
    # fork/vfork are deliberately NOT in the rule: aarch64 (Mac/Lima) has no such
    # syscall, so the token would be rejected and blind execve with it. clone is
    # arch-portable and is where glibc fork/vfork land. clone3 is deferred for the
    # same unknown-token reason (needs its own failure-tolerant fragment).
    for absent in ("-S fork", "-S vfork", "-S clone3"):
        assert absent not in rule, absent
    # ancestry syscall rides the SAME uid scope as execve, per arch
    for arch in ("b64", "b32"):
        assert f"-F arch={arch} -S execve -S clone" in rule


def test_parse_raw_epoch_dialect():
    # unambiguous epoch:serial — the preferred, unambiguous form
    text = (
        'type=SYSCALL msg=audit(1690000000.123:456): arch=c000003e syscall=59 '
        'success=yes exit=0 uid=1000042 key="warden-cap-1"\n'
        'type=EXECVE msg=audit(1690000000.123:456): argc=2 a0="/bin/echo" '
        'a1="WARDEN_MARKER_deadbeefdeadbeefdeadbeefdeadbeef"\n'
    )
    events = parse_events(text)
    assert len(events) == 1
    event = events[0]
    assert event.ts == 1690000000.123
    assert event.uid == 1000042
    assert event.key == "warden-cap-1"
    assert event.marker == "WARDEN_MARKER_deadbeefdeadbeefdeadbeefdeadbeef"


def test_parse_interpolated_localtime_dialect():
    # this host's dialect: ausearch -i interpolates fields and uses
    # local-time headers instead of raw epoch
    text = (
        'type=SYSCALL msg=audit(08/02/2026 19:40:00.123:456) : arch=x86_64 '
        'syscall=execve success=yes uid=1000042 key="warden-cap-1"\n'
        'type=EXECVE msg=audit(08/02/2026 19:40:00.123:456) : argc=2 '
        'a0=/bin/echo a1=WARDEN_MARKER_deadbeefdeadbeefdeadbeefdeadbeef\n'
    )
    events = parse_events(text)
    assert len(events) == 1
    event = events[0]
    assert event.ts is not None  # parsed despite the local-time header
    assert event.uid == 1000042
    assert event.marker == "WARDEN_MARKER_deadbeefdeadbeefdeadbeefdeadbeef"


def test_parse_tolerates_unrecognized_timestamp_dialect():
    # even if some future dialect shifts the date format again, uid/marker
    # matching (what prove_capture actually needs) must not depend on ts
    text = (
        'type=SYSCALL msg=audit(??? 456): uid=1000042 key="warden-cap-1"\n'
        'type=EXECVE msg=audit(??? 456): a0=/bin/true a1=WARDEN_MARKER_'
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n'
    )
    events = parse_events(text)
    assert len(events) == 1
    assert events[0].ts is None
    assert events[0].uid == 1000042
    assert events[0].marker == "WARDEN_MARKER_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def test_parse_does_not_fuse_events_that_reuse_a_serial():
    """The kernel's audit serial counter restarts at every boot while
    audit.log persists across boots, so a serial is unique only *within* a
    boot. The live host's log has 27 counter resets and serials appearing
    under two timestamps ~28h apart.

    Merging on the serial alone fuses those unrelated events, and because
    each field is taken from the first record carrying it, the fused event
    pairs a genuine marker with a uid and key lifted from somewhere else —
    `prove_capture` then reports capture proven for a rule that captured
    nothing. Exactly the confidently-wrong answer it exists to prevent.
    """
    text = (
        # boot A, serial 456: an unrelated event that happens to carry the
        # key and an in-range uid (e.g. the CONFIG_CHANGE from rule load)
        'type=CONFIG_CHANGE msg=audit(1690000000.100:456): op=add_rule '
        'key="warden-cap-1" uid=1000042 res=1\n'
        # boot B, serial 456 again: the real marker exec, captured under a
        # DIFFERENT key and a uid outside the range — i.e. not our capture
        'type=SYSCALL msg=audit(1790000000.500:456): syscall=59 uid=99 '
        'key="someone-elses-rule"\n'
        'type=EXECVE msg=audit(1790000000.500:456): argc=2 a0="/bin/echo" '
        'a1="WARDEN_MARKER_deadbeefdeadbeefdeadbeefdeadbeef"\n'
    )
    events = parse_events(text)
    assert len(events) == 2, "records from different events must not be merged"

    marker_events = [e for e in events if e.marker is not None]
    assert len(marker_events) == 1
    # The marker keeps its OWN uid and key, not the other event's.
    assert marker_events[0].uid == 99
    assert marker_events[0].key == "someone-elses-rule"

    # And so the fused false positive is impossible: nothing in this trail
    # is both in-range and marker-bearing.
    rng = IdRange(1_000_000, 65536)
    assert not any(
        e.marker is not None and e.uid is not None and rng.contains(e.uid) for e in events
    )


def test_prove_capture_succeeds_against_fake_trail():
    client = FakeIncusClient(first_host_uid=1_000_000)
    client.projects["warden"] = {}
    client.launch("images:debian/12", "cap-1", "warden", "warden-monitored")
    source = FakeEventSource(client)
    rng = IdRange(1_000_000, 65536)

    event = prove_capture(client, source, "cap-1", rng, project="warden", timeout=1.0)
    assert event.marker is not None
    assert rng.contains(event.uid)


def test_prove_capture_raises_when_range_is_stale():
    """The actual regression check: if the rule (and the caller's belief
    about the range) is scoped to a *stale* pre-restore range, prove_capture
    must fail loudly rather than report success — this is what auditctl -l
    would miss."""
    client = FakeIncusClient(first_host_uid=1_000_000)
    client.projects["warden"] = {}
    client.launch("images:debian/12", "cap-1", "warden", "warden-monitored")
    stale_rng = IdRange(1_000_000, 65536)

    client.snapshot("cap-1", "clean", project="warden")
    client.restore("cap-1", "clean", project="warden")  # reallocates

    source = FakeEventSource(client)
    with pytest.raises(CaptureNotProvenError):
        prove_capture(client, source, "cap-1", stale_rng, project="warden", timeout=0.3, poll_interval=0.05)
