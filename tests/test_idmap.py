import json

import pytest

from warden.idmap import (
    Idmap,
    IdmapDeriveError,
    IdRange,
    assert_unprivileged,
    derive_idmap,
    parse_idmap_current,
)
from tests.fakes import FakeIncusClient


def _idmap_json(host_start: int, size: int = 65536) -> str:
    return json.dumps([
        {"Isuid": True, "Isgid": False, "Hostid": host_start, "Nsid": 0, "Maprange": size},
        {"Isuid": False, "Isgid": True, "Hostid": host_start, "Nsid": 0, "Maprange": size},
    ])


def test_parse_idmap_current_basic():
    idmap = parse_idmap_current(_idmap_json(1_000_000))
    assert idmap.uid == IdRange(1_000_000, 65536)
    assert idmap.gid == IdRange(1_000_000, 65536)
    assert idmap.uid.host_end == 1_065_535


def test_parse_idmap_current_rejects_privileged_container():
    # a privileged container has no Nsid=0 idmap entries at all
    with pytest.raises(IdmapDeriveError):
        parse_idmap_current("[]")


def test_parse_idmap_current_rejects_garbage():
    with pytest.raises(IdmapDeriveError):
        parse_idmap_current("not json")


def test_assert_unprivileged_rejects_host_root():
    with pytest.raises(IdmapDeriveError):
        assert_unprivileged(Idmap(uid=IdRange(0, 65536), gid=IdRange(1000, 65536)))


def test_assert_unprivileged_accepts_high_subuid():
    assert_unprivileged(Idmap(uid=IdRange(1_000_000, 65536), gid=IdRange(1_000_000, 65536)))


def test_derive_idmap_reads_live_from_client():
    client = FakeIncusClient(first_host_uid=1_000_000)
    client.projects["warden"] = {}
    client.launch("images:debian/12", "cap-1", "warden", "warden-monitored")

    idmap = derive_idmap(client, "cap-1", project="warden")
    assert idmap.uid.host_start == 1_000_000
    assert_unprivileged(idmap)


def test_restore_reallocates_and_stale_range_misses_capture():
    """The regression test for the spec's I6-breaks-I5 gotcha: an idmap
    read *before* restore is not the idmap that's live *after* restore.
    Code that caches the pre-restore range instead of re-deriving would
    scope its audit rule to a range nothing runs in anymore."""
    client = FakeIncusClient(first_host_uid=1_000_000)
    client.projects["warden"] = {}
    client.launch("images:debian/12", "cap-1", "warden", "warden-monitored")

    stale_idmap = derive_idmap(client, "cap-1", project="warden")

    client.snapshot("cap-1", "clean", project="warden")
    client.restore("cap-1", "clean", project="warden")

    fresh_idmap = derive_idmap(client, "cap-1", project="warden")

    assert stale_idmap.uid.host_start != fresh_idmap.uid.host_start, (
        "fake didn't model reallocation — test is meaningless if these match"
    )

    # Prove the mechanism: exec a marker now (post-restore) and confirm it
    # only shows up in the *fresh* range, never the stale one.
    from warden.auditd import marker_argv

    argv, token = marker_argv()
    result = client.exec("cap-1", argv, project="warden")
    assert result.ok

    event = next(e for e in client.audit_log if e.marker == token)
    assert fresh_idmap.uid.contains(event.uid)
    assert not stale_idmap.uid.contains(event.uid)
