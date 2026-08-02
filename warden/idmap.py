"""idmap derivation — §1's load-bearing gotcha.

Never freeze the idmap range. Incus allocates (and can *reallocate*, notably
on `restore`) the host-uid/gid range an unprivileged container's ids map
into, recorded live in the instance's `volatile.idmap.current` config key.
Anything that needs the range (an auditd rule, an invariant check) must
re-read that key at the moment it's needed — never cache it across a
restore, a stop/start, or any other event that can trigger reallocation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from warden.incus import IncusClient

IDMAP_CONFIG_KEY = "volatile.idmap.current"


class IdmapDeriveError(RuntimeError):
    """Raised when an idmap range can't be derived — never guessed at."""


@dataclass(frozen=True)
class IdRange:
    host_start: int
    count: int

    @property
    def host_end(self) -> int:
        """Inclusive end of the host-id range."""
        return self.host_start + self.count - 1

    def contains(self, host_id: int) -> bool:
        return self.host_start <= host_id <= self.host_end

    def __str__(self) -> str:
        return f"{self.host_start}-{self.host_end}"


@dataclass(frozen=True)
class Idmap:
    uid: IdRange
    gid: IdRange


def parse_idmap_current(raw: str) -> Idmap:
    """Parse a `volatile.idmap.current` value into uid/gid host ranges.

    The value is a JSON array of entries with `Isuid`/`Isgid`/`Hostid`/
    `Nsid`/`Maprange` fields (Incus/LXD's idmap.Entry shape). We only care
    about the container-root (`Nsid == 0`) entries, since that anchors the
    whole contiguous range Incus allocates per container.
    """
    try:
        entries = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        raise IdmapDeriveError(f"unparseable {IDMAP_CONFIG_KEY!r}: {raw!r}") from exc

    uid_range: IdRange | None = None
    gid_range: IdRange | None = None
    for entry in entries:
        if entry.get("Nsid") != 0:
            continue
        rng = IdRange(host_start=entry["Hostid"], count=entry["Maprange"])
        if entry.get("Isuid") and uid_range is None:
            uid_range = rng
        if entry.get("Isgid") and gid_range is None:
            gid_range = rng

    if uid_range is None or gid_range is None:
        raise IdmapDeriveError(
            f"no uid/gid Nsid=0 entry in {IDMAP_CONFIG_KEY!r}: {raw!r} "
            "(instance may be privileged — refusing to assume a range)"
        )
    return Idmap(uid=uid_range, gid=gid_range)


def derive_idmap(client: "IncusClient", instance: str, project: str = "default") -> Idmap:
    """Read the *current* idmap straight from the instance config.

    Call this every time the range is needed — at first wire-up, and again
    after any restore. Do not hold onto the return value across a restore.
    """
    raw = client.config_get(instance, IDMAP_CONFIG_KEY, project=project)
    if not raw:
        raise IdmapDeriveError(
            f"{instance}: {IDMAP_CONFIG_KEY!r} is empty — instance may be "
            "privileged or not yet started; refusing to guess a range"
        )
    return parse_idmap_current(raw)


def assert_unprivileged(idmap: Idmap) -> None:
    """Structural proof the container is unprivileged: host uid 0 must not
    be in the mapped range that root-in-container is deriving into is not
    the actual concern here (`Isuid` root maps *to* `host_start`, and an
    unprivileged container's `host_start` must be > 0 — a privileged
    container has no idmap entry at all, which `derive_idmap` already
    rejects). This is the second, structural check: even with an idmap
    present, `host_start == 0` would mean container-root == host-root.
    """
    if idmap.uid.host_start == 0 or idmap.gid.host_start == 0:
        raise IdmapDeriveError(
            "idmap host range starts at 0 — container root would map to "
            "host root; this is not an unprivileged container"
        )
