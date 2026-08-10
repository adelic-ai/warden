"""Locate the agentwatch checkout for the integration tests.

`warden report` is the agentwatch↔wizard integration (DEMO-SPEC §4); the two live in separate repos,
so there is no package dependency to resolve — the operator puts agentwatch on PYTHONPATH. Since the
2026-08 consolidation there is ONE agentwatch (the merged standalone: `~/dev/agentwatch`, published to
`github.com/adelic-ai/agentwatch`); the old `agentwatch-v2` line was retired and deleted.

Resolution order, most explicit first:

  1. ``WARDEN_AGENTWATCH_PATH``
  2. already importable (e.g. pip-installed)
  3. a sibling ``agentwatch`` checkout next to this repo (``~/dev/agentwatch``)

If none apply, the integration tests **skip with a reason** rather than fail. warden's own logic is
fully covered without them; what would be lost is the cross-repo wiring, and a red suite on a
machine that simply has not checked out the other repo teaches people to ignore red.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent


def _agentwatch_root() -> Path | None:
    explicit = os.environ.get("WARDEN_AGENTWATCH_PATH")
    if explicit:
        return Path(explicit).expanduser()
    sibling = _REPO.parent / "agentwatch"
    if (sibling / "agentwatch" / "run.py").exists():
        return sibling
    return None


def _ensure_agentwatch_importable() -> bool:
    try:
        import agentwatch  # noqa: F401

        return True
    except ImportError:
        pass
    root = _agentwatch_root()
    if root is None or not (root / "agentwatch" / "run.py").exists():
        return False
    sys.path.insert(0, str(root))
    try:
        import agentwatch  # noqa: F401

        return True
    except ImportError:  # pragma: no cover - a broken checkout, not a missing one
        return False


AGENTWATCH_AVAILABLE = _ensure_agentwatch_importable()

requires_agentwatch = pytest.mark.skipif(
    not AGENTWATCH_AVAILABLE,
    reason=(
        "agentwatch is not importable — set WARDEN_AGENTWATCH_PATH or check it out beside this "
        "repo as ./agentwatch (the merged standalone; github.com/adelic-ai/agentwatch)."
    ),
)


def canon_available() -> bool:
    """canon is an OPTIONAL dependency of agentwatch (its DECISIONS: "canon is an OPTIONAL runtime
    dependency"). Where it is absent, `verdicts.jsonl` is simply not written and the finding
    pipeline is unaffected — so the tests assert that honest degradation instead of skipping."""
    if not AGENTWATCH_AVAILABLE:
        return False
    from agentwatch import canon_emit

    return bool(canon_emit.CANON_AVAILABLE)
