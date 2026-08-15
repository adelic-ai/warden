#!/usr/bin/env python3
"""Smoke-check a freshly-deployed vantage VM (VANTAGE-PLAN.md phases 2/4): warden + agentwatch are
importable from wherever this runs, and the specific fixes the vantage shape depends on are present.
Not a pytest suite — this runs ON the VM (`incus exec <vm> -- python3 verify-vantage-vm.py`), where
there is no test runner, only whatever got deployed. Exits non-zero on any failure so an automated
deploy step can treat it as pass/fail, not just printed text a human reads.

Checked in from what P5/Shape A actually ran by hand (reconstructed from the build transcript,
VANTAGE-PLAN.md's reference section) — it was the only step in that build that verified anything.
"""
from __future__ import annotations

import sys

sys.path.insert(0, "/root/agentwatch")
sys.path.insert(0, "/root/warden")


def main() -> int:
    checks: list[tuple[str, bool]] = []

    try:
        import warden.cli  # noqa: F401
        checks.append(("warden importable", True))
    except ImportError as exc:
        checks.append((f"warden importable ({exc})", False))

    # --no-agentwatch: deploy_code() can skip agentwatch entirely (dev --vantage --no-agentwatch —
    # the capture plane itself, auditd/bpftrace/cgroups, is baked into the golden image and doesn't
    # need it; only `report`'s reconciliation does). An absent agentwatch is then expected, not a
    # failure — this flag is what tells this script the difference.
    if "--no-agentwatch" not in sys.argv:
        try:
            import agentwatch.groundtruth.ebpf_capture as ebpf_capture
            from agentwatch.reconciler import runtime_scope as rs

            checks.append(("agentwatch importable", True))
            checks.append(("run_capture present", hasattr(ebpf_capture, "run_capture")))
            checks.append((
                "claude-basename detection present",
                "claude" in rs.DEFAULT_RUNTIME_BASENAMES,
            ))
        except ImportError as exc:
            checks.append((f"agentwatch importable ({exc})", False))

    ok = True
    for label, passed in checks:
        print(f"{'OK' if passed else 'FAIL'}: {label}")
        ok = ok and passed

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
