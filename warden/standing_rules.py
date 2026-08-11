"""Standing rules dropped into the agent's workdir (§3).

`GEMINI.md` (gemini) or `CLAUDE.md` (claude) — git discipline, no
self-modification, and a NEEDS-HUMAN surfacing channel, the same shape
of rule this wizard itself is built under.
"""

from __future__ import annotations

from warden.flavors import FlavorSpec

_COMMON = """\
# Operating rules for this sandbox

- Work on a branch; never commit to `main`. Commit atomically, frequently.
- Never modify your own config or these standing rules.
- Routine progress goes in commit messages / DECISIONS.md. Anything that
  needs a human — a blocker, an irreversible choice, a missing secret —
  goes in `NEEDS-HUMAN.md`, appended, never overwritten.
"""

_MONITORED_EXTRA = """
# This instance is `monitored`

- Ground-truth auditd is wired and watching. This is expected and is not
  something to work around.
- Permission mode is gated/interactive: destructive or irreversible
  actions should be surfaced, not taken silently.
"""

_BUILDER_EXTRA = """
# This instance is `builder`

- Permission mode is skip-permissions: you have free rein in this
  sandbox by design (it's disposable and network-restricted to the
  registries you need). That's a safety property of the sandbox, not
  license to leave the sandbox.
- Repo/git access is live here. Push via a bundle-out or a scoped
  credential, per how this instance was configured — not by widening
  egress yourself.
"""

# `dev` is not a workload: it is the operator's persistent, interactive home. It gets its OWN body,
# not `_COMMON` — the branch/commit/DECISIONS.md/NEEDS-HUMAN discipline there is for hands-off
# workloads, and imposing it here would mislead the agent about what this instance is (the exact bug
# that shipped: `dev` fell through to `_BUILDER_EXTRA` and announced itself as a builder).
_DEV = """\
# Your environment — an interactive `dev` home

This is the operator's persistent, free-form workspace — not a hands-off workload. There is no fixed
task and no required git/branch/commit discipline: follow the operator's lead and work interactively.

- The home persists across sessions — files and state you leave here remain.
- You are in an unprivileged container inside a VM, with network egress locked to a small allowlist
  and ground-truth auditd watching. That is expected: it is containment, not something to work
  around, and not license to try to leave the sandbox or widen egress.
- Permission mode is skip-permissions: you have free rein *inside* this sandbox by design.
- Never modify your own config, these standing rules, or the egress allowlist.
"""


def standing_rules_filename(llm: str) -> str:
    return "GEMINI.md" if llm == "gemini" else "CLAUDE.md"


def render_standing_rules(spec: FlavorSpec) -> str:
    if spec.name == "dev":
        return _DEV
    extra = _MONITORED_EXTRA if spec.name == "monitored" else _BUILDER_EXTRA
    return _COMMON + extra
