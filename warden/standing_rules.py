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


def standing_rules_filename(llm: str) -> str:
    return "GEMINI.md" if llm == "gemini" else "CLAUDE.md"


def render_standing_rules(spec: FlavorSpec) -> str:
    extra = _MONITORED_EXTRA if spec.name == "monitored" else _BUILDER_EXTRA
    return _COMMON + extra
