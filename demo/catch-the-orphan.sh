#!/usr/bin/env bash
#
# catch-the-orphan.sh — warden's differentiator in ~2 minutes.
#
# Shows warden catching an action the agent's own logs never recorded — where a monitor that trusts
# the agent's telemetry reports the session clean.
#
# ── HONESTY ──────────────────────────────────────────────────────────────────────────────────────
# Everything here is REAL: a real cage, real kernel-plane audit, real reconciliation, a real CONFIRMED
# verdict. The only thing SIMULATED is the attacker. We represent a post-compromise foothold — a
# prompt-injected reverse shell, a malicious npm dependency, a compromised MCP server, pick your vector
# — by running a command DIRECTLY in the container, bypassing the agent's tools. That is exactly what
# such a foothold's activity looks like to the audit plane: an exec the agent never made, absent from
# its self-report. We simulate the attacker (you always do, in a demo); warden's detection is real.
#
# The mechanism is validated: see DEV-LIVE-VALIDATION.md, where an operator's own `incus exec` commands
# showed up as CONFIRMED for precisely this reason (operator and agent share one uid at the plane).
#
# Requires: a working warden substrate (Incus 7.x, kernel-owned) and agentwatch on the import path.
# Your agent (claude) should be logged in inside the home once, so it can do the benign baseline task.
# ─────────────────────────────────────────────────────────────────────────────────────────────────
set -euo pipefail

INSTANCE="${1:-warden-home}"
LLM="${2:-claude}"
PROJECT="${3:-mywork}"

# Resolve warden whether or not it's on PATH yet (until it's packaged, `python3 -m warden.cli` from the
# repo works — this script lives in demo/, so the repo root is one up).
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
run_warden() {
  if command -v warden >/dev/null 2>&1; then warden "$@"; else (cd "$REPO_ROOT" && python3 -m warden.cli "$@"); fi
}

# warden drives incus under sudo; mirror that for the raw exec we do to simulate the attacker.
EXEC=(sudo incus exec "$INSTANCE" --project "$PROJECT" --)

say() { printf '\n\033[1m>>> %s\033[0m\n' "$*"; }

say "1/4  Cage a real agent (key-free, egress-locked, audited)"
# Idempotent: stands the home up if it isn't already. Does not drop you into a shell.
run_warden dev --name "$INSTANCE" --llm "$LLM" --project "$PROJECT" --no-shell

# Window start for the reconcile. `--no-shell` doesn't stamp a session boundary (only interactive entry
# does), so we scope report --live explicitly to everything from HERE on — the agent's turn + the
# foothold — excluding this home's prior history and the one-time furnishing.
DEMO_START="$(date +%s)"

say "2/4  The agent does a little benign, tool-authorized work"
# A real, non-interactive agent turn. Its Bash tool calls become 'authorized' execs — the honest
# baseline the foothold will stand out against. (If the agent isn't logged in yet, log in once with
# an interactive 'warden dev' and re-run; the demo still works with any prior real activity in the home.)
if "${EXEC[@]}" sh -lc 'command -v claude >/dev/null'; then
  "${EXEC[@]}" sh -lc 'cd /root && claude -p "create a file hello.txt containing a greeting, then list the files in this directory"' \
    || echo "    (agent turn skipped — log in with 'warden dev --llm '"$LLM"'' once, then re-run for the authorized baseline)"
else
  echo "    (claude CLI not found in the home — the demo continues; the foothold is what matters)"
fi

say "3/4  SIMULATE A POST-COMPROMISE FOOTHOLD — a command the agent never made, via NO tool call"
# This is the 'attacker'. Benign by design (egress is default-drop anyway), but to the audit plane it
# is indistinguishable from a real foothold's recon: an exec at the agent's uid with no authorizing
# tool_use in the transcript.
"${EXEC[@]}" sh -lc 'id; hostname; head -1 /etc/os-release; echo "[foothold] a real attacker would not stop here"'

say "4/4  Reconcile: the unforgeable plane vs the agent's own self-report"
# Scoped to this demo's window (see DEMO_START); the foothold falls in the accountable work phase.
run_warden report --live --instance "$INSTANCE" --llm "$LLM" --project "$PROJECT" --since "$DEMO_START" || true

cat <<'EOF'

────────────────────────────────────────────────────────────────────────────────────────────────────
What just happened:

  • The agent's tool-driven work reconciled as AUTHORIZED — accounted for by its own self-report.
  • The foothold reconciled as CONFIRMED — an action with NO authorizing intent. The agent's
    transcript has no line for it, because the agent never made that tool call.

  A monitor that trusts the agent's telemetry reports this session CLEAN. warden caught it — because
  the audit plane lives one level up, in the VM, on a kernel the container-bound attacker can't reach.
  The trust isn't a claim about the agent; it's a property of where the watcher sits.

  (Honest footnote: operator and agent share one uid at the plane, so if YOU opened another shell into
   this home, that would read as CONFIRMED too. Reconcile over a window you stayed out of. And ~half of
   an interactive agent's execs are runtime internals warden marks NONE — disclosed, not guessed.)
────────────────────────────────────────────────────────────────────────────────────────────────────
EOF
