#!/usr/bin/env bash
# Part A of FORK-GAP-VALIDATION.md: the warden fork-gap audit rule vs. REAL auditd, read by
# agentwatch's parser. Runs entirely in a real-kernel host/VM (e.g. Lima under maude) - no Incus,
# no Gemini, no pop-os, no network. Proves the assumptions the synthetic fixtures cannot: that real
# clone records parse (exit=child, pid=caller, the a0 CLONE_THREAD filter, the ausearch dialect) and
# that a genuinely never-execve'd forked process is bridged by the clone edges on real data.
#
# Usage:  ./validate-fork-gap-parser.sh /path/to/agent-oversight-console
#         AGENTWATCH_DIR=/path/to/agent-oversight-console ./validate-fork-gap-parser.sh
# Needs:  auditd (sudo apt-get install -y auditd) and sudo. Run as a normal (non-root) user.
set -uo pipefail

AGENTWATCH_DIR="${1:-${AGENTWATCH_DIR:-}}"
U="$(id -u)"
KEY="forktest-$$"
ARCH_FILTER="b64"                     # b64 == the native 64-bit arch on both x86_64 and aarch64
MARKER="FORKGAP_$$_$(date +%s 2>/dev/null || echo now)"
RAW_LOG="$(mktemp)"

fail() { echo "FAIL: $*" >&2; exit 1; }
cleanup() {
  sudo auditctl -d always,exit -F "arch=$ARCH_FILTER" -S execve -S clone \
    -F "uid>=$U" -F "uid<=$U" -k "$KEY" >/dev/null 2>&1
  rm -f "$RAW_LOG"
}
trap cleanup EXIT

# --- preflight -------------------------------------------------------------------------------
command -v auditctl >/dev/null || fail "auditctl not found - sudo apt-get install -y auditd"
command -v ausearch >/dev/null || fail "ausearch not found - sudo apt-get install -y auditd"
[ -n "$AGENTWATCH_DIR" ] || fail "pass the agent-oversight-console dir as arg 1 or AGENTWATCH_DIR env"
[ -d "$AGENTWATCH_DIR/agentwatch" ] || fail "no agentwatch package under '$AGENTWATCH_DIR'"
echo "arch: $(uname -m)   uid: $U   key: $KEY"

# --- load the rule (exactly warden's rule_fragments: execve + clone, uid-scoped) -------------
echo "== loading rule: -S execve -S clone, uid=$U =="
sudo auditctl -a always,exit -F "arch=$ARCH_FILTER" -S execve -S clone \
  -F "uid>=$U" -F "uid<=$U" -k "$KEY" \
  || fail "auditctl rejected the rule (on aarch64 confirm the kernel knows -S clone)"
sudo auditctl -l | grep -q "$KEY" || fail "rule not present in auditctl -l after load"

# --- workload: a subshell that NEVER execve's, forking an exec'd marker child -----------------
# `( /bin/echo M ; : )` - the subshell forks a child to run /bin/echo (an execve), but because the
# LAST command in the group is the `:` builtin, bash cannot tail-exec-optimize the subshell into a
# program, so the subshell process itself stays bash and never execve's. That subshell is the
# never-execve'd bridge; the marker echo must still walk back to bash through a clone edge.
echo "== running workload (marker=$MARKER) =="
bash -c "( /bin/echo $MARKER ; : )"

# --- pull the capture ------------------------------------------------------------------------
sleep 1                                # let auditd flush to /var/log/audit/audit.log
sudo ausearch -k "$KEY" --raw > "$RAW_LOG" 2>/dev/null || true
[ -s "$RAW_LOG" ] || fail "ausearch returned nothing for key=$KEY - the rule captured nothing"

# --- parse + compare full vs. exec-only ancestry on the REAL capture --------------------------
echo "== parsing with agentwatch and comparing ancestry =="
if PYTHONPATH="$AGENTWATCH_DIR" MARKER="$MARKER" RAW_LOG="$RAW_LOG" python3 - <<'PY'
import os
from collections import Counter
from agentwatch.events import CLONE, EXEC
from agentwatch.groundtruth.audit_log import parse_lines
from agentwatch.reconciler.process_tree import ProcessTree

marker = os.environ["MARKER"]
events, stats = parse_lines(open(os.environ["RAW_LOG"]))
print("  kinds:", dict(Counter(e.kind for e in events)))
print("  skips:", dict(stats.skip_reasons))

clones = [e for e in events if e.kind == CLONE]
assert clones, "no CLONE events parsed from real auditd - the clone arm is not being read"
for e in clones:
    assert e.pid is not None and e.ppid is not None, f"clone with missing pid/ppid: {e}"
print(f"  parsed {len(clones)} CLONE events, each with a child(pid)+parent(ppid)")

g = next((e for e in events if e.kind == EXEC and any(marker in (a or "") for a in e.args)), None)
assert g is not None, f"marker exec {marker!r} not found among the execve events"

full = ProcessTree(events)
execonly = ProcessTree([e for e in events if e.kind != CLONE])
chain_full = full.ancestry(g.pid)
chain_exec = execonly.ancestry(g.pid)
print(f"  marker pid={g.pid}")
print(f"  ancestry WITH clone  : {chain_full}")
print(f"  ancestry execve-only : {chain_exec}")

# The execve-only walk should DIE at a never-execve'd pid - the fork-hole itself - rather than at
# a normal root. (If it stopped at a pid that DID execve, that's just a scope boundary, and this
# workload failed to produce a real bridge on this shell.)
hole = chain_exec[-1]
assert hole != g.pid, "execve-only walk never left the marker pid - unexpected"
assert not full.exec_timestamps(hole), (
    f"execve-only walk ended at pid {hole}, which DID execve - a scope boundary, not a fork-hole")

# ...and the clone edges must bridge PAST that hole, extending the same prefix further up.
assert len(chain_full) > len(chain_exec) and chain_full[:len(chain_exec)] == chain_exec, (
    "clone edges did not extend the ancestry past the fork-hole on real data")
print(f"  fork-hole (never-execve'd) pid={hole}: execve-only dies here; "
      f"+clone bridges on to {chain_full[len(chain_exec):]}")

print("\nPASS: real auditd clone records parse, and the walk crossed a never-execve'd fork-hole")
print("      on real data - execve-only dies at the hole; +clone reaches further. The fork gap, closed.")
PY
then
  echo "== Part A PASSED =="
else
  fail "parser validation failed (see output above)"
fi
