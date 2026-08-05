#!/bin/sh
# The privileged half of DESIGN §4's split: a tiny, dumb root collector.
#
# The reconciler holds prompt-bearing data and is a lot of code — it must not run as root. Ground
# truth is root-protected by design; that is what makes it unforgeable. So exactly this much runs
# privileged: copy the records for ONE audit key to a file the operator can read. No parsing, no
# filtering beyond the key, no network, no interpretation. Everything else runs unprivileged over
# the file this produces.
#
#   usage: warden-collect-audit.sh <rule-key> <outfile> <owner-uid>
#
# `--raw` is not a preference. `ausearch -i` renders timestamps in the host's LOCAL time with no
# offset attached, which is ambiguous the moment the capture is read anywhere else; raw epoch is
# unambiguous. agentwatch's parser reads both dialects, and this still emits the one that cannot
# be misread.
#
# NEVER `auditctl -D` and never anything that touches another key: a co-located capsule build has
# its own rule on this host, and wiping the ruleset would blind an unrelated system's ground-truth
# plane. This script only ever reads.
set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 <rule-key> <outfile> <owner-uid>" >&2
    exit 2
fi

key="$1"
out="$2"
owner="$3"

case "$key" in
    warden-*) ;;
    *)
        # Refuse to collect under a key this tool does not own. The script runs as root via a
        # sudo rule; a caller that can choose an arbitrary key can read any audit stream on the
        # host, which is a wider grant than the privilege split intends.
        echo "$0: refusing key '$key' — only warden-* keys are collectable here" >&2
        exit 3
        ;;
esac

umask 077
dir="$(dirname "$out")"
mkdir -p "$dir"
tmp="$(mktemp "${out}.XXXXXX")"
# shellcheck disable=SC2064
trap "rm -f '$tmp'" EXIT INT TERM

# `--input-logs` reads the ROTATED log set, not just the current audit.log. Load-bearing on a busy
# host: a co-located capsule build under its own key can push enough volume to rotate
# /var/log/audit/audit.log, and a plain `ausearch` then returns nothing for events that rolled into
# audit.log.1/.2 — a silently-empty plane over a capture that actually worked. Surfaced by a real
# Part-B run (0 records via plain ausearch, 1783 with --input-logs).
set +e
ausearch -k "$key" --raw --input-logs >"$tmp" 2>"${tmp}.err"
status=$?
set -e

# ausearch exits 1 for "no matches", which is a legitimate empty capture and not an error — an
# instance that ran nothing yet has nothing to collect. Any other non-zero status is a real
# failure and must not be reported as an empty plane: "I collected nothing" and "I could not
# collect" are the two things this build keeps having to tell apart.
if [ "$status" -ne 0 ] && [ "$status" -ne 1 ]; then
    echo "$0: ausearch -k $key failed (rc=$status): $(cat "${tmp}.err")" >&2
    rm -f "${tmp}.err"
    exit "$status"
fi
rm -f "${tmp}.err"

chown "$owner" "$tmp"
chmod 640 "$tmp"
mv -f "$tmp" "$out"
trap - EXIT INT TERM
exit 0
