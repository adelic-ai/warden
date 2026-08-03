#!/usr/bin/env bash
# §4 acceptance tests, for real, against the nested Incus that
# scripts/install-incus-nested.sh set up. REQUIRES ROOT (auditd rules,
# nftables) and a real `incus` on PATH — neither is available in the VM
# this repo was built in (see NEEDS-HUMAN.md). `tests/test_acceptance.py`
# proves the same four invariants against a FakeIncusClient; this script
# is the same shape of check against the real substrate.
#
# Run from the repo root: sudo scripts/run-acceptance-nested.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [[ "${EUID}" -ne 0 ]]; then
  echo "must run as root (auditd rules + nftables need it)" >&2
  exit 1
fi
if ! command -v incus >/dev/null 2>&1; then
  echo "no incus on PATH — run scripts/install-incus-nested.sh first" >&2
  exit 1
fi

WARDEN="python3 -m warden.cli"
PROJECT="warden"
FAIL=0

# The tests never call Gemini — the key is only needed so `warden up` does not
# stop at its NEEDS-HUMAN gate for the gemini flavor. Default it so the suite
# runs under a plain `sudo scripts/run-acceptance-nested.sh`; a real key in the
# environment is still honoured.
: "${GEMINI_API_KEY:=dummy-setup-only-not-a-real-key}"
export GEMINI_API_KEY

LAN_GW="$(ip route | awk '/default/ {print $3; exit}')"

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; FAIL=1; }

# `producer | grep -q` is a trap in a `set -o pipefail` script, and it is the
# whole of the "ausearch found no marker" red: `grep -q` exits at the FIRST
# match and closes the pipe, the producer takes SIGPIPE, and the pipeline
# reports 141 *because the match was found*. Measured on this host:
# `ausearch -k capsule --raw` emits 1.4MB / 978 matching records and the naive
# pipeline still returns non-zero. It fails in both directions — a real match
# read as absent (a fake red) and, for the checks that pass *on* absence, a
# fake green. So: buffer the output, then match it. No pipe, no signal.
buffer() { "$@" 2>/dev/null || true; }
matches() {  # matches <pattern> <text>
  local pattern="$1" text="${2-}"
  grep -q -- "${pattern}" <<<"${text}"
}

# Egress probes. `--noproxy '*'` bypasses the proxy env warden sets on the
# instance, so it measures the NETWORK layer; without it, the request goes
# through the host-side allowlist proxy and measures the ALLOWLIST. A denial
# has to be distinguishable from a success, hence %{http_code} rather than
# curl's exit status: the capsule build aborted a passing run once by reading
# a working 403 denial as a breach.
code_direct() {
  incus exec "$1" --project "${PROJECT}" -- \
    curl -sS -o /dev/null -w '%{http_code}' --noproxy '*' -m 6 "$2" 2>/dev/null || true
}
code_proxy() {
  incus exec "$1" --project "${PROJECT}" -- \
    curl -sS -o /dev/null -w '%{http_code}' -m 20 "$2" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Pre-flight: leave no state from a previous (possibly crashed) run. Touches
# ONLY warden's own instances and proxy — never the gemini-capsule project
# sharing this host.
# ---------------------------------------------------------------------------
preflight() {
  echo "== pre-flight: clearing leftovers from any previous run =="
  for inst in cap-mon cap-build cap-mon2 cap-build2; do
    if incus config show "${inst}" --project "${PROJECT}" >/dev/null 2>&1; then
      ${WARDEN} down "${inst}" --project "${PROJECT}" || true
    fi
  done
  # A proxy left over from an earlier version of this code would be reused by
  # `warden up` (something is listening), so the run would test stale code.
  pkill -f 'warden\.cli proxy' 2>/dev/null || true
  sleep 1
}

# ---------------------------------------------------------------------------
# Test 1: warden up --flavor monitored
# ---------------------------------------------------------------------------
test_1_monitored() {
  echo "== test 1: monitored =="
  ${WARDEN} up --flavor monitored --llm gemini --project "${PROJECT}" --name cap-mon

  # unprivileged: container root maps to a high host uid, not 0
  local hostid
  hostid=$(incus config get cap-mon volatile.idmap.current --project "${PROJECT}" \
    | python3 -c 'import json,sys; e=json.load(sys.stdin); print(next(x["Hostid"] for x in e if x["Isuid"] and x["Nsid"]==0))')
  [[ "${hostid}" -gt 0 ]] && pass "unprivileged (host uid start ${hostid})" || fail "idmap starts at host uid 0"

  # no host disk device
  local root_dev
  root_dev="$(buffer incus config show cap-mon --project "${PROJECT}" | grep -A2 'root:' || true)"
  if matches 'source:' "${root_dev}"; then
    fail "instance has a host-sourced disk device"
  else
    pass "no host disk device"
  fi

  # egress, measured at both layers.
  # 1. the allowlisted LLM host is reachable THROUGH the proxy. This also
  #    establishes the proxy is up, so a 000 below means "denied", not
  #    "nothing listening".
  local llm_code
  llm_code="$(code_proxy cap-mon https://generativelanguage.googleapis.com/)"
  case "${llm_code}" in
    200|301|302|400|404) pass "egress reaches LLM host through the proxy (${llm_code})" ;;
    *) fail "egress to LLM host did not respond (${llm_code})" ;;
  esac

  # 2. a non-allowlisted domain is refused BY the proxy
  local ex_code
  ex_code="$(code_proxy cap-mon https://example.com/)"
  [[ "${ex_code}" == "000" ]] \
    && pass "non-allowlisted domain refused by the proxy allowlist (${ex_code})" \
    || fail "egress reached a non-allowlisted domain (example.com -> ${ex_code}) — should have been blocked"

  # 3. and there is no way AROUND the proxy at the network layer
  local ex_direct
  ex_direct="$(code_direct cap-mon https://example.com/)"
  [[ "${ex_direct}" == "000" ]] \
    && pass "no direct egress bypassing the proxy (${ex_direct})" \
    || fail "direct egress bypassed the proxy (example.com -> ${ex_direct})"

  # auditd capture is proven by `warden up` itself (prove_capture); double
  # check independently via ausearch, raw, per §1 ("never trust auditctl -l")
  # Retried, not a single shot: auditd's flush is not synchronous with the
  # exec, and the capsule build twice diagnosed a working plane as broken by
  # looking exactly once after a 2-3s sleep.
  local seen=no records
  for _ in $(seq 1 15); do
    records="$(buffer ausearch -k "warden-cap-mon" --raw)"
    if matches 'WARDEN_MARKER_' "${records}"; then
      seen=yes; break
    fi
    sleep 1
  done
  if [[ "${seen}" == "yes" ]]; then
    pass "independent ausearch confirms marker capture under warden-cap-mon"
  else
    fail "ausearch found no marker for warden-cap-mon"
    # Distinguish "the rule captured nothing" from "the rule isn't loaded" —
    # the first real run had no way to tell these apart from the failure alone.
    echo "  loaded rules for this key:" >&2
    buffer auditctl -l | grep 'warden-cap-mon' >&2 || echo "  (none)" >&2
    echo "  records under the key: $(grep -c 'type=SYSCALL' <<<"${records}" || true)" >&2
  fi

  # clean snapshot exists
  incus query "/1.0/instances/cap-mon/snapshots/clean?project=${PROJECT}" >/dev/null 2>&1 \
    && pass "clean snapshot exists" || fail "no clean snapshot"

  # restore re-derives the audit rule and re-proves capture — via the CLI,
  # which calls WardenApp.restore_and_reprove (restores the snapshot itself
  # too; don't restore twice)
  if ${WARDEN} restore cap-mon --flavor monitored --llm gemini --project "${PROJECT}"; then
    pass "restore re-derived the idmap and re-proved capture"
  else
    fail "restore-and-reprove failed — see warden output above"
  fi
}

# ---------------------------------------------------------------------------
# Test 2: warden up --flavor builder
# ---------------------------------------------------------------------------
test_2_builder() {
  echo "== test 2: builder =="
  ${WARDEN} up --flavor builder --llm claude --project "${PROJECT}" --name cap-build \
    --repo https://github.com/octocat/Hello-World.git

  incus exec cap-build --project "${PROJECT}" -- test -d /root/repo/.git \
    && pass "git clone landed a real repo" || fail "no /root/repo/.git after clone"

  local gh_code
  gh_code="$(code_proxy cap-build https://github.com/)"
  case "${gh_code}" in
    200|301|302) pass "egress reaches GitHub through the proxy (${gh_code})" ;;
    *) fail "egress to GitHub failed (${gh_code})" ;;
  esac

  # The LAN, at both layers again. Directly it must not route at all; through
  # the proxy an IP literal matches no allowlist entry, so the proxy refuses
  # it (403) — a refusal, not a reachable host.
  local lan_direct lan_proxy
  lan_direct="$(code_direct cap-build "http://${LAN_GW}/")"
  [[ "${lan_direct}" == "000" ]] \
    && pass "LAN gateway unreachable directly (${lan_direct})" \
    || fail "egress reached the LAN gateway directly (${LAN_GW} -> ${lan_direct}) — should be blocked"

  lan_proxy="$(code_proxy cap-build "http://${LAN_GW}/")"
  [[ "${lan_proxy}" == "403" || "${lan_proxy}" == "000" ]] \
    && pass "LAN gateway refused by the proxy allowlist (${lan_proxy})" \
    || fail "the proxy served the LAN gateway (${LAN_GW} -> ${lan_proxy}) — allowlist not enforced"
}

# ---------------------------------------------------------------------------
# Test 3: idempotent + reversible
# ---------------------------------------------------------------------------
test_3_idempotent_reversible() {
  echo "== test 3: idempotent + reversible =="
  ${WARDEN} up --flavor monitored --llm gemini --project "${PROJECT}" --name cap-mon  # re-run, should be a no-op
  pass "re-run of warden up did not error"

  ${WARDEN} down cap-mon --project "${PROJECT}"
  local names
  names="$(buffer incus list --project "${PROJECT}" --format csv | cut -d, -f1)"
  matches '^cap-mon$' "${names}" \
    && fail "cap-mon still exists after warden down" || pass "instance removed by warden down"

  incus project show "${PROJECT}" >/dev/null 2>&1 && pass "host project unchanged" || fail "project vanished"
  incus network show wardenbr0 >/dev/null 2>&1 && pass "host bridge unchanged" || fail "bridge vanished"

  ${WARDEN} down cap-build --project "${PROJECT}"
}

# ---------------------------------------------------------------------------
# Test 4: a monitored capsule and a builder side by side
# ---------------------------------------------------------------------------
test_4_side_by_side() {
  echo "== test 4: monitored + builder side by side =="
  ${WARDEN} up --flavor monitored --llm gemini --project "${PROJECT}" --name cap-mon2
  ${WARDEN} up --flavor builder --llm claude --project "${PROJECT}" --name cap-build2

  local mon_hostid build_hostid
  mon_hostid=$(incus config get cap-mon2 volatile.idmap.current --project "${PROJECT}" \
    | python3 -c 'import json,sys; e=json.load(sys.stdin); print(next(x["Hostid"] for x in e if x["Isuid"] and x["Nsid"]==0))')
  build_hostid=$(incus config get cap-build2 volatile.idmap.current --project "${PROJECT}" \
    | python3 -c 'import json,sys; e=json.load(sys.stdin); print(next(x["Hostid"] for x in e if x["Isuid"] and x["Nsid"]==0))')

  [[ "${mon_hostid}" != "${build_hostid}" ]] && pass "distinct idmaps (${mon_hostid} vs ${build_hostid})" \
    || fail "both instances got the same idmap start"

  # This one passes *on absence*, so the SIGPIPE trap would have turned a real
  # breach into a green. Buffered for that reason specifically.
  local builder_records
  builder_records="$(buffer ausearch -k "warden-cap-build2" --raw)"
  if [[ -n "${builder_records}" ]]; then
    fail "builder instance unexpectedly has audit rule activity"
  else
    pass "distinct audit scoping: no rule for the builder instance"
  fi

  ${WARDEN} down cap-mon2 --project "${PROJECT}"
  ${WARDEN} down cap-build2 --project "${PROJECT}"
}

preflight
test_1_monitored
test_2_builder
test_3_idempotent_reversible
test_4_side_by_side

if [[ "${FAIL}" -eq 0 ]]; then
  echo "== all §4 acceptance tests passed =="
else
  echo "== one or more §4 acceptance tests FAILED — see above ==" >&2
fi
exit "${FAIL}"
