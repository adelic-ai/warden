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

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; FAIL=1; }

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
  if incus config show cap-mon --project "${PROJECT}" | grep -A2 'root:' | grep -q 'source:'; then
    fail "instance has a host-sourced disk device"
  else
    pass "no host disk device"
  fi

  # egress: reaches the allowlisted LLM host, not a LAN IP, not a
  # non-allowlisted domain
  incus exec cap-mon --project "${PROJECT}" -- curl -sS -o /dev/null -w '%{http_code}' \
    --connect-timeout 5 https://generativelanguage.googleapis.com/ >/tmp/warden-egress-llm.txt || true
  grep -qE '^(200|301|302|404)$' /tmp/warden-egress-llm.txt && pass "egress reaches LLM host" || fail "egress to LLM host did not respond"

  if incus exec cap-mon --project "${PROJECT}" -- curl -sS -o /dev/null --connect-timeout 3 https://example.com/ 2>/dev/null; then
    fail "egress reached a non-allowlisted domain (example.com) — should have been blocked"
  else
    pass "non-allowlisted domain correctly blocked"
  fi

  # auditd capture is proven by `warden up` itself (prove_capture); double
  # check independently via ausearch, raw, per §1 ("never trust auditctl -l")
  if ausearch -k "warden-cap-mon" --raw 2>/dev/null | grep -q 'WARDEN_MARKER_'; then
    pass "independent ausearch confirms marker capture"
  else
    fail "ausearch found no marker for warden-cap-mon"
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

  incus exec cap-build --project "${PROJECT}" -- curl -sS -o /dev/null -w '%{http_code}' \
    --connect-timeout 5 https://github.com/ >/tmp/warden-egress-gh.txt || true
  grep -qE '^(200|301|302)$' /tmp/warden-egress-gh.txt && pass "egress reaches GitHub" || fail "egress to GitHub failed"

  if incus exec cap-build --project "${PROJECT}" -- curl -sS -o /dev/null --connect-timeout 3 \
      "http://$(ip route | awk '/default/ {print $3}')/" 2>/dev/null; then
    fail "egress reached the LAN gateway — should be blocked"
  else
    pass "LAN correctly unreachable"
  fi
}

# ---------------------------------------------------------------------------
# Test 3: idempotent + reversible
# ---------------------------------------------------------------------------
test_3_idempotent_reversible() {
  echo "== test 3: idempotent + reversible =="
  ${WARDEN} up --flavor monitored --llm gemini --project "${PROJECT}" --name cap-mon  # re-run, should be a no-op
  pass "re-run of warden up did not error"

  ${WARDEN} down cap-mon --project "${PROJECT}"
  incus list --project "${PROJECT}" --format csv | cut -d, -f1 | grep -qx cap-mon \
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

  ausearch -k "warden-cap-build2" --raw 2>/dev/null | grep -q . \
    && fail "builder instance unexpectedly has audit rule activity" \
    || pass "distinct audit scoping: no rule for the builder instance"

  ${WARDEN} down cap-mon2 --project "${PROJECT}"
  ${WARDEN} down cap-build2 --project "${PROJECT}"
}

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
