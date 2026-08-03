# warden wizard — first real-Incus validation (pop-os) — findings & fix directives

**Context.** This repo (`~/dev/warden-wizard-review`, branch `build`) was logic-proven against a
FakeIncusClient in the agent-vm, which had no root, so it was **never run against real Incus** until
now. It has now run `sudo scripts/run-acceptance-nested.sh` against pop-os real Incus 7.3, in an
isolated project `warden`, pool `wardenpool` (btrfs), with `GEMINI_API_KEY` a dummy (setup-only —
the tests never call Gemini). Full log: `/tmp/warden-acceptance.log`.

Fix on a NEW branch in this clone (`fix/real-incus-validation`), atomic commits, DECISIONS notes.
Keep the isolated `warden` project. Emit sudo commands for the human to run (same pattern as the
capsule build) — you can read but not sudo. We bundle fixes back to canonical afterward.

## What already PASSED (do not regress)
- Unprivileged container (host uid start 1065536); no host disk device.
- Egress *reaches* the allowlisted LLM host and GitHub (allow path OK).
- Clean snapshot creation; test 3 fully green: idempotent re-run, `warden down` removes instance,
  host project + bridge unchanged.

## Findings to fix

### 1. Egress is never enforced (LOAD-BEARING)
`egress.py` only has `generate_nft_ruleset()` + `assert_no_reject_and_correct_ordering()`. Nothing
loads the ruleset into the host firewall; `app.py:up()` only calls `proxy_controller.set_allowlist`.
Result: `example.com` reachable (test 1) and the LAN gateway reachable (test 2) — both should be
blocked. FIX: add an apply step that installs the nft ruleset on the host (default-drop on
`wardenbr0` except to the proxy port) AND forces the container through the proxy (transparent
redirect, or injected http(s)_proxy + block direct). Then re-verify: LLM host reachable,
example.com blocked, LAN blocked. Cross-check the capsule build for a working egress approach and
reuse it.

### 2. Audit capture unproven (LOGIC IS CORRECT — debug the integration)
Rule scopes on `uid` not `auid` (correct for containers) and `parse_events` handles both ausearch
dialects (correct). Yet `prove_capture` never observes the marker. Debug LIVE:
- Manually run the marker execve inside `cap-mon` and grep raw `/var/log/audit/audit.log` for the
  token + the SYSCALL uid. Confirm the exec's actual host uid and that a record is produced at all.
- Confirm the EventSource reads the SAME trail (raw audit.log vs `ausearch -k`), and that the key
  filter matches. Reconcile against the capsule's known-good capture (lib-idmap.sh + adapter).
- Test 4: `cap-mon2` under `security.idmap.isolated=true` gets a DIFFERENT range than cap-mon's
  1065536 — the error still cites 1065536, so the per-instance idmap derivation for the 2nd instance
  is suspect. Verify `derive_idmap` reads the right range for each instance.

### 3. Restore forbidden by restricted project (finding #4)
`incus snapshot restore cap-mon clean --project warden` -> `Changing "volatile.idmap.base" ... is
forbidden`. The restricted project blocks the idmap reallocation the restore relies on (the I6
phenomenon). Reconcile the restore-re-derive design with `restricted=true` + `security.idmap.isolated`
(the right restricted.idmap.* key, or rethink restore on restricted projects). This is the I5/I6 core.

### 4. project_config must set `restricted.snapshots=allow`
`restricted=true` blocks snapshot creation by default; the design REQUIRES the clean snapshot +
restore. Already set manually on the live project; bake `restricted.snapshots: allow` into
`profiles.py:project_config()`. (Note: `restricted.storage.pools` is NOT a valid Incus key — do not
add it; the pool just has to exist.)

### 5. warden up must create-or-verify its storage pool
It self-provisions the bridge (`app.py:52` network_create) but assumes `wardenpool` exists ->
"Storage pool not found" on any host where install-incus-nested.sh did not run. Add create-or-verify
(btrfs), or a `--pool` flag defaulting to wardenpool.

### 6. Builder git clone produced no .git
Test 2: `no /root/repo/.git after clone` though "egress reaches GitHub" passed. Investigate (git in
the debian/12 image? clone path/perms? provisioning allowlist timing?).

## Acceptance target
Re-run `sudo scripts/run-acceptance-nested.sh` until tests 1-4 are green (or each remaining red is a
documented, justified limitation — no faked passes, no over-wide allowlist to flatten a number).
