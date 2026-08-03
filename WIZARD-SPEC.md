# warden wizard — one command to stand up a sandboxed agent (spec)

**Status:** spec, 2026-08. Step 0 of the warden stack. Target backend: **Incus**. Build+test env:
**Lima with nested Incus** (disposable); final-validate on pop-os.

**Goal:** `warden up --flavor <monitored|builder> …` stands up a sandboxed LLM-agent container on an
Incus host, encoding every gotcha the manual builds hit so no one re-hits them. Two flavors from one
codepath; the flavor sets egress, repo/git, and whether the ground-truth plane is wired.

---

## 0. Why two flavors (the lesson that produced this)

The manual builds proved the substrate is one thing but the *use* is two:

- **monitored** — a *watched workload* (the Gemini capsule): locked down (default-drop egress +
  host-proxy allowlist to the LLM API only), no repo/git, **auditd ground-truth wired**, snapshotted.
  This is the microscope slide.
- **builder** — a *hands-off builder* (what maude's Claude-in-Lima is): repo + git access, egress
  wide enough to reach GitHub/npm/package registries, **skip-permissions** (free rein is safe because
  it's sandboxed), auditd optional. This is what should have run the pop-os agentwatch build instead
  of the permission-asking host — so builds go hands-off, and the human only touches the irreducible
  privileged captures.

Both share the substrate; **`--flavor` is the only difference at the config layer.** Watched-builds-
watcher is *allowed* (v1/v2 bootstrapped exactly that; the ground-truth plane is independent and the
result is git-reviewed) — the point of the two flavors is *configuration*, not permission.

## 1. Encoded gotchas (the whole reason the wizard exists)

Every one of these cost a debugging cycle; the wizard bakes in the fix:

- **Never freeze the idmap range — derive it** from `volatile.idmap.current` at load, and
  **re-derive on restore** (the restore reallocates it and silently blinds auditd — I6 broke I5
  three times over). `restore` must re-derive the audit rule *and prove capture with a marker exec*,
  not trust `auditctl -l`.
- **Incus config:** `restricted=true` requires `features.profiles=true` (define the profile *in* the
  project); `images:debian/12` (the `images:` remote dropped Ubuntu); install `btrfs-progs`; **pin**
  the bridge subnet (not `auto`), chosen not to collide with the host LAN; bridge ACLs use `drop`,
  not `reject`; rely on default-`drop` rather than a broad `10/8` rule that can shadow the `/32`
  allows.
- **Egress:** default-`drop` + a **host-side** forward proxy (SNI/CONNECT allowlist, no interception,
  not in-guest). Per-flavor allowlist (§2). Provisioning-vs-runtime: a builder needs a *wide*
  allowlist during setup (debian/nodesource/npm) that **narrows to runtime** after — swapping the
  list is not "disabling the ACL."
- **auditd (monitored flavor):** persistent rule in `/etc/audit/rules.d`, uid-scoped to the derived
  range; parse output with a dialect-tolerant reader (this host interpolates `ausearch -i` fields and
  uses local-time headers) **or capture raw** (unambiguous epoch — preferred).
- **Operator:** `gembox` (restricted `incus` group) is **optional** — it lets you operate without
  sudo; it is *not* required to have a sandbox (the idmap is what contains). Wizard supports both:
  run as `srh`+sudo, or grant a restricted operator.

## 2. The two flavors, concretely

| | monitored | builder |
|---|---|---|
| egress | default-drop + proxy → **LLM API only** | default-drop + proxy → LLM API **+ GitHub/npm/registries** |
| repo/git in-container | none | cloned repo + git (push via bundle-out, or a scoped credential) |
| auditd ground-truth | **wired** (the whole point) | optional |
| agent permission mode | interactive/gated (it's watched) | **skip-permissions** (sandboxed → safe) |
| snapshot | yes (`clean` before first run) | yes |
| use | watched workload / test subject | hands-off building |

Shared substrate both inherit: unprivileged container, idmap-derived, no host mounts (`restricted`
disk=managed as a second I2 enforcement), pinned bridge, snapshot/restore that re-derives the audit rule.

## 3. Inputs / config

`warden up --flavor <F> --host <incus> --llm <claude|gemini> [--project <name>] [--mem 4GiB --cpu 2]`

- **LLM + auth** — `claude` (OAuth/subscription) or `gemini` (API key). The key is **NEEDS-HUMAN**:
  injected as a container secret, never committed; the wizard stops before a real run without it.
- **Egress allowlist** — flavor default + `--allow <domain>` extras; verified against the LLM's
  actual endpoints (don't hardcode a stale CIDR — a domain allowlist, per the Capsule's D4).
- **Standing rules** — drops `GEMINI.md`/`CLAUDE.md` (git discipline, no self-mod, surface via
  NEEDS-HUMAN) into the agent's workdir.

## 4. Acceptance tests (run in Lima's nested Incus, then once on pop-os)

The wizard is done when each is one command and each invariant is *proven*, not assumed:

1. **`warden up --flavor monitored`** → verify: unprivileged (init at a high subuid, not 0); no host
   disk device; egress reaches the allowlisted LLM host but **not** a LAN IP and **not** a
   non-allowlisted domain; auditd captures a marker exec at the derived uid range; `clean` snapshot
   exists; **restore re-derives the audit rule and re-proves capture** (the I6→I5 regression test).
2. **`warden up --flavor builder`** → verify: can `git clone` a public repo and run the LLM
   hands-off (skip-permissions), egress reaches GitHub/npm **but not the LAN**; no auditd required.
3. **Idempotent** (re-run is a no-op or safe update) and **reversible** (`warden down` removes the
   instance; the host is unchanged).
4. **`warden up` twice** (two instances) → proves 1→N on one host: a monitored capsule *and* a
   builder coexisting, distinct idmaps, distinct audit scoping.

Test 4 is the payoff: a builder + a monitored instance side by side, each one command — the symmetric
setup the manual work never reached.

## 5. Build + test environment

- **Written and tested hands-off in the Lima VM** (agent-vm): install Incus inside it
  (`apt install incus` / zabbly), `incus admin init` a throwaway pool+bridge, and exercise the wizard
  against *that* nested Incus. The builder can create/destroy containers freely — it's disposable.
- **Unprivileged containers work nested** (namespaces on the Lima kernel; no nested HW virt). auditd
  runs against the Lima VM's own kernel. Egress ACLs (nftables) work.
- **Final validation on pop-os** — one pass of §4 on the real host, since a few auditd/kernel
  specifics may differ nested. Bulk of the work is hands-off in Lima; only the final pop-os pass and
  the `GEMINI_API_KEY` are human steps.

## 6. Non-goals (v1)

- **Lima backend** — the wizard targets Incus; a Lima flavor (for a local Mac Gemini) is a later
  adapter over the same flavor/config model.
- **Enforcement** — detective only; the wizard stands up sandboxes and wires monitoring, it never
  blocks.
- **Clustering / multi-host** — single host per invocation; fleet orchestration is future.

## 7. Build order

1. Substrate: unprivileged container + idmap-derive lib + pinned bridge + snapshot/restore-re-derive.
2. `--flavor` config layer (egress allowlist, repo/git, auditd toggle, permission mode).
3. The host-side proxy (SNI/CONNECT allowlist) + provisioning→runtime narrowing.
4. auditd wiring (monitored) with the dialect-tolerant/raw reader.
5. `warden up` / `warden down` CLI + the §4 acceptance tests in nested Incus.
6. Final validate on pop-os; then it's the one-command substrate the rest of the stack stands on.
