# warden — workload demo: "try it on your own box" (spec)

**Status:** spec, 2026-08. The self-service loop: someone spins up a fresh cloud VM, runs five
commands, and walks away with an unforgeable, reconciled account of what an LLM workload actually
did — on their own hardware, reproducible, no trust in us required.

**Goal:** make the whole warden thesis runnable in five commands, honestly. This is the **workload
lifecycle** end-to-end: provision → run (one prompt) → produce a work product → report → tear down.

---

## 0. The experience

```
warden up --flavor builder --audit --llm claude     # sandboxed, egress-locked, audited agent
warden run --example                                 # or: warden run "your build prompt"  (hands-off, one prompt)
warden report                                        # agentwatch: what it did vs. what it said
warden export ./out                                  # copy all: transcript, findings, verdicts, built repo + git log, raw audit
warden down                                           # exit — host left as it was
```

**Substrate constraint (this decides "Linode or whatever"):** a real Linux VM with **full root and
a normal kernel** — Incus unprivileged containers + auditd + nftables all require it. Rules out
Codespaces / most PaaS. Linode / Hetzner / DO / Vultr / EC2 all work; 2–4 vCPU / 4–8 GB is plenty.
The README ships a "provision a box, install Incus, run these five" quickstart.

## 1. The workload lifecycle (and the phase split)

A workload is bounded and autonomous: **provision → run → report → teardown.** Within `run` there
are two phases warden already distinguishes via the egress model (D13: wide provisioning allowlist
that **narrows to runtime**):

- **provisioning** — clone, install deps, environment prep. No git record yet; actions here often
  have no authorizing tool call (the startup `git rev-parse` is the canonical example) and are
  *expected*.
- **work** — the authored changes, the commits. This is the accountable phase.

`git init`/clone sits at (or near) that boundary. **The report segments the two** — provisioning
noise must not drown the work-phase signal. The git-history plane covers only the work phase.

## 2. What exists vs. what this adds

- `warden up` / `warden down` — **exist, validated on real Incus** (16/16). Reuse.
- `--audit` on `builder` — **config toggle**, not new architecture: the flavor model is data-driven,
  so this is `auditd_wired=True` on the builder flavor. A build (repo/git) that is *also* audited —
  required because reconciliation needs the ground-truth plane, which was `monitored`-only.
- `warden run "<prompt>"` — **new.** Exec the LLM CLI in the container hands-off (skip-permissions),
  single prompt, to completion. `--example` uses a shipped default prompt; a bare string is the
  user's own. Adapter must match `--llm` (Claude Code / Gemini CLI both have agentwatch adapters).
- `warden report` — **new. The core: the agentwatch↔wizard integration.**
- `warden export <dir>` — **new.** Tar the artifacts out.

## 3. `warden run`

Exec the agent CLI inside the container, non-interactive, single prompt, hands-off:
- Claude: skip-permissions + print/prompt mode; Gemini: `--skip-trust` + prompt, `logPrompts` per the
  adapter's needs.
- Runs to completion or a wall-clock cap; the transcript lands where the adapter expects it
  (Claude's session dir / Gemini's OTel log).
- Records a run manifest (llm, version, prompt, start/end ts, the derived uid range) so `report` can
  scope precisely.

## 4. `warden report` — the agentwatch↔wizard integration (the real work)

Wire agentwatch's existing pipeline (`agentwatch.run.run_once`) against this container's two planes:

1. **Self-report** — pull the transcript out of the container; the matching adapter normalizes it →
   `NormalizedEvent` stream.
2. **Ground truth** — the host-side auditd capture, uid-scoped to the container's **derived** idmap
   range (never a frozen value — same derive-on-load rule as the wizard). Respect the privilege split
   (DESIGN §4): a tiny **root collector** copies audit records to an operator-readable file; the
   reconciler runs unprivileged. Parse → `GroundTruthEvent` (EXEC/CONNECT/LAN_DROP/FILE_WRITE).
3. **Reconcile** — `reconcile_orphans` + `reconcile_divergence` under `RuntimeScope` (the session
   subtree + runtime-internal allowlist) → candidates → `Finding`s → **canon verdicts** via
   `canon_emit` → `findings.jsonl` + `verdicts.jsonl`.
4. **Segment by phase** (§1): tag each verdict provisioning vs. work.
5. **Summarize honestly** — a human-readable rollup that **separates the verdict kinds** (§7).

Output: `findings.jsonl`, `verdicts.jsonl`, and a printed summary. No analysis engine (§7).

## 5. `warden export`

Tar into `<dir>`: the transcript, `findings.jsonl`, `verdicts.jsonl`, the **built repo + its git
log** (the work-product plane), the raw audit capture, and the run manifest. That's "copy all" — the
person keeps everything and analyzes with their own tools. **Git history is agent-controlled** (it
picks what to commit); it's exported as the *claimed* work product, reconcilable against FILE_WRITE
ground truth (a v2 axis — see §10), not trusted alone.

## 6. The example prompt

A shipped default (`--example`) that does a small, real build (e.g., clone a tiny public repo, add a
function + a test, run the tests, commit) — chosen to produce a **genuinely reconcilable trace** (git,
a compiler/interpreter, a test runner — real execs against a real transcript). **Not rigged** to
manufacture a gotcha. A normal build reconciles to mostly *authorized*, plus the honest boundaries.
The interesting output is the reconciliation *working on real work*, not a staged catch.

## 7. Honest framing (the bar — non-negotiable)

- **No analysis engine.** warden produces + exports; consumers analyze. Don't build (or imply)
  interpretation warden would have to defend.
- **Separate the verdict kinds; never collapse them.** `CONFIRMED` (action with no authorizing
  intent) vs `NONE` (plane structurally couldn't observe — runtime-internal tools, the fork gap) vs
  `GAP` vs authorized. A run that only hits coverage boundaries must read as *blind spots*, not
  misbehavior. Collapsing them into one "deviation" number would lie.
- **Recall is validated for the shell-out case only.** The example must not stage a fork-gap scenario
  and present it as caught. The fork gap is *reported* (canon `fidelity_attestation`,
  `cause=missing-telemetry`), never hidden.
- **Not calibrated.** The report shows the *mechanism* on one real run — not FP/FN rates. No triggers,
  no thresholds (those need a corpus — §10).
- **canon verdicts stay honest:** guarantee tier ≤ `well_formed`, `calibration` absent, custody `true`
  only where the collector signed the records.

## 8. Acceptance

On a fresh real host (VPS or pop-os), synthetic/benign example only:
1. The five-command loop runs end to end; `up`→`run`→`report`→`export`→`down` each one command.
2. `warden run --example` completes a real build hands-off; a transcript + git commits result.
3. `warden report` emits `findings.jsonl` + `verdicts.jsonl` + a summary that (a) segments
   provisioning vs. work and (b) breaks out CONFIRMED / NONE / GAP / authorized separately.
4. Every verdict is schema-valid (`detection_verdict.schema.json`) and SHACL `well_formed`; tiers ≤
   `well_formed`, calibration absent (an honesty assertion, as in the canon-wiring acceptance).
5. `warden export` produces a tarball containing transcript, findings, verdicts, built repo + git log,
   raw audit, manifest.
6. `warden down` removes the instance; host unchanged (reversibility, per wizard test 3).
7. Audit scope uses the **derived** idmap range (re-derived, not frozen) — a marker exec is proven
   captured before `report` trusts the plane.

## 9. Discipline / build environment

- Needs a **real host** (root + Incus + auditd) — same reason the wizard validation did; the agent-vm
  can't (no root, auditd doesn't nest). Build/validate on pop-os (has the validated wizard) or a
  throwaway VPS, in an isolated Incus project. Scoped sudo if run hands-off (incus/auditctl/ausearch/
  nft), never `auditctl -D` / `nft flush ruleset` (protect any co-located capsule).
- Branch on `~/dev/warden` (`main`); atomic commits; DECISIONS notes. agentwatch pieces land on its
  `build` (v2) line; integrate via bundle→push (host-side-gated).
- Reuse: `warden up/down` and agentwatch's `run_once`/adapters/`canon_emit` — this is glue + two CLI
  verbs + a config toggle, not new detection code.

## 10. Out of scope (future — but don't foreclose)

The live **deviation view** (session did-vs-said surprise, top-line + drill-down), the **cohort
baselines** (tool-deviation / error entropy with an *acceptable band vs. trigger*), and the
Darktrace-style monitor are all **downstream view/calibration layers** that need a **corpus** of
completed workloads + sessions — impossible with one run, honestly far. This demo's job is to start
producing that corpus cleanly. So: **keep `verdicts.jsonl` / `findings.jsonl` schema stable and
versioned** — they are the eventual input to those layers. Don't drift the schema for demo
convenience.

## 11. Build order

1. `--audit` toggle on the builder flavor (data-only change to the flavor table).
2. `warden run` — hands-off single-prompt exec in-container, per-adapter, with a run manifest.
3. `warden report` — wire `run_once`/reconcilers/`canon_emit` against the container's two planes,
   with the root-collector privilege split and the derived-idmap audit scope; add the phase segment
   and the verdict-kind breakout.
4. `warden export` — the tarball incl. built repo + git log.
5. The `--example` prompt + fixtures.
6. Acceptance (§8) on a real host; then the README quickstart ("provision a box → five commands").
