# warden — a governed LLM workload-runner + accountability stack

**Status:** design doc, 2026-08. Working name (`warden` = oversight / custody). Headed by the Incus
wizard (step 0); everything else is a layer over it.

**One line:** run an LLM agent in an isolated, egress-controlled container, and reconcile what it
*said* it did against **unforgeable** ground truth — then attest the result and map coverage against
the AI-threat landscape.

---

## 0. Thesis

Reading an agent's own transcript is not oversight — it's trusting the thing you're supposed to be
watching. warden's premise is the opposite: every claim the agent makes is checked against a plane
it cannot forge (host syscalls, network egress it can't see or edit). That reconciliation — not the
transcript — is the product. Everything else (attestation, coverage) makes that reconciliation
*accountable* and *legible*.

The audience is dev-platform and security engineers deploying LLM agents into real workflows. The
bar is actuarial, not demo-grade: measured false-positive **and** false-negative rates, calibrated,
defensible. A governance tool that cries wolf or certifies a blind "all clear" is a liability, not a
feature.

---

## 1. The stack (read bottom-up)

```
omega + ATLAS     coverage cartography   what we cover / where we're silent, on the AI-threat spine
canon             attestation / PROV     verdicts + chain-of-custody + fidelity, machine-checkable
agentwatch        detection              two-plane reconciliation → CONFIRMED / GAP / NONE
Incus wizard      substrate  ← step 0    isolated, egress-controlled, audited LLM runner
```

Each layer is only meaningful over a working one below it. Build and validate bottom-up; name the
top for direction, don't build it first.

---

## 2. Step 0 — the Incus wizard (the substrate)

The reusable foundation: an unprivileged Incus container per agent, egress-locked, with a live
ground-truth plane. Spinning a second container for another LLM reuses all of it — that's the point
of building it once.

**What the wizard automates** — and, more importantly, **the gotchas it encodes so no one re-hits
them** (every one of these cost a debugging cycle in the first build):

- **Never freeze the idmap range — derive it.** An unprivileged container's uid range can change
  under you; a value read once and frozen is the recurring bug (it bit three times):
  1. an audit rule built from `volatile.idmap.base` (reported `0`) would have watched host root;
  2. a **snapshot restore reallocated the idmap**, so a frozen audit rule filtered a dead range —
     the ground-truth plane went **silently blind while `auditctl -l` looked correct** (exercising
     reversibility destroyed the ground truth, and the test had passed *before* the restore);
  3. a probe's hardcoded default range classified every real exec as out-of-range.
  The fix is structural: one `lib-idmap` derivation, sourced everywhere; re-derive on restore.
- **Incus config traps:** `restricted=true` requires `features.profiles=true` (a restricted project
  must own its profiles); `images:ubuntu/*` no longer resolves (use `images:debian/12`);
  `btrfs-progs` must be installed for the pool; pin the bridge subnet (not `auto`); bridge ACLs
  support `drop`, not `reject`.
- **Egress done right:** default-`drop` + a **host-side** forward proxy with a domain allowlist
  (SNI/CONNECT, no interception) — *not* a CIDR allowlist (pinning `generativelanguage.googleapis.com`
  opens most of Google) and *not* an in-guest proxy (the agent is root-in-container and could edit
  its own allowlist). The proxy's access log is a third, network-side ground-truth plane.
- **Ground truth:** persistent auditd rule (`/etc/audit/rules.d`), uid-scoped to the derived range,
  parsed for *this host's* `ausearch -i` dialect (the output format varies by auditd version).
- **Operator posture:** the container runs unprivileged; an escape lands on an unnamed subuid, not a
  real account. A dedicated operator user (`incus` group, not `incus-admin`) can drive it without
  sudo and without root — optional defense-in-depth, since the idmap is what actually contains.
- **Host hygiene:** disable sleep (`systemctl mask …`), pin the box's IP (DHCP reservation), run the
  agent inside `tmux` so a dropped connection doesn't kill it.

## 3. The value ladder

The wizard offers exactly the tier that can honestly work — computed from what's wired up, never
claimed:

- **Sandbox** *(always)* — isolated container + egress lock + the LLM + auth. "Run any LLM safely."
- **Viewer** *(cheap opt-in)* — the parsed-transcript timeline. Works for any parseable LLM.
  Labeled **viewing, not detection** — it reads self-report only, no ground truth.
- **Detection** *(opt-in, adapter-gated)* — the two-plane reconciliation. Offered **only** when an
  adapter exists for the detected (LLM, version) *and* the auditd plane is wired. Falls back to
  Viewer or Sandbox honestly when it can't.

The tier is derived, so the word "detection" only ever appears when it's true.

## 4. Privilege split

The monitor holds prompt-bearing data and is a lot of code — it must not run as root. Ground truth
is root-protected *by design* (that's what makes it unforgeable). So:

- **Privileged capture** — a tiny, dumb root collector: `ausearch` → an operator-readable file;
  telemetry pulled via Incus. Minimal, auditable.
- **Unprivileged analysis** — the reconciler runs as the operator on those files. No root.

## 5. The normalization waist

Adapters turn each LLM's raw logs into one schema — `NormalizedEvent` — and everything else is a
view over that stream:

```
raw LLM logs → [adapters: per LLM × schema-version, drift-gated] → NormalizedEvent
                                                                     ├─ live view (top-for-agents)
                                                                     ├─ query / extract (by timerange…)
                                                                     ├─ the detector (→ findings)
                                                                     └─ public JSONL / API entrypoint
```

- **Adapters are written once per LLM and shipped** — the bespoke cost is one-time, amortized across
  every user, a growing library (Claude ✓, Gemini ~✓, Codex/Aider/… addable). Pinned to a schema
  version/range; **version-keyed** and **drift-gated** so a format change downgrades verdicts to
  NONE (under-reports, safe) rather than fabricating CONFIRMEDs (lies, dangerous).
- **The public entrypoint is the strategic move:** expose `NormalizedEvent` as a documented schema
  so third parties write analyzers against *one* format instead of re-parsing each vendor. warden
  becomes a normalization layer / event bus, not just a detector.

## 6. Dev-team usage — two modes, canon spans both

Dev teams don't only run autonomous workloads; most use is **interactive and continuous** (pairing,
review, exploration). Different modes ask different accountability questions:

- **Autonomous workload** → agentwatch **detection** is primary ("did it do only what it claimed").
- **Broad / interactive** → canon **provenance/attestation** is primary — lineage of AI-authored
  code, chain-of-custody of what the assistant touched — because there's no discrete task to
  reconcile.

**canon is the unifying accountability layer.** agentwatch's CONFIRMED/GAP/NONE verdicts are already
canon's detection-verdict vocabulary; canon adds PROV-O provenance + in-toto/DSSE chain-of-custody
(a tamper-evident evidence chain from raw record to verdict) and `fidelity_attestation` — a
machine-checkable claim of what the detector covers and **structurally cannot**. The honest limits
we track in prose become signed, scoped artifacts.

**omega + ATLAS** maps that coverage onto **MITRE ATLAS** (the AI-threat framework, ATT&CK's analog
for AI systems). omega's cartography — agnostic IR → FCA → "where is it silent" — charts which ATLAS
techniques warden's detectors cover and which are unaddressed. ATLAS is young and sparse, so the
silences *are* the map — greenfield, and it feeds canon's coverage attestation with a standard spine.

## 7. Enterprise / workload-runner direction — and the honest gaps

The convergence: agents are becoming workload runners; runners need behavioral accountability. The
primitives transfer (Incus is built for fleets; two-plane accountability is the IP; the adapter
library is multi-vendor). But scaling from "one home box" to "deployment model" **inverts** things
we relaxed locally:

- **Prompt-sensitivity flips back on.** Locally it's your own data; at enterprise it's other
  people's — PII, proprietary code, cross-tenant. Multi-tenancy + RBAC + retention is the hard part.
- **Ground truth becomes a pipeline** — centralized, tamper-evident, cross-host.
- **The reliability bar becomes a liability bar** — recall must be validated, not assumed.
- **Stack integration** — SIEM, IdP (Entra), policy (DSC/OPA) as adapters, standalone-first.

Name it for direction; earn it with measured reliability. Don't let the deck get ahead of the
detector.

## 8. Status & honest limits

- **Substrate:** a working Gemini capsule exists (unprivileged, egress-locked via host proxy,
  auditd ground truth). The **wizard itself is not built** — the knowledge is captured (§2); the
  automation is the next deliverable.
- **Detection (Gemini):** false-positive side works, **structurally** — **34 → 0 CONFIRMED-on-benign**
  (baseline vs tuned scope config), the Gemini analog of Claude's 83 → 0. Achieved without
  over-allowlisting (a startup `git rev-parse` was judged, not swept away; `curl` was kept visible).
- **The 0 is bounded, and this bound is load-bearing:** it validates **scoping/classification**, not
  the **tool_call↔exec correlation** path — the benign run used an in-process tool that never
  exec'd, so `matched` is 0. A run that shells out is needed before the matching half is validated.
  Recall is **not yet proven.**
- **Gemini telemetry** is prompt-bearing; tool calls are recorded name-only unless `logPrompts` is on
  (`function_args` exists but is gated). Adapter is version-keyed against 0.53.1.
- **canon / omega-ATLAS:** not wired in. canon has the verdict schema, custody, and fidelity
  attestation; connecting it is future work. omega maps ATT&CK today, not yet ATLAS.

## 9. Build order

1. **Harden the wizard** (encode §2) — the substrate everything stands on.
2. **Validate the detector** — the shell-out run, real recall numbers, calibration.
3. **Stabilize the `NormalizedEvent` schema** + publish the entrypoint.
4. **Wire canon** (verdicts → attested, provenance-backed claims).
5. **omega on ATLAS** (coverage cartography).
6. Live view, query tools, enterprise adapters — views over a validated base.
