# Remediation plan — capture & reconciliation (warden ↔ agentwatch)

**Follow-through doc for the issues surfaced 2026-08-12/13.** The reconciler-calibration experiment
(`experiments/reconciler-calibration/FINDINGS.md`) falsified the demo's premise and exposed a coupled
chain: warden's shipping capture is fork-gap-blind (`CAPTURE-CONSTRAINT.md`), and the reconciler's
attribution rests on a fragile process-ancestry walk. Fixing it spans **two repos**, and the analytical
core is **agentwatch** — this plan is the cross-repo source of truth; items are tagged `[warden]` /
`[agentwatch]` / `[both]`.

## The boundary (who owns what)

- **`[warden]`** — substrate + **capture** (`auditd.py` rule install / future eBPF probe / the collector)
  + the **glue** (`report.py`) + operator docs. Produces raw telemetry, presents the result.
- **`[agentwatch]`** — the **reconciler**: scoping (`runtime_scope.py` — ancestry walk, `in_scope`) and
  verdicts (`orphan.py`/`verdict.py`). **Decides attribution.**
- **The seam** — the telemetry *contract*: what warden captures → what agentwatch consumes. The
  eBPF/cgroup upgrade CHANGES this contract, so both sides move together.

## Phase 0 — honesty debts (do first; cheap; no dependencies)

- **`[warden/docs]` Finish the correction: "under re-verification" → "falsified".** The
  `catch-the-orphan` demo premise (injected exec → CONFIRMED) is *wrong* (it's `unevaluable`). Rewrite
  the demo, DEV-LIVE finding #1, and the QUICKSTART punchline to the observed truth; disclose per
  `DEMO-SPEC §7`. **Done when:** no artifact claims injected-exec → CONFIRMED; the demo either shows the
  honest `unevaluable` disclosure or is removed pending Phase 1.
- **`[warden/report.py]` Fix `not_evaluated_by_comm` under-disclosure.** Unevaluable execs are counted
  in the not-evaluated total but invisible in the per-comm breakdown (19 of 37 in the run). Surface
  them. **Done when:** a test asserts `by_comm` accounts for every not-evaluated exec.

## Phase 1 — characterize (before building the fix)

- **`[experiment + agentwatch]` Re-run the in-scope cell cleanly.** `EXP_INSCOPE` was inconclusive (no
  execve record). Determine: does *any* realistic input produce a truthful `CONFIRMED`? — i.e. an
  in-session-subtree exec with no authorizing tool_use that isn't runtime-internal. **Done when:** the
  truth table has either a confirmed CONFIRMED-producing input, or a documented "none exists under these
  conditions." *This decides whether a truthful "catch" demo can exist at all* (see strategic question).

## Phase 2 — the capture upgrade (the real fix; spans both)

- **`[warden/capture]` eBPF (cgroup-labeled) process-lifecycle telemetry.** Add an eBPF
  `sched_process_fork`/`sched_process_exec` probe (de-risked: measured 9/11 + cgroup vs auditd-execve's
  0/11) producing cgroup-labeled events; auditd can stay as a portable fallback. **Done when:** the
  pty-spawned and host-root-injected cases are captured (0/11 → 11/11 on the same build).
- **`[agentwatch/runtime_scope]` cgroup-keyed scoping.** Consume **cgroup membership** as the scope key
  instead of relying on the ancestry walk; the ancestry walk becomes a fallback/cross-check, not the
  sole basis. **Done when:** an injected exec is scoped by cgroup (in/out of session) rather than left
  `unevaluable` for lack of walkable ancestry.
- **`[both/contract]` Update the telemetry contract** (warden emits ↔ agentwatch consumes) for the
  richer, cgroup-labeled events — the one place the two repos must land together.
- **`[both/test]` Fork-gap acceptance test.** A pty-spawned or host-root-injected exec must receive a
  *verdict*, not `unevaluable`. This is the guard that was missing — a validated finding with no in-repo
  test is what let the gap ship. **Done when:** the test exists and fails on regression.

## Phase 3 — granularity (the recorded open problem)

- **`[warden + agentwatch]` Per-agent-session sub-cgroup.** cgroup is *complete but coarse* (one ID per
  container — all execs share it), so it gives completeness without agent-session-vs-noise granularity.
  A per-session sub-cgroup (warden creates it; agentwatch scopes by it) distinguishes the agent's session
  from a co-resident operator/injection. Pairs with the **non-root-agent uid split (ROADMAP 1b)**.
  **Done when:** the reconciler separates agent-session from a co-resident injection by cgroup/uid, not
  by timing.

## The open strategic question (surfaced, not answered)

If Phase 1 finds that **no realistic input produces a truthful `CONFIRMED`**, then warden's honest value
proposition is **"unforgeable capture + honest blind-spot disclosure," not "catches the attacker."** That
reshapes the demo *and* the publish/positioning story. **Decide it with the Phase 1 evidence, not before**
— and note the value survives either way (disclosure of what the plane can't attribute still beats a
telemetry-trusting monitor that reports clean).

## Sequencing

0 → 1 → 2 → 3. Phase 0 is pure honesty cleanup (do now). Phase 1 is a cheap experiment that gates the
strategic question. Phase 2 is the real build and must land warden+agentwatch together *with* the test.
Phase 3 is the granularity refinement, coupled to the non-root-agent work already on the ROADMAP.
