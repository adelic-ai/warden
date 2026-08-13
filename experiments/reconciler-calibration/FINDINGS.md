# Reconciler-calibration — findings (run 20260813-012225-pop-os)

The preregistered experiment ran on gembox against the authed `warden-claude`. It **falsified** the
claim it was built to test, identified the exact mechanism, and surfaced a reporting bug — and then,
reading warden's own docs, showed the design had already called for the honest behavior my demo skipped.

## Observed truth table

| marker | staged as | predicted (H_ancestry) | **OBSERVED** | status |
|---|---|---|---|---|
| `EXP_EXT` | external `incus exec` | not_evaluated | **`unevaluable`** (in `unevaluable_exec` finding) | ✓ decisive |
| `EXP_DETACH` | external `setsid` | not_evaluated | **`unevaluable`** | ✓ |
| `EXP_INSCOPE` | agent runs it via Bash tool | authorized | **inconclusive** — no `execve` record found despite the transcript claiming it ran; absent from all findings | ✗ open |

## 1. Decisive result — the demo premise is FALSIFIED

An externally-injected exec reconciles as **`unevaluable`**, **not `CONFIRMED`**. So the DEV-LIVE
"operator/foothold → CONFIRMED" finding, the demo premise, and the QUICKSTART punchline are **wrong**.
The old "shared-uid → CONFIRMED" model was an inference from correlation; the ancestry model
(from reading `runtime_scope.py`) predicted `not_evaluated`, and the controlled test confirms it.

## 2. Exact mechanism — a host-root fork the uid-scoped rule can't see

`EXP_EXT` (pid 876215) has `ppid=876212`; the ancestry walk gets two hops (`[876215, 876212]`) and dies
because **876212 has no exec record**. `audit.raw` has 490 `clone` events — but **none** name 876212 or
876215. Reason: warden's audit rule filters to the **container uid range** (`-F uid>=1327680 …`), and the
fork that *created* the injected process was done by **`incusd` at host root (uid 0)** — outside that
range. The process only becomes visible when it `execve`s at the container uid. Its birth-fork is
structurally invisible to the capture.

This matters because warden **does** capture `clone` specifically to bridge fork-without-exec
(`auditd.py: ANCESTRY_SYSCALLS = ("clone",)` — "so a forked-but-never-execve'd bridge process reaches
the runtime pid instead of dying"). That bridge works for **in-container** forks (e.g. the Gemini
persistent-bridge case). It **cannot** work for **host-root injection**, because that clone happens where
the uid-scoped rule isn't looking. My last-turn hope of closing it with the existing clone records is
therefore wrong.

**Security consequence:** the fork gap is an **evasion vector** — anything entering the container via a
host-root fork (`incus exec`, and by extension a real cross-namespace injection) lands `unevaluable` by
construction. warden *discloses* it; it does not *catch* it.

## 3. This is already warden's stated design — and the demo violated it

`DEMO-SPEC.md §7`: **"The example must not stage a fork-gap scenario and present it as caught. The fork
gap is reported (`fidelity_attestation`, `cause=missing-telemetry`), never hidden."** `DEMO-VALIDATION.md
R1` records a prior instance where the fork gap "swallowed the work product." So the honest behavior
(report the blind spot, never claim the catch) is *doctrine*. The `catch-the-orphan` demo staged exactly
a fork-gap scenario and presented it as a CONFIRMED catch — a direct §7 violation. **The fix is to align
with the existing design, not to invent a new stance.**

## 4. A real reporting bug the experiment surfaced

work-phase `not_evaluated` totals **37**, but `not_evaluated_by_comm` sums to only **18** — **19
unevaluable execs (including the markers) are invisible in the breakdown.** `report.py` counts
unevaluable candidates in the not-evaluated total but never surfaces them per-comm, so a reader sees
half the blind-spot set. That under-discloses warden's own gaps and should be fixed
(`report.py`: fold unevaluable candidates into a visible bucket).

## 5. Capture-layer upgrade — the path to "complete event resolution"

The operator's requirement is that **every event in the container be resolvable when needed.** That is
**not met today**, and the reason is structural, not incidental: auditd is `execve`+`clone`, **uid-scoped**,
so a host-root fork into the container is a permanent blind spot. Ranked honestly:

- **(a) existing clone records — insufficient.** Covers in-container forks only; the injecting fork is
  out of scope. (Corrects my prior optimism.)
- **(b) cgroup/LSM identity — partial.** The audit record already carries `subj=incus-…warden-claude…`,
  so container *membership* is knowable without ancestry. But it says "in the container," not "the
  agent's session vs. an injection" — both share one container cgroup. **Not currently used for scoping
  at all** (scoping is uid-keyed).
- **(c) non-root agent uid (ROADMAP step 1b) — helps this case.** If the agent is `dev` and injections
  run as `root`, uid separates them, sidestepping the ancestry walk for operator/host-root injection.
- **(d) eBPF (cgroup-labeled) — the complete instrument, ALREADY VALIDATED, NOT integrated into warden.**
  An eBPF program on `sched_process_fork`/`sched_process_exec` captures *every* process creation —
  including incusd's host-root fork into the container — with cgroup attached, independent of
  uid-filtering. This is **not speculative**: the CageTheAgent testbed already prototyped and *measured*
  it — `auditd execve` alone orphaned **0/11** build actions (agent spawns via pty: forkpty→setsid),
  **eBPF `sched_process_fork` got 9/11 and cgroup covered the rest** (memory `warden-substrate-kernel-
  ownership`; `cagetheagent/DESIGN.md`). The design invariant is *"host-side process-lifecycle telemetry
  keyed by cgroup."* **warden's shipping capture layer (`auditd.py`) diverged from this** — it ships
  `execve`+`clone`, uid-scoped, i.e. the exact approach the prior work measured as insufficient.

**The real finding, then:** this is not new research and not vaporware — it is an **integration gap**.
warden ships a capture approach its own validation already found blind to the fork gap; the eBPF/cgroup
solution is designed and measured but never ported into warden. "Complete event resolution" =
**integrate the validated eBPF/cgroup capture into warden**, plus the non-root-agent uid split (c) for
the operator/injection distinction.

**The honest synthesis with warden's ethos:** completeness is the *goal* (integrate the already-validated
eBPF/cgroup capture); disclosure of whatever gap remains is the *invariant* (never present an unresolved
event as resolved). Today warden's *shipping* code sits at "auditd, blind to host-root forks, and it
should disclose that, not hide it"; getting to "resolve completely" is porting (d) — a build that is
de-risked because the approach is already measured.

## Next actions

1. **Retract/rewrite** DEV-LIVE finding #1, `demo/catch-the-orphan.sh`, and the QUICKSTART punchline from
   "under re-verification" to "falsified — external injection is `unevaluable`, per DEMO-SPEC §7 disclose,
   never present as caught." Keep the surviving value: unforgeable capture + honest blind-spot disclosure.
2. **Fix the `report.py` not_evaluated_by_comm gap** (surface unevaluable execs). Encode as a test.
3. **Re-run the in-scope cell** cleanly (`EXP_INSCOPE` was inconclusive) to characterize what *does*
   produce CONFIRMED — the only path to a truthful "catch" demo, if one exists.
4. **Scope the eBPF/cgroup capture upgrade** as the roadmap item for "complete event resolution" — it is
   the real fix for the fork-gap blind spot + the evasion vector, and it is currently unbuilt.
