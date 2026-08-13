# Refactor — the three-repo boundary, and the seam that must be enforced

**What this is:** the module-boundary reorganization across **warden / agentwatch / canon**, and the one
principle that prevents tonight's failure from recurring. Distinct from `REMEDIATION-PLAN.md` (which
*fixes the gaps*) and `CANONICAL-SHAPE.md` (which *states the invariant*): this decides *which repo owns
what*, and *where the enforced seam sits*.

## Why a refactor at all

The fork gap shipped because the **capture↔reconcile seam diverged with nothing testing it.** warden's
auditd config produced fork-gap-blind telemetry; agentwatch's reconciler needed complete lineage; the
"fix" (eBPF/cgroup) lived in a loose briefing outside both repos; no test guarded the contract. That is a
*boundary* failure, not a code bug — and no amount of Phase-0/2 patching prevents the *next* one unless
the boundary itself is made enforceable.

## The principle (non-negotiable): the CONTRACT is the enforced seam

agentwatch already has the seam — `CONTRACT.md` + `contract.py` + a normalized `GroundTruthEvent`
model fed by pluggable `groundtruth/` adapters (auditd, journald; eBPF next). The refactor's core move is
to make that contract **load-bearing and tested for completeness**, so *no* implementation on either side
can silently ship an incomplete plane:

- The contract specifies both halves: (a) the **evidence** agentwatch consumes (`GroundTruthEvent` +
  `cgroup`), and (b) the **environment** it requires (a kernel-owned vantage above the container, the
  container's identity, the transcript's location).
- The contract carries a **completeness test** — a pty-spawned / host-root-injected process must yield a
  verdict (or, where a gap genuinely remains, a `fidelity_attestation`), never silent `unevaluable`.
- **Whoever produces telemetry must pass the contract test.** That is what makes the boundary safe
  regardless of which repo owns the probe.

Everything below is *organizational*; the contract-as-tested-seam is the part that actually matters.

## Target module map

- **warden = the cage + the vantage (setup convenience).** Stands up the kernel-owned substrate
  (VM/container), egress, and *placement* — a spot above the container on a kernel it owns — and hands
  agentwatch the container's **identity** (cgroup/uid) and the **transcript location**. It does this
  *gracefully* (the wedge/version/profile handling). It is swappable: any environment that satisfies the
  contract's environment half can replace it (a cloud VM, a hand-rolled host).
- **agentwatch = the monitor.** Owns the **fused `GroundTruthEvent` evidence model** (parsing + fusion)
  and the **reconciler** (scope + verdicts) — the analytical core and center of gravity — *unconditionally*.
  Whether it *also* owns the privileged **capture mechanism** (the probe loader) is the open decision
  below; parsing/fusion/reconcile are agentwatch's either way. Contract-bound, not run-anywhere.
- **canon = fidelity + qualification.** Attests the **evidence's fidelity** (`fidelity_attestation`,
  `cause=missing-telemetry`, a tier — the evidence-model output stage) and qualifies **verdicts**
  (guarantee tiers). Wired into the reconcile/report path; currently unimportable, so nothing fires.

## The one open decision — where the capture MECHANISM lives (A vs B)

The reconciler + the fusion/parsing are agentwatch's either way. The open call is the **privileged capture
mechanism** — the thing that loads the probe / installs the rule and emits the event stream:

- **A. warden owns capture** — emits a shared event stream; agentwatch consumes it, unprivileged.
- **B. agentwatch owns capture** — the monitor loads its own probe + reads its own buffer; warden provides
  the vantage + container identity and invokes it at setup.

**First, the mechanics, because they tilt the setup effort.** eBPF is *not* configured like `auditctl`:
auditd is a *declarative rule* feeding a **shared system log** (multi-consumer, free), whereas eBPF is a
*loaded program* writing a **private ring buffer the loader reads** — loader and reader are naturally one
process. So **B is the mechanically natural shape for eBPF** (loader = reader = agentwatch). A is still
possible, but warden must run a **privileged eBPF collector** that re-emits events to a shared stream —
more machinery, though the *same pattern* as warden's existing privileged auditd collector.

**The safety axis — two distinct strengths; do not conflate them:**
- **B kills divergence *structurally*.** Capture and reconcile are one codebase, so there is *no seam* to
  diverge — the failure mode is **impossible by construction**.
- **A kills divergence *detectively*.** The seam exists (warden emits ↔ agentwatch consumes); the contract
  completeness-test **catches** divergence — the failure mode is *possible but detected*. Structural
  (impossible) is stronger than detective (caught-if-the-test-holds-and-nobody-disables-it); that is B's
  real edge, and a test in A does not fully replace it.

**The privilege axis — here A wins:**
- **A keeps warden's DESIGN §4 privilege split.** All root stays in warden's capture/collector;
  **agentwatch stays fully unprivileged** — a pure analysis component that can even reconcile an *exported*
  log off-host, after the fact, and be consumed by other tools (a SIEM reading the same stream).
- **B spreads privilege.** agentwatch grows a root probe-loader (bounded — it runs on the vantage, above
  the agent's reach, like warden's collector) and loses the pure-unprivileged / offline-analysis property.

**The tradeoff, flat: structural safety (B) vs. privilege discipline + analysis purity (A).** Both are
coherent architectures; there is deliberately **no lean here**. The **contract completeness-test is
required either way** — the safeguard in A, a completeness check in B. Settle the A/B call **before Phase 2
touches capture code**, and land the **contract test first regardless** — it is what makes A *safe* and B
*verified*.

## Migration = the remediation phases, boundary-attributed

The refactor doesn't add work; it *places* the remediation-plan work:

- **Phase 0** (honesty debts) — no boundary change; warden-side docs + `report.py`.
- **Contract-test first** (the principle above) — lands in **agentwatch**, before any capture change.
- **Phase 2 capture fusion** — lands in **agentwatch** under decision B (probe + adapter + fuse), or split
  warden(probe)/agentwatch(adapter) under A. cgroup-keyed scoping is agentwatch regardless.
- **canon wiring** — canon repo + the reconcile/report call site.
- **Phase 3 sub-cgroup** — warden creates the per-session sub-cgroup (part of the vantage it hands over);
  agentwatch scopes by it.

## Positioning implication (consistent with the publish story)

Under this refactor the **product is the stack**, not three independent things. agentwatch is
*contract-bound*, not a run-anywhere standalone — publishing it as one would invite the exact misuse
(reconciling against forgeable telemetry) the invariant exists to prevent. warden is the swappable cage;
canon is the attestation layer; the moat is the *invariant* they jointly hold. See
[[stack-publish-sequencing]].

## The single sentence

**Make the evidence-model contract a tested seam; agentwatch owns fusion + reconcile (and *maybe* capture,
per the A/B call); warden owns the cage and the vantage it hands over; wire canon for fidelity — land the
contract test first, then decide A-vs-B (structural safety vs. privilege purity) before Phase 2 touches
capture code.**
