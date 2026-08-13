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
- **agentwatch = the complete monitor.** Owns **capture → fuse → reconcile**: the eBPF/auditd/cgroup
  *capture library*, the fused `GroundTruthEvent` evidence model, and the reconciler (scope + verdicts).
  Contract-bound, not run-anywhere. This is the analytical core and the center of gravity of the work.
- **canon = fidelity + qualification.** Attests the **evidence's fidelity** (`fidelity_attestation`,
  `cause=missing-telemetry`, a tier — the evidence-model output stage) and qualifies **verdicts**
  (guarantee tiers). Wired into the reconcile/report path; currently unimportable, so nothing fires.

## The one open decision — where the eBPF *probe* lives

The reconciler side is agentwatch either way. The capture *mechanism* (the privileged probe/rule loader)
is the open call:

- **A. warden loads it** (part of standing up the cage) → capture-config stays with substrate setup;
  agentwatch parses. Keeps warden's all-in-one setup cohesive; **re-creates the seam that just failed**
  (warden emits, agentwatch consumes, they can diverge — mitigated only by the contract test).
- **B. agentwatch owns it** (the *complete monitor* captures its own telemetry; warden invokes it during
  setup and provides the vantage). **Eliminates the divergence seam** (one repo owns capture→reconcile),
  matches "a monitor that slots into any vantage," at the cost of a privileged component in agentwatch
  (fine — it runs on the vantage, above the agent's reach).

**Recommendation: B**, gated on the contract test existing first. B is the only option that structurally
prevents the divergence; A only papers over it with a test. The privilege concern is real but bounded —
the probe loader is a small root component on the vantage, exactly like warden's existing privileged
collector, and it never runs where the agent can reach it. *Settle this before Phase 2 code starts.*

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

**Make the evidence-model contract a tested seam; give agentwatch the whole monitor (capture→reconcile);
leave warden the cage and the vantage it hands over; wire canon for fidelity — and decide B-vs-A before
Phase 2 touches capture code.**
