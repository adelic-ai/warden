# The canonical shape

The whole idea, minimally. Everything in warden/agentwatch/canon is a parameter on, or a layer above,
this one invariant.

## The invariant

> **Put the watcher where the watched cannot reach it, and reconcile the agent's own account of what it
> did against the kernel's unforgeable record of what it actually did.**

## The layering

```
[ a kernel you own ]                    ← bare-metal OR a VM (isolation strength varies)
   ├─ the monitor (agentwatch)          ← ABOVE the agent, unreachable by it: reconciles the planes
   ├─ the egress chokepoint (host proxy)← host-side: CONTAINS network reach, and RECORDS it (unforgeable)
   └─ container
        └─ agent (LLM), UNPRIVILEGED    ← BELOW, confined; can forge its own words, not the kernel's
```

## Two ground-truth planes, one self-report

The agent produces exactly **one, forgeable** thing: its **self-report** (the transcript — its claimed
tool calls). Against it stand **two host-side, unforgeable planes** the agent cannot reach:

1. **Process-lifecycle** — the kernel's record of every `exec`/`fork` (auditd today; the target is the
   *fused* evidence model below — auditd + eBPF + cgroups, not eBPF alone).
   *"What did it run."* This is where the reconciliation deep-work lives (scope, verdicts, the fork gap).
2. **Network egress** — the host-side proxy chokepoint. *"What did it try to reach."* Deny-by-default
   (**containment**) **and** an unforgeable log the agent can't touch (**observation**). Today warden
   uses it for containment; its observation value — reconciling reached-hosts against intent — is
   **under-realized**, and it is the more robust plane (it sits outside the container, so it survives
   the fork gap and even the VM-root case where the process plane goes forgeable).

Reconciliation = self-report **vs** the ground-truth planes → *accounted* (authorized) / *unaccounted*
(CONFIRMED) / *unobservable* (NONE) / *unattributable* (unevaluable).

## The evidence model — the process plane is FUSED, and its fidelity is attested

The process plane is not one source; it is a **fusion**, because each source covers the others' gaps:

```
auditd   (exec semantics: what program, what args)
         \
eBPF  ---→   Warden Evidence Model   ---→   Canon Fidelity
(complete lineage: fork/exec —            (attests the evidence's COMPLETENESS:
 closes the pty/host-root fork gap)        a gap → fidelity_attestation,
         /                                  cause=missing-telemetry, a guarantee tier)
cgroups  (membership/scope: the universal,
          fork-gap-robust correlation key — a kernel attribute, not an ancestry walk)
```

- The three fuse into the normalized `GroundTruthEvent` stream (agentwatch's contract, `groundtruth/`).
- **Canon Fidelity is the output stage:** canon attests how *complete* the evidence is. A blind spot is
  not hidden — it flows through as a formal `fidelity_attestation` (`cause=missing-telemetry`, a tier).
  This is the honest-disclosure invariant, *formalized* (already present as `canon_emit.fork_gap_attestation()`).

**Designed to fuse; shipped with only auditd — and canon unwired.** The implementation ships the portable
source (auditd) *alone* and does not wire canon. So **both** stages are missing: no fusion → the evidence
is incomplete (the fork gap); no canon → the incompleteness isn't formally attested (the disclosure is
prose in the README instead of a fidelity tier). Remediation is therefore two-part: **actually fuse** (add
eBPF lineage + cgroup keying to the evidence model) **and wire canon** (so the fidelity attestation flows).
It is not "auditd vs eBPF"; it is "one of three fused inputs shipped, and the attestation stage skipped."

## The two functions of the cage — do not conflate them

- **Contain** (preventive): unprivileged container + VM isolation + **deny-by-default egress**. Stops harm
  before it happens.
- **Account** (detective): **capture + reconcile**. Records what happened and explains where the agent's
  story and the kernel's record disagree.

The differentiator is holding **both**, on a kernel the agent can't reach the accounting on. A cage that
only contains is a sandbox (commodity); a monitor that only accounts, on a plane the agent can reach, is
forgeable (Roblox/Darktrace). The shape is contain **and** account, on an owned kernel.

## Three roles

- **kernel** — *observes.* Normal operation; sees every syscall in every namespace. The source of
  unforgeability (an unprivileged agent cannot reach it).
- **environment (warden)** — *configures + sets up.* Installs the capture rule (or eBPF probe) to satisfy
  the monitor's contract, stands up the container / egress / placement, and does it *gracefully* (handles
  the wedge/version/profile failure modes). A convenience/orchestration layer — **swappable**.
- **monitor (agentwatch)** — *reconciles.* **Contract-bound**, not run-anywhere: it needs a contracted
  event stream + a transcript. Portable across any environment that satisfies its contract.

## The contract is the seam

agentwatch defines what it consumes: a normalized `GroundTruthEvent` stream from a **pluggable source**
(`groundtruth/`: auditd + journald today, eBPF next) + a transcript from a **pluggable adapter**
(`adapters/`: claude, gemini). The environment must *produce* contract-satisfying telemetry. **Tests on
the contract** (e.g. a pty-spawned / host-root-injected process must yield an event that gets a *verdict*,
not `unevaluable`) are what keep any environment — auditd, eBPF, or a future one — from silently shipping
an incomplete plane. (This is exactly the guard whose absence let the fork gap ship.)

## Parameters (everything that is NOT the invariant)

- **What owns the kernel:** bare-metal (weakest isolation, simplest) → VM (strong isolation, the default)
  → cloud **IaaS** VM (remote, at scale). **Never** managed containers/serverless (no owned kernel → the
  invariant breaks, telemetry goes forgeable).
- **Container runtime:** any (Docker / incus / podman / nspawn) — all namespaces on one shared kernel;
  **cgroup is the universal correlation key**. incus is warden's choice, not a requirement.
- **Capture sources:** *fused, not chosen* — auditd (exec semantics), eBPF (lineage / fork-gap closure),
  cgroups (membership/scope key). Each covers the others' gaps; see the evidence model. Portability sets
  which are available (auditd everywhere; eBPF wants a modern kernel), but the target is the fusion.
- **Auth:** keyed (hands-off, vendor-sanctioned) / keyless (hands-on, own subscription). Keyless-hands-off
  is technically possible but **ToS-dependent** per LLM vendor. ("Key" is the LLM credential; it is *not*
  the privilege/root axis.)

## Layers ABOVE the shape, and things deferred (not core)

- **Agent credential identity** (JWT+Vault / SPIFFE) — *who the agent is*, for enterprise. Orthogonal to
  the invariant; **deferred**.
- **Canon** — two roles, at two points. (1) **Fidelity attestation** of the *evidence* (`cause=missing-telemetry`,
  a tier) — this is part of the honest-disclosure spine (the evidence-model output stage above), core, and
  partly implemented. (2) **Qualification** of *verdicts/detections* (guarantee tiers over findings) — a
  layer above the core mechanism. Both currently unwired in the shipping path (canon not importable).
- **Real-time process enforcement** — the shape *accounts* for process activity post-hoc and *contains*
  network activity pre-hoc; real-time process *blocking* (seccomp/LSM) is a possible addition, not core.

## The contrast, in one line

Roblox et al. build a strong cage but place the monitor **inside the agent's reach** (forgeable
telemetry) — they *foreclose* the invariant. This shape *holds* it. That is the entire delta, and it is
an **infrastructure** property, which is why it's the moat.
