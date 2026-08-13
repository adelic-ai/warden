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

1. **Process-lifecycle** — the kernel's record of every `exec`/`fork` (auditd today; eBPF the target).
   *"What did it run."* This is where the reconciliation deep-work lives (scope, verdicts, the fork gap).
2. **Network egress** — the host-side proxy chokepoint. *"What did it try to reach."* Deny-by-default
   (**containment**) **and** an unforgeable log the agent can't touch (**observation**). Today warden
   uses it for containment; its observation value — reconciling reached-hosts against intent — is
   **under-realized**, and it is the more robust plane (it sits outside the container, so it survives
   the fork gap and even the VM-root case where the process plane goes forgeable).

Reconciliation = self-report **vs** the ground-truth planes → *accounted* (authorized) / *unaccounted*
(CONFIRMED) / *unobservable* (NONE) / *unattributable* (unevaluable).

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
- **Capture source:** auditd (portable, fork-gap-blind) or eBPF (modern kernel, complete). A pluggable
  ground-truth adapter.
- **Auth:** keyed (hands-off, vendor-sanctioned) / keyless (hands-on, own subscription). Keyless-hands-off
  is technically possible but **ToS-dependent** per LLM vendor. ("Key" is the LLM credential; it is *not*
  the privilege/root axis.)

## Layers ABOVE the shape, and things deferred (not core)

- **Agent credential identity** (JWT+Vault / SPIFFE) — *who the agent is*, for enterprise. Orthogonal to
  the invariant; **deferred**.
- **Qualification** (canon) — attestation + guarantee tiers *over* the verdicts. A layer above, not the
  core mechanism.
- **Real-time process enforcement** — the shape *accounts* for process activity post-hoc and *contains*
  network activity pre-hoc; real-time process *blocking* (seccomp/LSM) is a possible addition, not core.

## The contrast, in one line

Roblox et al. build a strong cage but place the monitor **inside the agent's reach** (forgeable
telemetry) — they *foreclose* the invariant. This shape *holds* it. That is the entire delta, and it is
an **infrastructure** property, which is why it's the moat.
