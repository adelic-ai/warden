# The capture-plane constraint — kernel ownership, and the fork-gap warden ships with

**Status: in-repo record of a load-bearing constraint that warden's shipping capture layer does NOT yet
satisfy.** Moved into the repo 2026-08-13 from a loose, un-versioned BlackHat briefing
(`warden_demo_substrate_constraint.md`, written 2026-08-08) that the implementation never read — which
is *why* the gap below shipped. It is here now so it is tracked, testable, and contradiction-visible.

## The binding constraint: own the kernel, not the container format

warden's unforgeable observation plane lives on the **host kernel**, not in the container. auditd (and
eBPF) run on the host and see syscalls from every namespace — that is *precisely why the agent can't
forge them*: it has no reach into a plane one level above it. So the container runtime is a nearly free
choice (Incus / Docker / podman / nspawn are all namespaces on one shared kernel; each yields a cgroup
that works as the correlation key). The binding question is only: **do we own the kernel the agent's
processes run on?**

> **VM = stronger cage, weaker unforgeable observation. Container = weaker cage, stronger unforgeable
> observation.** A VM guest runs its own kernel → host telemetry goes blind → the plane must move
> *inside* the guest, i.e. inside the agent's reach. (Plausibly why Roblox's EC2-VM Devspace falls back
> to agent-emitted OTEL for Ring-5 visibility — the strongest isolation with the most forgeable
> telemetry. See [[caging-the-agent-roblox]] reasoning.)

Container-in-VM (warden's shape) threads this: the VM owns a kernel *we* control, and the agent runs in a
container *inside* it, so the plane sits above the agent yet on an owned kernel. Good — **provided the
plane on that kernel is complete.** It currently is not.

## The gap warden ships with — `auditd execve` is fork-gap-blind

**Measured, not theorized.** On a clean agent build, `auditd execve` ancestry orphaned **0 of 11** build
actions — because the agent spawns work through a pty (`forkpty → setsid`, native fork inside
`node-pty`), so the ancestry walk dies at a forked-but-never-execve'd mediator. **eBPF
`sched_process_fork` recovered 9 of 11; cgroup membership covered the remainder.** A capture relying on
execve therefore looks like it is *finding nothing* — which reads as "broken," not "clean."

warden's shipping capture (`auditd.py`) is exactly this: `execve` + `clone`, **uid-scoped**. The `clone`
capture bridges *in-container* fork-without-exec (e.g. a Gemini persistent bridge), but not:
- **host-root injection** — anything forked into the container by `incusd` at uid 0 is outside the
  uid-scoped rule entirely (the injecting fork is invisible; the process only appears when it execs at
  the container uid). Re-confirmed by the preregistered `experiments/reconciler-calibration/` run:
  an external `incus exec` lands **`unevaluable`**, not evaluated — the fork gap, and an **evasion
  vector** (double-fork / cross-namespace injection is unattributable by construction).
- **pty-spawned work** — the 0/11 case above.

## The validated target: a FUSED evidence model, keyed by cgroup

**Not "eBPF replaces auditd."** The evidence model *fuses* three complementary sources — auditd (exec
semantics) + eBPF `sched_process_fork`/`_exec` (lineage, closing the fork gap) + cgroups (scope key) —
into one `GroundTruthEvent` stream (see `CANONICAL-SHAPE.md`). The briefing's cruder "use eBPF and/or
cgroup, *not* auditd" phrasing is superseded by this fusion: auditd stays for its semantics; eBPF and
cgroup are *added*, not swapped in.

Define the invariant as **host-side process-lifecycle telemetry keyed by cgroup membership.** Any runtime
that yields a cgroup on a kernel we own satisfies it. Concretely: an eBPF program on
`sched_process_fork` / `sched_process_exec` captures *every* process creation — including the host-root
and pty forks auditd misses — with the cgroup attached, independent of uid-filtering. This is the 9/11 +
cgroup result above. It is **de-risked** (already prototyped and measured); the work is **integration
into warden**, not research.

**Open sub-problem (already recorded):** cgroup is *complete but coarse* — one ID per container (all
execs in a run share it), so it gives completeness without agent-session-vs-noise granularity until a
**per-agent-session sub-cgroup** exists. Pairs naturally with the non-root-agent uid split (ROADMAP 1b)
for the operator-vs-agent distinction.

## Obligation

1. **Disclose, per `DEMO-SPEC.md §7`.** Until integrated, warden's shipping docs must state the capture is
   fork-gap-blind (auditd-execve), never present a fork-gap event as caught. (README / QUICKSTART.)
2. **Fuse eBPF lineage + cgroup keying INTO the evidence model** (alongside auditd's exec semantics), and
   **wire canon** so the residual-gap `fidelity_attestation` flows — the tracked ROADMAP item. It closes
   the pty gap, the host-root-injection gap, and the evasion vector.
3. **Guard it with a test** — the failure mode that let this ship was a validated finding living outside
   the repo with no test. A fork-gap scenario must have a test that pins its verdict, so a regression
   fails loudly instead of rotting silently.

See also: `experiments/reconciler-calibration/FINDINGS.md`, `FORK-GAP-VALIDATION.md`, `DECISIONS.md`.
