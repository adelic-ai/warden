# warden — quickstart

**Run an AI coding agent with the leash off, safely — and get an *unforgeable* record of what it
actually did.**

You want to let Claude (or gemini) work with `--dangerously-skip-permissions`, because gated prompts
every thirty seconds defeat the point. But an agent with free rein can trash your machine, exfiltrate
your code, or get prompt-injected into running something you never asked for. warden gives the agent a
**cage** it can't escape and a **watcher it can't reach** — so free rein stops being a risk you take on
faith.

## The one idea

Most "agent monitoring" trusts the agent's own telemetry — it asks the thing it's watching what it did.
That's forgeable: a compromised or injected agent simply doesn't report the bad part.

warden is different in kind. It's not analysis — it's **infrastructure**: the agent runs in an
unprivileged **container**, and the audit runs one level up, in the **VM around it**, on a kernel the
agent doesn't own. The watcher sits where the watched **cannot reach it**. So the record of what the
agent did isn't a report you have to trust — it's a kernel-level fact the agent can't edit. Then warden
reconciles that unforgeable record against the agent's *own* self-report and shows you exactly where
they disagree.

That asymmetry — **a place to watch from that the watched can't tamper with** — is the whole thing.

## What you need

warden is honest about its footing: the unforgeable plane requires **kernel ownership**, so it runs on
**Incus** (7.x) with a Linux kernel warden controls.

- **Linux:** Incus on the host (bare metal or a VM you own).
- **macOS:** a Lima VM running Incus (warden lives in the VM; your agent runs in a container inside it).
- **Not** managed containers / serverless (Fargate, Cloud Run) — those don't give you the kernel, so the
  plane goes blind. That's a real limit, stated plainly.

`report` also needs the reconciler, **agentwatch**, on the import path (it's not on PyPI — check it out
beside warden, or set `WARDEN_AGENTWATCH_PATH`).

## 60 seconds: cage an agent

```bash
# stand up a persistent, egress-locked, audited home and drop into it.
# key-free: you log in with your own Claude subscription — no API key handed to the box.
warden dev --llm claude --name warden-home --project mywork
```

You land in a root shell **inside the container**. It's "root," but namespaced — mapped to an
unprivileged host uid, so it has zero power over your real machine. Network egress is default-drop:
the agent can reach the LLM endpoint and the package registries it needs, and **nothing else** — no
arbitrary hosts, no exfiltration path. Run `claude`, log in once, and work exactly as you would
anywhere. Re-running the same command drops you back into the *same* home; your files persist.

## The demonstration: warden catches what the agent's logs never admit

This is the part that matters. Suppose an attacker gets a foothold in the agent's container — a
prompt-injected reverse shell, a malicious npm dependency, a compromised MCP server, any real vector.
They run commands. **The agent never made those tool calls, so its transcript has no record of them.**
A monitor that trusts the agent's telemetry reports the session clean.

`demo/catch-the-orphan.sh` stages exactly this — honestly: everything is real (real cage, real
kernel-plane audit, real reconciliation); the only thing *simulated* is the attacker, represented by a
command run **directly in the container, bypassing the agent's tools** — which is precisely what a real
foothold's activity looks like to the audit plane. Then it reconciles:

```
warden report — warden-home (claude) on your-host
  scope     uid 1327680-1393215 (derived at report time, never frozen)
  plane     capture proven: yes · N ground-truth execs · M self-report events

  work phase — the accountable one.
    agent-uid execs   …
      authorized      …   matched to an authorizing tool call   (the agent's real work)
      CONFIRMED        1   action with NO authorizing intent     <-- the foothold
      NONE             …   the plane structurally could not observe this (runtime internals)
    not evaluated      …   outside the agent's session subtree (the fork gap — disclosed, not hidden)
```

The foothold lands as **CONFIRMED** — an action with no authorizing intent, caught by the plane the
attacker-in-the-container can't reach. The agent's self-report has no line for it. **A telemetry-trusting
monitor sees nothing; warden sees it as a fact.** That's the differentiator, on a real threat.

Run it:

```bash
demo/catch-the-orphan.sh warden-home claude mywork
```

## What warden honestly does — and does NOT — see

warden's whole ethos is stating its limits, because a security tool that hides its blind spots is worse
than useless. From a real validated run (`DEV-LIVE-VALIDATION.md`):

- It **attributes** the agent's tool-driven actions (authorized) and **flags** anything unattributed
  (CONFIRMED). No false-positive on a clean window — remove the operator, and it flags nothing.
- **~half** of an interactive agent's execs are the runtime's own internal `sh`/`git` (spawned directly,
  not via a tool call). warden marks these **NONE** — "structurally can't attribute" — rather than
  guessing. It discloses the blind spot; it doesn't paper over it.
- A shell that forks without exec breaks the ancestry walk (the **fork gap**) — those execs are reported
  as **not-evaluated**, never counted as clean. "No CONFIRMED here" is absence of evidence, not evidence
  of absence, and warden says so.
- It is **not calibrated** — this is a working mechanism, not an FP/FN rate. No corpus, no thresholds,
  no confident numbers it can't back.
- One structural caveat the demo itself exposes: at the audit plane, **operator and agent share one
  uid**. If *you* open a second shell into the home, your commands read as CONFIRMED too. Reconcile over
  a window you stayed out of.

## Why this is different

Every other approach either watches from *inside* (forgeable) or trusts the agent's telemetry (forgeable).
warden manufactures trust in the *substrate* — a vantage the agent can't reach — and then is relentlessly
honest about what that vantage can and can't see. The trust isn't a claim; it's a property of where the
watcher sits.

This is a **proof of concept**, and shown as one. The core loop — cage, capture, reconcile — is real and
validated; the edges (calibration, live streaming, a broader detector taxonomy) are roadmap, and named
as such. If you want to run an agent off-leash without flying blind, this is the honest version.
