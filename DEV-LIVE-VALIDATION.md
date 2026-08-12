# DEV-LIVE-VALIDATION — reconciling a live free-form dev home

**Date:** 2026-08-11 · **Host:** gembox (pop-os, bare-metal Incus 7.x) · **Instance:** `warden-claude`
(`dev` flavor, key-free, persistent) · **Runtime:** Claude Code v2.1.227 (Sonnet 5), authenticated
by Claude Pro *subscription login* — no injected key · **Reconciler:** `warden report --live`.

## What this validates

That the whole stack works end-to-end on a **live, interactive** home — not a bounded workload:
free-form Claude in the cage (unprivileged container, egress default-drop, auditd ground-truth plane),
reconciled by agentwatch through `warden report --live`, producing an honest verdict. It is the first
demonstration of the reconciler against the free-form loop, which previously had no path to it (a
workload's `report` scopes from a run manifest; a dev home has no run).

**This is one demonstration run, not a calibration.** It is not an FP/FN rate — no corpus, no
thresholds, no triggers, exactly as the report's own honesty block asserts (`calibrated: false`).

## Method — a controlled contrast

The reconciler scopes an accountable window from a boundary (`--since`, or the stamped
`session_started_at` / `provisioned_at`). Two runs over the *same home*, changing exactly one
variable — whether the **operator** touched the container inside the window:

- **Contaminated run:** `--since 3h`, a wide window during which the operator ran `incus exec`
  verification probes (checking `claude --version`, egress `curl`s, re-pushing `CLAUDE.md`).
- **Clean run:** a fresh boundary set host-side (`incus config set`, no container exec), after which
  the operator stayed **off** the container; only Claude acted, driven by the human interactively
  (create a file, `git init`/`add`/`commit`, dump output to a file).

## Result — work phase (the accountable window)

| metric | contaminated | **clean** |
|---|---:|---:|
| agent-uid execs | 218 | 238 |
| evaluated | 128 | 236 |
| authorized (matched to a tool call) | 59 | **111** |
| **CONFIRMED** (action, no authorizing intent) | **6** | **0** |
| NONE (structurally unobservable) | 63 | 125 |
| GAP | 0 | 0 |
| not-evaluated (fork gap) | 90 | **2** |

**CONFIRMED tracked the one changed variable: 6 → 0.** That is the result. It turns the interpretation
into evidence rather than a claim: remove the operator, and the reconciler flags nothing.

## Findings

### 1. Operator and agent share one uid — operator activity reads as CONFIRMED

An operator `incus exec` into the container runs as container-root, which the idmap maps to the **same
host uid the agent runs under**. The audit plane sees one uid; the reconciler finds execs the agent's
transcript does not explain and — correctly — calls them CONFIRMED. In the contaminated run the 6
CONFIRMED were a single 0.2-second burst that matched the operator's probing, not the agent.

**Implication, and it bites the dev home specifically.** A hands-off workload has no operator exec-ing
in, so this never arises. The interactive home — where operators *do* open shells — carries this as a
structural noise source. The audit plane cannot distinguish "operator exec'd in" from "agent acted
off-transcript." Reconciling a dev home is only meaningful over a window the operator stayed out of.

### 2. ~Half of interactive Claude's execs are runtime-internal blind spots

Of the clean run's 238 execs, **111 were attributable to tool calls (authorized) and 125 were NONE** —
Claude Code's own `sh`/`git` machinery, spawned directly by the runtime, not via a Bash tool call, so
the plane cannot tie them to intent. The honest reach for this runtime: **attribute the tool-driven
actions, flag anything unattributed, and disclose the runtime-internal half it cannot see.** Not
omniscience — but no silent blind spots either. The fork gap (a shell that `clone`s without `execve`,
dropping its subtree from the ancestry walk) is the residue: 2 not-evaluated in the clean window.

## The home under test (config it validates against)

Empirically hardened this session, each fix surfaced by *actually using it*:
`platform.claude.com` added to the `dev` egress allowlist (login 403'd without it); a dev-specific
`CLAUDE.md` (it had fallen through to the builder body); the agent CLI installed at provisioning
(dev has no run step; node's apt source is provisioning-only); interactive-login egress
(`accounts.google.com` for gemini, the Anthropic login hosts for claude).

## Reproduce

```
# enter the home (stamps the session boundary automatically):
warden dev --name warden-claude --llm claude --project wardendemo
# ... drive Claude; do NOT open a second shell into the home ...
# reconcile this session (zero-config — defaults to the session boundary):
warden report --live --instance warden-claude --llm claude --project wardendemo
```

`canon` was not importable on gembox, so `verdicts.jsonl` was not emitted — reported as a stated
condition, never worked around.
