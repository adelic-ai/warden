# warden

**Don't trust an agent's account of itself. Reconcile it against a plane it can't forge.**

warden is a reference model for **governed LLM deployment**: run an LLM agent in an isolated,
egress-controlled container, and reconcile what it *said* it did (its transcript) against
unforgeable ground truth (the host syscalls it actually made, the network it actually reached).
That reconciliation — not the transcript — is the product. Reading the transcript alone is
trusting the thing you're supposed to be watching.

> **An assembly, not *the* assembly.** This is a PoC / prototype — *one* coherent way to wire
> accountable autonomy from composable parts, not a product you adopt wholesale. Every layer is
> an independent repo; use any subset. warden is the reference that shows them working together.

## Two shapes, one substrate

The same wizard stands up two flavors from one codepath (`--flavor`):

| | **builder** | **monitored** |
|---|---|---|
| for | your dev / platform engineers | LLM *workloads* |
| use | hands-off building (skip-permissions is safe — it's sandboxed) | a watched runner |
| egress | proxy allowlist → LLM API **+ GitHub/npm/registries** | proxy allowlist → **LLM API only** |
| repo/git | cloned repo + git | none |
| ground-truth plane (auditd) | optional | **wired** |

Free rein is safe in `builder` *because* it's contained; `monitored` is the microscope slide.

## The stack (read bottom-up — each layer only means something over a working one below it)

| Layer | Repo | Role |
|---|---|---|
| **omega + ATLAS** | [adelic-ai/omega](https://github.com/adelic-ai/omega) | coverage cartography — what we catch, and where we're silent, on the AI-threat landscape |
| **canon** | *(attestation layer — see below)* | verdicts + chain-of-custody + a machine-checkable claim of what's covered and what structurally isn't |
| **agentwatch** | [adelic-ai/agentwatch](https://github.com/adelic-ai/agentwatch) | two-plane reconciliation of self-report vs. ground truth → `CONFIRMED / GAP / NONE` |
| **Incus wizard** | **this repo** | the substrate: an isolated, egress-controlled, audited LLM runner |

Each is usable on its own. warden (this repo) is the substrate **and** the narrative that
assembles them — the [design doc](DESIGN.md) and the [3-view site](web/) tell the whole story.

## Quickstart

Requires a real `incus` on the host (Incus ≥ 7.x) and a btrfs storage pool.

```
python3 -m warden.cli up --flavor builder   --host local --llm claude  --project warden
python3 -m warden.cli up --flavor monitored --host local --llm gemini  --project warden
python3 -m warden.cli restore <instance>    --flavor monitored --llm gemini   # re-derives the audit rule (see below)
python3 -m warden.cli down <instance>
```

`up`/`down`/`restore` need only the privilege the invoking user already has with `incus`
(sudo, or membership in the host's `incus` group). Root is needed once, up front, for Incus
install and the auditd/nftables wiring. Without a real `incus`, `up` fails fast rather than
pretending to succeed. A Gemini API key (`--secret-file` or `GEMINI_API_KEY`) is injected as a
container secret, never committed.

## Status — measured, and honestly bounded

**Validated on a real Incus host** (not a fake, not nested): the §4 acceptance passes 16/16 —
unprivileged containers, no host disk, egress reaches the allowlisted LLM host but **not** the
LAN or off-allowlist domains, auditd captures a marker exec at the derived uid range, and — the
load-bearing one — **snapshot restore re-derives the audit rule and re-proves capture** (an
idmap reallocation on restore silently blinds a frozen rule; deriving it every time is the fix).
Idempotent and reversible. The real-host run surfaced six bugs a fake never could (egress that
generated a ruleset nothing loaded; audit records fused by a reused serial; a restricted project
that blocked its own snapshots).

**agentwatch** ships Claude and Gemini adapters. False-positive side works structurally
(CONFIRMED-on-benign **83 → 0** Claude, **34 → 0** Gemini, without over-allowlisting). Recall
(the tool_call↔exec correlation) is validated for the shell-out case.

**Honest limits — stated so no layer above certifies past them:**
- Not calibrated. These are single-run measurements, not actuarial FP/FN rates.
- The **fork gap**: `fork` without `exec` is invisible to execve-only audit — a real coverage
  boundary, reported (via canon's fidelity attestations) as `missing-telemetry`, not hidden.
- Gemini logs tool calls **name-only** unless `logPrompts` is on — reconciliation authorizes on
  timestamp, not command-level claimed-vs-actual.
- canon wiring emits verdicts at guarantee tier ≤ `well_formed` with calibration **absent** — it
  refuses to claim a bound it hasn't earned.

## What this is *not*

- **Not a product.** A reference model / prototype.
- **Detective, not preventive.** It stands up sandboxes and wires monitoring; it never blocks.
  (Containment comes from the sandbox + egress lock; detection tells you what mattered.)
- **Single host per invocation.** Fleet orchestration is future work.

## Layout

```
warden/          the wizard package (idmap derive-on-load + re-derive-on-restore, restricted
                 project/profile config, egress via Incus network ACLs, host CONNECT-allowlist
                 proxy, auditd rule + marker-capture proof, the two-flavor codepath, CLI)
scripts/         install-incus-nested.sh (setup) · run-acceptance-nested.sh (the §4 tests)
tests/           unit tests + the §4 acceptance against a FakeIncus double
DESIGN.md        the full design doc
web/             the 3-view site (overview · findings · design)
DECISIONS.md     judgment calls, incl. the six real-host findings (D13–D20)
```

```
python3 -m pytest tests/ -v
```

## A note on canon

canon is the attestation/provenance layer — it turns each agentwatch verdict into a
SHACL-validated `detection_verdict` with a walkable PROV-O provenance chain, and turns
agentwatch's structural limits into machine-checkable `fidelity_attestation`s. The wiring lives
on the agentwatch side (canon stays a stable, context-agnostic contract). Its public face is
being sorted out; until then, treat the attestation layer as described here and in `DESIGN.md`.

---

*Part of [adelic-ai](https://github.com/adelic-ai). Behavioral accountability for autonomous
LLM agents — earned with measured reliability, not asserted.*
