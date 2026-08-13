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

## Quickstart — the workload loop, on your own box

Provision a plain Linux VM with **full root and a normal kernel** (Linode / Hetzner / DO / Vultr /
EC2 all work; 2–4 vCPU, 4–8 GB). Incus unprivileged containers + auditd all need that, which rules
out Codespaces and most PaaS. Then run `scripts/install-incus-nested.sh`.

**`warden report` reconciles via [agentwatch](https://github.com/adelic-ai/agentwatch) — a separate
repo by design (no package dependency), and *not on PyPI*.** `up`/`run`/`down` do not need it; only
`report` does. The zero-setup path is to check agentwatch out **beside** your warden clone — `report`
discovers a sibling `./agentwatch` automatically:

```
# put the two repos side by side, e.g. ~/dev/warden and ~/dev/agentwatch
git clone https://github.com/adelic-ai/agentwatch.git
```

Equivalently: `pip install -e /path/to/agentwatch` (a local editable install — no PyPI needed;
agentwatch has zero third-party deps), `export WARDEN_AGENTWATCH_PATH=/path/to/agentwatch`, or put it
on `PYTHONPATH`. If it is missing, `report` stops with an actionable message — never a silent or
invented result. (`verdicts.jsonl` *additionally* needs canon importable — see the canon note; without
canon you still get `findings.jsonl` and the full reconciliation summary.)

Then:

```
warden up     --flavor builder --llm gemini --audit --project wardendemo --name wd-demo \
              --secret-file ~/.warden/gemini.key     # sandboxed, egress-locked, audited
warden run    --example --llm gemini --project wardendemo --instance wd-demo \
              --secret-file ~/.warden/gemini.key     # one prompt, hands-off, to completion
warden report --llm gemini --project wardendemo --instance wd-demo   # what it did vs. what it said
warden export ./out --llm gemini --project wardendemo --instance wd-demo   # copy all
warden down   wd-demo --project wardendemo                                 # host left as it was
```

You walk away with `findings.jsonl`, `verdicts.jsonl`, the transcript, the built repo and its git
log, the raw audit capture and the run manifest — reproducible, on your hardware, no trust in us
required. **`--audit` is what makes a builder reconcilable**: reconciliation needs both planes, and
`builder` ships with only the self-report one.

`up`/`run`/`down` need only the privilege the invoking user already has with `incus` (sudo, or
membership in the host's `incus` group). `report` additionally needs a scoped sudo rule for
`scripts/warden-collect-audit.sh` — a tiny root collector that copies this instance's audit records
to an operator-readable file and does nothing else, so the reconciler itself never runs as root
(DESIGN §4). Without a real `incus`, `up` fails fast rather than pretending to succeed. A Gemini API
key (`--secret-file` or `GEMINI_API_KEY`) is injected as a container secret, never committed, and
never placed in any argv.

Substrate-only verbs, unchanged:

```
python3 -m warden.cli up --flavor monitored --llm gemini --project warden
python3 -m warden.cli restore <instance> --flavor monitored --llm gemini --audit  # re-derives the audit rule
python3 -m warden.cli down <instance>
```

### What `warden report` will and won't tell you

It separates **authorized** / **CONFIRMED** / **NONE** / **GAP** and segments provisioning from
work — deliberately with no combined "deviation" number, because a run that only hits coverage
boundaries is showing you blind spots, not misbehaviour, and one number cannot say both. It is not
calibrated, offers no thresholds or triggers, and reports the fork gap rather than catching it. The
shipping capture plane (auditd-execve, uid-scoped) is **measurably** fork-gap-blind — execve-ancestry
orphaned 0/11 actions on a real agent build (pty-spawned work); eBPF recovered 9/11 + cgroup the rest.
The validated fix — eBPF process-lifecycle capture keyed by cgroup — is **not yet integrated**
(`CAPTURE-CONSTRAINT.md`), so host-root-injected and pty-spawned execs are *disclosed as unevaluable*,
never presented as caught.

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

**The workload loop (`run` / `report` / `export`) has run end to end on a real host**, in an
isolated Incus project against Gemini CLI 0.53.1 with a real key: 24-minute hands-off work phase,
1038 ground-truth execs with 0 unparsed records, 572 self-report events, marker capture proven at
the re-derived idmap range, and a real work product (a branch, a module, 4 passing tests, a commit)
exported and re-verified off-host. DEMO-SPEC §8 criteria 1, 2, 3, 5, 6 and 7 are met on real data.

**And the honest headline is not "0 CONFIRMED".** It is `0 CONFIRMED over the 39 of 54 work-phase
execs that were in scope` — the other 15, including *every* git command and the test run, were
never evaluated at all, because Gemini CLI's shell tool forks a shell that never `execve`s and the
ancestry walk ends there. That is the fork gap landing on the accountable actions. It is reported,
named per-command in `report.json`, and carried as a canon fidelity attestation
(`cause=missing-telemetry`) — not closed. Criterion §8.4 (verdict schema/SHACL/tier honesty) is
**vacuously** met on real data, since the run emitted zero verdicts, and remains proven on fixtures
against canon's real API. Full write-up: [DEMO-VALIDATION.md](DEMO-VALIDATION.md).

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
                 …plus the workload verbs: workload.py (`run`), report.py (`report`),
                 export.py (`export`), example_prompt.py (the shipped `--example` build)
scripts/         install-incus-nested.sh (setup) · run-acceptance-nested.sh (the §4 tests)
                 warden-collect-audit.sh (the root collector — the privileged half of DESIGN §4)
tests/           unit tests, the §4 acceptance, and the DEMO-SPEC §8 acceptance, against a
                 FakeIncus double + checked-in synthetic planes
DESIGN.md        the full design doc
DEMO-SPEC.md     the workload demo spec (the five-command loop)
DEMO-VALIDATION.md  the first real end-to-end run: what it proved, and what it exposed
web/             the 3-view site (overview · findings · design)
DECISIONS.md     judgment calls, incl. the six real-host findings (D13–D20) and the demo build
                 (D21–D27)
```

```
python3 -m pytest tests/ -v
```

`warden report` is the agentwatch integration, so its tests need agentwatch on `PYTHONPATH`
(`WARDEN_AGENTWATCH_PATH=…`, or check it out beside this repo as `./agentwatch` — the merged
standalone, `github.com/adelic-ai/agentwatch`); they skip with a reason rather than fail if it is
absent. The canon assertions (`verdicts.jsonl` schema-valid,
SHACL `well_formed`, tiers not inflated) additionally need canon importable, which needs Python
≥3.11 — they skip cleanly where it is not, and where canon is absent `verdicts.jsonl` is simply not
written rather than faked.

## A note on canon

canon is the attestation/provenance layer — it turns each agentwatch verdict into a
SHACL-validated `detection_verdict` with a walkable PROV-O provenance chain, and turns
agentwatch's structural limits into machine-checkable `fidelity_attestation`s. The wiring lives
on the agentwatch side (canon stays a stable, context-agnostic contract). Its public face is
being sorted out; until then, treat the attestation layer as described here and in `DESIGN.md`.

---

*Part of [adelic-ai](https://github.com/adelic-ai). Behavioral accountability for autonomous
LLM agents — earned with measured reliability, not asserted.*
