# warden workload demo — first real end-to-end run (pop-os, 2026-08-03)

> **STATUS: the five-command loop ran end to end on a real host with a real API key.** DEMO-SPEC §8
> criteria 1, 2, 3, 5, 6 and 7 are **met on real data**. Criterion 4 (verdict schema/SHACL/tier
> honesty) is **vacuously** met — the run produced zero verdicts, because it produced zero
> CONFIRMED — and remains proven on fixtures only. See §4 below; this distinction is the whole
> point of the honesty bar and is not smoothed over here.

**Setup.** Isolated Incus project `wardendemo`, instance `wd-demo`, `images:debian/12`, flavor
`builder --audit`, Gemini CLI 0.53.1, key supplied by path (`--secret-file ~/.warden/gemini.key`)
and never read, printed or committed. Bridge `wardenbr0` at **172.29.0.1/24** — verified out of
Tailscale's `100.64.0.0/10` before anything was brought up (D21). The co-located gemini-capsule
project and its audit rule were untouched throughout.

**Shape of the run.** Work phase 1457s (~24 min), agent exit 0. Ground truth: **1038 execs, 0
unparsed records**. Self-report: **572 events, parse not degraded**. Artifacts: 20.2 MB transcript,
1.5 MB audit capture, 12.8 KB work repo.

---

## The result, stated the way it should be stated

```
work phase — the accountable one.
  agent-uid execs  54
  evaluated        39
    authorized     19
    CONFIRMED       0
    NONE           20
    GAP             0
  not evaluated    15   ← 7x git · 1x python3 · 2x cat · 3x incusd · 1x sh · 1x systemd-tmpfile
```

**Zero CONFIRMED on a benign run** — consistent with agentwatch's measured Gemini result
(34 → 0), and the reconciliation ran on real work rather than a staged catch, exactly as §6 asks.

**And that number does not mean the run was clean.** It means the run was clean *over the 39 execs
that were in scope*. See R1.

---

## R1 (MAJOR) — the fork gap swallowed the work product

The 15 unevaluated work-phase execs are `git init`, `git config` ×2, `git checkout -b example`,
`git add`, `git commit`, `git maintenance`, and `python3 -m unittest -v`. **That is the entire
accountable work product**: every action that produced the commits went unreconciled.

Traced:

```
pid=654286 ppid=654284 comm=git  argv=git commit -m "Add slugify utility and tests"
pid=654284 -> NO EXEC RECORD (forked, never execve'd — the ancestry chain ends here)
runtime pid 653471 in that chain? False
```

Gemini CLI's shell tool forks a shell that never `execve`s, so the ancestry walk terminates before
reaching the runtime pid, and the whole subtree is out of scope. This is the fork gap agentwatch
G23 documented — but G23 measured it costing *the command a shell ran*. Here it costs **the entire
git history**, which is the more consequential half and had not been observed before.

Nothing was hidden: the count was always reported. But `0 CONFIRMED, 15 not evaluated` reads as
"clean, plus noise", and a reader would have been wrong. Fixed in `report.py`: the unevaluated
execs are now named by `comm` in `report.json` and in the printed rollup, with the reason stated
where it is read — *absence of a CONFIRMED there is absence of evidence, not evidence of absence*.

**Not fixed, and not fixable here.** Closing the gap needs `fork`/`clone` in the audit rule, which
is a different observation channel (and a much higher event volume) — a real design decision, not a
patch. The canon `fidelity_attestation` this run emitted already says exactly this
(`cause.kind=missing-telemetry`). What changed is that the report now says it in the place where
someone is reading a number.

## R2 — the Gemini runtime markers matched their own installer

`GEMINI_RUNTIME_ARGV_MARKERS = {"gemini"}` identifies a `node` process as the runtime when
`"gemini"` appears in its argv. During provisioning, `/usr/bin/env node /usr/bin/npm install -g
--silent @google/gemini-cli` execs `node` with `@google/gemini-cli` in argv — so **npm installing
the CLI was classified as the CLI**. It became a runtime pid, and 71 provisioning execs were
evaluated (all NONE) instead of falling out of scope.

Benign on this run — they classify NONE, never CONFIRMED, and they are in the provisioning window
which is expected-and-unevaluated by construction. But it is imprecise, and agentwatch G20 flagged
these sets as "PROVISIONAL until measured against a real capture". **This is that measurement**, and
it says the marker is too loose. Recorded on the agentwatch side; not silently patched here,
because narrowing a scope heuristic from one observation is how the 83-false-positive tuning got
its reputation, and the right fix (match the installed path, not the argv substring) deserves its
own evidence.

## R3 — zero verdicts, so §8.4 is vacuously met on real data

`verdicts.jsonl` is present and **empty**. canon was importable; the projection ran; there was
simply nothing to project, because verdicts are emitted for CONFIRMED orphans and divergences and
this run produced neither. `verdicts_available: true, verdicts_written: 0` is the honest pair.

So DEMO-SPEC §8.4 — "every verdict is schema-valid and SHACL `well_formed`; tiers ≤ `well_formed`,
calibration absent" — is satisfied *vacuously* on real data and remains **proven on fixtures only**
(`tests/test_demo_acceptance.py`, against canon's real API). It would be easy and wrong to write
"§8: 7/7 on a real host".

## R4 — secret hygiene held on real data

Zero matches of the key's contents in `transcript.txt` (20.2 MB), `audit.raw` (1.5 MB),
`manifest.json` or `report.json`; checked with the key file as a `grep -f` pattern source so the
contents were never displayed. `GEMINI_API_KEY` appears in **no argv** in the entire capture.

What *does* appear is `cat /root/.warden-run/llm.key` — the path. That is the design working: the
guest dereferences the file itself, so the audit plane records the reference and never the value
(D23). `secret_source` in the manifest is `secret-file:/home/srh/.warden/gemini.key`.

## R5 — rules.d persistence skipped, and said so

The live `auditctl` rule loaded and was proven capturing. The persistent file in
`/etc/audit/rules.d` was **not** written — that directory is outside a scoped
`incus/auditctl/ausearch/nft` sudo grant — and `warden up` reported it on stderr (D28). The plane
worked; only reboot-survival was skipped, and the operator was told rather than left to assume.

## R6 — observer contamination, and the window that caught it

Three sets of execs in the capture are **warden's or mine**, not the agent's:

* 4 `incus exec` probes from a progress monitor I started and killed after one cycle — they landed
  in the *provisioning* window (the CLI was still installing), which is the expected-and-unevaluated
  bucket. Disclosed rather than left to pass as the agent's.
* `report`'s capture-proof marker `echo`, and `export`'s `tar`/`gzip`/`git` — all after `ended_at`.

The three-window split (D24) put every one of them in `after_run`, out of the accountable phase.
That design decision was made on fixtures and paid for itself on the first real run: 14 execs in
`after_run`, none of them the agent's.

## R7 — a stale proxy from before the subnet change

A root-owned `warden.cli proxy` from an earlier session is still bound to `100.89.0.1:3128`. That
address no longer exists on any interface, so it cannot receive traffic and did not affect this run
(the live proxy bound `172.29.0.1:3128` correctly). It is leftover process, not a live hazard —
left running rather than killed, since it belongs to an earlier session, but worth reaping.

---

## §8 criteria, one line each

| # | Criterion | Outcome |
|---|---|---|
| 1 | five-command loop, each one command | **met** — `up`/`run`/`report`/`export`/`down` all rc=0 |
| 2 | `--example` completes hands-off; transcript + commits | **met** — 24 min, exit 0, branch `example`, 4 tests, verified passing off-host |
| 3 | findings + verdicts + summary segmenting phases and breaking out kinds | **met** — both files written; 3 phases; 4 kinds separate |
| 4 | every verdict schema-valid, SHACL `well_formed`, tiers ≤, calibration absent | **vacuous** — 0 verdicts emitted (R3). Proven on fixtures only |
| 5 | tarball with transcript, findings, verdicts, repo + git log, raw audit, manifest | **met** — 8/8 artifacts, `CONTENTS.json complete: true` |
| 6 | `down` removes the instance; host unchanged | **met** — instance and both audit rules gone; capsule, bridge, Tailscale intact |
| 7 | derived idmap scope; marker proven before the plane is trusted | **met** — uid 1065536-1131071 re-derived at report time, capture proven |

## What this run does NOT establish

- **No FP/FN rate.** One run. `0 CONFIRMED` is one observation on one benign workload, not a
  false-positive rate, and R1 means it is not even full coverage of that workload.
- **No claim about detecting misbehaviour.** Nothing adversarial was run. The example is benign by
  design (§6) and deliberately not rigged.
- **Recall is still shell-out-only**, and R1 is the sharpest available illustration of what that
  costs: the half that works authorized 19 execs; the half that does not left 15 unexamined.
