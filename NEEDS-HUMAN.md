# NEEDS-HUMAN

Append-only. Each entry: what, why it needs a human, what was done meanwhile.

---

## 2026-08-02 — No root path in this VM; Incus cannot be installed or run here

**What:** The spec's §5 assumes the build agent can `apt install incus` (zabbly repo) and run
`incus admin init` (throwaway btrfs pool + bridge) in this Lima VM. The `agent` user in this
VM has **no path to root**: not in the `sudo` group (`groups` → `agent` only), no NOPASSWD
sudoers entry (`sudo -n true` and even `sudo -l` demand a password neither I nor any
env/config here has), no `su` (auth failure), no `pkexec`, `docker`, or `podman`. `apt-get
update` fails on `/var/lib/apt/lists/lock` (root-owned). This is a full stop on installing
Incus, running `incus admin init`, writing `/etc/audit/rules.d/*`, or loading nftables rules
— every privileged step in §1/§4/§5.

**Why it needs a human:** installing packages and creating system network/storage state is
inherently privileged; there is no unprivileged workaround (Incus's daemon has no rootless
mode). Someone with sudo on this VM (or the actual pop-os host) needs to either (a) add
`agent` to `sudo` with a usable auth path, or (b) run `scripts/install-incus-nested.sh`
themselves, or (c) hand this repo to a session that already has root.

**What I did meanwhile:** built the full `warden` implementation and proved every piece of
logic that *doesn't* require root against a `FakeIncus` test double (idmap derive-on-restore,
marker-capture proof, profile/project config rendering, egress ACL rendering, auditd rule
generation + dialect-tolerant/raw parsing) — see `tests/`. The one component that needs no
root at all — the host-side CONNECT-allowlist proxy (`warden/proxy.py`) — is tested for real,
live, against actual network egress (`tests/test_proxy.py`), not faked. Wrote
`scripts/install-incus-nested.sh` (zabbly repo + `incus admin init` with a pinned-subnet
bridge + throwaway btrfs pool) and `scripts/run-acceptance-nested.sh` (the real §4 tests
against actual nested Incus) ready to run the moment root is available. **Did not** attempt
to guess/brute-force a sudo password or otherwise route around the permission boundary.

**Remaining before this is actually validated:** run `scripts/install-incus-nested.sh` as
root in this VM (or an equivalent Incus host), then `scripts/run-acceptance-nested.sh`, which
runs the real §4 test 1-4 against real containers. Until that runs, everything in this repo
is logic proven against a model of Incus's behavior, not the real substrate.

---

## 2026-08-02 — `GEMINI_API_KEY` (per spec §3)

The `gemini` LLM flavor needs a real API key injected as a container secret. Never
committed; `warden up --llm gemini` stops before a real run without one (see
`config.py:resolve_llm_auth`). A human needs to supply `GEMINI_API_KEY` (env var or a
`--secret-file` path) when actually running a `gemini`-backed instance.

---

## 2026-08-02 — Final pop-os validation (per spec §5)

Per spec, one pass of the §4 acceptance tests against the real pop-os host is a human step
even once nested-Incus testing works in Lima, since some auditd/kernel specifics may differ.
Not attempted here — no access to that host from this VM.

---

## 2026-08-03 — The workload demo's one real end-to-end run is pending `~/.warden/gemini.key`

**What:** DEMO-SPEC §8's acceptance is the five-command loop (`up → run → report → export →
down`) on a real host, in the isolated Incus project `wardendemo`, driven with
`warden run --example --secret-file ~/.warden/gemini.key`. That file **does not exist** on this
host, and `GEMINI_API_KEY` is not in the environment.

**Why it needs a human:** a real Gemini API key is exactly the class of secret `resolve_llm_auth`
refuses to proceed without and that warden must never conjure, guess, or commit. `warden up` and
`warden run` both stop with `NEEDS-HUMAN:` rather than launching a gemini instance without one —
that refusal is the designed behaviour, not a blocker to route around, and it was not routed
around.

**Status, stated exactly:** **logic validated on fixtures; one real run pending the key.**

**What IS validated, and how**

* The whole five-verb loop, against `FakeIncusClient` + checked-in synthetic planes:
  `tests/test_demo_acceptance.py` walks all seven §8 criteria. 152 tests green.
* §8.4 for real, not modelled: the `verdicts.jsonl` warden actually writes is validated against
  canon's own `detection_verdict.schema.json`, each verdict's provenance cid is resolved back to
  its PROV-O root and SHACL-validated against `well_formed` + the detection shapes, and the
  tier/calibration gate is asserted over the emitted contracts. canon is not importable under the
  host's Python 3.10 (it needs ≥3.11); the check ran under a 3.12 venv with the canon workspace
  installed editable, and skips cleanly where canon is absent.
* **The privileged half of DESIGN §4's split, on this real host.** `scripts/warden-collect-audit.sh`
  was exercised via `sudo -n` against a real, by-key auditd rule (`warden-collectorprobe`, scoped
  to a single uid): the marker exec was captured, the collector wrote a 10,943-byte
  operator-readable capture in the raw-epoch dialect, and agentwatch's `audit_log.parse_lines`
  read it with **0 skipped records**. Its refusals were exercised too — a non-`warden-*` key is
  rejected (rc=3), a no-match key produces an empty capture and rc=0 (an empty plane and an
  unreadable one must not look alike). The probe rule was removed **by key**; `auditctl -l` shows
  only the co-located capsule's rule, untouched. `auditctl -D` was never run.

**What is NOT validated, stated plainly**

1. That Gemini CLI, driven `--skip-trust -p "$(cat …)"` hands-off, runs to completion and writes
   the OTel telemetry file the adapter expects at the configured `outfile`. The adapter was
   measured against a real capture (agentwatch G6/G23); *warden's own driving of it* has never
   run.
2. That a real auditd rule captures that run's execs at the container's derived idmap range, and
   that `prove_capture` passes against them.
3. Any number in a report over a real run. The fixture numbers (4 authorized / 1 CONFIRMED /
   3 NONE) are properties of the fixture, not measurements of Gemini CLI.

**To finish it** (needs the key and ~15 minutes on this host):

```
printf '%s' "$GEMINI_KEY" > ~/.warden/gemini.key && chmod 600 ~/.warden/gemini.key
warden up     --flavor builder --llm gemini --audit --project wardendemo \
              --name wd-demo --secret-file ~/.warden/gemini.key
warden run    --example --llm gemini --project wardendemo --instance wd-demo \
              --secret-file ~/.warden/gemini.key
warden report --llm gemini --project wardendemo --instance wd-demo
warden export ./out --llm gemini --project wardendemo --instance wd-demo
warden down   wd-demo --project wardendemo
```

`report` needs the collector's sudo rule. Nothing above touches the `warden` project or the
capsule's audit rule.
