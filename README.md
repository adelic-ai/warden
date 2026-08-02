# warden-wizard

`warden up --flavor <monitored|builder> …` stands up a sandboxed LLM-agent container on an
Incus host. One codepath, two flavors — see `/tmp/WIZARD-SPEC.md` (source spec) for the design.

## Status

Built hands-off per the spec's §5 (Lima + nested Incus). **This particular VM has no root
path available to the build agent** (no sudo, no docker/pkexec, not in the `sudo` group) —
see `NEEDS-HUMAN.md`. That blocks actually installing Incus and running the real §4
acceptance tests here. What's in this repo instead:

- The full `warden` implementation (idmap derivation, profiles, egress/proxy, auditd wiring,
  CLI) — written against a real `incus` CLI wrapper (`warden/incus.py`).
- A `FakeIncus` test double (`tests/fakes.py`) that models the parts of Incus's behavior the
  logic depends on (idmap (re)allocation on launch/restore, snapshots, exec, an in-memory
  audit trail keyed by host-mapped uid). The §4 acceptance scenarios are encoded as tests
  against this fake in `tests/test_acceptance.py` — they prove the *logic*, not the real
  substrate.
- `warden/proxy.py`'s CONNECT-allowlist proxy is tested for real (`tests/test_proxy.py`) —
  it's just a userspace TCP listener on a high port, no root needed, so that one gotcha is
  proven against live network egress, not a fake.
- `scripts/install-incus-nested.sh` and `scripts/run-acceptance-nested.sh` — written and
  ready to run *with root*, either by a human in this VM or by a future session that has
  one. That's the missing last mile; see `NEEDS-HUMAN.md`.

## Layout

```
warden/
  idmap.py        derive-on-load + re-derive-on-restore (§1's load-bearing gotcha)
  profiles.py      restricted project/profile config (§1 Incus-config gotchas)
  egress.py        nftables default-drop bridge ACL generator
  proxy.py         host-side CONNECT allowlist proxy (no in-guest interception)
  auditd.py        persistent rule + dialect-tolerant/raw reader + marker-capture proof
  flavors.py       the monitored/builder table (§2), one codepath
  config.py        CLI-input -> resolved WardenConfig, LLM auth checks (§3)
  incus.py         IncusClient protocol + subprocess-backed RealIncusClient
  standing_rules.py  drops GEMINI.md/CLAUDE.md into the agent workdir (§3)
  app.py           WardenApp — up/down orchestration, flavor-agnostic
  cli.py           argparse entrypoint
scripts/
  install-incus-nested.sh   §5 setup: zabbly repo, incus admin init (btrfs pool + pinned bridge)
  run-acceptance-nested.sh  §4 acceptance tests against a *real* nested Incus
tests/
  fakes.py            FakeIncusClient + FakeAuditReader
  test_*.py           unit tests per module
  test_acceptance.py  §4 test 1-4 against the fakes
```

## Running

```
python3 -m warden.cli up --flavor monitored --host local --llm gemini --project warden
python3 -m warden.cli up --flavor builder   --host local --llm claude --project warden
python3 -m warden.cli down <instance-name>
```

Requires a real `incus` on PATH and root for the auditd/nftables install steps (see
`scripts/install-incus-nested.sh`). Without those, `up` fails fast with a clear error
rather than pretending to succeed.

## Tests

```
python3 -m pytest tests/ -v
```

No external dependencies beyond `pytest` (already present in this VM's user site-packages).
