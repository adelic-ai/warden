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
