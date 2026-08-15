# Vantage — automating the container-in-VM shape (Shape B)

**What this is:** the plan for turning the container-in-VM topology — proven once, by hand, as
`warden-mon` on pop-os — into something `warden dev` does itself. Distinct from `REFACTOR.md` (the
repo-boundary seam) and `CANONICAL-SHAPE.md` (the evidence-model invariant): this is about *where
warden runs*, not what it captures once it's running.

## Why this exists

`warden report --live --ebpf` (decision B, `REFACTOR.md`) needs its probe loaded on a kernel *above*
the container — that's the entire mechanism the fork-gap fix relies on (`DECISIONS.md` D29's
neighbor entries, `CAPTURE-CONSTRAINT.md`). On the bare-host topology, "above the container" is
pop-os's own kernel: an eBPF probe there sees every process on that machine, not just the monitored
workload, and the privilege to load it has to be granted on production infrastructure. Putting the
container inside a VM shrinks the vantage kernel down to only what that VM hosts, and confines the
privilege grant to something disposable.

That's the architecture. It was validated manually — `warden-mon` stands, right now, on pop-os. What
doesn't exist is a way to get there without a human running nine SSH commands by hand. This document
is that gap.

## Reference: what Shape A (manual) actually did

Reconstructed from the session transcript that built it, parsed through `agentwatch`'s own
`ClaudeCodeAdapter` — not inferred from `warden-mon`'s end state, which turned out to be an
unreliable source on its own (see the D29 note below). Every step below is a real, timestamped tool
call, not a guess:

1. **Launch the VM.** `incus launch images:debian/12 warden-mon --vm --project default -c
   limits.memory=3GiB -c limits.cpu=2 -d root,size=30GiB -s wardenpool`, then poll for the guest
   agent (up to ~120s), then confirm kernel/OS/IP.
2. **Egress sanity check** inside the VM — `apt-get update` + resolve `pkgs.zabbly.com`/
   `deb.debian.org` — before trusting the installer to run unattended.
3. **Stage and run `install-incus-nested.sh`** — scp the script to gembox, `incus file push` it into
   the VM, install `curl`/`ca-certificates`, run it. **First attempt failed** on the btrfs pool bug
   (D29) — Incus ≥7.x rejected the manual `source:` image path.
4. **Patch and re-run.** The pool fix was made locally on the Mac's warden checkout (never
   committed at the time — this is the exact uncommitted diff this session found and landed as
   D29), then the fixed script was re-pushed and re-run. This is the one step worth internalizing:
   **the only thing that made Shape A work was a fix that lived nowhere but a working tree.** Shape
   B must ship the fix, not rediscover it — trivially true now that D29 is on `main`, but it's the
   reason this reference build could not be trusted by reading `warden-mon`'s files alone.
5. **Dependency check** inside the VM: `python3`/`git`/`bpftrace` — `bpftrace` confirmed absent.
   Still absent today.
6. **Bundle and deploy code.** `git bundle create` for warden (`speed/warden-half-b`, not `main`)
   and agentwatch (`main`), scp both to gembox, `incus file push` into the VM, install `git` inside
   the VM, clone both as siblings under `/root`. Same bundle-then-clone mechanism
   `PART-B-POPOS-RUNBOOK.md` §1 already documents for staging repos onto gembox's home directory on
   pop-os — this reuses it one level deeper (onto the VM via `incus file push`, not plain `scp`), not
   a new pattern.
7. **Re-clone and verify.** `git init -b main && git pull <bundle> speed/warden-half-b` (which is
   why the VM's local branch is named `main` but its content is `speed/warden-half-b`'s), then push
   and run a small ad hoc script confirming agentwatch imports and the runtime-detection fix is
   present — the only step in this whole build that verified anything rather than just running and
   hoping. Checked into the repo as `scripts/verify-vantage-vm.py` (formalized from what was pushed
   from a scratchpad and never committed at the time).
8. **Create the nested container.** A 2GB swapfile as a memory backstop, then, run *inside the VM*
   with no code changes at all: `python3 -m warden.cli dev --llm claude --no-shell --mem 2GiB --cpu
   2`. This is the load-bearing fact for Shape B's design: **the container-creation step needs zero
   new warden code.** `up()`/`dev`'s existing idmap/egress/auditd logic already worked, unmodified,
   the moment it was run one level up.

**What Shape A does not yet prove:** the actual payoff. No `findings.jsonl`/`verdicts.jsonl`/capture
artifacts exist anywhere on the VM — the eBPF live-reconcile has never been rerun at this topology,
blocked concretely on step 5's `bpftrace` gap. Closing that is a small, separate task (install
bpftrace, rerun `warden report --live --ebpf` against the nested `warden-dev`, confirm CONFIRMED via
cgroup rescue) — real work, but decoupled from everything below, and doable against `warden-mon`
directly without waiting on any of this automation.

## Design goals for Shape B

- **One command.** `warden dev` does the whole thing — VM, nested Incus, nested container, you land
  in a shell. No separate provisioning step to remember.
- **Bare-host stays, explicit opt-out.** `--local`/`--no-vm` keeps today's working behavior (this is
  already-shipped code, not new work) for cases that don't need VM isolation. The report/summary must
  say plainly when this mode is active that the fork-gap closure the VM vantage exists for isn't in
  effect — same honesty-bar rule the project applies everywhere else.
- **Mold once, launch fast.** Step 1–5 above (OS + Incus + `admin init`) get baked into a published
  Incus image (`incus publish` a stopped, fully-provisioned VM) so every subsequent launch is
  `incus launch <golden-alias>` — seconds, zero `apt`. Rebuilt only on an Incus-version bump or a
  `install-incus-nested.sh` change, not per-session.
- **Code stays fresh, every launch.** warden + agentwatch (steps 6–7) do **not** go in the golden
  image. They're under active development; baking them in reproduces exactly the class of bug D29
  fixed — a golden copy silently drifting from the real one. Deploy fresh every time instead; it's
  cheap (a git bundle + clone, already proven fast in Shape A).
- **Files travel with you.** Push your working directory in before you land in the shell (or land in
  an empty one, starting fresh); pull results back out. Neither exists today — `up --repo` only
  git-clones from a URL, `export` only pulls everything at teardown.
- **Privilege stays where it already is.** No change to `warden/privilege.py` or the trust model —
  the VM absorbs the eBPF privilege grant that would otherwise have to sit on pop-os itself. (An
  earlier attempt at this — SSH-wrapping just the bpftrace capture from `report.py`, so warden kept
  running on the base host and reached over per-command — was built, then reverted: it assumed
  warden's operating home stays on the base host, which is backwards. Noted here so nobody rebuilds
  it by the same reasoning.)

## Build order

Each phase is independently testable; nothing later depends on golden-image tooling existing before
phase 1 does.

**Precondition, not a phase:** every `incus launch`/`incus exec`/`incus file push` call below runs as
`sudo -n incus ...` via `gembox`, which only works because of the scoped sudoers grant
`PART-B-POPOS-RUNBOOK.md` §2 (R2/R3) already establishes — `NOPASSWD` for
`incus`/`auditctl`/`ausearch`/`nft`, deliberately *not* `bpftrace`. Phase 1 assumes that grant exists;
it is not something this plan sets up or re-derives.

1. **Persistent vantage-VM lifecycle — landed, validated on pop-os.** `warden/vantage.py`,
   `ensure_vantage_vm()`. A create-if-absent counterpart to `build_vm.py`'s create-and-destroy-per-
   build primitive — same VM-instance shape (`images:debian/12` today, `<golden-alias>` once phase 2
   exists), but the vantage VM survives across invocations like the `dev` home it hosts does.
   `_wait_ready` is the first-boot poll from the failure-handling section below, not `recover.py`.
   4 tests against `FakeIncusClient` (`tests/test_vantage.py`). Real-host run: first call created a
   genuine `VIRTUAL-MACHINE` instance in 47.9s (within the 120s bound), second call was a 0.1s
   no-op. **One real bug the fake couldn't catch:** the module originally defaulted to the `default`
   project, matching Shape A's manual command — but `ensure_build_vm_substrate` restricts a
   project's allowed networks, and `default` is shared with unrelated tenants (`cta-dev-vm`). Incus
   refused the restriction, but the convergence loop had already set 2–4 keys on `default` before
   failing on the conflicting one each time, leaving it partially modified twice (reverted by hand
   both times, verified clean after). Fixed by defaulting to the dedicated `warden` project instead
   (same one `build_vm.py`'s own builds already use). The underlying atomicity gap —
   `ensure_build_vm_substrate` has no rollback on a mid-loop failure — is still there; noted, not
   fixed, since the actual fix here was not triggering the conflict at all.
2. **The mold — landed and validated for real.** `warden/mold.py`, `build_vantage_mold()`. Egress
   check, apt prereqs (`curl`/`ca-certificates`/`git`), push + run `install-incus-nested.sh`, an
   inline dependency check, `stop` + `publish` to a local image alias, tear down. 5 tests against
   `FakeIncusClient`, **plus a real published image on pop-os**: `warden-vantage-golden`,
   fingerprint `4801d10909d6`, 1264.87 MiB, published 2026-08-14 14:02 EDT — confirmed via
   `incus image list`, not inferred. The build instance was gone afterward, which only happens on
   `mold.py`'s success path (`client.delete` runs only after `publish` succeeds).

   **This took five real-host attempts, and the first four failures were genuinely informative, not
   noise.** All four died at the identical step — `apt-get install incus incus-client btrfs-progs`
   stalling in `dpkg --unpack` (`D` state, near-zero CPU) — and two real bugs got found and fixed
   along the way, independent of the eventual timeout fix: (1) the mold originally never wired the
   guest through warden's own proxy or populated its allowlist — `apt` got "Network is unreachable"
   outright (`set_proxy_env` + `MOLD_ALLOWLIST = DEBIAN_SETUP + pkgs.zabbly.com`); (2) the egress
   check's `sh -c "apt-get update | tail -3"` masked apt-get's real exit code with tail's — fixed to
   `bash -c "set -o pipefail; ..."`. Neither fake test could have caught either; `FakeIncusClient`'s
   substring-matching `exec()` can't model proxy routing or shell pipe semantics.

   **The actual fifth-attempt fix was recognizing the 600s timeout was unrealistic, not that
   something was broken.** `pop-os` turned out to be an active desktop (two logged-in users, GNOME,
   several Chrome instances) under real contention, not a dedicated build host — a fresh, empty
   storage pool made no difference (ruled out `wardenpool` fragmentation specifically), and host
   disk showed zero IOs in progress while the guest sat blocked (ruled out raw disk saturation).
   `INSTALL_TIMEOUT` went 600s → 1800s, `PREREQ_INSTALL_TIMEOUT` 120s → 300s, and the fifth attempt
   — after also logging out the second user and closing the first user's browser to further reduce
   contention — completed and published cleanly. Worth remembering: the timeout bump alone might
   have been sufficient even without the user/process cleanup; both changed at once, so which one
   was load-bearing isn't fully isolated.

   **Correction from the original plan, still true:** this does *not* use `scripts/verify-vantage-vm.py`
   — that checks warden/agentwatch imports, which the mold deliberately never has deployed. Stays
   scoped to phase 4.
3. **Fast launch — landed and validated for real.** `ensure_vantage_vm()` checks
   `image_exists(GOLDEN_ALIAS)` before launch and uses it automatically when present — no
   caller-supplied flag, every call benefits the moment a mold exists. `VantageInfo` gained an
   `image` field so callers can see which source was actually used. Real-host run on pop-os: fresh
   launch from the golden alias in 115.0s (almost entirely VM boot/guest-agent time — the same cold
   boot cost phase 1 always had, not new), confirmed `image='warden-vantage-golden'`, and confirmed
   `incus version` (client + server, both 7.3) and `git` already present with **zero apt calls** —
   the actual point of molding, working as designed. 2 tests against `FakeIncusClient`.
4. **Code deploy — landed and validated for real.** `warden/deploy.py`, `deploy_code()`. Bundles the
   CURRENT HEAD of both repos (not a pinned branch, unlike Shape A's manual build), pushes, clones
   as `/root/warden` + `/root/agentwatch`, then pushes and runs `scripts/verify-vantage-vm.py` and
   raises `DeployError` on anything but all-green. **Found and fixed a real bug in the verify script
   itself while wiring this up:** it added `/root/agentwatch` to `sys.path` but never
   `/root/warden`, so the "warden importable" check would have failed every single time regardless
   of correctness — never exercised for real until now, since the script this was recovered from
   (Shape A's) only ever checked agentwatch. Real-host run on pop-os: `ensure_vantage_vm()` reused
   the golden alias, then `deploy_code()` completed in 8.5s — `warden@f1b2573` +
   `agentwatch@12a689d`, and a direct re-run of `verify-vantage-vm.py` confirmed all four checks
   green, including the one just fixed. 5 tests (real `git bundle` against this repo + the sibling
   agentwatch checkout, Incus-side wiring against `FakeIncusClient`).
5. **Remote-drive container creation — landed and validated for real.** `warden/remote_dev.py`,
   `create_nested_dev()`. Invokes step 8's `warden dev`-equivalent over `incus exec` from the base
   host. Container-side code needed zero changes, as expected — but getting *to* the container
   surfaced the deepest real-host finding of this whole plan: `warden/proxy.py`'s `AllowlistProxy`
   had no concept of an upstream proxy, so a proxy running inside the vantage VM (serving the
   container it creates) tried direct connections to every target, which the outer bridge's
   default-drop ACL blocked — confirmed empirically at 522s before a 502, not a fast refusal.
   Fixed with real proxy chaining (`_dial()`, a shared CONNECT-tunnel-through-upstream helper;
   `_handle_plain` relays absolute-form to the upstream instead of rewriting to origin-form),
   threaded through `run_forever`/`ensure_running`/`RealProxyAllowlistController`, a new
   `warden proxy --upstream-proxy` flag, and `profiles.UPSTREAM_PROXY_ENV_VAR`
   (`WARDEN_UPSTREAM_PROXY`) — unset by default, every non-nested caller unaffected. A second,
   smaller fix followed once chaining actually worked: the outer proxy's allowlist needs the
   *container's* provisioning hosts too, not just the VM's own image-fetch host — fixed by reusing
   `flavors.resolve(Flavor.DEV, llm).provisioning_allowlist` rather than a second hand-maintained
   list. 4 tests in `test_remote_dev.py`, plus 3 new tests in `test_proxy.py` that stand up two
   *real* chained `AllowlistProxy` instances and prove real TLS to `github.com` and real HTTP to
   `deb.debian.org` both relay correctly through two hops.

   Real-host run: `warden-dev` created inside the vantage VM's own nested Incus, snapshot taken
   (`up()`'s own clean-snapshot step, proof of a genuinely completed provisioning, not a partial
   one), verified against the nested Incus directly. The first attempt hit `DEV_TIMEOUT` (300s) —
   but `up()` had actually completed on its own past that client-side bound; a re-run converged in
   16.8s (idempotent), confirming success rather than assuming it from a timeout's own honest
   uncertainty.
6. **File transfer — landed and validated for real.** `warden/transfer.py`, `push_path()`/
   `pull_path()`. Tar locally, stage through the VM's own filesystem via `file_push`/`file_pull`
   (proven binary-safe already, `build_vm.py`'s artifact collection), then onto/off the container
   via `incus exec <vantage> -- incus file push/pull` (file-to-file, not through captured
   stdout — `exec()`'s stdout capture is not proven binary-safe and nothing here should be the
   first thing to find that out). 5 tests against `FakeIncusClient` plus real local tar/untar.
   Real-host run: pushed a directory with a nested subdirectory from the base host into the actual
   `warden-dev` container, verified byte-for-byte *inside* the container via a direct `incus exec`
   check (not just trusting the push succeeded), then pulled it back to the base host and confirmed
   an exact match — a genuine round trip, not just one direction.
7. **Double-hop shell entry.** Replace `dev`'s single `incus exec` with base-host → VM → container.

Phase 8, decoupled: install `bpftrace` on a vantage VM and close the P5 eBPF validation loop. Can
happen against `warden-mon` today, independent of phases 1–7.

**Known gap surfaced late: `build_vantage_mold()` can't rebuild incrementally.** It always launches
fresh from the stock `IMAGE`, never from the current golden alias — so adding one missing prereq
(`auditd`, discovered when phase 5 actually exercised `up()`'s audit-pruning path — install-incus-
nested.sh installs Incus but nothing else `up()` needs) meant redoing the entire ~25-minute Incus
install + `admin init` cycle for a change that's a few seconds of actual work. The cheap fix — launch
from `GOLDEN_ALIAS` when it already exists, install just the new thing, republish — isn't built.
Worth adding before the next prereq gets discovered the same way.

## Failure handling — reuse what warden already has, don't reinvent it per layer

`warden/recover.py` and `warden/workload.py` already solved two of this plan's four new failure
modes; the point of this section is pinning each one to the specific existing mechanism it must
build on, so phases 1 and 5 don't grow bespoke, parallel versions of logic that already exists.

- **VM boot — two different problems, not one.** `recover.py`'s L2 diagnosis ("hung instance") is
  `incus exec <instance> -- /bin/true` failing to answer within `LIVENESS_PROBE_TIMEOUT` (15s), with
  `incus restart --force` as the fix. That's safe for a container, which answers `exec` almost
  immediately once `incus launch` returns. It is **not** safe applied to a freshly-launched VM: a VM
  doesn't answer `exec` until its guest agent finishes booting, which Shape A's own transcript shows
  taking up to ~120s cold. Routing initial launch through `diagnose_and_recover` unmodified would
  misdiagnose a VM mid-first-boot as wedged within 15 seconds and force-restart it — interrupting a
  normal boot, not recovering a stuck one. So: **first boot keeps Shape A's own patient
  guest-agent poll** (bounded, no restart action, run once right after `incus launch` succeeds), and
  only *after* the VM has come up once does `recover.py`'s L1/L2/L3 apply — unmodified, exactly as
  it already does for containers — to diagnosing it going unresponsive later.
- **The nested daemon.** Not new extension work — `IncusClient` is already a `Protocol`
  (`warden/incus.py`), with `RealIncusClient` as one concrete transport (shell out to local `incus`,
  through `elevate()`) and `FakeIncusClient` as another (the test double). A wedged nested daemon
  needs a *third* transport, not a new diagnosis engine: a thin `RealIncusClient` variant whose
  `_run` routes the same argv through `incus exec <vm> --project <p> -- incus ...` instead of
  running it locally. Handed to the unmodified `diagnose_and_recover`, all three tiers work against
  the nested daemon exactly as written — this is the Protocol boundary doing the job it exists for.
- **The unattended mold run.** Nothing bounds `install-incus-nested.sh` today; a human watched it in
  Shape A. Reuse the wall-clock-cap pattern already established for exactly this shape of problem —
  `ebpf_capture.capture_argv`'s `timeout(1)`-wrapping of an unattended external process — rather
  than inventing a second one.
- **`warden dev`'s silent furnish.** Flagged by a peer session, not discovered here: the furnish step
  is silent for minutes by design (the progress log isn't wired to the CLI's stdout), which reads as
  hung but isn't — tolerable only because a human knows to wait. `workload.py` already has the right
  shape for this exact problem: `run`'s `--timeout`/`DEFAULT_WALL_CLOCK_SECONDS`, where hitting the
  cap is recorded as *truncated*, never silently swallowed as failure. Furnish should get the same
  treatment — a wall-clock cap plus a truncated-not-failed result — instead of new progress-logging
  machinery invented from scratch. Must land before phase 5, since an automated caller can't apply
  the human judgment call that made silence tolerable in Shape A.

## Open questions to settle while building, not before

- **VM lifecycle vs. `dev` home lifecycle.** Does `warden down` tear down the vantage VM, or only the
  nested container (VM persists like a golden environment across sessions)? Leaning toward the
  latter — matches "mold once" — but not decided.
- **One shared vantage VM vs. one per dev home.** `warden-mon` is a proof of one. Whether multiple
  concurrent `dev` homes share a vantage VM (multiple nested containers) or each gets its own is
  still open, and affects the golden-image reuse story.
- **Naming collisions.** Shape A already produced one real instance of this — a bare-host `warden-dev`
  and a nested `warden-dev` coexisting under the same name, distinguished only by which Incus daemon
  you're asking. Worth deciding a naming convention before phase 5 ships, not after.

## Testing

Phases 1, 4, 6, 7 are orchestration over subprocess/`incus` calls and can follow the existing
`FakeIncusClient` convention the container path already uses — nothing here needs a real host to
unit-test the wiring. Phase 2 (the mold) and phase 8 (bpftrace) cannot be faked in any way that means
anything; they need pop-os, the same as every other "validated on a real Incus host" claim in this
repo's status sections. State that plainly wherever this lands in README/DECISIONS — a mocked mold
test proves the orchestration calls happen in the right order, not that the VM actually boots.

`scripts/verify-vantage-vm.py` is the one piece of real, on-VM verification in phases 2 and 4 — it
runs where there's no test runner, only whatever actually got deployed, and exits non-zero on failure
so those phases can treat it as pass/fail rather than printed text a human has to read. It is not a
substitute for the `FakeIncusClient` unit tests above; it's the thing that would have caught D29's
staged-script-vs-checked-out-repo divergence automatically, had it been checked in and run as part of
the deploy step instead of ad hoc by hand.
