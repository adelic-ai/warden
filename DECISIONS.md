# DECISIONS

Append-only log of non-obvious calls made while building, and what was rejected. Ambiguity
in the spec is resolved here rather than blocking (per operating instructions).

---

## Language/runtime: Python 3, stdlib + pytest only

Rejected: bash (the idmap JSON parsing, dialect-tolerant audit-log parsing, and the
CONNECT-proxy all want real data structures and are painful in bash); Go (no toolchain
readily available in this VM without root to install one, and the spec doesn't call for a
compiled binary). Python 3.12 and pytest are already present in this VM's user
site-packages — zero new install surface, which matters given the no-root constraint
(see `NEEDS-HUMAN.md`). No pip installs beyond what's already here.

## Dependency injection over subprocess mocking

`warden/incus.py` defines an `IncusClient` protocol; `RealIncusClient` shells out to the
`incus` CLI, `tests/fakes.py:FakeIncusClient` is an in-memory model of the same interface.
`WardenApp` (the up/down orchestration) takes a client in its constructor and never imports
`subprocess` or `RealIncusClient` itself. This is what makes it possible to prove the §4
acceptance logic hands-off in an environment with no real Incus: the orchestration code
under test is *identical* between a real run and a fake-backed test — only the adapter
differs.

## FakeIncus models idmap reallocation on restore, not just storage

The spec calls out I6 breaking I5 three times over — idmap silently changing under restore
and blinding auditd. For the regression test to mean anything, `FakeIncusClient` must
actually reallocate `volatile.idmap.current` to a *different* host-uid range on `restore()`
(same as real Incus does), and its simulated audit trail must only record marker execs
tagged with the uid range active *at exec time*. That way, code that reads-and-caches the
idmap before restore instead of re-deriving after would provably fail to find its marker in
the post-restore capture-proof step — the test can actually fail, not just pass by
construction. See `tests/fakes.py`, `tests/test_idmap.py::test_restore_reallocates_and_stale_range_misses_capture`.

## Audit scoping key: uid range, not auid (loginuid)

Considered scoping the persistent audit rule by `auid` (login UID) instead of `uid`.
Rejected: unprivileged Incus/LXC containers have no PAM login session, so `auid` is
typically unset (`-1`/`4294967295`) for everything running inside — it wouldn't distinguish
containers at all. The idmap-derived host-uid range is the only thing that's actually
scoped per-container, so the rule filters `-F uid>=<start> -F uid<=<end>`.

## `security.idmap.isolated=true` on every profile

Not explicitly named in the spec, but it's the actual Incus knob that guarantees distinct,
non-overlapping idmap ranges per instance — which is exactly what §4 test 4 requires
("distinct idmaps"). Without it, Incus is permitted to hand two unprivileged containers the
same shared idmap range, which would make monitored/builder audit scoping ambiguous between
them. Set unconditionally in `profiles.py`, both flavors.

## Egress proxy: CONNECT-hostname allowlist, no SNI sniffing

The spec's phrase is "SNI/CONNECT allowlist". Since the design also says "host-side forward
proxy... no interception, not in-guest" — i.e. an *explicit* proxy the guest is configured to
use, not a transparent intercept — the target hostname is already present in plaintext on
the `CONNECT host:port HTTP/1.1` request line. SNI-sniffing is only needed for a *transparent*
proxy (traffic redirected via nftables without the client's cooperation), which the spec
explicitly rules out ("not in-guest" / "no interception"). So `warden/proxy.py` allowlists on
the CONNECT target, and never terminates or inspects the TLS stream itself (it can't MITM
even if it wanted to — it just relays bytes after the CONNECT handshake). If a transparent
mode is ever wanted, SNI-sniffing would need to be added as a separate egress path; out of
scope for v1 per this reading.

## Provisioning-vs-runtime allowlist as a reloadable file, not a proxy restart

§1 says "swapping the list is not disabling the ACL" — implemented literally: the proxy reads
its allowlist from a file and reloads it before handling each new CONNECT if the file's
content changed, so `warden` can narrow provisioning → runtime by rewriting the file, without
ever stopping enforcement. Deliberately compares raw file *content*, not mtime: a first real
test run showed this VM's filesystem can give two rewrites within the same tick an identical
`st_mtime_ns` (confirmed: two `write_text` calls a few microseconds apart landed on the exact
same nanosecond-resolution timestamp), which would make an mtime-only cache silently miss a
rapid provisioning→runtime narrow. Content comparison costs a small read on each check, which
is fine at this proxy's request volume.

## `warden down` only removes the instance, not the shared substrate

§4 test 3 says "`warden down` removes the instance; the host is unchanged." Read literally:
`down` deletes the one instance (and its snapshots) and leaves the project/profile/bridge/
proxy allowlist alone, even if it was the last instance in the project. A `warden teardown`
for the shared substrate is out of scope for v1 (not asked for, and tearing down a bridge
other instances might still reference is exactly the kind of irreversible host-level action
the operating instructions say to be careful with).

## Operator model: `warden` itself never requires root, only installation does

§1 says the `gembox` restricted-`incus`-group operator is optional — sudo+root works too,
the idmap is what contains, not the operator's privilege level. This falls out of the design
for free rather than needing special-casing: `warden/incus.py`'s `RealIncusClient` just shells
out to `incus` with whatever privileges the invoking user already has. If that user is in the
host's `incus` group, `warden up`/`down`/`restore` need no sudo at all. Only
`scripts/install-incus-nested.sh` (package install, `incus admin init`) and the auditd/nftables
installers (`RealAuditRuleInstaller`, the nft ruleset loader) are root-only, and they're the
one-time/host-level pieces, not per-instance operation.

## No root in this build VM — see `NEEDS-HUMAN.md`

The single largest decision this build made: rather than blocking on root access, built and
proved everything provable without it, and was explicit in `NEEDS-HUMAN.md` about exactly
what's left unproven (the real §4 acceptance run against actual nested Incus, and the pop-os
final validation). Did not attempt to acquire root by guessing credentials or otherwise
routing around the permission boundary — that would be exactly the kind of action the
"security hygiene" section of the operating instructions warns against.

---

# Post-validation: decisions from the first real-Incus run (`fix/real-incus-validation`)

Everything above was proven against `FakeIncusClient` only. The first run against real Incus
7.3 on pop-os produced `VALIDATION-FINDINGS.md`; these are the calls made fixing it. The
recurring theme is the one the build already knew about and still got caught by twice more:
**a check that reports success without having measured the thing it claims to measure.**

## D13 — egress is enforced with Incus network ACLs, not a host nft table

`egress.py` originally only *generated* an nftables ruleset. Nothing loaded it, so egress was
entirely unenforced: `example.com` and the LAN gateway were both reachable from a container
that was supposed to have one path out. The module had a careful ordering assertion about
rules that were never installed anywhere.

Rejected the obvious fix (actually load the generated table) for two reasons:

1. **A host nft table cannot be safely scoped to our bridge.** nftables evaluates every
   table's chain at a hook, so a `policy drop` forward chain in `table inet warden` drops
   packets for *every* bridge on the host — including the unrelated gemini-capsule build
   sharing this machine. Incus ACLs attach to a NIC device and structurally cannot leak.
2. Incus already owns `table inet incus` for bridge filtering. A second table racing it is
   the kind of thing that works until it doesn't.

So the enforcement point is `incus network acl`, attached at the *profile's* NIC device
(fail-safe: anything launched into the project inherits it) plus `security.acls.default.
{in,e}gress.action=drop` on the warden bridge only. `assert_enforceable()` survives as a
pre-push guard, but it now guards a document that is actually applied.

Carried over from the capsule build's measurements on this same host: `drop` never `reject`
(a `reject` hands a scanning workload a clean fast signal, and the capsule found `reject` is
accepted at rule-creation but not enforced on bridges); and specific drops outrank broad
allows, so no drop may cover the bridge gateway or it shadows the proxy/DNS allows and leaves
the container with no egress at all.

The proxy is now started by `warden up` itself rather than being a separate step an operator
must remember — forgetting it is how the first run ended up with a carefully-narrowed
allowlist file that no process was reading.

## D14 — a deleted instance's audit rule shadows the next instance's

`warden down` removed the instance but left `/etc/audit/rules.d/60-warden-<instance>.rules`
behind and the rule loaded. Incus then re-allocated that freed host-uid range to the *next*
instance, whose execs the kernel tagged with the **dead instance's key** — the exit filter
stops at the first matching rule. `ausearch -k <live instance>` found nothing while the
capture looked fine on a uid-only check.

Two fixes, because the crash case matters as much as the clean one: `uninstall()` on `down`,
and `prune()` on `up` for any rule file whose instance no longer exists. And `prove_capture`
now requires the marker to match **key as well as uid range** — matching on uid alone was
what called the shadowed case a pass.

## D15 — load audit rules by key with `auditctl`, never `augenrules --load`

Two independent failures here. `augenrules --load` is a no-op when the compiled ruleset is
byte-identical ("No change" in the first run's log), so a rule present on disk but absent
from the kernel stays that way and nothing notices. And its output begins with `-D`, which
would momentarily wipe **every** audit rule on the host — including the gemini-capsule
build's ground-truth plane, which has nothing to do with warden.

So the file in `rules.d` is still written (reboot persistence), but the live load is surgical:
`auditctl -a` per fragment, `auditctl -d` per fragment by key to unload, and the result is
verified against `auditctl -l` rather than assumed. Same rule applies to operators and to
this repo's tooling: never `auditctl -D`.

## D16 — restore opens `restricted.containers.lowlevel` for exactly one operation

`incus snapshot restore` failed with `Changing "volatile.idmap.base" ... is forbidden`. A
restricted project implies `restricted.containers.lowlevel=block`, and the restore has to
rewrite `volatile.idmap.*` — which is the I6 phenomenon itself, the idmap moving under the
container. The design *requires* restore, so the two cannot simply coexist.

Rejected leaving the permission on: it also permits `raw.lxc`/`raw.idmap`, which can weaken
confinement, and a project-wide standing grant to enable one operation is how a restricted
project stops being restricted. Rejected dropping restore: it is §1's load-bearing
regression path.

So `restore_and_reprove()` sets the key, restores, and unsets it in a `finally` — closed even
when the restore fails. Related: `restricted=true` also blocks snapshot *creation*, so
`project_config()` now sets `restricted.snapshots: allow` (the capsule build recorded the
same finding as its D9). `restricted.storage.pools` is deliberately NOT set — it is not a
valid Incus key; the pool merely has to exist.

## D17 — an audit event's identity is `(timestamp, serial)`, never the serial alone

`parse_events` merged records by the serial from `msg=audit(ts:serial)`, on the assumption
that a serial identifies an event. It does — but only *within a boot*. The kernel's counter
restarts at zero on every boot while `/var/log/audit/audit.log` persists across them.
Measured on the live host: 27 counter resets in the current log and two serials appearing
under timestamps ~28 hours apart.

The consequence is not a missed event, it is a **fabricated** one. Fields are taken from the
first record that carries them, so merging on the serial alone can fuse a genuine marker
`EXECVE` from one boot with a `uid` and `key` from an unrelated record in another — and
`prove_capture` then reports capture proven for a rule that captured nothing. The regression
test constructs exactly that trail; against the old merge it yields a single event with the
expected key, an in-range uid, and the marker. A textbook confident wrong answer, produced by
the one function whose entire job is refusing to give one.

Merging now uses the full `ts:serial` id. `tests/test_auditd.py::
test_parse_does_not_fuse_events_that_reuse_a_serial` fails against the old behaviour.

## D18 — `producer | grep -q` is a false-negative generator under `set -o pipefail`

The last remaining red — `FAIL: ausearch found no marker for warden-cap-mon` — was not a
capture failure at all. The check was:

    if ausearch -k "warden-cap-mon" --raw 2>/dev/null | grep -q 'WARDEN_MARKER_'; then

`grep -q` exits at the *first* match and closes the pipe; the producer then takes SIGPIPE and
the pipeline reports 141. With `set -o pipefail` that is a failure — **caused by the match
being found**. It only bites once the producer outstrips the 64K pipe buffer, which is why it
never showed up against the small fake trails and appeared the moment a real container ran
`apt-get` and generated a few thousand audit records under its key.

Measured directly on this host: `ausearch -k capsule --raw` emits 1.4 MB containing 978
matching records, and the naive pipeline still returns non-zero.

It fails in both directions, and the second is worse: the test-4 check that *passes on
absence* (`no audit rule activity for the builder`) would have reported a real breach as
green. Every such check now buffers the producer's output and matches the buffer — no pipe,
no signal, no ambiguity. The failure path also dumps the loaded rules and record count for
the key, because the first run's output gave no way to tell "the rule captured nothing" from
"the rule was never loaded".

Worth stating plainly, since it cuts against the acceptance suite's own purpose: for one
whole validation cycle this harness reported a working audit plane as broken, and the fix was
in the harness, not the plane.

## D19 — the image has no `git`, and a failing `incus exec` was never checked

Test 2's "no `/root/repo/.git` after clone" had nothing to do with egress (which reached
GitHub fine). `images:debian/12` is minimal and ships no `git`; the clone exec returned rc
127 and **nothing looked at the result**. Every provisioning command now goes through
`_exec_ok`, which raises `ProvisioningError` with the rc and stderr, and the clone is proven
afterwards with an explicit `test -d /root/repo/.git` rather than trusting the exit code of a
compound command. `_provision` installs `git` and `ca-certificates` first.

This also forced plain-HTTP support in the proxy: Debian's apt repositories are `http://`,
so a CONNECT-only proxy cannot provision a container at all. Absolute-form HTTP requests are
allowlisted on the same hostname as CONNECT, so one list governs both, and the https path is
still never intercepted.

## D21 — every `incus` invocation is bounded, and a hang raises rather than returns

Found while re-running the acceptance suite for reproducibility: an `incus launch` client sat
for 25 minutes while the daemon had **already created and started the instance**. The client
simply never stopped waiting for its response. Nothing in `warden up` could notice, because a
subprocess with no timeout has no failure mode — only an absence of progress. The environment
was healthy throughout; the same launch worked before and after.

Two calls here worth stating.

**The bounds are per-operation, not global.** A metadata read that takes a minute is broken; an
`apt-get install` through the allowlist proxy legitimately takes several. A single bound would
have to be sized for the slowest operation, which leaves the fast ones effectively unbounded —
the exact hang this is meant to catch. So: 60s for metadata, 600s for lifecycle, 900s for
launch (image download), 1800s for in-guest exec. Deliberately generous: this is a
stuck-forever backstop, not a latency SLO, and failing a slow-but-working run is the more
expensive mistake.

**A timeout raises; it never returns a non-zero result.** The existence checks
(`project_exists` and friends) read `.returncode`, so a returned timeout would quietly become
"doesn't exist" and send warden off to recreate something that already exists. That is this
build's recurring failure shape yet again, and it would have been introduced *by the fix for
it*. `IncusTimeoutError` subclasses `IncusCommandError` so every existing handler — `warden
up`'s error path, `_wait_ready`'s retry loop — treats a hang as the failure it is, with no new
call sites.

The error message is careful about what it claims. Killing the `incus` client does **not**
cancel the operation on the daemon — the run that motivated this bound had the instance
created, started and running while its client hung. So a timeout means "we stopped waiting",
not "it did not happen", and the message says to re-run to converge rather than assuming
otherwise. `up` is idempotent and re-derives rather than caching, so that re-run is safe.

Related: `_wait_ready`'s readiness probe now passes its own short bound. Inheriting the exec
default would let one `/bin/true` block for half an hour and make the function's 60s deadline
decorative — a bound that a caller can outlive is not a bound.

## D20 — `warden up` self-provisions its storage pool

`up` already self-provisioned the bridge but assumed `wardenpool` existed, so it failed with
"Storage pool not found" on any host where `install-incus-nested.sh` had not run. It now
creates-or-verifies the pool (btrfs), with a `--pool` flag for operators who want their own.
Consistent with the bridge: the substrate `up` depends on is either verified or created, not
assumed.

## D21 — the default bridge subnet was Tailscale-hostile (100.89.0.1/24 → 172.29.0.1/24)

**Finding, reported by the operator before the first `warden up` of the demo build.** The pinned
bridge subnet `100.89.0.1/24` sits inside `100.64.0.0/10` — RFC 6598 CG-NAT, which is the range
**Tailscale allocates every node from** and routes as a whole. A managed Incus bridge with a `/24`
inside it is the more specific route, so it wins: every tailnet peer addressed in `100.89.x`
becomes unreachable from this host, and an operator driving warden *over* the tailnet can lose the
connection they are driving it over.

The original reasoning is in the old comment, and it is worth keeping visible because it was
careful and still wrong: CG-NAT was chosen precisely *because* it is "unlikely to be in use on a
host's LAN, unlike 10.0.0.0/8 or 192.168.0.0/16". That is true and irrelevant. The check considered
the physical LAN and not the overlay networks a host also routes — and an overlay is exactly the
thing that claims a range no LAN uses.

**Nothing in warden could have noticed.** The bridge comes up, the ACL applies, the containers get
egress, every test passes. The damage is entirely off-box, on a plane warden does not observe.
Measured on the pop-os validation host at the time of the report: `tailscale0` at `100.120.63.5/32`,
and `100.89.0.0/24 dev wardenbr0 ... linkdown` already installed in the main routing table — latent
only because no instance had carrier yet.

Three parts to the fix, because the first alone would have been decorative:

1. **The constant** is now `172.29.0.1/24` — RFC 1918, clear of CG-NAT and of Incus's own
   `incusbr0` (10.234.56.0/24 on this host).
2. **`profiles.assert_subnet_sane`** raises on any bridge subnet inside `100.64.0.0/10`. A comment
   would not have prevented this; the previous value was chosen *by* reasoning about ranges. It is
   deliberately narrow — it names the one range that is by convention always someone else's, and
   does not attempt to enumerate every overlay a host might run.
3. **`ensure_substrate` converges the bridge**, the same way it already converges project config. A
   bridge created by an older warden keeps the address it was created with, so changing the
   constant would have left every already-provisioned host — including this one — still hijacking
   the tailnet while the code claimed to be fixed.

### The carve-out this forced, and the guard that caught it

Moving out of CG-NAT put the bridge *inside* `172.16.0.0/12`, which is one of the LAN drops. On
this Incus, specific drops outrank broad allows (capsule T8), so the drop would have shadowed the
`/32` allows for the proxy and resolver and left the container with **no egress at all**.
`egress.assert_enforceable` refused the document immediately — the guard written for a footgun this
build had already hit caught a *different* instance of it, introduced by an unrelated change. That
is the argument for structural guards over comments, made without anyone having to make it.

`egress.lan_drops` now subtracts the bridge network from whichever private range contains it, via
exact `address_exclude` rather than dropping the containing `/12` wholesale — dropping RFC 1918 is
the point of the rule, and discarding ~1M addresses to make one `/24` reachable would trade a
broken container for a quiet hole. Output is sorted so the ACL document is byte-stable and
`ensure_substrate` does not rewrite it on every run.

Note the prior comment "the bridge's own subnet is deliberately absent [from LAN_DROPS]" was true
*by accident*: CG-NAT is not an RFC 1918 range, so nothing had to enforce it. It is enforced now.

Also fixed in passing: `RealIncusClient.network_set` used the space-separated `<key> <value>` form,
which Incus 7.x deprecates with a warning. Harmless until now; `ensure_substrate` calls it on every
`up` as of this change, so it was made the supported `<key>=<value>` form.

## D22 — `--audit` on `builder` is a flavor-table boolean, not a third flavor

DEMO-SPEC §11.1. Reconciliation needs both planes; `builder` — the flavor that has a repo and a git
history worth reconciling against — shipped `auditd_wired=False`, so `warden report` would have had
a self-report plane and nothing to check it against.

Kept as one boolean on the existing table rather than a `builder-audited` flavor or a branch in
`app.py`, because that is what the data-driven flavor model is *for*: `app.py` already reads
`cfg.spec.auditd_wired` and does the right thing. The test asserts the negative too — every other
field of the spec is unchanged by the toggle — so this stays a config change rather than quietly
becoming a second codepath.

`restore` takes the flag as well. A restore reallocates the idmap, and an audited builder restored
without it would skip the re-derive-and-re-prove and leave the ground-truth plane filtering a dead
range while `auditctl -l` still looked correct — §1's I6-breaks-I5 gotcha, which is the whole reason
`restore` is a warden verb instead of an `incus` invocation.

On `monitored` the flag is a no-op rather than an error: asking for audit on something already
audited is a reasonable thing to say.

## D23 — `warden run`: the phase boundary is drawn before the work window, not inside it

DEMO-SPEC §3/§11.2. Three judgment calls, all of which would have been invisible if made the other
way.

**Installing the agent CLI is provisioning, so it happens before `started_at`.** §1 splits `run`
into provisioning (clone, install, env prep — actions that often have no authorizing tool call and
are *expected*) and work (the accountable phase). The agent CLI is not installed by `up` at all:
`_provision` installs git and ca-certificates and nothing else, and `deb.nodesource.com` sits in
the builder's *provisioning* allowlist and deliberately not in its runtime one. So `run` installs
it, widening to the provisioning allowlist and narrowing back **before** the agent runs — the same
D13 discipline `up` follows, and the narrow-back is in a `finally` so a failed install cannot leave
the wide list active. Had installation landed inside the work window, several hundred `npm`/`dpkg`
execs that no tool call authorizes would flood the accountable phase, and the demo would be
presenting reconciliation noise as reconciliation.

**The secret never enters an argv, on either side.** `incus exec --env K=V` puts the value in the
*host's* `incus` argv (visible to `ps`); building `sh -c "K=$KEY …"` on the host puts it in the
guest's. So the key is pushed into the instance as bytes — read, never decoded, never formatted
into a message — and dereferenced *inside* the guest by a `$(cat …)` that is literal text in every
argv that exists. auditd captures syscall arguments and not environments, so the key is absent from
the ground-truth plane **by construction rather than by redaction**. `resolve_llm_auth` returns a
description of where the secret came from, and the description is what the manifest records. The
test asserts the material appears in no argv and in no manifest.

Same reasoning applies to the **prompt**, for a different failure: it is pushed as a file and read
with `"$(cat …)"` rather than interpolated, so a prompt containing a quote cannot rewrite the shell
command. That is a bug class warden should not have.

**The manifest records the derived idmap; it is not a source for it.** The range is derived at run
time so the record of the run is complete, and `report` derives it *again* rather than reading it
back. §1's never-freeze-the-idmap rule has already been violated three times by exactly this shape
— a plausible-looking cache — and a manifest is the most plausible one yet.

Smaller calls: a non-zero *agent* exit is recorded, not raised — an agent that failed at its task
still produced a transcript and a trace, and that run is still reportable. A wall-clock cap is
recorded as `timed_out` rather than swallowed, because a capped run's trace is truncated and a
reader has to know that before drawing conclusions from what is missing. `WORKDIR` is `/root/work`,
not `up --repo`'s `/root/repo`, so a run with no `--repo` still has a git history to export and a
run with one keeps the two separate.

`RUN_MANIFEST_SCHEMA_VERSION` is checked on load and refuses a version it does not speak, per
§10's "keep the outputs schema-stable and versioned — they are the eventual input to the cohort and
calibration layers".

## D24 — `warden report`: what warden contributes, and the three places it refuses

DEMO-SPEC §4/§11.3. This is glue, and keeping it glue is a decision: every reconciliation call is
agentwatch's (`run_once`, the reconcilers, `canon_emit`), every custody call is canon's. warden
contributes only the four things agentwatch cannot know — which uid to scope to, proof the plane is
live, where the phase boundary is, and the privilege split.

### It refuses rather than reporting something plausible, in three places

**No ground-truth plane** — an instance created without `--audit` has a self-report plane and
nothing to check it against. Reporting over that would be "trusting the thing you're supposed to be
watching", which is DESIGN §0's opening line as a failure mode.

**Capture not proven** — a marker exec must be captured under *this instance's own key* before the
plane is trusted at all. `auditctl -l` proves a rule is loaded text, not that it matches; D14 had a
deleted instance's rule with an overlapping uid range tagging a live instance's execs under the
dead key, and uid-only matching called that a pass.

**Idmap reallocated between `run` and `report`** — a restore moves the range. The run's records
carry the OLD host uids and the live rule watches the new ones, so *neither* value reconciles that
run: the new range matches none of the run's records and reads as a beautifully clean run, and the
old range is the frozen value §1 exists about. There is no third option that is honest, so it
stops. §8.7's "re-derived, not frozen" is satisfied by deriving here and comparing, not by picking.

### The phase split has three windows, not two

§1 asks for provisioning vs. work. There is a third, and leaving it out would have quietly
inflated the accountable one: `after_run` holds warden's **own** capture-proof marker exec, which
`report` runs at report time. The observer's footprint must not be counted inside the window it is
observing.

Related, and initially wrong in the design: provisioning noise does not stay out of the work phase
because of the phase split. It stays out because `RuntimeScope` excludes anything outside the
agent's session subtree — `apt-get`/`npm` are not descendants of the agent runtime, so they are
never evaluated. The phase split's real job is to make that *visible*: `not_evaluated` is reported
**per phase**, because "47 unevaluated execs, all in the provisioning window" and "47 unevaluated
execs in the work window" mean opposite things, and one number cannot distinguish them.

### The one duplication is a cross-check

`run_once` must own `findings.jsonl`/`verdicts.jsonl` or their schema drifts from agentwatch's
(§10). But it returns only *newly written* findings, and the summary needs the whole candidate
population including the ones that were correctly silent. So the candidate pass runs here too, over
the same two files. Rather than accept that as duplication, `Summary.consistent` asserts the two
agree and the CLI exits non-zero if they do not — a disagreement means one pass is wrong, and the
report says so instead of printing a confident number.

### `findings.jsonl` is touched; `verdicts.jsonl` is not

A clean run writes no findings, and `FindingsStore` only creates the file on append — so a
genuinely clean reconciliation and a report that never ran are byte-identical on disk (both: no
file). An empty file says "I looked and found nothing". `verdicts.jsonl` is deliberately *not*
touched when canon is unavailable, because an empty verdicts file would imply the canon projection
ran and produced none — a different claim from "canon was not importable here", which is what
`verdicts_unavailable_reason` says instead.

### The honesty bar is data in the artifact, not prose in a README

`report.json` carries `calibrated: false`, `analysis_engine: false`,
`recall_validated_for: "shell-out only"`, `guarantee_tier_max: "well_formed"` and
`calibration_field: "absent"` as fields. A README nobody exports is not a caveat; a field in the
file that travels with the data is. The verdict kinds are separate fields with no total that fuses
them, and the test asserts the *keys* — no `deviation`, `risk_score`, `severity_total` anywhere.

### The collector refuses a non-`warden-*` key

It runs as root via a sudo rule, so a caller that could choose an arbitrary key could read any
audit stream on the host — a wider grant than the privilege split intends. It only ever reads, and
never `auditctl -D`: a co-located capsule build has its own rule here.

## D25 — `warden export`: the archive says what it is missing, and labels the git history a claim

DEMO-SPEC §5/§11.4. `export` is deliberately dumb — it collects and never summarises, because §7's
"no analysis engine" means the consumer analyses. Two things it does that a plain `tar` would not:

**`CONTENTS.json` lists every artifact §5 asks for, present or not, with a reason.** An archive
silently lacking `verdicts.jsonl` is indistinguishable from one where the reconciliation found
nothing to verdict, and those are opposite claims. Same for the built repo: "the agent never
created one" is a fact *about the run*, so it is recorded rather than raised — a traceback there
would also have cost the reader the audit capture and the findings, which are the parts that
matter most.

**`README.txt` labels the git history as claimed, not verified.** §5 says it outright: git history
is agent-controlled — the agent picks what to `git add` and what the message says — so it is the
*claimed* work product, reconcilable against FILE_WRITE ground truth (a v2 axis, §10) and not
trustworthy alone. That sentence ships inside the archive, along with which plane is forgeable and
which is not, and the three limits from §7. A caveat that lives in a README on the producer's
machine is not a caveat; one that travels with the data is.

The archive name is derived from the run's own clock, so two exports of one run produce one path
rather than a pile of near-identical tarballs. Members are rooted in a single directory — an
archive that explodes into the reader's cwd is a hostile artifact.

## D26 — `warden up --secret-file` passed its own pre-check and then failed inside `up`

Found by writing the §8 acceptance loop, which is the first thing to drive `up` and `run` in
sequence with a secret file and no `GEMINI_API_KEY` in the environment.

`cli._up` called `resolve_llm_auth(llm, secret_file=args.secret_file)` as a fail-fast pre-check —
correctly — and then `app.up(cfg)` called `resolve_llm_auth(cfg.llm)` again with **no secret_file**,
because the flag lived only on the argparse namespace. On any host that had not also exported
`GEMINI_API_KEY`, that second call raised `NeedsHumanError` *after* the pre-check had passed. The
flag was, in practice, only useful to people who did not need it.

Two things made this survive review. The pre-check reads like the check, so the second call looks
redundant rather than differently-parameterised. And every existing test that exercises `up` with
gemini either sets the environment variable or uses claude (whose `resolve_llm_auth` takes neither
path). Nothing was wrong with the second call existing — `app.up` should not trust its caller to
have validated — it was wrong that it could not see what the caller had validated *with*.

Fixed by carrying `secret_file` on `WardenConfig`: the path, never the material, and `repr` of a
config is safe to log. Both calls now check the same thing.

## D27 — §8 acceptance, and exactly which half is modelled

`tests/test_demo_acceptance.py` walks DEMO-SPEC §8's seven criteria against `FakeIncusClient` plus
the checked-in synthetic planes — the same arrangement `test_acceptance.py` uses for the wizard's
§4, for the same reason (no real host in the loop here).

The file says in its docstring which half is not proven, and the loop marks the substitution
inline rather than letting the fake quietly manufacture it:

  * that Gemini CLI driven with `--skip-trust -p` runs hands-off to completion and writes the
    telemetry file the adapter expects — **unproven**, needs a real host and a key;
  * that a real auditd rule captures that run's execs at the derived range — **unproven**, same.

Everything else is proven here, and one thing is proven *for real* rather than modelled: §8.4. The
verdicts warden actually writes are validated against canon's own
`detection_verdict.schema.json`, their provenance cids are resolved back to PROV-O roots and
SHACL-validated against `well_formed` + the detection shapes, and the tiers/calibration gate is
asserted over the emitted contracts. That check runs against the real canon API or it skips; it is
never simulated.

The example prompt gets an assertion of its own (§6/§7): the shipped text must contain a real build
(`git init`, `unittest`, `commit`) and must NOT contain the words that would indicate a staged
gotcha (`&`, `nohup`, `background`, `curl`, `wget`, `fork`). A later "improvement" that plants a
fork gap so the demo can catch it now fails a test, which is the only durable way to hold §7's line
on a file that looks harmless to edit.

The loop runs in project `wardendemo`, never `warden`, and asserts the `warden` project stays
empty — a demo must not share a project with a co-located capsule build.

## D28 — per-invocation `sudo -n`, not `sudo warden`

Driving the real end-to-end run surfaced that the real adapters shell out to `incus` and
`auditctl` unelevated. On the validation host the operator is in `sudo` but not in `incus`, so
`incus` cannot reach the daemon socket and `auditctl` refuses outright. DEMO-SPEC §9 already asked
for "scoped sudo if run hands-off (incus/auditctl/ausearch/nft)"; this is that.

**Per-invocation, not per-process.** `sudo warden up` would have been one line, and it is the wrong
shape: running the whole wizard as root moves `Path.home()` to `/root`, so the allowlist file, the
run directory and every exported artifact silently relocate — and the *monitor*, which holds
prompt-bearing data and is most of the code, ends up with exactly the privilege DESIGN §4's split
exists to keep it away from. So the process stays unprivileged and only the individual
root-requiring invocations are elevated (`warden/privilege.py`). `sudo -n` never prompts: a
hands-off run that blocks on a password is a hang with no output, which reads like a broken plane.

### Two things this broke, both caught

**The missing-binary message.** With `sudo -n incus …` the process that launches is `sudo`, which
exists — so a missing `incus` came back as sudo's own rc=1 "command not found" instead of a
`FileNotFoundError`, and the clear "Incus isn't installed here, see install-incus-nested.sh"
message was silently replaced by an opaque exit code. `shutil.which` is now checked *before* the
prefix goes on. A pre-existing test caught this; it is the kind of regression that would otherwise
only surface on someone else's fresh box.

**The rules.d write.** `/etc/audit/rules.d` is root-owned and writing it is *not* in a scoped
`incus/auditctl/ausearch/nft` grant. Widening the grant (a `tee`/`rm` rule, or a second privileged
script that writes arbitrary paths) buys only reboot-persistence, at the cost of a much broader
privilege than the read-only collector. So persistence is **best-effort and reported**:
`persistence_installed` records whether the file was written, `warden up` says so on stderr when it
was not, and the live `auditctl` rule — the half that actually captures — is unaffected. Failing a
working ground-truth plane over a property the demo does not use would be the wrong trade; claiming
it silently would be worse.

### `prune` now reads the loaded rules, and that is a fix, not a workaround

It scanned `rules.d` for stale instances. Where persistence is skipped there are no files, so it
would have found nothing — but the *loaded* rules are still there, and a dead instance's loaded
rule with an overlapping uid range is precisely the D14 shadowing hazard (the kernel's exit filter
stops at the first match, tagging a live instance's execs under the dead key). It now derives stale
instances from `auditctl -l` and adds the directory scan when readable. That is strictly better
than the file-only version on *any* host: a rule loaded with no file — after a crash, on any
machine — was previously invisible to it.

The key-prefix filter is unchanged and tested: `prune` only ever considers `warden-*` keys, so a
co-located capsule's rule is never a candidate.
