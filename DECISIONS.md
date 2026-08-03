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

## D20 — `warden up` self-provisions its storage pool

`up` already self-provisioned the bridge but assumed `wardenpool` existed, so it failed with
"Storage pool not found" on any host where `install-incus-nested.sh` had not run. It now
creates-or-verifies the pool (btrfs), with a `--pool` flag for operators who want their own.
Consistent with the bridge: the substrate `up` depends on is either verified or created, not
assumed.
