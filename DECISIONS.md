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
its allowlist from a file and reloads it on `SIGHUP` (or before each new connection if the
file's mtime changed), so `warden` can narrow provisioning → runtime by rewriting the file and
signaling, without ever stopping enforcement.

## `warden down` only removes the instance, not the shared substrate

§4 test 3 says "`warden down` removes the instance; the host is unchanged." Read literally:
`down` deletes the one instance (and its snapshots) and leaves the project/profile/bridge/
proxy allowlist alone, even if it was the last instance in the project. A `warden teardown`
for the shared substrate is out of scope for v1 (not asked for, and tearing down a bridge
other instances might still reference is exactly the kind of irreversible host-level action
the operating instructions say to be careful with).

## No root in this build VM — see `NEEDS-HUMAN.md`

The single largest decision this build made: rather than blocking on root access, built and
proved everything provable without it, and was explicit in `NEEDS-HUMAN.md` about exactly
what's left unproven (the real §4 acceptance run against actual nested Incus, and the pop-os
final validation). Did not attempt to acquire root by guessing credentials or otherwise
routing around the permission boundary — that would be exactly the kind of action the
"security hygiene" section of the operating instructions warns against.
