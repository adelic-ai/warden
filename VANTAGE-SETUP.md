# Vantage setup — the container-in-VM shape, on your own host

This is the setup guide for `warden dev --vantage` / `warden report --live --vantage` — the
container-in-VM shape (decision B, `REFACTOR.md`, `VANTAGE-PLAN.md`). If you just want the
ordinary sandboxed workload loop (`warden up`/`run`/`report`/`down`, no nesting), you don't need any
of this — see the Quickstart in `README.md`, which runs on any plain rooted VM.

**Why this exists, briefly:** `warden report --live --ebpf` needs its probe loaded on a kernel
*above* the container. On a bare host, "above the container" is your host's own kernel — an eBPF
probe there can see every process on the machine, not just the sandboxed workload. Putting the
container inside a disposable VM shrinks that kernel down to only what the VM hosts. Everything
below is what it takes to stand that up.

## 1. Hardware: you need *real* nested virtualization, not just any VM

This is the one requirement that's genuinely different from the direct path. `warden up`/`dev`
(no `--vantage`) runs fine on any rootful Linux VM — Linode, DigitalOcean, standard Hetzner Cloud,
standard EC2 all work, because it never launches a VM itself. `--vantage` does: it launches a real
KVM-backed VM from the *base* host, and most VPS providers don't expose that to their own tenants
(their hypervisor doesn't pass `vmx`/`svm` through). Checked directly against several providers —
**Linode, DigitalOcean, and standard Hetzner Cloud do not support this**; Linode's own staff have
confirmed it outright, DigitalOcean's own docs call it unsupported.

What does work:
- **Your own physical machine**, or a **bare-metal** rental (Hetzner's dedicated/AX line, OVH bare
  metal, etc.) — no hypervisor above you at all, so nested virt isn't a feature you enable, it's
  just what a real kernel on real hardware does.
- **Google Compute Engine**, with `--enable-nested-virtualization` on a Haswell+ platform — officially
  documented, works on ordinary (non-bare-metal) instances.
- **Azure**, Dv3/Ev3-series or later — similarly documented.

Verify before doing anything else:
```
grep -Eo 'vmx|svm' /proc/cpuinfo   # must print something
ls /dev/kvm                        # must exist
```
If both are empty/missing, stop here — nothing below will work on this host.

## 2. Incus on the base host itself

Your base host needs its own working Incus install *before* any of this — same requirement the
direct-path Quickstart already has. Run:
```
scripts/install-incus-nested.sh
```
This is the same script `mold.py` runs unattended *inside* the vantage VM — running it yourself on
the base host does the identical thing (apt + zabbly repo + `incus admin init` with a pinned-subnet
bridge and a throwaway btrfs pool). Needs root once, for this one step.

## 3. The scoped sudoers grant

warden self-elevates individual root-requiring tools (`sudo -n`, never runs itself as root —
`privilege.py`, DEMO-SPEC §9). Write `/etc/sudoers.d/warden`:

```
sudo visudo -f /etc/sudoers.d/warden
```
```
Cmnd_Alias WARDEN = /usr/bin/incus, /sbin/auditctl, /usr/sbin/auditctl, \
                    /usr/bin/ausearch, /usr/sbin/nft, \
                    /path/to/your/warden/checkout/scripts/warden-collect-audit.sh
<your-user> ALL=(root) NOPASSWD: WARDEN
```
Confirm the real binary paths with `command -v incus auditctl ausearch nft` first — they vary by
distro. Must be `NOPASSWD`: warden's `sudo -n` never prompts, so a password-gated entry just fails
closed instead of hanging.

**`bpftrace` deliberately is NOT in this grant, and doesn't need to be.** Unlike the auditd/nft
tools above (which the *base host* process calls directly), `bpftrace` for decision B's eBPF plane
runs *inside the vantage VM*, invoked over `incus exec` — and `incus exec` into a VM's guest drops
you in as that guest's own root already. `privilege.elevation_prefix()` skips `sudo` entirely when
already root, so there's no sudoers boundary to cross there at all. (An earlier design assumed
`bpftrace` would run under a restricted account needing its own scoped grant — `NEEDS-HUMAN.md`'s
2026-08-13 entry — that concern predates the container-in-VM shape and doesn't apply to it.)

## 4. Clone warden + agentwatch as siblings

Same as the direct path — see `README.md`'s Quickstart. `deploy_code` (the step that pushes fresh
code onto the vantage VM on every launch) discovers agentwatch via `WARDEN_AGENTWATCH_PATH` or a
sibling `../agentwatch` checkout, same discovery order as `report.py` uses everywhere else.

## 5. Build the golden image — once

```
python3 -m warden.cli vantage-mold --vantage-project warden
```
This is the expensive, one-time step: launches a throwaway VM, installs Incus + `bpftrace` +
`auditd`/`git`/`curl`/`ca-certificates`, runs `incus admin init`, verifies everything (including
actually attaching a real bpftrace probe, not just checking `--version`), publishes it as
`warden-vantage-golden`, tears the throwaway instance down. Real-host timing on the reference
machine: **~30 minutes**, ~1GB published image. Expect similar; this is not a fast operation and
isn't meant to be — everything *after* this is fast specifically because this step exists.

Known rough edge: this can't rebuild incrementally. It always builds from scratch, even to add one
package — budget the full ~30 minutes for any future rebuild, not just the first one. If
`warden-vantage-golden` already exists (a previous mold run, or a rebuild), `incus publish` will
refuse to reassign the alias — delete the old alias (`incus image alias delete
warden-vantage-golden`, never the image bytes, until the new one is proven) before retrying.

## 6. Stand up your dev home

```
python3 -m warden.cli dev --vantage --llm claude
```
First call: ensures the vantage VM (launches from the golden image if absent, ~1-2 minutes),
deploys fresh warden + agentwatch onto it, drives its own nested Incus to create your persistent
`warden-dev` container, then hands you an interactive shell inside it. Reprovisioning the container
itself (installing `git`/the LLM CLI) is the slowest part of a *first* run — budget several minutes,
not seconds; every call after that is fast (idempotent reuse).

`--no-shell` for scripted/unattended use. `warden dev` (no `--vantage`) is a completely separate,
simpler home — direct on the base host, no nesting; the two are not interchangeable state.

**`--no-agentwatch`** skips deploying agentwatch onto the VM — see §7 below for exactly what you
get and don't get by doing this. `warden report --live --vantage` against a home built this way
refuses immediately, before even attempting to reconcile, until you redeploy without the flag.

## 7. What the image gives you, independent of agentwatch (or any reconciler at all)

**This describes what `mold.py`'s current `PREREQ_PACKAGES` bakes in by default, not a fixed
property of "the image" as a concept.** The golden image only ever contains what you build into it
— add or drop a package there and this section changes with it. If you customize the mold, this is
your prompt to also update this doc, not a promise warden is making on your behalf.

The golden image's job (as currently built) is producing an unforgeable capture plane; reading and
reconciling it is a separate concern (`report.py`'s own principle: *"warden produces and exports;
consumers analyse"*). This section is for anyone who wants the raw ground truth without agentwatch
— either to bring their own tooling, or just to understand what's actually there by default.

**The auditd plane — fully warden's own, reusable by anything.** `warden/auditd.py` installs and
prunes a rule keyed `warden-<instance>`, scoped to the container's *derived* unprivileged host uid
range (`derive_idmap()` — re-derived fresh every time, never trusted from a cached value; an idmap
reallocation, e.g. from a restore, changes this). The raw record format is the standard
`auditctl`/`ausearch` audit log — `ausearch -k warden-<instance>` (as root, or via
`scripts/warden-collect-audit.sh`, the same scoped root collector `report` itself uses) gets you the
same records `report --live --vantage` reconciles, with no agentwatch involved at all.

**The eBPF plane — the *capability* is warden's; the *probe* is not.** `bpftrace` is installed and
runnable as the vantage VM's own root (`incus exec <vantage> -- bpftrace ...`, no sudoers grant
needed — see §3). That's the raw capability: a kernel with BTF, a working bpftrace, invocable
without prompting. The actual probe *program* — what it traces, how it identifies which processes
belong to which agent session (cgroup-based scoping) — is agentwatch's own code
(`agentwatch/groundtruth/ebpf_capture.py`), not baked into the image or into warden. Bringing your
own reconciler for this plane means bringing your own bpftrace program too; warden hands you the
privilege and the container identity (`agent_uid`, the instance), not a ready-made script.

**cgroups — not warden's doing at all.** `cgroup2` with the standard controllers is just what a
modern Linux kernel has by default; nothing in the mold specifically adds it. It's there because
the base Debian image has it, same as it would be anywhere else.

One precision worth being clear about: this is "bring your own tooling that reads the same raw
planes," not "plug your own reconciler into `warden report`." The `report` command itself calls
agentwatch's `run_once` directly — there's no pluggable interface to swap it out. A different
reconciler means separate tooling, run separately, reading `ausearch -k warden-<instance>` and/or
your own bpftrace capture yourself.

## 8. Reconcile (with agentwatch)

```
python3 -m warden.cli report --live --vantage --llm claude          # auditd plane
python3 -m warden.cli report --live --vantage --llm claude --ebpf   # decision B's kernel-level plane
```
Both remote-drive the ordinary `report --live` command *inside* the vantage VM (the plane being
reconciled is a property of that VM's own kernel, not the base host's — there's nothing to read from
the base host's side at all) and pull the resulting artifacts back to this host. Both require
agentwatch actually deployed (§6) — `report` needs it on every path, direct or vantage, auditd or
eBPF; there is no agentwatch-free mode of `report` itself, only of standing the home up.

## Sanity checklist before you file a bug

- `incus version` inside the vantage VM answers, and shows a *nested* daemon, not the base host's.
- `mount | grep cgroup2` inside the vantage VM shows the unified hierarchy with the standard
  controllers (`cpuset cpu io memory hugetlb pids rdma misc`).
- `bpftrace -e 'BEGIN { exit(); }'` inside the vantage VM prints `Attaching 1 probe...` and exits
  clean, with no sudo prompt.
- `systemctl is-active auditd` inside the vantage VM says `active`, and `auditctl -s` shows a real
  pid, not just the package being present.

If any of those fail on a freshly-molded image, the mold build itself is suspect — re-run it before
debugging anything downstream.
