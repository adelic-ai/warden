# Part B — end-to-end fork-gap reproduction on pop-os (real Incus + Gemini)

The payoff run: prove that a **real Gemini build's git work product**, which the fork gap left
"not evaluated" (DEMO-VALIDATION R1), now **scopes in** with the clone rule + the reconciler's
clone-bridge. Part A already proved the parser reads real clone records; Part B proves the whole
loop on the substrate warden is built for.

**Root model for this run:** warden stays **unprivileged**; only specific host tools are elevated
(`privilege.py`, DEMO-SPEC §9). Root appears in exactly the steps marked **🔒 ROOT** below — you
run each one yourself when the runbook asks. Everything else runs as **gembox**, non-root. Legend:

- **🔒 ROOT** — you run this (srh via sudo); approve it manually.
- **📦 gembox** — unprivileged, on pop-os, as gembox.
- **💻 Mac** — staging, from your Mac.

---

## 0. Preconditions (from the last recon — verify, don't assume)

- Incus **7.3** installed ✓ (root install step already behind you).
- gembox uid 1002, **not** in the `incus` group yet.
- btrfs storage pool: **UNKNOWN** — must be verified/created (🔒 R1). `up` fails fast without one.
- warden wizard: **not on the box** (torn down) — stage it (§1).
- agentwatch on pop-os (`/home/srh/dev/agentwatch`) is **STALE / pre-fork-gap-fix**. Part B MUST
  use the fixed line — the `speed/agentwatch-demo-integration` branch from the Mac (§1). Using the
  stale copy would leave the git subtree orphaned and fail the test for the wrong reason.
- A **Gemini API key** file on the box (the agent is Gemini; `--secret-file`).

---

## 1. Stage the two repos onto pop-os (💻 Mac → 📦 gembox; no root)

Both repos live only on the Mac as branches. Bundle the exact fork-gap branches and copy them over
(a git bundle is a single file, clean over ssh):

```
# 💻 Mac — bundle the integrated branches (warden with report/--audit; agentwatch with the fix)
git -C ~/dev/warden bundle create /tmp/warden-partb.bundle speed/warden-demo-integration
git -C ~/dev/agent-oversight-console bundle create /tmp/aw-partb.bundle speed/agentwatch-demo-integration
scp /tmp/warden-partb.bundle /tmp/aw-partb.bundle srh@pop-os:/tmp/

# 📦 pop-os as gembox — clone both from the bundles into gembox's home
git clone -b speed/warden-demo-integration /tmp/warden-partb.bundle ~/warden
git clone -b speed/agentwatch-demo-integration /tmp/aw-partb.bundle ~/agentwatch-fixed
python3 -c "import sys; sys.path.insert(0,'$HOME/agentwatch-fixed'); import agentwatch; print('agentwatch (fixed) importable')"
```

`~/warden` and `~/agentwatch-fixed` under **gembox**, not srh. (scp to srh's /tmp then gembox
clones — or copy the bundles somewhere gembox reads.)

---

## 2. Root setup — you approve each (🔒 ROOT, one-time)

**🔒 R1 — btrfs storage pool.** Verify it exists; create it if not:

```
sudo incus storage list                     # look for a btrfs pool
# only if none exists (adjust size/backing to the box):
sudo incus storage create warden-pool btrfs size=50GiB
```

**🔒 R2 — the scoped sudo grant** (this is what lets warden self-elevate the *individual*
root-requiring tools without ever running the reconciler as root — DEMO-SPEC §9 / `privilege.py`).
Write `/etc/sudoers.d/warden` via `visudo -f`:

```
sudo visudo -f /etc/sudoers.d/warden
```
Contents (scoped to the exact binaries + the collector script; NOT `ALL`):
```
Cmnd_Alias WARDEN = /usr/bin/incus, /sbin/auditctl, /usr/sbin/auditctl, \
                    /usr/bin/ausearch, /usr/sbin/nft, \
                    /home/gembox/warden/scripts/warden-collect-audit.sh
gembox ALL=(root) NOPASSWD: WARDEN
```
(Confirm the real paths with `command -v incus auditctl ausearch nft`; the collector path is where
you cloned `~/warden`. `warden` uses `sudo -n` — non-prompting — so it must be NOPASSWD.)

**🔒 R3 — (optional) operator identity.** If you want gembox to drive Incus as itself (the
gembox↔maude parallel) rather than via the grant, add it to the `incus` group. Then you can drop
`/usr/bin/incus` from R2. Re-login for the group to take effect:
```
sudo usermod -aG incus gembox        # restricted `incus` group — NEVER incus-admin
```

That is the entire root surface: a pool, a scoped grant, an optional group add. Nothing below is root.

---

## 3. The run (📦 gembox, unprivileged)

warden self-elevates only the allowlisted tools via R2; the reconciler and all prompt-bearing data
stay unprivileged. Point PYTHONPATH at the **fixed** agentwatch.

```
cd ~/warden
export PYTHONPATH="$HOME/warden:$HOME/agentwatch-fixed"

# 3a. up — builder + --audit (a build that is ALSO audited: the fork-gap config).
python3 -m warden.cli up --flavor builder --audit --llm gemini \
        --secret-file ~/.warden/gemini.key --project warden

# 3b. run — a real, unrigged build that produces genuine git history + a test run.
#     --example ships a small real build (DEMO-SPEC §6); or pass your own prompt.
python3 -m warden.cli run --example --flavor builder --audit --llm gemini \
        --secret-file ~/.warden/gemini.key --project warden

# 3c. report — pulls both planes, derives the scope uid itself, reconciles via agentwatch.
python3 -m warden.cli report --flavor builder --llm gemini --project warden

# 3d. export — copy-all for off-box analysis.
python3 -m warden.cli export ./partb-out --flavor builder --llm gemini --project warden
```

---

## 4. Pass criteria — the fork-gap payoff

In the `report` output (and `findings.jsonl` / the summary):

1. **The git work-phase execs are EVALUATED, not in the "not evaluated" remainder.** DEMO-VALIDATION
   R1 had `git init/config/checkout/add/commit` + the unittest run fall out of scope (15 unevaluated).
   With the clone rule + bridge, those execs now walk back to the runtime pid and get a **verdict**
   (almost all NONE/authorized on a benign build — the point is they're *judged*, not dropped).
2. **The "not evaluated" count for the work phase drops toward zero** (only the true floor remains:
   shell builtins, pure in-process work — `cd`/`export`, never-exec'd internals).
3. **0 CONFIRMED on the benign build** stays correct (a real build has no unexplained orphans).
4. **prove_capture still passes the execve arm** — the clone rule didn't break execve loading.

Compare against DEMO-VALIDATION.md R1 directly: same shape of build, the git subtree that was
invisible is now reconciled. That delta *is* Part B.

**If git is still unevaluated:** check PYTHONPATH points at `~/agentwatch-fixed` (the fixed line),
not pop-os's stale `/home/srh/dev/agentwatch`. That is the most likely wrong-reason failure.

---

## 5. Teardown (📦 gembox; `down` self-elevates auditctl via R2)

```
python3 -m warden.cli down warden-builder --project warden
sudo auditctl -l | grep warden || echo "no warden audit rule left"   # 🔒 confirm the rule is gone
```

`down` removes the instance and its audit rule (by key — never `auditctl -D`). Leftover: the proxy
daemon if one lingers (`pkill -f 'warden.cli proxy'`), and `/tmp/*.bundle`.

---

## Tradeoff / honest limits

- **The R2 grant is a *standing* passwordless grant**, scoped to specific binaries. warden uses
  `sudo -n` (non-interactive) precisely so a hands-off run never hangs on a password — so it cannot
  instead pause and ask per-call. If you want **zero standing grant**, the only alternative is
  `sudo python3 -m warden.cli up/report/down …` (whole process root) — which `privilege.py`
  explicitly argues against: it relocates `$HOME` to `/root` (allowlist/run-dir/artifacts move) and
  runs the reconciler as root, the very thing the privilege split exists to prevent. Recommendation:
  use the scoped R2 grant; it keeps the reconciler unprivileged, which is the security property.
- **Single run, not calibrated.** Like the earlier measurements — one capture, not an FP/FN rate.
- **Gemini authorizes on timestamp/ancestry, not command** (its transcript is name-only). The clone
  fix buys the ground-truth ancestry; it does not make Gemini's self-report command-level.
- **prove_capture proves the execve arm only.** Proving the clone arm fires on this host still wants
  a forking marker (tracked follow-up) — but Part A already showed real clone records parse on a
  real kernel, so this is belt-and-suspenders, not a gap.
```
