# Fork-gap fix — validation runbook

The fork-gap fix (warden `speed/fork-gap-audit-rule` + agent-oversight-console
`speed/fork-gap-ancestry-walk`) is proven against **synthetic** audit fixtures (13 tests). What is
NOT yet proven is that it holds against **real auditd output** — the actual kernel record layout,
the `ausearch` dialect, and the field assumptions the parser makes (`exit`=child pid, `pid`=caller,
`a0`=clone flags, the per-arch syscall numbers).

"The pop-os run" splits into **two** validations. They answer different questions and have very
different setup cost. Do Part A first — it catches the assumptions most likely to be wrong, needs
no Incus / no Gemini / no pop-os, and runs entirely on the Mac in a Lima VM.

---

## Part A — Parser vs. REAL auditd (Lima under maude; no Incus, no Gemini, no network)

**Question:** do the parser's clone-record assumptions survive real kernel output? This is the
highest-risk, lowest-setup half. A Lima VM is a real-kernel qemu VM, so its auditd is first-class
(the "auditd doesn't nest" caveat is about container-in-container, not a VM). Any forking process
exercises the clone path — you don't need the agent at all.

1. **In the Lima VM** (default user has sudo):
   ```
   sudo apt-get update && sudo apt-get install -y auditd
   ```

2. **Load the rule, scoped to your own uid.** On the Mac's aarch64, `arch=b64` = aarch64. This is
   exactly `rule_fragments` output (execve + clone; NO fork/vfork — aarch64 has no such syscall,
   which is why the rule is clone-only):
   ```
   U=$(id -u)
   sudo auditctl -a always,exit -F arch=b64 -S execve -S clone -F uid>=$U -F uid<=$U -k forktest
   sudo auditctl -l | grep forktest      # confirm it loaded (does NOT prove it captures)
   ```
   (Skip an `arch=b32` fragment here — a 64-bit-only arm64 kernel has no 32-bit compat and would
   reject it. That's a pre-existing warden concern on aarch64, not part of this fix.)

3. **Produce a real fork, including a never-execve'd bridge** (a subshell that runs a builtin
   before spawning an external command can't be exec-optimized away, so it forks a shell that
   never execs — the fork-gap shape):
   ```
   bash -c '( : ; /bin/echo forkgap-child ); /bin/true'
   ```

4. **Pull the capture and run the parser.** `--raw` gives unambiguous epoch timestamps; rerun with
   `-i` too, since the interpolated dialect is the harder one the parser must also read:
   ```
   sudo ausearch -k forktest --raw > /tmp/forktest.raw.log
   # agent-oversight-console must be importable here (limactl copy it in, or clone it); from its root:
   python3 - <<'PY'
   from collections import Counter
   from agentwatch.groundtruth.audit_log import parse_lines
   from agentwatch.reconciler.process_tree import ProcessTree
   evs, stats = parse_lines(open('/tmp/forktest.raw.log'))
   print("kinds:", Counter(e.kind for e in evs))
   for e in evs:
       if e.kind == "clone":
           print(f"CLONE child(pid)={e.pid} parent(ppid)={e.ppid} uid={e.uid}")
   print("skips:", stats.skip_reasons)
   tree = ProcessTree(evs)
   # spot-check a real bridge: pick an execve'd pid whose parent only appears via a clone edge
   PY
   ```
   **Pass criteria:** CLONE events appear; `child`/`parent` pids are sane (child = the new pid, parent
   = the shell that forked it); no unexpected skip reasons; and for a pid whose parent never execve'd,
   `ProcessTree.ancestry()` still reaches the root (the clone edge bridged it). If `clone_thread_filtered`
   fires on the plain fork above, the a0 flag read is wrong — investigate before trusting the filter.

5. **Cleanup:**
   ```
   sudo auditctl -d always,exit -F arch=b64 -S execve -S clone -F uid>=$U -F uid<=$U -k forktest
   ```

This validates `exit`=child, `pid`=caller, the a0 CLONE_THREAD filter, the arch numbers, and both
`ausearch` dialects — against a real kernel, with nothing else in the stack.

---

## Part B — End-to-end fork-gap reproduction (pop-os real Incus, or Lima-nested-Incus)

**Question:** does a real **Gemini** build — whose git subtree was orphaned ("15 not evaluated" in
DEMO-VALIDATION R1) — now scope in? This needs Gemini (the fork gap is its persistent-shell
behavior; Claude shells out per-command and won't reproduce it) plus the full wizard loop.

**BLOCKED on integration — verify before scheduling this run.** Canonical `~/dev/warden` does NOT
currently expose the pieces this needs:
- `warden up` has **no `--audit` flag** (so `builder` can't be audited from the CLI; only
  `monitored` wires auditd, and `monitored` has no git repo to orphan).
- there is **no `warden report` / `warden export`** subcommand (CLI is up/down/proxy/restore only).

These were demo-bundle work per `DEMO-SPEC.md`; they live in `warden-demo.bundle`, not warden main.
So Part B first requires folding builder+`--audit` + report/export (plane-pull + reconcile) into
warden, or decomposing them by hand. Do NOT write these commands as if they exist today.

Once integrated, the shape is:
1. `warden up --flavor builder --audit --llm gemini --secret-file <key>` on a real Incus host.
2. Drive a prompt that produces genuine git work (`git init` / edits / `git commit`) + a test run.
3. Pull **both planes**: the container transcript (self-report) and the host audit log (ground truth).
4. Reconcile: `python -m agentwatch --agent-uid <derived-uid> --audit-log <pulled> --transcript <pulled> --findings out.jsonl`.
5. **Pass criteria:** the git execs that were previously out of scope now appear as *evaluated*
   candidates (in `reconcile_orphans_scoped` output), with a verdict — not silently dropped. Also
   confirm `prove_capture` still passes the execve arm (the clone rule didn't break execve loading).

**Substrate choice for Part B:**
- **pop-os real Incus** — the proven substrate (16/16). Needs: gembox added to the `incus` group
  (restricted, not `incus-admin`); a btrfs pool (`sudo incus storage list`); a Gemini API key; and
  srh's root once for the auditd/nftables wiring. Run when home on trusted infra, not over con/hotspot.
- **Lima-nested-Incus under maude** — could do it fully locally (real-kernel auditd is faithful, and
  Gemini's fork behavior is a property of the CLI, not the substrate). Caveats: we've only run Claude
  in Lima (Gemini-in-Lima is new), and nested Incus is "feasible" but not yet proven — setup risk. If
  it stands up, it's a legitimate faithful test; if nesting fights, pop-os is the fallback.

---

## Order of operations

1. **Part A in Lima/maude now** — no blockers, fully local, catches the real-auditd parsing bugs.
2. **Integrate the demo-bundle pieces** (builder+`--audit`, report/export) into warden — the Part B
   prerequisite.
3. **Part B** on pop-os when home (or attempt Lima-nested-Incus if you want it local).
