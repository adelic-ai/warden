"""`LimaAuditRuleInstaller` / `LimaEventSource` — same job as `RealAuditRuleInstaller`/
`RealEventSource`, but auditd runs *inside* the Lima VM, not on the Mac. Same reason
`LimaProxyAllowlistController` exists: `auditctl`/`ausearch` and `/etc/audit/rules.d` all live in
the guest's own filesystem/kernel, not the host's — real gap, found running `warden dev --lima` end
to end for the first time, right after the proxy one.

Deliberately NOT a subclass of `RealAuditRuleInstaller`: several of its methods are `@staticmethod`/
`@classmethod` (existing tests monkeypatch them as such — `test_auditd.py`), so converting them to
instance methods to support an overridable seam would be a real behavior change to already-validated
code, not a safe refactor. Instead, this reuses the same pure, already-tested module-level functions
(`rule_key`, `rule_file_path`, `generate_rule`, `rule_fragments`, `parse_events`) — the actual
audit-rule domain logic — and only re-implements the thin subprocess/file-I/O plumbing around them,
routed through `limactl shell` instead of a local `elevate()`.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from warden.auditd import (
    RULE_KEY_PREFIX,
    AuditEvent,
    AuditRuleLoadError,
    generate_rule,
    parse_events,
    rule_file_path,
    rule_fragments,
    rule_key,
)
from warden.lima import LIMACTL_BIN
from warden.privilege import SUDO
from warden.report import COLLECTOR, ReportError

if TYPE_CHECKING:
    from warden.idmap import IdRange


class LimaAuditRuleInstaller:
    """Writes the persistent rules.d file and loads/unloads live rules by key, same as
    `RealAuditRuleInstaller`, but every `auditctl` call and the rules.d file itself live inside
    `vm_name`'s guest filesystem, not this Mac's. `rules_dir` is a GUEST path (a plain string,
    never touched locally with `Path` — there's nothing on this side to touch)."""

    def __init__(self, vm_name: str, rules_dir: str = "/etc/audit/rules.d"):
        self.vm_name = vm_name
        self.rules_dir = rules_dir
        #: Same meaning as RealAuditRuleInstaller's — set by `install`, read by the CLI.
        self.persistence_installed: bool | None = None

    # -- the one seam every auditctl call funnels through --------------------
    def _auditctl(self, args: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(
            [LIMACTL_BIN, "shell", self.vm_name, "--", *SUDO, "auditctl", *args],
            capture_output=True, text=True,
        )

    def _loaded_lines(self) -> list[str]:
        proc = self._auditctl(["-l"])
        if proc.returncode != 0:
            return []
        return [line.strip() for line in proc.stdout.splitlines() if line.strip()]

    def _delete_loaded(self, key: str) -> None:
        # Never `auditctl -D` — same reasoning as RealAuditRuleInstaller: this VM may host more
        # than one instance's rule, and wiping everything would blind an unrelated one.
        for line in self._loaded_lines():
            tokens = line.split()
            if not any(t in (f"key={key}", key) for t in tokens):
                continue
            args: list[str] = []
            i = 0
            while i < len(tokens):
                tok = tokens[i]
                if tok == "-a":
                    args.append("-d")
                elif tok == "-F" and i + 1 < len(tokens) and tokens[i + 1].startswith("key="):
                    args += ["-k", tokens[i + 1][len("key="):]]
                    i += 1
                else:
                    args.append(tok)
                i += 1
            self._auditctl(args)

    def _is_loaded(self, key: str) -> bool:
        return any(
            any(t in (f"key={key}", key) for t in line.split()) for line in self._loaded_lines()
        )

    # -- protocol --------------------------------------------------------------
    def install(self, instance: str, uid_range: "IdRange") -> None:
        key = rule_key(instance)
        self.persistence_installed = self._write_rule_file(
            rule_file_path(instance), generate_rule(uid_range, instance)
        )
        self._delete_loaded(key)
        for fragment in rule_fragments(uid_range, instance):
            proc = self._auditctl(["-a", *fragment])
            if proc.returncode != 0:
                raise AuditRuleLoadError(
                    f"auditctl -a for {instance} failed inside {self.vm_name} "
                    f"(rc={proc.returncode}): {proc.stderr.strip()}"
                )
        if not self._is_loaded(key):
            raise AuditRuleLoadError(
                f"{instance}: key {key!r} is not present in `auditctl -l` inside {self.vm_name} — "
                "the kernel does not have the rule. This is the only half that matters for "
                "capture; do not trust a written rules.d file as evidence the plane is live."
            )

    def _write_rule_file(self, path: str, content: str) -> bool:
        """True if the persistent rule file was written inside the guest. False — not an
        exception — on any failure, matching RealAuditRuleInstaller's own best-effort contract:
        the live rule above is what actually captures."""
        proc = subprocess.run(
            [LIMACTL_BIN, "shell", self.vm_name, "--", *SUDO, "sh", "-c",
             f"mkdir -p $(dirname {path}) && cat > {path}"],
            input=content, capture_output=True, text=True,
        )
        return proc.returncode == 0

    def _remove_rule_file(self, path: str) -> None:
        subprocess.run(
            [LIMACTL_BIN, "shell", self.vm_name, "--", *SUDO, "rm", "-f", path],
            capture_output=True, text=True,
        )

    def uninstall(self, instance: str) -> None:
        self._delete_loaded(rule_key(instance))
        self._remove_rule_file(rule_file_path(instance))

    def _loaded_warden_instances(self) -> set[str]:
        instances: set[str] = set()
        prefix = f"{RULE_KEY_PREFIX}-"
        for line in self._loaded_lines():
            for token in line.split():
                key = token[len("key="):] if token.startswith("key=") else token
                if key.startswith(prefix):
                    instances.add(key[len(prefix):])
        return instances

    def prune(self, live_instances: set[str]) -> None:
        stale = self._loaded_warden_instances()
        proc = subprocess.run(
            [LIMACTL_BIN, "shell", self.vm_name, "--", *SUDO, "sh", "-c",
             f"ls {self.rules_dir}/60-{RULE_KEY_PREFIX}-*.rules 2>/dev/null"],
            capture_output=True, text=True,
        )
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                name = Path(line.strip()).name
                if name.startswith(f"60-{RULE_KEY_PREFIX}-") and name.endswith(".rules"):
                    stale.add(name[len(f"60-{RULE_KEY_PREFIX}-"):-len(".rules")])
        for instance in stale - set(live_instances):
            self.uninstall(instance)


class LimaEventSource:
    """Same job as `RealEventSource`, but `ausearch` runs inside `vm_name`. Deliberately narrower:
    `RealEventSource`'s local-file fallback (reading `/var/log/audit/audit.log` directly when
    `ausearch` isn't on PATH at all) isn't implemented here — a stated, honest gap, not a silent
    behavior difference. It should rarely matter: `ausearch` ships in the same `auditd` package
    already confirmed present on every Lima VM this bootstraps."""

    def __init__(self, vm_name: str, instance: str):
        self.vm_name = vm_name
        self.key = rule_key(instance)

    def poll(self) -> list[AuditEvent]:
        proc = subprocess.run(
            [LIMACTL_BIN, "shell", self.vm_name, "--", *SUDO,
             "ausearch", "-k", self.key, "--raw", "--input-logs"],
            capture_output=True, text=True,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return parse_events(proc.stdout)
        return []


class LimaAuditCollector:
    """Same job as `report.AuditCollector` (DESIGN §4's privileged half — a tiny root collector that
    copies one instance's audit records to a file the unprivileged reconciler can read), but the
    collector script has to run *inside* the Lima VM, since that's where auditd/the audit log
    actually live.

    `script` is the SAME path on both sides — Lima's default `$HOME` mount makes
    `scripts/warden-collect-audit.sh` visible inside the guest already, same reasoning as
    `LimaProxyAllowlistController`'s allowlist file. But that mount is read-only from the guest, so
    the collector can't write its *output* there directly — it stages to a guest-local path first,
    then `limactl copy` pulls the result back to `out_path` on the Mac. The script's own `chown
    $owner` is harmless-but-irrelevant here: `limactl copy` re-materializes the file under whichever
    account ran the copy, on this side, regardless of what it was chowned to inside the guest.
    """

    STAGING_PATH = "/tmp/warden-audit-collect.raw"

    def __init__(self, vm_name: str, script: Path = COLLECTOR):
        self.vm_name = vm_name
        self.script = Path(script)

    def collect(self, rule_key: str, out_path: Path, owner_uid: int) -> Path:
        out_path = Path(out_path)
        argv = [
            LIMACTL_BIN, "shell", self.vm_name, "--", *SUDO,
            str(self.script), rule_key, self.STAGING_PATH, str(owner_uid),
        ]
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            raise ReportError(
                f"audit collector failed inside {self.vm_name} (rc={proc.returncode}): "
                f"{proc.stderr.strip()}\n"
                f"  argv: {' '.join(argv)}\n"
                "  This is the privileged half of the split (DESIGN §4) and it needs root inside "
                "the VM. Grant a scoped, passwordless sudo rule for exactly this script there."
            )

        out_path.parent.mkdir(parents=True, exist_ok=True)
        pull = subprocess.run(
            [LIMACTL_BIN, "copy", f"{self.vm_name}:{self.STAGING_PATH}", str(out_path)],
            capture_output=True, text=True, timeout=60,
        )
        if pull.returncode != 0:
            raise ReportError(
                f"audit collector ran inside {self.vm_name} but pulling its output back failed "
                f"(rc={pull.returncode}): {pull.stderr.strip()}"
            )

        subprocess.run(
            [LIMACTL_BIN, "shell", self.vm_name, "--", "rm", "-f", self.STAGING_PATH],
            capture_output=True, timeout=15,
        )
        return out_path
