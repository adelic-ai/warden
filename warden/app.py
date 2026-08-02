"""`WardenApp` — the up/down orchestration, flavor-agnostic (§0, §7 step 5).

Everything here reads a `WardenConfig`/`FlavorSpec` and never branches on
`if flavor == ...` directly — the flavor difference already got baked
into the config in `flavors.py`/`config.py`. This is "one codepath, two
flavors" made literal: the same `up()` runs for both, and the *shape* of
what it does (whether it wires auditd, which allowlist it hands the
proxy, what permission mode it configures) all comes from `cfg.spec`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from warden.auditd import AuditEvent, AuditRuleInstaller, EventSource, prove_capture
from warden.config import WardenConfig, resolve_llm_auth
from warden.idmap import Idmap, assert_unprivileged, derive_idmap
from warden.incus import IncusClient
from warden.proxy import ProxyAllowlistController
from warden import profiles
from warden.standing_rules import render_standing_rules, standing_rules_filename

CLEAN_SNAPSHOT = "clean"


@dataclass
class UpResult:
    instance: str
    created: bool  # False => idempotent no-op, instance already existed
    idmap: Idmap
    capture_proof: Optional[AuditEvent]


class WardenApp:
    def __init__(
        self,
        client: IncusClient,
        audit_installer: Optional[AuditRuleInstaller] = None,
        event_source_factory: Optional[Callable[[str], EventSource]] = None,
        proxy_controller: Optional[ProxyAllowlistController] = None,
    ):
        self.client = client
        self.audit_installer = audit_installer
        self.event_source_factory = event_source_factory
        self.proxy_controller = proxy_controller

    # -- shared substrate (idempotent) -------------------------------------
    def ensure_substrate(self, cfg: WardenConfig) -> None:
        if not self.client.project_exists(cfg.project):
            self.client.project_create(cfg.project, profiles.project_config())
        if not self.client.network_exists(profiles.BRIDGE_NAME):
            self.client.network_create(profiles.BRIDGE_NAME, profiles.network_config())
        profile_spec = profiles.build_profile(cfg.spec.name, mem=cfg.mem, cpu=cfg.cpu)
        if not self.client.profile_exists(profile_spec.name, cfg.project):
            self.client.profile_create(
                profile_spec.name, cfg.project, profile_spec.config, profile_spec.devices
            )

    def _wire_auditd(self, cfg: WardenConfig, idmap: Idmap) -> AuditEvent:
        if self.audit_installer is None or self.event_source_factory is None:
            raise RuntimeError(
                "flavor requires auditd but WardenApp has no audit_installer/event_source_factory wired"
            )
        self.audit_installer.install(cfg.instance, idmap.uid)
        source = self.event_source_factory(cfg.instance)
        return prove_capture(self.client, source, cfg.instance, idmap.uid, project=cfg.project)

    # -- up -----------------------------------------------------------------
    def up(self, cfg: WardenConfig) -> UpResult:
        resolve_llm_auth(cfg.llm)  # raises NeedsHumanError if a real run can't proceed

        self.ensure_substrate(cfg)

        created = not self.client.instance_exists(cfg.instance, cfg.project)
        if created:
            profile_name = profiles.build_profile(cfg.spec.name).name
            self.client.launch(profiles.IMAGE, cfg.instance, cfg.project, profile_name)
            if self.proxy_controller is not None:
                # wide, one-time provisioning allowlist for setup
                self.proxy_controller.set_allowlist(cfg.spec.provisioning_allowlist)

        idmap = derive_idmap(self.client, cfg.instance, project=cfg.project)  # never cached
        assert_unprivileged(idmap)

        rules_text = render_standing_rules(cfg.spec)
        filename = standing_rules_filename(cfg.llm)
        self.client.file_push(cfg.instance, rules_text.encode(), f"/root/{filename}", project=cfg.project)

        if cfg.spec.repo_git and cfg.repo_url:
            self.client.exec(cfg.instance, ["git", "clone", cfg.repo_url, "/root/repo"], project=cfg.project)

        capture_proof = None
        if cfg.spec.auditd_wired:
            capture_proof = self._wire_auditd(cfg, idmap)

        if cfg.spec.snapshot and not self.client.snapshot_exists(cfg.instance, CLEAN_SNAPSHOT, cfg.project):
            self.client.snapshot(cfg.instance, CLEAN_SNAPSHOT, project=cfg.project)

        if self.proxy_controller is not None:
            # narrow provisioning -> runtime (never disables the ACL, just
            # re-scopes it — §1) whether this call created the instance or
            # found it already up, so a re-run always leaves the runtime
            # (narrow) list active.
            self.proxy_controller.set_allowlist(cfg.spec.runtime_allowlist)

        return UpResult(instance=cfg.instance, created=created, idmap=idmap, capture_proof=capture_proof)

    # -- restore: the I6-breaks-I5 regression path ---------------------------
    def restore_and_reprove(
        self, cfg: WardenConfig, snapshot: str = CLEAN_SNAPSHOT
    ) -> Optional[AuditEvent]:
        """§1's other load-bearing bit: restore reallocates the idmap, so
        the audit rule must be re-derived and re-proven — never trust
        `auditctl -l` for this."""
        self.client.restore(cfg.instance, snapshot, project=cfg.project)
        idmap = derive_idmap(self.client, cfg.instance, project=cfg.project)  # fresh, post-restore
        assert_unprivileged(idmap)
        if not cfg.spec.auditd_wired:
            return None
        return self._wire_auditd(cfg, idmap)

    # -- down ---------------------------------------------------------------
    def down(self, instance: str, project: str) -> bool:
        """Removes only the instance. The shared substrate (project,
        profile, network, proxy allowlist) is left alone — see
        DECISIONS.md."""
        if not self.client.instance_exists(instance, project):
            return False
        self.client.delete(instance, project=project)
        return True
