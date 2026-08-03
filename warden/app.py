"""`WardenApp` — the up/down orchestration, flavor-agnostic (§0, §7 step 5).

Everything here reads a `WardenConfig`/`FlavorSpec` and never branches on
`if flavor == ...` directly — the flavor difference already got baked
into the config in `flavors.py`/`config.py`. This is "one codepath, two
flavors" made literal: the same `up()` runs for both, and the *shape* of
what it does (whether it wires auditd, which allowlist it hands the
proxy, what permission mode it configures) all comes from `cfg.spec`.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Optional

from warden import egress, profiles
from warden.auditd import AuditEvent, AuditRuleInstaller, EventSource, prove_capture
from warden.config import WardenConfig, resolve_llm_auth
from warden.idmap import Idmap, assert_unprivileged, derive_idmap
from warden.incus import ExecResult, IncusClient, IncusCommandError
from warden.proxy import ProxyAllowlistController
from warden.standing_rules import render_standing_rules, standing_rules_filename

CLEAN_SNAPSHOT = "clean"
REPO_PATH = "/root/repo"
# Restore has to rewrite volatile.idmap.*, which `restricted=true` blocks by
# implying restricted.containers.lowlevel=block. Opened for the duration of
# one restore and closed again — never left on. See DECISIONS.md "D16".
LOWLEVEL_KEY = "restricted.containers.lowlevel"


class ProvisioningError(RuntimeError):
    """A command run inside the instance failed.

    Exists because the first real-Incus run's `git clone` failed silently:
    the image has no `git`, `exec` returned rc 127, and nothing looked at
    the result. The test then reported "no /root/repo/.git" with no clue why.
    """


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
        pool: str = profiles.STORAGE_POOL,
    ):
        self.client = client
        self.audit_installer = audit_installer
        self.event_source_factory = event_source_factory
        self.proxy_controller = proxy_controller
        self.pool = pool

    # -- shared substrate (idempotent) -------------------------------------
    def ensure_substrate(self, cfg: WardenConfig) -> None:
        # The pool is no longer assumed to exist: `up` self-provisions the
        # bridge, so assuming a pool that only install-incus-nested.sh
        # creates made `warden up` fail with "Storage pool not found" on any
        # other host.
        if not self.client.storage_pool_exists(self.pool):
            self.client.storage_pool_create(self.pool, profiles.STORAGE_DRIVER)

        if not self.client.project_exists(cfg.project):
            self.client.project_create(cfg.project, profiles.project_config())
        else:
            # Converge: a project created by an older warden is missing
            # restricted.snapshots, and re-running should fix it rather
            # than leave the operator to notice at snapshot time.
            for key, value in profiles.project_config().items():
                self.client.project_set(cfg.project, key, value)

        if not self.client.network_exists(profiles.BRIDGE_NAME):
            self.client.network_create(profiles.BRIDGE_NAME, profiles.network_config())
        else:
            # Converge the subnet, for the same reason the project config is
            # converged above: a bridge created by an older warden keeps the
            # address it was created with, and the old default sat inside
            # CG-NAT — the range Tailscale routes (see profiles.py). Fixing
            # the constant without this leaves every already-provisioned host
            # hijacking the tailnet, which is precisely the "looks fixed, is
            # not" shape. `assert_subnet_sane` runs inside network_config().
            for key, value in profiles.network_config().items():
                self.client.network_set(profiles.BRIDGE_NAME, key, value)

        self._ensure_egress()

        profile_spec = profiles.build_profile(cfg.spec.name, mem=cfg.mem, cpu=cfg.cpu, pool=self.pool)
        if not self.client.profile_exists(profile_spec.name, cfg.project):
            self.client.profile_create(
                profile_spec.name, cfg.project, profile_spec.config, profile_spec.devices
            )
        else:
            # An existing profile predating the ACL would leave its
            # instances with no egress policy at all — fail open, silently.
            self.client.profile_device_set(
                profile_spec.name, cfg.project, "eth0", "security.acls", egress.ACL_NAME
            )

    def _ensure_egress(self) -> None:
        """Install the ACL, put the bridge on default-drop, and make sure
        the allowlist proxy is actually listening (§1).

        The first real run enforced none of this: `egress.py` generated an
        nftables ruleset that nothing loaded, and the proxy was a file
        nobody read. `example.com` and the LAN gateway were both reachable.
        """
        document = egress.build_acl_document(
            profiles.BRIDGE_GATEWAY, profiles.PROXY_PORT, profiles.BRIDGE_SUBNET
        )
        egress.assert_enforceable(document, profiles.BRIDGE_GATEWAY, profiles.PROXY_PORT)
        if self.client.network_acl_get(egress.ACL_NAME) != document:
            self.client.network_acl_put(egress.ACL_NAME, document)

        # Scoped to warden's own bridge — never a host-wide policy, so an
        # unrelated bridge on this host is unaffected.
        self.client.network_set(
            profiles.BRIDGE_NAME, "security.acls.default.egress.action", "drop"
        )
        self.client.network_set(
            profiles.BRIDGE_NAME, "security.acls.default.ingress.action", "drop"
        )

        if self.proxy_controller is not None:
            self.proxy_controller.ensure_running()

    # -- provisioning helpers ------------------------------------------------
    def _exec_ok(self, cfg: WardenConfig, argv: list[str], what: str) -> ExecResult:
        result = self.client.exec(cfg.instance, argv, project=cfg.project)
        if not result.ok:
            raise ProvisioningError(
                f"{cfg.instance}: {what} failed (rc={result.returncode}): "
                f"{(result.stderr or result.stdout).strip()}"
            )
        return result

    # A readiness probe must not be able to outlive the loop that polls it.
    # `exec`'s own bound is sized for `apt-get install`, so inheriting it here
    # would let one `/bin/true` block far past this function's deadline and
    # make the deadline decorative.
    PROBE_TIMEOUT = 15.0

    def _wait_ready(self, cfg: WardenConfig, timeout: float = 60.0) -> None:
        """Block until the instance can run a command.

        A snapshot restore stops and restarts the container; execing into
        it immediately afterwards races the boot and fails in a way that
        looks like a capture failure."""
        deadline = time.monotonic() + timeout
        last = ""
        while time.monotonic() < deadline:
            try:
                if self.client.exec(
                    cfg.instance, ["/bin/true"], project=cfg.project, timeout=self.PROBE_TIMEOUT
                ).ok:
                    return
            except IncusCommandError as exc:  # pragma: no cover - timing dependent
                last = str(exc)
            time.sleep(1.0)
        raise ProvisioningError(f"{cfg.instance}: not ready within {timeout}s {last}")

    def _set_proxy_env(self, cfg: WardenConfig) -> None:
        """Point the guest at the host-side proxy.

        Set as instance `environment.*` keys rather than a shell profile so
        that every `incus exec` — including the acceptance tests' bare
        `curl` — inherits it. Egress is default-drop, so a process that
        ignores these simply has no network, which is the intended
        direction of failure."""
        url = f"http://{profiles.BRIDGE_GATEWAY}:{profiles.PROXY_PORT}"
        for key in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
            self.client.config_set(cfg.instance, f"environment.{key}", url, project=cfg.project)
        # The bridge and loopback must not be proxied, or in-guest traffic
        # would loop back out through the proxy and be denied.
        self.client.config_set(
            cfg.instance, "environment.no_proxy", f"127.0.0.1,localhost,{profiles.BRIDGE_GATEWAY}",
            project=cfg.project,
        )

    def _provision(self, cfg: WardenConfig) -> None:
        """Install what the flavor needs, through the proxy.

        `images:debian/12` is minimal: it has curl but **no git**. That is
        the whole of finding 6 — the clone never ran."""
        self._exec_ok(cfg, ["sh", "-c", "apt-get update -qq"], "apt-get update")
        self._exec_ok(
            cfg,
            ["sh", "-c", "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends git ca-certificates"],
            "apt-get install git",
        )

    def _clone_repo(self, cfg: WardenConfig) -> None:
        assert cfg.repo_url is not None
        self._exec_ok(
            cfg,
            ["sh", "-c", f"test -d {REPO_PATH}/.git || git clone {cfg.repo_url} {REPO_PATH}"],
            f"git clone {cfg.repo_url}",
        )
        # Prove it, rather than trusting the exit code of a compound command.
        self._exec_ok(cfg, ["test", "-d", f"{REPO_PATH}/.git"], f"{REPO_PATH}/.git missing after clone")

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
        # Raises NeedsHumanError if a real run can't proceed. The secret FILE is checked, not just
        # the environment: `warden up --secret-file …` passed the CLI's pre-check and then failed
        # here on any host without `GEMINI_API_KEY` also exported, because this call could not see
        # the flag. See DECISIONS D26.
        resolve_llm_auth(cfg.llm, secret_file=cfg.secret_file)

        self.ensure_substrate(cfg)

        created = not self.client.instance_exists(cfg.instance, cfg.project)
        if created:
            profile_name = profiles.build_profile(cfg.spec.name).name
            self.client.launch(profiles.IMAGE, cfg.instance, cfg.project, profile_name)

        # Stale rules from instances that no longer exist would shadow this
        # one if they overlap its uid range — see auditd.prune / D14.
        if self.audit_installer is not None:
            self.audit_installer.prune(set(self.client.list_instances(cfg.project)))

        self._set_proxy_env(cfg)
        self._wait_ready(cfg)

        needs_provisioning = created or (
            cfg.spec.repo_git
            and cfg.repo_url is not None
            and not self.client.exec(
                cfg.instance, ["test", "-d", f"{REPO_PATH}/.git"], project=cfg.project
            ).ok
        )
        if needs_provisioning and self.proxy_controller is not None:
            # wide, one-time provisioning allowlist for setup
            self.proxy_controller.set_allowlist(cfg.spec.provisioning_allowlist)

        idmap = derive_idmap(self.client, cfg.instance, project=cfg.project)  # never cached
        assert_unprivileged(idmap)

        rules_text = render_standing_rules(cfg.spec)
        filename = standing_rules_filename(cfg.llm)
        self.client.file_push(cfg.instance, rules_text.encode(), f"/root/{filename}", project=cfg.project)

        if needs_provisioning:
            self._provision(cfg)
        if cfg.spec.repo_git and cfg.repo_url:
            self._clone_repo(cfg)

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
        `auditctl -l` for this.

        A restricted project blocks the idmap rewrite the restore depends
        on, so the low-level permission is opened for exactly this one
        operation and closed again in `finally` — including on failure.
        Leaving it on would also permit `raw.lxc`/`raw.idmap`, which can
        weaken confinement; that is not a trade worth making permanent.
        """
        self.client.project_set(cfg.project, LOWLEVEL_KEY, "allow")
        try:
            self.client.restore(cfg.instance, snapshot, project=cfg.project)
        finally:
            self.client.project_unset(cfg.project, LOWLEVEL_KEY)

        self._wait_ready(cfg)
        idmap = derive_idmap(self.client, cfg.instance, project=cfg.project)  # fresh, post-restore
        assert_unprivileged(idmap)
        if not cfg.spec.auditd_wired:
            return None
        return self._wire_auditd(cfg, idmap)

    # -- down ---------------------------------------------------------------
    def down(self, instance: str, project: str) -> bool:
        """Removes only the instance. The shared substrate (project,
        profile, network, ACL, proxy allowlist) is left alone — see
        DECISIONS.md.

        The instance's audit rule is *not* shared substrate: leaving it
        behind is what let a dead instance's rule capture a live one's
        execs under the wrong key."""
        if self.audit_installer is not None:
            self.audit_installer.uninstall(instance)
        if not self.client.instance_exists(instance, project):
            return False
        self.client.delete(instance, project=project)
        return True
