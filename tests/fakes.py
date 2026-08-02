"""In-memory `IncusClient` double — see DECISIONS.md.

Models exactly the behaviors warden's logic depends on: idmap allocation
that's distinct per instance (`security.idmap.isolated=true` in
`profiles.py`) and *reallocates* on restore (the I6-breaks-I5 gotcha),
snapshots, and an audit trail keyed off "who's actually running" so
`auditd.prove_capture` has something real to poll.

This is a test double, not a mock of Incus's CLI surface — it exists so
the *orchestration logic* in `warden/app.py` can be exercised end to end
without a real Incus daemon, per DECISIONS.md's "no root in this VM"
constraint.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from warden.auditd import AuditEvent, extract_marker
from warden.incus import ExecResult, IncusCommandError


@dataclass
class _Instance:
    name: str
    project: str
    image: str
    profile: str
    config: dict[str, str] = field(default_factory=dict)
    snapshots: set[str] = field(default_factory=set)
    running: bool = True


class FakeIncusClient:
    def __init__(self, first_host_uid: int = 1_000_000, range_size: int = 65536):
        self._next_host_uid = first_host_uid
        self._range_size = range_size
        self.projects: dict[str, dict[str, str]] = {}
        self.profiles: dict[tuple[str, str], dict] = {}
        self.networks: dict[str, dict[str, str]] = {}
        self.instances: dict[tuple[str, str], _Instance] = {}
        self.audit_log: list[AuditEvent] = []
        self._serial = 0

    # -- internal ---------------------------------------------------------
    def _alloc_range(self) -> int:
        start = self._next_host_uid
        self._next_host_uid += self._range_size
        return start

    def _idmap_json(self, host_start: int) -> str:
        return json.dumps([
            {"Isuid": True, "Isgid": False, "Hostid": host_start, "Nsid": 0, "Maprange": self._range_size},
            {"Isuid": False, "Isgid": True, "Hostid": host_start, "Nsid": 0, "Maprange": self._range_size},
        ])

    def _require_instance(self, name: str, project: str) -> _Instance:
        key = (project, name)
        if key not in self.instances:
            raise IncusCommandError(["config", "show", name], 1, f'Instance not found: "{name}"')
        return self.instances[key]

    # -- existence ----------------------------------------------------------
    def project_exists(self, name: str) -> bool:
        return name in self.projects

    def profile_exists(self, name: str, project: str) -> bool:
        return (project, name) in self.profiles

    def network_exists(self, name: str) -> bool:
        return name in self.networks

    def instance_exists(self, name: str, project: str) -> bool:
        return (project, name) in self.instances

    def snapshot_exists(self, name: str, snapshot: str, project: str) -> bool:
        key = (project, name)
        return key in self.instances and snapshot in self.instances[key].snapshots

    # -- create ---------------------------------------------------------------
    def project_create(self, name: str, config: dict[str, str]) -> None:
        if name in self.projects:
            raise IncusCommandError(["project", "create", name], 1, "already exists")
        self.projects[name] = dict(config)

    def profile_create(
        self, name: str, project: str, config: dict[str, str], devices: dict[str, dict]
    ) -> None:
        key = (project, name)
        if key in self.profiles:
            raise IncusCommandError(["profile", "create", name], 1, "already exists")
        self.profiles[key] = {"config": dict(config), "devices": dict(devices)}

    def network_create(self, name: str, config: dict[str, str]) -> None:
        if name in self.networks:
            raise IncusCommandError(["network", "create", name], 1, "already exists")
        self.networks[name] = dict(config)

    def launch(self, image: str, name: str, project: str, profile: str) -> None:
        key = (project, name)
        if key in self.instances:
            raise IncusCommandError(["launch", image, name], 1, "already exists")
        host_start = self._alloc_range()
        self.instances[key] = _Instance(
            name=name,
            project=project,
            image=image,
            profile=profile,
            config={"volatile.idmap.current": self._idmap_json(host_start)},
        )

    # -- instance ops -----------------------------------------------------------
    def config_get(self, name: str, key: str, project: str = "default") -> str:
        return self._require_instance(name, project).config.get(key, "")

    def config_set(self, name: str, key: str, value: str, project: str = "default") -> None:
        self._require_instance(name, project).config[key] = value

    def exec(
        self,
        name: str,
        argv: list[str],
        project: str = "default",
        env: dict[str, str] | None = None,
    ) -> ExecResult:
        inst = self._require_instance(name, project)
        if not inst.running:
            return ExecResult(1, "", f"{name} is not running")

        idmap = json.loads(inst.config["volatile.idmap.current"])
        uid_entry = next(e for e in idmap if e["Isuid"] and e["Nsid"] == 0)
        host_uid = uid_entry["Hostid"]  # container root -> this host uid

        self._serial += 1
        marker = extract_marker(" ".join(argv))
        line = (
            f'type=SYSCALL msg=audit({1_700_000_000 + self._serial}.000:{self._serial}): '
            f'uid={host_uid} exe="{argv[0]}" key="warden-{name}"'
        )
        self.audit_log.append(AuditEvent(
            ts=float(1_700_000_000 + self._serial),
            uid=host_uid,
            key=f"warden-{name}",
            marker=marker,
            raw=line,
        ))
        return ExecResult(0, "", "")

    def file_push(
        self, name: str, content: bytes, remote_path: str, project: str = "default"
    ) -> None:
        inst = self._require_instance(name, project)
        inst.config.setdefault("_files", {})  # type: ignore[arg-type]
        inst.config[f"_file:{remote_path}"] = content.decode()

    def snapshot(self, name: str, snapshot: str, project: str = "default") -> None:
        inst = self._require_instance(name, project)
        inst.snapshots.add(snapshot)

    def restore(self, name: str, snapshot: str, project: str = "default") -> None:
        inst = self._require_instance(name, project)
        if snapshot not in inst.snapshots:
            raise IncusCommandError(["snapshot", "restore", name, snapshot], 1, "no such snapshot")
        # The real gotcha this models: restore reallocates the idmap range.
        # Everything else about the instance is unaffected in this fake —
        # only the id mapping moves, which is exactly what silently blinded
        # auditd in the manual builds (I6 breaking I5).
        new_start = self._alloc_range()
        inst.config["volatile.idmap.current"] = self._idmap_json(new_start)

    def delete(self, name: str, project: str = "default") -> None:
        self.instances.pop((project, name), None)

    def list_instances(self, project: str) -> list[str]:
        return [n for (p, n) in self.instances if p == project]


class FakeEventSource:
    """`auditd.EventSource` backed by a `FakeIncusClient`'s in-memory trail."""

    def __init__(self, client: FakeIncusClient):
        self._client = client

    def poll(self) -> list[AuditEvent]:
        return list(self._client.audit_log)


class FakeAuditRuleInstaller:
    """`auditd.AuditRuleInstaller` — records what would've been written to
    `/etc/audit/rules.d`, without needing root to actually write it."""

    def __init__(self):
        self.installed: dict[str, "IdRange"] = {}

    def install(self, instance: str, uid_range) -> None:
        self.installed[instance] = uid_range


class FakeProxyAllowlistController:
    """`proxy.ProxyAllowlistController` — records the active allowlist
    in memory instead of rewriting a file a real proxy process watches."""

    def __init__(self):
        self.current: tuple[str, ...] = ()
        self.history: list[tuple[str, ...]] = []

    def set_allowlist(self, domains: tuple[str, ...]) -> None:
        self.current = tuple(domains)
        self.history.append(self.current)
