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
from warden.incus import ExecResult, IncusCommandError, IncusTimeoutError

_REPO_PATH = "/root/repo"


@dataclass
class _Instance:
    name: str
    project: str
    image: str
    profile: str
    instance_type: str = "container"
    config: dict[str, str] = field(default_factory=dict)
    snapshots: set[str] = field(default_factory=set)
    running: bool = True
    # Just enough filesystem to model "did the clone actually land?" —
    # the real bug was `git clone` failing silently in an image with no git.
    paths: set[str] = field(default_factory=set)
    # Pushed file content, as bytes — never decoded/encoded through `config` (a `dict[str, str]`),
    # which corrupted the first binary push (a gzip'd tarball) with a UnicodeDecodeError. Text and
    # binary pushes are the same mechanism now; a caller comparing against a string encodes it.
    files: dict[str, bytes] = field(default_factory=dict)


class FakeIncusClient:
    def __init__(self, first_host_uid: int = 1_000_000, range_size: int = 65536):
        self._next_host_uid = first_host_uid
        self._range_size = range_size
        self.projects: dict[str, dict[str, str]] = {}
        self.profiles: dict[tuple[str, str], dict] = {}
        self.networks: dict[str, dict[str, str]] = {}
        self.instances: dict[tuple[str, str], _Instance] = {}
        self.storage_pools: dict[str, str] = {}
        self.network_acls: dict[str, dict] = {}
        self.images: dict[str, str] = {}  # alias -> fingerprint (VANTAGE-PLAN.md phase 2)
        self.audit_log: list[AuditEvent] = []
        self.exec_calls: list[tuple[str, list[str]]] = []
        self.exec_envs: list[dict | None] = []  # parallel to exec_calls, same index
        # substring of the joined argv -> the ExecResult to return. Named `failures` because that
        # was its only use; `exec_results` is the same mechanism under a name that also covers
        # "return this stdout", which `export` needs (a `git log` that prints nothing and a
        # `git log` that fails are different outcomes it has to distinguish).
        self.exec_failures: dict[str, ExecResult] = {}
        self.exec_results: dict[str, ExecResult] = {}
        self._serial = 0
        # -- recovery simulation knobs (see warden/recover.py) --
        self._responsive = True            # tests set False to simulate a wedged daemon (L3)
        self._operations: list[dict] = []  # tests populate to simulate stuck operations (L1)
        self._hung: set[str] = set()       # instance names whose exec hangs (L2)
        self.restarts: list[tuple[str, bool]] = []  # (name, force) recorded by restart()

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

    def storage_pool_exists(self, name: str) -> bool:
        return name in self.storage_pools

    def storage_pool_create(self, name: str, driver: str = "btrfs") -> None:
        if name in self.storage_pools:
            raise IncusCommandError(["storage", "create", name], 1, "already exists")
        self.storage_pools[name] = driver

    # -- convergence ---------------------------------------------------------
    def project_set(self, name: str, key: str, value: str) -> None:
        if name not in self.projects:
            raise IncusCommandError(["project", "set", name], 1, "not found")
        self.projects[name][key] = value

    def project_unset(self, name: str, key: str) -> None:
        if name not in self.projects:
            raise IncusCommandError(["project", "unset", name], 1, "not found")
        self.projects[name].pop(key, None)

    def network_set(self, name: str, key: str, value: str) -> None:
        if name not in self.networks:
            raise IncusCommandError(["network", "set", name], 1, "not found")
        self.networks[name][key] = value

    def profile_device_set(
        self, profile: str, project: str, device: str, key: str, value: str
    ) -> None:
        entry = self.profiles.get((project, profile))
        if entry is None:
            raise IncusCommandError(["profile", "device", "set", profile], 1, "not found")
        entry["devices"].setdefault(device, {})[key] = value

    # -- network ACLs ---------------------------------------------------------
    def network_acl_get(self, name: str) -> dict | None:
        return self.network_acls.get(name)

    def network_acl_put(self, name: str, document: dict) -> None:
        self.network_acls[name] = json.loads(json.dumps(document))

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

    def launch(
        self, image: str, name: str, project: str, profile: str, instance_type: str = "container"
    ) -> None:
        if instance_type not in ("container", "virtual-machine"):
            raise ValueError(f"unknown instance_type {instance_type!r}")
        key = (project, name)
        if key in self.instances:
            raise IncusCommandError(["launch", image, name], 1, "already exists")
        host_start = self._alloc_range()
        self.instances[key] = _Instance(
            name=name,
            project=project,
            image=image,
            profile=profile,
            instance_type=instance_type,
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
        timeout: float | None = None,  # accepted for interface parity; nothing here blocks
    ) -> ExecResult:
        inst = self._require_instance(name, project)
        self.exec_calls.append((name, list(argv)))
        self.exec_envs.append(env)  # parallel list, same index as exec_calls
        if name in self._hung:
            # a hung agent: the bounded exec times out rather than returning (the L2 signal)
            raise IncusTimeoutError(list(argv), timeout or 0.0)
        if not inst.running:
            return ExecResult(1, "", f"{name} is not running")

        joined = " ".join(argv)
        for table in (self.exec_failures, self.exec_results):
            for needle, canned in table.items():
                if needle in joined:
                    return canned
        # `test -d <path>` is the shape warden uses to decide whether the
        # clone landed, so it has to answer honestly.
        if argv[:2] == ["test", "-d"]:
            return ExecResult(0 if argv[2] in inst.paths else 1, "", "")
        if "git clone" in joined:
            inst.paths.add(f"{_REPO_PATH}/.git")

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
        inst.files[remote_path] = content
        inst.paths.add(remote_path)

    def file_pull(self, name: str, remote_path: str, project: str = "default") -> bytes:
        inst = self._require_instance(name, project)
        if remote_path not in inst.files:
            raise FileNotFoundError(f"{name}:{remote_path}")
        return inst.files[remote_path]

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

    def stop(self, name: str, project: str = "default", force: bool = False) -> None:
        self._require_instance(name, project).running = False

    # -- image publishing (VANTAGE-PLAN.md phase 2, the mold) -----------------
    def image_exists(self, alias: str, project: str = "default") -> bool:
        return alias in self.images

    def publish(self, name: str, alias: str, project: str = "default") -> str:
        self._require_instance(name, project)
        fingerprint = f"fake-fingerprint-{alias}"
        self.images[alias] = fingerprint
        return fingerprint

    # -- operational recovery (simulatable via the knobs in __init__) --------
    def responsive(self, timeout: float = 60.0) -> bool:
        return self._responsive

    def operations(self) -> list[dict]:
        return list(self._operations)

    def operation_delete(self, op_id: str) -> None:
        self._operations = [o for o in self._operations if o.get("id") != op_id]

    def restart(self, name: str, project: str = "default", force: bool = False) -> None:
        inst = self._require_instance(name, project)
        inst.running = True
        self._hung.discard(name)  # a force-restart clears the hang
        self.restarts.append((name, force))


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
        self.pruned: list[set[str]] = []

    def install(self, instance: str, uid_range) -> None:
        self.installed[instance] = uid_range

    def uninstall(self, instance: str) -> None:
        self.installed.pop(instance, None)

    def prune(self, live_instances: set[str]) -> None:
        self.pruned.append(set(live_instances))
        for instance in list(self.installed):
            if instance not in live_instances:
                del self.installed[instance]


class FakeProxyAllowlistController:
    """`proxy.ProxyAllowlistController` — records the active allowlist
    in memory instead of rewriting a file a real proxy process watches."""

    def __init__(self):
        self.current: tuple[str, ...] = ()
        self.history: list[tuple[str, ...]] = []
        self.ensure_running_calls = 0

    def set_allowlist(self, domains: tuple[str, ...]) -> None:
        self.current = tuple(domains)
        self.history.append(self.current)

    def ensure_running(self) -> bool:
        self.ensure_running_calls += 1
        return False
