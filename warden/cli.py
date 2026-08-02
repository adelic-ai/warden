"""`warden up` / `warden down` — the CLI entrypoint (§3, §7 step 5).

Wires the real (subprocess/root-requiring) adapters. All the actual logic
lives in `warden/app.py` and is identical to what's exercised against
`FakeIncusClient` in `tests/` — this module's only job is argument
parsing and adapter construction.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from warden.app import WardenApp
from warden.auditd import RealAuditRuleInstaller, RealEventSource
from warden.config import NeedsHumanError, build_config, resolve_llm_auth
from warden.incus import IncusCommandError, IncusNotFoundError, RealIncusClient
from warden.proxy import RealProxyAllowlistController

DEFAULT_ALLOWLIST_FILE = Path.home() / ".warden" / "allowlist.txt"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="warden")
    sub = parser.add_subparsers(dest="command", required=True)

    up = sub.add_parser("up", help="stand up a sandboxed instance")
    up.add_argument("--flavor", choices=["monitored", "builder"], required=True)
    up.add_argument("--host", default="local", help="Incus remote (unused for a local daemon)")
    up.add_argument("--llm", choices=["claude", "gemini"], required=True)
    up.add_argument("--project", default="warden")
    up.add_argument("--mem", default="4GiB")
    up.add_argument("--cpu", default="2")
    up.add_argument("--name", default=None, help="instance name; defaults to warden-<flavor>")
    up.add_argument("--allow", action="append", default=[], dest="extra_allow", metavar="DOMAIN")
    up.add_argument("--repo", default=None, dest="repo_url", help="repo to clone (builder only)")
    up.add_argument("--secret-file", type=Path, default=None, help="gemini API key file")
    up.add_argument("--allowlist-file", type=Path, default=DEFAULT_ALLOWLIST_FILE)

    down = sub.add_parser("down", help="remove a sandboxed instance (host substrate is unchanged)")
    down.add_argument("instance")
    down.add_argument("--project", default="warden")

    restore = sub.add_parser(
        "restore",
        help="restore a snapshot and re-derive+re-prove the audit rule (§1's I6-breaks-I5 fix)",
    )
    restore.add_argument("instance")
    restore.add_argument("--flavor", choices=["monitored", "builder"], required=True)
    restore.add_argument("--llm", choices=["claude", "gemini"], required=True)
    restore.add_argument("--project", default="warden")
    restore.add_argument("--snapshot", default="clean")

    return parser


def _up(args: argparse.Namespace) -> int:
    instance = args.name or f"warden-{args.flavor}"
    cfg = build_config(
        instance=instance,
        flavor=args.flavor,
        llm=args.llm,
        host=args.host,
        project=args.project,
        mem=args.mem,
        cpu=args.cpu,
        extra_allow=args.extra_allow,
        repo_url=args.repo_url,
    )
    try:
        # fail fast on a missing secret before touching the host at all
        resolve_llm_auth(args.llm, secret_file=args.secret_file)
    except NeedsHumanError as exc:
        print(f"NEEDS-HUMAN: {exc}", file=sys.stderr)
        return 2

    args.allowlist_file.parent.mkdir(parents=True, exist_ok=True)
    client = RealIncusClient()
    app = WardenApp(
        client,
        audit_installer=RealAuditRuleInstaller(),
        event_source_factory=lambda inst: RealEventSource(inst),
        proxy_controller=RealProxyAllowlistController(args.allowlist_file),
    )
    try:
        result = app.up(cfg)
    except IncusNotFoundError as exc:
        print(f"NEEDS-HUMAN: {exc}", file=sys.stderr)
        return 2
    except IncusCommandError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"up: {result.instance} created={result.created} idmap-uid={result.idmap.uid}")
    if result.capture_proof is not None:
        print(f"auditd: capture proven (uid={result.capture_proof.uid})")
    return 0


def _down(args: argparse.Namespace) -> int:
    client = RealIncusClient()
    app = WardenApp(client)
    try:
        removed = app.down(args.instance, args.project)
    except IncusNotFoundError as exc:
        print(f"NEEDS-HUMAN: {exc}", file=sys.stderr)
        return 2
    print(f"down: {args.instance} removed={removed}")
    return 0


def _restore(args: argparse.Namespace) -> int:
    cfg = build_config(instance=args.instance, flavor=args.flavor, llm=args.llm, project=args.project)
    client = RealIncusClient()
    app = WardenApp(
        client,
        audit_installer=RealAuditRuleInstaller(),
        event_source_factory=lambda inst: RealEventSource(inst),
    )
    try:
        event = app.restore_and_reprove(cfg, snapshot=args.snapshot)
    except IncusNotFoundError as exc:
        print(f"NEEDS-HUMAN: {exc}", file=sys.stderr)
        return 2
    if cfg.spec.auditd_wired and event is None:
        print("error: auditd_wired but no capture event returned", file=sys.stderr)
        return 1
    if event is not None:
        print(f"restore: {args.instance} re-derived + re-proven (uid={event.uid})")
    else:
        print(f"restore: {args.instance} restored (no auditd for this flavor)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "up":
        return _up(args)
    if args.command == "down":
        return _down(args)
    if args.command == "restore":
        return _restore(args)
    parser.error("unknown command")
    return 2  # unreachable — parser.error exits


if __name__ == "__main__":
    raise SystemExit(main())
