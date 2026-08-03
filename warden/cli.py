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

from warden import profiles, workload
from warden.app import ProvisioningError, WardenApp
from warden.auditd import CaptureNotProvenError, RealAuditRuleInstaller, RealEventSource
from warden.config import NeedsHumanError, build_config, resolve_llm_auth
from warden.example_prompt import EXAMPLE_PROMPT
from warden.incus import IncusCommandError, IncusNotFoundError, RealIncusClient
from warden.proxy import RealProxyAllowlistController, run_forever
from warden.export import Exporter
from warden.report import REPORT_NAME, ReportError, Reporter, render
from warden.workload import MANIFEST_NAME, RunManifest, WorkloadError, WorkloadRunner, run_dir_for

DEFAULT_ALLOWLIST_FILE = Path.home() / ".warden" / "allowlist.txt"
DEFAULT_RUNS_DIR = Path.home() / ".warden" / "runs"


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
    up.add_argument(
        "--audit", action="store_true",
        help="wire the auditd ground-truth plane (already on for `monitored`; this is what "
             "makes a `builder` reconcilable — `warden report` needs both planes)",
    )
    up.add_argument("--secret-file", type=Path, default=None, help="gemini API key file")
    up.add_argument("--allowlist-file", type=Path, default=DEFAULT_ALLOWLIST_FILE)
    up.add_argument(
        "--pool", default=profiles.STORAGE_POOL,
        help="storage pool; created (btrfs) if absent",
    )

    run = sub.add_parser(
        "run",
        help="run the agent hands-off against a single prompt, to completion or a wall-clock cap",
    )
    run.add_argument("prompt", nargs="?", default=None, help="the prompt; omit with --example")
    run.add_argument(
        "--example", action="store_true",
        help="use the shipped example prompt (a small, real, unrigged build — DEMO-SPEC §6)",
    )
    run.add_argument("--instance", default=None, help="defaults to warden-<flavor>")
    run.add_argument("--flavor", choices=["monitored", "builder"], default="builder")
    run.add_argument("--llm", choices=["claude", "gemini"], required=True)
    run.add_argument("--project", default="warden")
    run.add_argument("--audit", action="store_true", help="must match the `up` that created it")
    run.add_argument("--secret-file", type=Path, default=None, help="gemini API key file")
    run.add_argument("--allowlist-file", type=Path, default=DEFAULT_ALLOWLIST_FILE)
    run.add_argument("--out", type=Path, default=DEFAULT_RUNS_DIR, help="host artifact root")
    run.add_argument(
        "--timeout", type=float, default=workload.DEFAULT_WALL_CLOCK_SECONDS,
        help="wall-clock cap in seconds; a capped run is recorded as truncated, not as a failure",
    )

    report = sub.add_parser(
        "report",
        help="reconcile what the agent said it did against the host's syscall record",
    )
    report.add_argument("--instance", default=None, help="defaults to warden-<flavor>")
    report.add_argument("--flavor", choices=["monitored", "builder"], default="builder")
    report.add_argument("--llm", choices=["claude", "gemini"], required=True)
    report.add_argument("--project", default="warden")
    report.add_argument("--audit", action="store_true", default=True,
                        help="(implied — report requires the ground-truth plane)")
    report.add_argument("--out", type=Path, default=DEFAULT_RUNS_DIR, help="host artifact root")
    report.add_argument("--host", default=None, help="hostname recorded in verdicts; defaults to this host")

    export = sub.add_parser("export", help="tar everything out: copy all, nothing summarised")
    export.add_argument("dest", type=Path, help="directory to write the tarball into")
    export.add_argument("--instance", default=None, help="defaults to warden-<flavor>")
    export.add_argument("--flavor", choices=["monitored", "builder"], default="builder")
    export.add_argument("--llm", choices=["claude", "gemini"], required=True)
    export.add_argument("--project", default="warden")
    export.add_argument("--out", type=Path, default=DEFAULT_RUNS_DIR, help="host artifact root")

    down = sub.add_parser("down", help="remove a sandboxed instance (host substrate is unchanged)")
    down.add_argument("instance")
    down.add_argument("--project", default="warden")

    proxy = sub.add_parser(
        "proxy",
        help="run the host-side CONNECT/HTTP allowlist proxy in the foreground "
             "(`warden up` starts one automatically if none is listening)",
    )
    proxy.add_argument("--allowlist-file", type=Path, default=DEFAULT_ALLOWLIST_FILE)
    proxy.add_argument("--bind", default=profiles.BRIDGE_GATEWAY)
    proxy.add_argument("--port", type=int, default=profiles.PROXY_PORT)

    restore = sub.add_parser(
        "restore",
        help="restore a snapshot and re-derive+re-prove the audit rule (§1's I6-breaks-I5 fix)",
    )
    restore.add_argument("instance")
    restore.add_argument("--flavor", choices=["monitored", "builder"], required=True)
    restore.add_argument("--llm", choices=["claude", "gemini"], required=True)
    restore.add_argument("--project", default="warden")
    restore.add_argument("--snapshot", default="clean")
    # Must match the `up` that created the instance. A restore reallocates the
    # idmap, so an audited builder restored without this flag would silently
    # skip the re-derive-and-re-prove and leave the plane pointed at a dead
    # range — the exact I6-breaks-I5 failure `restore` exists to prevent.
    restore.add_argument("--audit", action="store_true")

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
        audit=args.audit,
        secret_file=args.secret_file,
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
        proxy_controller=RealProxyAllowlistController(
            args.allowlist_file, bind=profiles.BRIDGE_GATEWAY, port=profiles.PROXY_PORT
        ),
        pool=args.pool,
    )
    try:
        result = app.up(cfg)
    except IncusNotFoundError as exc:
        print(f"NEEDS-HUMAN: {exc}", file=sys.stderr)
        return 2
    except (IncusCommandError, ProvisioningError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"up: {result.instance} created={result.created} idmap-uid={result.idmap.uid}")
    if result.capture_proof is not None:
        print(f"auditd: capture proven (uid={result.capture_proof.uid})")
    return 0


def _run(args: argparse.Namespace) -> int:
    if bool(args.prompt) == bool(args.example):
        print(
            "error: give exactly one of a prompt argument or --example", file=sys.stderr
        )
        return 2
    prompt = EXAMPLE_PROMPT if args.example else args.prompt
    prompt_source = "example" if args.example else "argument"

    instance = args.instance or f"warden-{args.flavor}"
    cfg = build_config(
        instance=instance, flavor=args.flavor, llm=args.llm,
        project=args.project, audit=args.audit, secret_file=args.secret_file,
    )
    try:
        # Fail before touching the instance, and before the wide provisioning
        # allowlist goes up — same fail-fast order as `up`.
        resolve_llm_auth(args.llm, secret_file=args.secret_file)
    except NeedsHumanError as exc:
        print(f"NEEDS-HUMAN: {exc}", file=sys.stderr)
        return 2

    runner = WorkloadRunner(
        RealIncusClient(),
        proxy_controller=RealProxyAllowlistController(
            args.allowlist_file, bind=profiles.BRIDGE_GATEWAY, port=profiles.PROXY_PORT
        ),
    )
    try:
        manifest = runner.run(
            cfg, prompt,
            prompt_source=prompt_source,
            secret_file=args.secret_file,
            wall_clock_seconds=args.timeout,
        )
    except IncusNotFoundError as exc:
        print(f"NEEDS-HUMAN: {exc}", file=sys.stderr)
        return 2
    except (IncusCommandError, WorkloadError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    out = run_dir_for(args.out, cfg.project, cfg.instance)
    out.mkdir(parents=True, exist_ok=True)
    (out / MANIFEST_NAME).write_text(manifest.to_json())
    elapsed = manifest.ended_at - manifest.started_at
    print(
        f"run: {cfg.instance} llm={manifest.llm}{'/' + manifest.llm_version if manifest.llm_version else ''} "
        f"rc={manifest.returncode}{' TIMED-OUT' if manifest.timed_out else ''} "
        f"work-phase={elapsed:.1f}s uid-scope={manifest.idmap_uid_start}-{manifest.idmap_uid_end}"
    )
    print(f"run: manifest -> {out / MANIFEST_NAME}")
    if manifest.returncode != 0:
        # Not an error exit: an agent that failed at its task still produced a
        # transcript and a trace, and that run is still reportable.
        print(
            f"run: the agent exited {manifest.returncode} — the run is still reportable",
            file=sys.stderr,
        )
    return 0


def _report(args: argparse.Namespace) -> int:
    instance = args.instance or f"warden-{args.flavor}"
    cfg = build_config(
        instance=instance, flavor=args.flavor, llm=args.llm,
        project=args.project, audit=True,
    )
    out = run_dir_for(args.out, cfg.project, cfg.instance)
    manifest_path = out / MANIFEST_NAME
    if not manifest_path.exists():
        print(
            f"error: no run manifest at {manifest_path} — run `warden run` first. "
            "`report` scopes itself from the manifest and will not guess a window.",
            file=sys.stderr,
        )
        return 1

    reporter = Reporter(
        RealIncusClient(),
        event_source_factory=lambda inst: RealEventSource(inst),
    )
    try:
        summary = reporter.report(cfg, RunManifest.load(manifest_path), out, host=args.host)
    except IncusNotFoundError as exc:
        print(f"NEEDS-HUMAN: {exc}", file=sys.stderr)
        return 2
    except CaptureNotProvenError as exc:
        # The plane is not proven capturing. Refusing is the point: reporting a clean
        # reconciliation over a blind plane is the confident-wrong-answer this build keeps
        # digging out.
        print(f"error: ground truth not proven — refusing to report over it: {exc}", file=sys.stderr)
        return 1
    except (IncusCommandError, ReportError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    (out / REPORT_NAME).write_text(summary.to_json())
    print(render(summary))
    print(f"\nartifacts: {out}")
    if not summary.consistent:
        return 1
    return 0


def _export(args: argparse.Namespace) -> int:
    instance = args.instance or f"warden-{args.flavor}"
    cfg = build_config(
        instance=instance, flavor=args.flavor, llm=args.llm, project=args.project, audit=True
    )
    run_dir = run_dir_for(args.out, cfg.project, cfg.instance)
    manifest_path = run_dir / MANIFEST_NAME
    if not manifest_path.exists():
        print(f"error: no run manifest at {manifest_path} — nothing to export", file=sys.stderr)
        return 1

    try:
        result = Exporter(RealIncusClient()).export(
            cfg, RunManifest.load(manifest_path), run_dir, args.dest
        )
    except IncusNotFoundError as exc:
        print(f"NEEDS-HUMAN: {exc}", file=sys.stderr)
        return 2
    except IncusCommandError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"export: {result.archive} ({len(result.present)} artifacts)")
    if result.missing:
        # Named, not swallowed: a tarball that is quietly short an artifact reads as a complete
        # one. CONTENTS.json inside carries the same list with reasons.
        print(f"export: NOT present — {', '.join(result.missing)} (see CONTENTS.json for why)")
    return 0


def _down(args: argparse.Namespace) -> int:
    client = RealIncusClient()
    # The audit installer is wired here too: `down` must take the
    # instance's audit rule with it, or the next instance to be allocated
    # that uid range gets captured under a dead instance's key.
    app = WardenApp(client, audit_installer=RealAuditRuleInstaller())
    try:
        removed = app.down(args.instance, args.project)
    except IncusNotFoundError as exc:
        print(f"NEEDS-HUMAN: {exc}", file=sys.stderr)
        return 2
    print(f"down: {args.instance} removed={removed}")
    return 0


def _proxy(args: argparse.Namespace) -> int:
    args.allowlist_file.parent.mkdir(parents=True, exist_ok=True)
    print(f"proxy: serving {args.allowlist_file} on {args.bind}:{args.port}", flush=True)
    run_forever(args.allowlist_file, args.bind, args.port)
    return 0


def _restore(args: argparse.Namespace) -> int:
    cfg = build_config(
        instance=args.instance, flavor=args.flavor, llm=args.llm,
        project=args.project, audit=args.audit,
    )
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
    except (IncusCommandError, ProvisioningError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
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
    if args.command == "run":
        return _run(args)
    if args.command == "report":
        return _report(args)
    if args.command == "export":
        return _export(args)
    if args.command == "down":
        return _down(args)
    if args.command == "restore":
        return _restore(args)
    if args.command == "proxy":
        return _proxy(args)
    parser.error("unknown command")
    return 2  # unreachable — parser.error exits


if __name__ == "__main__":
    raise SystemExit(main())
