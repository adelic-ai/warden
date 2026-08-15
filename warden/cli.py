"""`warden up` / `warden down` — the CLI entrypoint (§3, §7 step 5).

Wires the real (subprocess/root-requiring) adapters. All the actual logic
lives in `warden/app.py` and is identical to what's exercised against
`FakeIncusClient` in `tests/` — this module's only job is argument
parsing and adapter construction.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path
from typing import Optional

from warden import profiles, workload
from warden.app import PersistentInstanceError, ProvisioningError, WardenApp
from warden.privilege import elevate
from warden.auditd import CaptureNotProvenError, RealAuditRuleInstaller, RealEventSource
from warden.config import NeedsHumanError, build_config, resolve_llm_auth
from warden.deploy import DeployError, deploy_code
from warden.example_prompt import EXAMPLE_PROMPT
from warden.incus import IncusCommandError, IncusNotFoundError, RealIncusClient
from warden.mold import MoldError, build_vantage_mold
from warden.proxy import RealProxyAllowlistController, run_forever
from warden.recover import SubstrateUnrecovered, diagnose_and_recover, run_with_recovery
from warden.remote_dev import RemoteDevError, create_nested_dev, enter_nested_shell
from warden.remote_report import RemoteReportError, report_nested_live
from warden.export import Exporter
from warden.idmap import derive_idmap
from warden.vantage import (
    DEFAULT_NAME as VANTAGE_DEFAULT_NAME,
    DEFAULT_PROJECT as VANTAGE_DEFAULT_PROJECT,
    GOLDEN_ALIAS,
    VantageError,
    ensure_vantage_vm,
)
from warden.report import (
    DEFAULT_EBPF_CAPTURE_SECONDS,
    PROVISIONED_AT_KEY,
    REPORT_NAME,
    SESSION_STARTED_KEY,
    TRANSCRIPT_NAME,
    ReportError,
    Reporter,
    live_manifest,
    parse_since,
    render,
)
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
    report.add_argument(
        "--live", action="store_true",
        help="reconcile a persistent `dev` home that has no run manifest — scope from the live "
             "instance and a --since window instead. Forces --flavor dev.",
    )
    report.add_argument(
        "--since", default=None,
        help="live only: window of lookback (e.g. 45m, 2h, 3d) or an absolute epoch. Defaults to the "
             "home's recorded provisioning time; refuses to guess if neither is available.",
    )
    report.add_argument("--project", default="warden")
    report.add_argument("--audit", action="store_true", default=True,
                        help="(implied — report requires the ground-truth plane)")
    report.add_argument("--out", type=Path, default=DEFAULT_RUNS_DIR, help="host artifact root")
    report.add_argument("--host", default=None, help="hostname recorded in verdicts; defaults to this host")
    report.add_argument(
        "--ebpf", action="store_true",
        help="capture with the eBPF probe (fork-gap-robust, decision B) instead of the auditd log. "
             "Live-only (the ring buffer is ephemeral), so it requires --live and captures a window.",
    )
    report.add_argument(
        "--capture-seconds", type=int, default=DEFAULT_EBPF_CAPTURE_SECONDS, dest="capture_seconds",
        help=f"eBPF live-capture window in seconds (default {DEFAULT_EBPF_CAPTURE_SECONDS}; --ebpf only)",
    )
    report.add_argument(
        "--vantage", action="store_true",
        help="reconcile a `dev --vantage` home: the auditd/eBPF plane belongs to the vantage VM's "
             "OWN kernel, not this host's, so this remote-drives `report --live` inside the VM "
             "(against its own nested Incus) and pulls the artifacts back. Requires --live.",
    )
    report.add_argument("--vantage-name", default=VANTAGE_DEFAULT_NAME, help="--vantage only")
    report.add_argument("--vantage-project", default=VANTAGE_DEFAULT_PROJECT, help="--vantage only")

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
    down.add_argument("--force", action="store_true",
                      help="delete even a persistent dev home (otherwise refused — Fork P)")

    dev = sub.add_parser(
        "dev",
        help="stand up (or reuse) your persistent free-form dev home — key-free, egress-locked, "
             "audited — and drop into a shell inside it",
    )
    dev.add_argument("--name", default="warden-dev", help="dev home instance (default: warden-dev)")
    dev.add_argument("--llm", choices=["claude", "gemini"], required=True,
                     help="scopes egress to this LLM's endpoint; you bring your own auth inside")
    dev.add_argument("--project", default="warden")
    dev.add_argument("--mem", default="4GiB")
    dev.add_argument("--cpu", default="2")
    dev.add_argument("--allow", action="append", default=[], dest="extra_allow", metavar="DOMAIN")
    dev.add_argument("--allowlist-file", type=Path, default=DEFAULT_ALLOWLIST_FILE)
    dev.add_argument("--pool", default=profiles.STORAGE_POOL)
    dev.add_argument("--no-shell", action="store_true",
                     help="just ensure the home is up; do not exec a shell into it")
    dev.add_argument(
        "--no-agentwatch", action="store_true",
        help="--vantage only: skip deploying agentwatch — the capture plane (auditd/bpftrace/"
             "cgroups) is baked into the golden image and needs no code; only `report`'s "
             "reconciliation needs agentwatch, not `dev` standing the home up. A later "
             "`report --live --vantage` against a home built this way refuses until redeployed "
             "without this flag.",
    )
    dev.add_argument(
        "--vantage", action="store_true",
        help="run the dev home nested inside a persistent vantage VM instead of directly on this "
             "host (decision B: gives eBPF a kernel above the container to attach to, closing the "
             "fork-gap blind spot a shared-kernel container has). Requires a golden image already "
             "published — see `warden vantage-mold`.",
    )
    dev.add_argument("--vantage-name", default=VANTAGE_DEFAULT_NAME, help="--vantage only")
    dev.add_argument("--vantage-project", default=VANTAGE_DEFAULT_PROJECT, help="--vantage only")
    dev.add_argument("--vantage-mem", default="3GiB", help="--vantage only")
    dev.add_argument("--vantage-cpu", default="2", help="--vantage only")

    vantage_mold = sub.add_parser(
        "vantage-mold",
        help="build (or rebuild) the golden vantage-VM image `dev --vantage` launches from — "
             "OS + Incus + `admin init` only, no warden/agentwatch (those deploy fresh every "
             "launch); one-time and slow (~30min), not run automatically by `dev --vantage`",
    )
    vantage_mold.add_argument("--vantage-project", default=VANTAGE_DEFAULT_PROJECT)
    vantage_mold.add_argument("--mem", default="3GiB")
    vantage_mold.add_argument("--cpu", default="2")
    vantage_mold.add_argument("--allowlist-file", type=Path, default=DEFAULT_ALLOWLIST_FILE)
    vantage_mold.add_argument("--pool", default=profiles.STORAGE_POOL)

    proxy = sub.add_parser(
        "proxy",
        help="run the host-side CONNECT/HTTP allowlist proxy in the foreground "
             "(`warden up` starts one automatically if none is listening)",
    )
    proxy.add_argument("--allowlist-file", type=Path, default=DEFAULT_ALLOWLIST_FILE)
    proxy.add_argument("--bind", default=profiles.BRIDGE_GATEWAY)
    proxy.add_argument("--port", type=int, default=profiles.PROXY_PORT)
    proxy.add_argument(
        "--upstream-proxy", default=None, metavar="HOST:PORT",
        help="relay through a parent proxy instead of connecting to targets directly — needed "
             "when this proxy itself runs behind another one (container-in-VM shape)",
    )

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

    verify = sub.add_parser(
        "verify",
        help="runtime-PROVE every ring on a running instance (measures deny; does not assume)",
    )
    verify.add_argument("instance")
    verify.add_argument("--flavor", choices=["monitored", "builder"], required=True)
    verify.add_argument("--llm", choices=["claude", "gemini"], required=True)
    verify.add_argument("--project", default="warden")
    verify.add_argument("--audit", action="store_true",
                        help="must match the up that created it — verify re-proves audit capture when set")
    verify.add_argument("--probe-host", default="example.com",
                        help="a NON-allowlisted host that must be blocked (default: example.com)")
    verify.add_argument("--lan-gateway", default=None,
                        help="optional LAN gateway IP that must be unreachable (e.g. from `ip route`)")

    recover = sub.add_parser(
        "recover",
        help="diagnose a wedged Incus substrate and self-heal what warden is privileged for "
             "(stuck operation / hung instance); a daemon-level wedge is surfaced, never faked",
    )
    recover.add_argument("--instance", default=None,
                         help="also probe this instance for a hung agent (the L2 check)")
    recover.add_argument("--project", default="warden")

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
    audit_installer = RealAuditRuleInstaller()
    app = WardenApp(
        client,
        audit_installer=audit_installer,
        event_source_factory=lambda inst: RealEventSource(inst),
        proxy_controller=RealProxyAllowlistController(
            args.allowlist_file, bind=profiles.BRIDGE_GATEWAY, port=profiles.PROXY_PORT,
            upstream_proxy=os.environ.get(profiles.UPSTREAM_PROXY_ENV_VAR),
        ),
        pool=args.pool,
    )
    try:
        # up() is idempotent, so on a mid-operation Incus timeout warden auto-diagnoses the
        # substrate, self-heals a stuck-op/hung-instance (L1/L2), and retries once; an L3 daemon
        # wedge it can't fix is surfaced (SubstrateUnrecovered), never retried into a hang.
        result = run_with_recovery(
            app.client, lambda: app.up(cfg),
            instance=cfg.instance, project=cfg.project,
            log=lambda m: print(m, file=sys.stderr),
        )
    except IncusNotFoundError as exc:
        print(f"NEEDS-HUMAN: {exc}", file=sys.stderr)
        return 2
    except SubstrateUnrecovered as exc:
        print(f"NEEDS-HUMAN: {exc}", file=sys.stderr)
        return 2
    except (IncusCommandError, ProvisioningError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"up: {result.instance} created={result.created} idmap-uid={result.idmap.uid}")
    if result.capture_proof is not None:
        print(f"auditd: capture proven (uid={result.capture_proof.uid})")
    if audit_installer.persistence_installed is False:
        # The live rule is loaded and proven capturing; only reboot-persistence was skipped.
        # Said out loud, because the alternative is an operator who believes the plane survives a
        # restart when it does not.
        print(
            "auditd: rules.d persistence SKIPPED (no write access) — the live rule is loaded and "
            "proven, but it will not survive a reboot",
            file=sys.stderr,
        )
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
            args.allowlist_file, bind=profiles.BRIDGE_GATEWAY, port=profiles.PROXY_PORT,
            upstream_proxy=os.environ.get(profiles.UPSTREAM_PROXY_ENV_VAR),
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


def _resolve_live_since(client, cfg, since_arg: Optional[str]) -> float:
    """The `--since` epoch for a live reconcile. Explicit relative/epoch wins; else default to THIS
    session (stamped by `warden dev` on entry) — the zero-config common case; else the furnishing
    time; else refuse — `report` does not guess a window (same rule as the workload path)."""
    if since_arg:
        rel = parse_since(since_arg)
        if rel is not None:
            return time.time() - rel
        try:
            return float(since_arg)
        except ValueError:
            raise ReportError(
                f"--since {since_arg!r} is neither a window (45m/2h/3d) nor an epoch."
            )
    # Default: this session, then the furnishing boundary — whichever is present and later.
    for key in (SESSION_STARTED_KEY, PROVISIONED_AT_KEY):
        stamped = client.config_get(cfg.instance, key, project=cfg.project)
        if stamped:
            return float(stamped)
    raise ReportError(
        f"{cfg.instance} has no session or provisioning boundary recorded and no --since was given. "
        "A live reconcile will not guess a window — enter it with `warden dev` (which stamps the "
        "session), or pass --since (e.g. --since 1h)."
    )


def _report_vantage(args: argparse.Namespace) -> int:
    """`warden report --live --vantage` — remote-drives the ordinary `report --live` command inside
    the vantage VM (see `remote_report.py`'s module docstring for why: the plane it reconciles is a
    property of that VM's kernel, not this host's) and pulls the artifacts back."""
    instance = args.instance or "warden-dev"
    client = RealIncusClient()
    app = WardenApp(client)
    out = run_dir_for(args.out, args.project, instance)

    try:
        result = report_nested_live(
            app, vantage_instance=args.vantage_name, vantage_project=args.vantage_project,
            container_name=instance, nested_project=args.project, llm=args.llm,
            local_out_dir=out, since=args.since, ebpf=getattr(args, "ebpf", False),
            capture_seconds=getattr(args, "capture_seconds", None), host=args.host,
        )
    except IncusNotFoundError as exc:
        print(f"NEEDS-HUMAN: {exc}", file=sys.stderr)
        return 2
    except RemoteReportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except IncusCommandError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    if result.artifacts_pulled:
        # The remote stdout above already printed its OWN "artifacts: ..." line — that path is on
        # the vantage VM's disk, not reachable from here. Labeled so the two don't read as the same
        # claim printed twice.
        print(f"\nartifacts (pulled to this host): {out}")
    else:
        # Not swallowed: the remote command's own stdout/stderr above already carries its honest
        # failure — this just says out loud that nothing was fetched, rather than silently leaving
        # a stale or absent local directory that looks the same as "ran clean, wrote nothing".
        print(f"\nartifacts: NOT pulled ({result.pull_error})", file=sys.stderr)
    return result.returncode


def _report(args: argparse.Namespace) -> int:
    live = getattr(args, "live", False)
    use_ebpf = getattr(args, "ebpf", False)
    vantage = getattr(args, "vantage", False)
    if use_ebpf and not live:
        print(
            "error: --ebpf is live-only (its ring buffer is ephemeral, unlike the auditd log). "
            "Use `warden report --live --ebpf`.",
            file=sys.stderr,
        )
        return 1
    if vantage and not live:
        print(
            "error: --vantage reconciles a `dev --vantage` home, which only exists as a live "
            "(persistent, manifest-free) instance. Use `warden report --live --vantage`.",
            file=sys.stderr,
        )
        return 1
    if vantage:
        return _report_vantage(args)
    flavor = "dev" if live else args.flavor
    instance = args.instance or f"warden-{flavor}"
    cfg = build_config(
        instance=instance, flavor=flavor, llm=args.llm,
        project=args.project, audit=True,
    )
    out = run_dir_for(args.out, cfg.project, cfg.instance)

    reporter = Reporter(
        RealIncusClient(),
        event_source_factory=lambda inst: RealEventSource(inst),
    )
    try:
        if use_ebpf:
            # Decision B: agentwatch loads its own probe on the vantage (warden elevates + invokes).
            # A synthesized live manifest just supplies the transcript location + runtime; the eBPF
            # capture window, not a --since lookback, defines what the plane covers.
            since = _resolve_live_since(reporter.client, cfg, args.since)
            manifest = live_manifest(reporter.client, cfg, since=since, out_dir=out)
            agent_uid = derive_idmap(reporter.client, cfg.instance, project=cfg.project).uid.host_start
            transcript_path = reporter.pull_transcript(cfg, manifest, out / TRANSCRIPT_NAME)
            result = reporter.reconcile_ebpf_live(
                out,
                agent_uid=agent_uid,
                duration_s=args.capture_seconds,
                transcript_path=transcript_path,
                runtime=manifest.agentwatch_runtime,
                host=args.host,
            )
            print(
                f"eBPF live reconcile ({result.capture_window_s}s window): "
                f"{result.ground_truth_execs} agent execs captured, "
                f"{result.findings_written} finding(s) written to {out / 'findings.jsonl'}"
            )
            return 0
        if live:
            since = _resolve_live_since(reporter.client, cfg, args.since)
            manifest = live_manifest(reporter.client, cfg, since=since, out_dir=out)
        else:
            manifest_path = out / MANIFEST_NAME
            if not manifest_path.exists():
                print(
                    f"error: no run manifest at {manifest_path} — run `warden run` first. "
                    "`report` scopes itself from the manifest and will not guess a window.",
                    file=sys.stderr,
                )
                return 1
            manifest = RunManifest.load(manifest_path)
        summary = reporter.report(cfg, manifest, out, host=args.host)
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
        removed = app.down(args.instance, args.project, force=args.force)
    except IncusNotFoundError as exc:
        print(f"NEEDS-HUMAN: {exc}", file=sys.stderr)
        return 2
    except PersistentInstanceError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    print(f"down: {args.instance} removed={removed}")
    return 0


def _dev(args: argparse.Namespace) -> int:
    if args.vantage:
        return _dev_vantage(args)
    cfg = build_config(
        instance=args.name, flavor="dev", llm=args.llm, host="local",
        project=args.project, mem=args.mem, cpu=args.cpu, extra_allow=args.extra_allow,
    )
    args.allowlist_file.parent.mkdir(parents=True, exist_ok=True)
    app = WardenApp(
        RealIncusClient(),
        audit_installer=RealAuditRuleInstaller(),
        event_source_factory=lambda inst: RealEventSource(inst),
        proxy_controller=RealProxyAllowlistController(
            args.allowlist_file, bind=profiles.BRIDGE_GATEWAY, port=profiles.PROXY_PORT,
            upstream_proxy=os.environ.get(profiles.UPSTREAM_PROXY_ENV_VAR),
        ),
        pool=args.pool,
    )
    try:
        # up() is idempotent, so auto-recover a mid-up wedge and retry — the daily home must never
        # lock you out (ROADMAP: reliability = SLA). No key gate: `dev` is needs_secret=False.
        result = run_with_recovery(
            app.client, lambda: app.up(cfg),
            instance=cfg.instance, project=cfg.project,
            log=lambda m: print(m, file=sys.stderr),
        )
    except IncusNotFoundError as exc:
        print(f"NEEDS-HUMAN: {exc}", file=sys.stderr)
        return 2
    except SubstrateUnrecovered as exc:
        print(f"NEEDS-HUMAN: {exc}", file=sys.stderr)
        return 2
    except (IncusCommandError, ProvisioningError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"dev: {result.instance} up (created={result.created}, persistent, key-free)", file=sys.stderr)
    enter = f"sudo incus exec {result.instance} --project {args.project} -- bash -l"
    if args.no_shell:
        print(f"dev: home ready — enter with: {enter}")
        return 0
    # Stamp the session boundary NOW — the last thing before the shell is yours — so warden's own
    # up execs stay before it and `warden report --live` defaults its window to this session with no
    # --since and no manual reset. Host-side config_set: it does not exec into the container.
    app.client.config_set(
        result.instance, SESSION_STARTED_KEY, str(time.time()), project=args.project
    )
    # Hand the terminal to an interactive login shell inside the home. os.execvp REPLACES warden, so
    # you ARE in the container until you exit; on exit, control returns to your host shell.
    print(f"dev: entering {result.instance} … (exit the shell to return)", file=sys.stderr)
    argv = elevate(["incus", "exec", result.instance, "--project", args.project, "--", "bash", "-l"])
    os.execvp(argv[0], argv)
    return 0  # unreachable — execvp replaces the process


def _dev_vantage(args: argparse.Namespace) -> int:
    """`warden dev --vantage` — VANTAGE-PLAN.md's 7 phases wired end to end: ensure the persistent
    vantage VM, deploy fresh warden+agentwatch onto it, drive its OWN nested Incus to stand up the
    dev home, and (unless --no-shell) hand the terminal to a shell inside it, one level down.

    Known gap, not silently papered over: `warden report --live` still talks to the outer Incus
    directly and cannot see a nested container yet — reconciling a --vantage dev home needs that
    path taught the double-hop too; not done here.
    """
    args.allowlist_file.parent.mkdir(parents=True, exist_ok=True)
    client = RealIncusClient()
    app = WardenApp(
        client,
        proxy_controller=RealProxyAllowlistController(
            args.allowlist_file, bind=profiles.BRIDGE_GATEWAY, port=profiles.PROXY_PORT,
            upstream_proxy=os.environ.get(profiles.UPSTREAM_PROXY_ENV_VAR),
        ),
        pool=args.pool,
    )

    # Refuse to launch a fresh vantage VM from the stock image — it would have no nested Incus at
    # all, and deploy/create-nested-dev would fail confusingly two steps later instead of here. An
    # ALREADY-running vantage VM is trusted as-is (it may predate the mold, e.g. built by hand).
    if not client.instance_exists(
        args.vantage_name, args.vantage_project
    ) and not client.image_exists(GOLDEN_ALIAS, project=args.vantage_project):
        print(
            f"NEEDS-HUMAN: no {GOLDEN_ALIAS!r} image in project {args.vantage_project!r} yet — "
            f"build one first (one-time, ~30min): "
            f"warden vantage-mold --vantage-project {args.vantage_project}",
            file=sys.stderr,
        )
        return 2

    try:
        vm = run_with_recovery(
            client, lambda: ensure_vantage_vm(
                app, name=args.vantage_name, project=args.vantage_project,
                mem=args.vantage_mem, cpu=args.vantage_cpu,
            ),
            instance=args.vantage_name, project=args.vantage_project,
            log=lambda m: print(m, file=sys.stderr),
        )
    except IncusNotFoundError as exc:
        print(f"NEEDS-HUMAN: {exc}", file=sys.stderr)
        return 2
    except SubstrateUnrecovered as exc:
        print(f"NEEDS-HUMAN: {exc}", file=sys.stderr)
        return 2
    except (IncusCommandError, VantageError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"dev --vantage: {vm.name} vantage VM up (created={vm.created})", file=sys.stderr)

    try:
        deployed = deploy_code(
            app, instance=vm.name, project=vm.project, include_agentwatch=not args.no_agentwatch,
        )
    except DeployError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    agentwatch_note = (
        f"agentwatch@{deployed.agentwatch_commit}" if deployed.agentwatch_commit
        else "agentwatch SKIPPED (--no-agentwatch — report --live --vantage will refuse until redeployed)"
    )
    print(f"dev --vantage: deployed warden@{deployed.warden_commit} {agentwatch_note}", file=sys.stderr)

    try:
        nested = create_nested_dev(
            app, vantage_instance=vm.name, vantage_project=vm.project,
            llm=args.llm, name=args.name, mem=args.mem, cpu=args.cpu,
            nested_project=args.project,
        )
    except RemoteDevError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    enter = (
        f"sudo incus exec {vm.name} --project {vm.project} -- "
        f"incus exec {nested.name} --project {nested.nested_project} -- bash -l"
    )
    if args.no_shell:
        print(f"dev --vantage: home ready — enter with: {enter}")
        return 0

    print(
        f"dev --vantage: entering {nested.name} inside {vm.name} … (exit the shell to return)",
        file=sys.stderr,
    )
    # os.execvp REPLACES warden, same as the direct-container path above — control returns to your
    # host shell only when you exit the nested shell.
    enter_nested_shell(
        vantage_instance=vm.name, container_name=nested.name,
        vantage_project=vm.project, nested_project=nested.nested_project,
    )
    return 0  # unreachable — enter_nested_shell's execvp replaces the process


def _vantage_mold(args: argparse.Namespace) -> int:
    script_path = Path(__file__).resolve().parent.parent / "scripts" / "install-incus-nested.sh"
    try:
        install_script = script_path.read_text()
    except OSError as exc:
        print(f"error: could not read {script_path}: {exc}", file=sys.stderr)
        return 1

    args.allowlist_file.parent.mkdir(parents=True, exist_ok=True)
    client = RealIncusClient()
    app = WardenApp(
        client,
        proxy_controller=RealProxyAllowlistController(
            args.allowlist_file, bind=profiles.BRIDGE_GATEWAY, port=profiles.PROXY_PORT,
            upstream_proxy=os.environ.get(profiles.UPSTREAM_PROXY_ENV_VAR),
        ),
        pool=args.pool,
    )
    try:
        result = build_vantage_mold(
            app, install_script, project=args.vantage_project, mem=args.mem, cpu=args.cpu,
        )
    except IncusNotFoundError as exc:
        print(f"NEEDS-HUMAN: {exc}", file=sys.stderr)
        return 2
    except (IncusCommandError, VantageError, MoldError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"vantage-mold: published {result.alias} (fingerprint={result.fingerprint})")
    return 0


def _proxy(args: argparse.Namespace) -> int:
    args.allowlist_file.parent.mkdir(parents=True, exist_ok=True)
    suffix = f" via upstream {args.upstream_proxy}" if args.upstream_proxy else ""
    print(f"proxy: serving {args.allowlist_file} on {args.bind}:{args.port}{suffix}", flush=True)
    run_forever(args.allowlist_file, args.bind, args.port, upstream_proxy=args.upstream_proxy)
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


def _verify(args: argparse.Namespace) -> int:
    cfg = build_config(
        instance=args.instance, flavor=args.flavor, llm=args.llm,
        project=args.project, audit=args.audit,
    )
    app = WardenApp(
        RealIncusClient(),
        audit_installer=RealAuditRuleInstaller(),
        event_source_factory=lambda inst: RealEventSource(inst),
        # verify only reads/probes; no allowlist file is written, so no proxy controller is needed.
    )
    try:
        result = app.verify(cfg, probe_host=args.probe_host, lan_gateway=args.lan_gateway)
    except IncusNotFoundError as exc:
        print(f"NEEDS-HUMAN: {exc}", file=sys.stderr)
        return 2
    except IncusCommandError as exc:
        # e.g. the readiness check times out on a wedged daemon — a clean error + exit 1, the same
        # shape every other handler uses, never a raw traceback.
        print(f"error: {exc}", file=sys.stderr)
        return 1

    symbol = {"pass": "PASS", "fail": "FAIL", "skip": "skip"}
    for r in result.rings:
        print(f"  [{symbol.get(r.status, r.status):4}] {r.ring}: {r.detail}")
    print(f"verify: {result.instance} — {'ALL RINGS PROVEN' if result.ok else 'FAILED (see above)'}")
    return 0 if result.ok else 1


def _recover(args: argparse.Namespace) -> int:
    client = RealIncusClient()
    try:
        result = diagnose_and_recover(client, instance=args.instance, project=args.project)
    except IncusNotFoundError as exc:
        print(f"NEEDS-HUMAN: {exc}", file=sys.stderr)
        return 2
    except IncusCommandError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"diagnosis: {result.diagnosis.tier} — {result.diagnosis.detail}")
    if result.needs_human is not None:
        # a daemon-level wedge warden cannot fix — surfaced, exit 2 (NEEDS-HUMAN), never a false green
        print(f"NEEDS-HUMAN: {result.needs_human}", file=sys.stderr)
        return 2
    print(f"recover: {result.action}")
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
    if args.command == "dev":
        return _dev(args)
    if args.command == "vantage-mold":
        return _vantage_mold(args)
    if args.command == "restore":
        return _restore(args)
    if args.command == "verify":
        return _verify(args)
    if args.command == "recover":
        return _recover(args)
    if args.command == "proxy":
        return _proxy(args)
    parser.error("unknown command")
    return 2  # unreachable — parser.error exits


if __name__ == "__main__":
    raise SystemExit(main())
