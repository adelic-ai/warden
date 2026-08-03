"""`warden export` — copy all (DEMO-SPEC §5, §11.4).

The person keeps everything and analyses it with their own tools. That is the whole design: warden
produces and exports, consumers analyse (§7's "no analysis engine"). So this verb is deliberately
dumb — it collects, it does not summarise, and it never omits something because it looked
uninteresting.

Two things it does that a plain `tar` would not:

**It records what is missing, in the tarball.** `CONTENTS.json` lists every expected artifact and
whether it is present, with a reason when it is not. An archive that silently lacks
`verdicts.jsonl` is indistinguishable from one where the reconciliation found nothing to verdict —
and those are opposite claims. The manifest travels with the data, because a caveat that lives in a
README on someone else's machine is not a caveat.

**It labels the git history as claimed, not verified.** §5 is explicit: git history is
agent-controlled — the agent picks what to commit and what the message says. It is exported as the
*claimed* work product, reconcilable against FILE_WRITE ground truth (a v2 axis, §10), never
trusted alone. That sentence ships inside the archive rather than being left for the reader to
infer.
"""

from __future__ import annotations

import json
import tarfile
from dataclasses import dataclass
from pathlib import Path
from warden.config import WardenConfig
from warden.incus import IncusClient
from warden.report import (
    AUDIT_CAPTURE_NAME,
    FINDINGS_NAME,
    REPORT_NAME,
    TRANSCRIPT_NAME,
    VERDICTS_NAME,
)
from warden.workload import MANIFEST_NAME, RunManifest

EXPORT_SCHEMA_VERSION = 1

WORKREPO_TAR = "workrepo.tar.gz"
GIT_LOG_NAME = "git-log.txt"
CONTENTS_NAME = "CONTENTS.json"
READ_ME = "README.txt"

#: `(filename, what it is, why a reader should care)`. Iterated in order, so `CONTENTS.json` lists
#: everything §5 asks for whether or not the run produced it.
EXPECTED = (
    (MANIFEST_NAME, "run manifest", "what ran, when, against which derived uid range"),
    (TRANSCRIPT_NAME, "agent transcript", "the SELF-REPORT plane — what the agent says it did"),
    (AUDIT_CAPTURE_NAME, "raw audit capture", "the GROUND-TRUTH plane — host syscalls, unforgeable"),
    (FINDINGS_NAME, "findings", "agentwatch findings, one JSON object per line"),
    (VERDICTS_NAME, "verdicts", "canon DetectionVerdicts, one JSON object per line"),
    (REPORT_NAME, "report summary", "the phase split and the verdict-kind breakout"),
    (WORKREPO_TAR, "built repo", "the CLAIMED work product — agent-controlled, see README.txt"),
    (GIT_LOG_NAME, "git log", "the CLAIMED history — agent-controlled, see README.txt"),
)

_README = """\
warden export — copy all
========================

This archive is a complete copy of one warden workload run. warden does not analyse it; you do.
Nothing here has been summarised, filtered or scored on your behalf.

TWO PLANES, AND THE ASYMMETRY BETWEEN THEM

  {transcript}   the agent's SELF-REPORT. The agent produced it. It can be wrong, and an agent
                       that wanted to mislead you could make it wrong on purpose.
  {audit}        the GROUND TRUTH. The host kernel produced it, outside the container, at a
                       uid the container cannot write to. This is the plane the agent cannot forge.

The reconciliation between them is in {findings} and {verdicts}; the rollup is in {report}.

THE GIT HISTORY IS A CLAIM, NOT A RECORD

{workrepo} and {gitlog} are the work product as the agent chose to present it. The agent decides
what to `git add`, what to leave out, and what the commit message says. Treat the history as the
*claimed* work product. It is reconcilable against FILE_WRITE ground truth — that axis is not built
yet (DEMO-SPEC §10) — and it is not trustworthy on its own.

WHAT THIS RUN DOES NOT TELL YOU

  * No false-positive or false-negative rate. This is the mechanism on ONE run. Rates need a corpus
    of completed workloads; none exists yet. There are no thresholds and no triggers here.
  * Recall is validated for the shell-out case only. Fork-without-exec is invisible to an
    execve-only auditd configuration; that blind spot is REPORTED (as a canon fidelity attestation
    with cause=missing-telemetry), not caught.
  * CONFIRMED, NONE, GAP and authorized are separate on purpose. A run that only hits coverage
    boundaries is showing you blind spots, not misbehaviour. Do not add them together.

See {contents} for what is present in this archive and what is not, with reasons.
"""


@dataclass(frozen=True)
class ExportResult:
    archive: Path
    present: tuple
    missing: tuple

    @property
    def complete(self) -> bool:
        return not self.missing


class Exporter:
    """Collects the work-product plane out of the instance, then tars the run directory."""

    def __init__(self, client: IncusClient) -> None:
        self.client = client

    # -- the work-product plane ------------------------------------------------
    def collect_work_product(
        self, cfg: WardenConfig, manifest: RunManifest, run_dir: Path
    ) -> list[str]:
        """Pull the built repo and its git log out of the instance.

        Returns the reasons anything could not be collected — returned rather than raised, because
        "the agent never made a repo" is a fact about the run and belongs in `CONTENTS.json`, not
        in a traceback that loses the rest of the export.
        """
        problems: list[str] = []
        workdir = manifest.workdir
        staged = f"{manifest.run_dir}/{WORKREPO_TAR}"

        # `-C <parent> <basename>` so the archive has a directory at its root rather than exploding
        # into the reader's cwd.
        parent, _, base = workdir.rpartition("/")
        tar_cmd = f"tar -czf {staged} -C {parent or '/'} {base} 2>/dev/null"
        result = self.client.exec(cfg.instance, ["sh", "-c", tar_cmd], project=cfg.project)
        if result.ok:
            try:
                (run_dir / WORKREPO_TAR).write_bytes(
                    self.client.file_pull(cfg.instance, staged, project=cfg.project)
                )
            except FileNotFoundError:
                problems.append(f"{WORKREPO_TAR}: staged tar vanished from the instance")
        else:
            problems.append(
                f"{WORKREPO_TAR}: could not archive {workdir} "
                f"(rc={result.returncode}) — the agent may not have created it"
            )

        log = self.client.exec(
            cfg.instance,
            ["sh", "-c", f"git -C {workdir} log --stat --format=fuller --all 2>&1"],
            project=cfg.project,
        )
        if log.ok and log.stdout.strip():
            (run_dir / GIT_LOG_NAME).write_text(log.stdout)
        else:
            problems.append(
                f"{GIT_LOG_NAME}: no git history in {workdir} — the agent did not commit "
                "(or did not initialise a repository)"
            )
        return problems

    # -- the archive -----------------------------------------------------------
    def export(
        self,
        cfg: WardenConfig,
        manifest: RunManifest,
        run_dir: Path,
        dest_dir: Path,
        *,
        collect_work_product: bool = True,
    ) -> ExportResult:
        run_dir = Path(run_dir)
        dest_dir = Path(dest_dir)
        dest_dir.mkdir(parents=True, exist_ok=True)

        problems: list[str] = []
        if collect_work_product:
            problems.extend(self.collect_work_product(cfg, manifest, run_dir))

        present: list[str] = []
        missing: list[dict] = []
        entries: list[dict] = []
        for name, what, why in EXPECTED:
            path = run_dir / name
            reason = next((p.split(": ", 1)[1] for p in problems if p.startswith(f"{name}: ")), None)
            if path.exists():
                present.append(name)
                entries.append({
                    "file": name, "what": what, "why": why,
                    "present": True, "bytes": path.stat().st_size,
                })
            else:
                missing.append({"file": name, "reason": reason or "not produced by this run"})
                entries.append({
                    "file": name, "what": what, "why": why,
                    "present": False,
                    "reason": reason or (
                        "not produced by this run — see the run manifest and report summary"
                    ),
                })

        contents = {
            "schema_version": EXPORT_SCHEMA_VERSION,
            "instance": manifest.instance,
            "project": manifest.project,
            "llm": manifest.llm,
            "run_started_at": manifest.started_at,
            "run_ended_at": manifest.ended_at,
            "entries": entries,
            "complete": not missing,
            "note": (
                "An artifact listed as absent is absent for the reason given. A missing file and "
                "an empty one are different claims and are not conflated here."
            ),
        }
        (run_dir / CONTENTS_NAME).write_text(json.dumps(contents, indent=2, sort_keys=True))
        (run_dir / READ_ME).write_text(
            _README.format(
                transcript=TRANSCRIPT_NAME, audit=AUDIT_CAPTURE_NAME, findings=FINDINGS_NAME,
                verdicts=VERDICTS_NAME, report=REPORT_NAME, workrepo=WORKREPO_TAR,
                gitlog=GIT_LOG_NAME, contents=CONTENTS_NAME,
            )
        )

        # Deterministic name from the run's own clock — two exports of one run produce one path,
        # rather than accumulating near-identical archives nobody can tell apart.
        stem = f"warden-{manifest.project}-{manifest.instance}-{int(manifest.started_at)}"
        archive = dest_dir / f"{stem}.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            for path in sorted(run_dir.iterdir()):
                if path.is_file():
                    tar.add(path, arcname=f"{stem}/{path.name}")
        return ExportResult(
            archive=archive, present=tuple(present), missing=tuple(m["file"] for m in missing)
        )
