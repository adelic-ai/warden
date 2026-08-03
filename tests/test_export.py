"""`warden export` — copy all (DEMO-SPEC §5, §8.5).

The assertions worth having are about what the archive *says about itself*. A tarball that is
quietly short an artifact reads exactly like a complete one, and "verdicts.jsonl is absent" and
"the reconciliation produced no verdicts" are opposite claims that a bare `tar` cannot tell apart.
"""

from __future__ import annotations

import json
import tarfile
from pathlib import Path

import pytest

from tests.fakes import FakeIncusClient
from warden.config import build_config
from warden.export import (
    CONTENTS_NAME,
    EXPECTED,
    GIT_LOG_NAME,
    READ_ME,
    WORKREPO_TAR,
    Exporter,
)
from warden.incus import ExecResult
from warden.report import (
    AUDIT_CAPTURE_NAME,
    FINDINGS_NAME,
    REPORT_NAME,
    TRANSCRIPT_NAME,
    VERDICTS_NAME,
)
from warden.workload import MANIFEST_NAME, RUN_MANIFEST_SCHEMA_VERSION, RunManifest

T0 = 1785632030.0


def _cfg():
    return build_config(
        instance="wd-1", flavor="builder", llm="gemini", project="wardendemo", audit=True
    )


def _manifest(**kw) -> RunManifest:
    base = dict(
        schema_version=RUN_MANIFEST_SCHEMA_VERSION,
        instance="wd-1", project="wardendemo", llm="gemini", flavor="builder",
        auditd_wired=True, agentwatch_runtime="gemini",
        prompt="synthetic", prompt_source="example", prompt_sha256="0" * 64,
        llm_version="0.53.1", started_at=T0, ended_at=T0 + 50, returncode=0, timed_out=False,
        idmap_uid_start=1132072, idmap_uid_end=1197607,
        transcript_glob="/root/.warden-run/telemetry.txt", workdir="/root/work",
        run_dir="/root/.warden-run", secret_source="secret-file:/dev/null",
    )
    base.update(kw)
    return RunManifest(**base)


def _client(cfg, *, with_repo: bool = True) -> FakeIncusClient:
    client = FakeIncusClient()
    client.launch("images:debian/12", cfg.instance, cfg.project, "warden-builder")
    if with_repo:
        # The fake stages whatever `tar -czf <staged>` would have produced.
        client.file_push(
            cfg.instance, b"SYNTHETIC-TARBALL", "/root/.warden-run/workrepo.tar.gz",
            project=cfg.project,
        )
        client.exec_results["git -C"] = ExecResult(
            0, "commit deadbeef\nAuthor: agent\n\n    add slugify\n", ""
        )
    else:
        client.exec_failures["tar -czf"] = ExecResult(2, "", "tar: /root/work: No such file")
        client.exec_failures["git -C"] = ExecResult(128, "", "not a git repository")
    return client


def _populate_run_dir(run_dir: Path, *, skip=()) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / MANIFEST_NAME).write_text(_manifest().to_json())
    for name, body in (
        (TRANSCRIPT_NAME, "{}"),
        (AUDIT_CAPTURE_NAME, "type=SYSCALL ...\n"),
        (FINDINGS_NAME, ""),
        (VERDICTS_NAME, '{"provenance": "cid:x"}\n'),
        (REPORT_NAME, "{}"),
    ):
        if name not in skip:
            (run_dir / name).write_text(body)


def test_archive_contains_every_artifact_section_5_asks_for(tmp_path):
    cfg = _cfg()
    run_dir = tmp_path / "run"
    _populate_run_dir(run_dir)
    result = Exporter(_client(cfg)).export(cfg, _manifest(), run_dir, tmp_path / "out")

    with tarfile.open(result.archive) as tar:
        names = {Path(m.name).name for m in tar.getmembers()}
    for expected in (
        MANIFEST_NAME, TRANSCRIPT_NAME, AUDIT_CAPTURE_NAME, FINDINGS_NAME,
        VERDICTS_NAME, REPORT_NAME, WORKREPO_TAR, GIT_LOG_NAME, CONTENTS_NAME, READ_ME,
    ):
        assert expected in names, expected
    assert result.complete


def test_contents_json_names_what_is_missing_and_why(tmp_path):
    """The point of the file: an archive silently lacking verdicts.jsonl is indistinguishable from
    one where the reconciliation found nothing to verdict, and those are opposite claims."""
    cfg = _cfg()
    run_dir = tmp_path / "run"
    _populate_run_dir(run_dir, skip=(VERDICTS_NAME,))
    result = Exporter(_client(cfg, with_repo=False)).export(
        cfg, _manifest(), run_dir, tmp_path / "out"
    )

    contents = json.loads((run_dir / CONTENTS_NAME).read_text())
    by_file = {e["file"]: e for e in contents["entries"]}
    assert by_file[VERDICTS_NAME]["present"] is False
    assert by_file[VERDICTS_NAME]["reason"]
    assert by_file[WORKREPO_TAR]["present"] is False
    assert "may not have created it" in by_file[WORKREPO_TAR]["reason"]
    assert by_file[GIT_LOG_NAME]["present"] is False
    assert "did not commit" in by_file[GIT_LOG_NAME]["reason"]
    assert contents["complete"] is False
    assert not result.complete
    assert VERDICTS_NAME in result.missing


def test_every_expected_artifact_is_listed_even_when_absent(tmp_path):
    cfg = _cfg()
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / MANIFEST_NAME).write_text(_manifest().to_json())
    Exporter(_client(cfg, with_repo=False)).export(cfg, _manifest(), run_dir, tmp_path / "out")

    contents = json.loads((run_dir / CONTENTS_NAME).read_text())
    assert {e["file"] for e in contents["entries"]} == {name for name, _w, _y in EXPECTED}


def test_a_missing_repo_does_not_abort_the_rest_of_the_export(tmp_path):
    """"The agent never made a repo" is a fact about the run, not a reason to lose the audit
    capture and the findings."""
    cfg = _cfg()
    run_dir = tmp_path / "run"
    _populate_run_dir(run_dir)
    result = Exporter(_client(cfg, with_repo=False)).export(
        cfg, _manifest(), run_dir, tmp_path / "out"
    )
    with tarfile.open(result.archive) as tar:
        names = {Path(m.name).name for m in tar.getmembers()}
    assert AUDIT_CAPTURE_NAME in names
    assert FINDINGS_NAME in names
    assert WORKREPO_TAR not in names


def test_readme_labels_the_git_history_as_claimed_not_verified(tmp_path):
    """§5 is explicit: git history is agent-controlled and is exported as the CLAIMED work product.
    That sentence ships inside the archive rather than being left for the reader to infer."""
    cfg = _cfg()
    run_dir = tmp_path / "run"
    _populate_run_dir(run_dir)
    Exporter(_client(cfg)).export(cfg, _manifest(), run_dir, tmp_path / "out")

    readme = (run_dir / READ_ME).read_text()
    assert "CLAIM, NOT A RECORD" in readme
    assert "not trustworthy on its own" in readme
    # and the honesty bar travels with the data
    assert "ONE run" in readme
    assert "shell-out case only" in readme
    assert "Do not add them together." in readme


def test_readme_names_which_plane_is_forgeable(tmp_path):
    cfg = _cfg()
    run_dir = tmp_path / "run"
    _populate_run_dir(run_dir)
    Exporter(_client(cfg)).export(cfg, _manifest(), run_dir, tmp_path / "out")
    readme = (run_dir / READ_ME).read_text()
    assert "SELF-REPORT" in readme and "GROUND TRUTH" in readme
    assert "cannot forge" in readme


def test_archive_name_is_deterministic_for_one_run(tmp_path):
    """Two exports of one run produce one path, rather than accumulating near-identical archives
    nobody can tell apart."""
    cfg = _cfg()
    run_dir = tmp_path / "run"
    _populate_run_dir(run_dir)
    exporter = Exporter(_client(cfg))
    first = exporter.export(cfg, _manifest(), run_dir, tmp_path / "out").archive
    second = exporter.export(cfg, _manifest(), run_dir, tmp_path / "out").archive
    assert first == second
    assert first.name == f"warden-wardendemo-wd-1-{int(T0)}.tar.gz"


def test_archive_members_are_rooted_in_one_directory(tmp_path):
    """Not a nicety: an archive that explodes into the reader's cwd is a hostile artifact."""
    cfg = _cfg()
    run_dir = tmp_path / "run"
    _populate_run_dir(run_dir)
    result = Exporter(_client(cfg)).export(cfg, _manifest(), run_dir, tmp_path / "out")
    with tarfile.open(result.archive) as tar:
        roots = {Path(m.name).parts[0] for m in tar.getmembers()}
    assert len(roots) == 1
