from __future__ import annotations

import hashlib
import io
import tarfile

from tests.fakes import FakeIncusClient, FakeProxyAllowlistController
from warden.app import WardenApp
from warden.build_vm import BuildResult
from warden.incus import ExecResult
from warden.output_verify import (
    FunctionalVerifier,
    check_artifacts,
    self_report,
)

T0 = 1785632030.0


def _build_result(**kw) -> BuildResult:
    base = dict(
        instance="build-1", project="warden", returncode=0, stdout="", stderr="",
        timed_out=False, started_at=T0, ended_at=T0 + 10, secret_source=None, artifacts=None,
    )
    base.update(kw)
    return BuildResult(**base)


def _tarball(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, content in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _app(client):
    proxy = FakeProxyAllowlistController()
    return WardenApp(client, proxy_controller=proxy)


# -- check_artifacts: host-verifiable, never touches the build again -----------------------------


def test_check_artifacts_absent_when_no_bytes():
    check = check_artifacts(_build_result(artifacts=None))
    assert check.present is False
    assert check.file_count == 0
    assert "no artifacts produced" in check.problems[0]


def test_check_artifacts_flags_a_corrupt_tarball():
    check = check_artifacts(_build_result(artifacts=b"not actually a tarball"))
    assert check.present is False
    assert "corrupt" in check.problems[0]


def test_check_artifacts_counts_files_and_hashes_real_bytes():
    payload = _tarball({"out.txt": b"hello", "sub/file.py": b"print(1)\n"})
    check = check_artifacts(_build_result(artifacts=payload))
    assert check.present is True
    assert check.file_count == 2
    assert check.sha256 == hashlib.sha256(payload).hexdigest()
    assert check.problems == ()


def test_check_artifacts_flags_an_empty_tarball():
    payload = _tarball({})
    check = check_artifacts(_build_result(artifacts=payload))
    assert check.present is False
    assert "no files" in check.problems[0]


# -- self_report: forgeable, carried through and labeled, truncated ------------------------------


def test_self_report_carries_returncode_and_truncates_long_output():
    huge = "x" * 10_000
    result = _build_result(returncode=1, stdout=huge, stderr="boom", timed_out=True)
    report = self_report(result)
    assert report.returncode == 1
    assert report.timed_out is True
    assert len(report.stdout_tail) == 4000
    assert report.stdout_tail == huge[-4000:]


# -- FunctionalVerdict: the load-bearing separation -----------------------------------------------


def test_tests_verified_is_none_when_no_rerun_was_requested():
    client = FakeIncusClient()
    verifier = FunctionalVerifier(_app(client))
    payload = _tarball({"out.txt": b"x"})

    verdict = verifier.verify(_build_result(artifacts=payload, returncode=0))

    assert verdict.trusted_rerun is None
    assert verdict.tests_verified is None
    assert verdict.artifacts_present is True


def test_tests_verified_never_derives_from_the_builds_own_returncode():
    # The build self-reports success (returncode=0, "all tests passed") — exactly the forgeable
    # claim this module exists to not trust. The trusted re-run says otherwise, and the re-run
    # must win: this is the whole point.
    client = FakeIncusClient()
    client.exec_results["python3 -m pytest"] = ExecResult(1, "", "2 failed")
    verifier = FunctionalVerifier(_app(client))
    payload = _tarball({"out.txt": b"x"})
    build_result = _build_result(artifacts=payload, returncode=0, stdout="all tests passed")

    verdict = verifier.verify(
        build_result, test_cmd=["python3", "-m", "pytest"], instance="verify-1", project="warden"
    )

    assert verdict.build_self_report.returncode == 0  # the (forgeable) claim, carried through
    assert verdict.trusted_rerun.ran is True
    assert verdict.trusted_rerun.returncode == 1
    assert verdict.tests_verified is False  # the re-run's real result, not the build's claim


def test_tests_verified_true_when_trusted_rerun_actually_passes():
    client = FakeIncusClient()
    client.exec_results["python3 -m pytest"] = ExecResult(0, "4 passed", "")
    verifier = FunctionalVerifier(_app(client))
    payload = _tarball({"out.txt": b"x"})

    verdict = verifier.verify(
        _build_result(artifacts=payload),
        test_cmd=["python3", "-m", "pytest"], instance="verify-1", project="warden",
    )

    assert verdict.tests_verified is True


# -- trusted_rerun: the part that actually touches Incus ------------------------------------------


def test_trusted_rerun_skips_without_launching_when_no_artifacts():
    client = FakeIncusClient()
    verifier = FunctionalVerifier(_app(client))

    rerun = verifier.trusted_rerun(
        _build_result(artifacts=None), test_cmd=["true"], instance="verify-1", project="warden"
    )

    assert rerun.ran is False
    assert "no artifacts" in rerun.skip_reason
    assert client.instance_exists("verify-1", "warden") is False


def test_trusted_rerun_extracts_and_runs_in_a_fresh_instance_then_tears_down():
    client = FakeIncusClient()
    client.exec_results["python3 -m pytest"] = ExecResult(0, "4 passed", "")
    verifier = FunctionalVerifier(_app(client))
    payload = _tarball({"out.txt": b"x"})

    rerun = verifier.trusted_rerun(
        _build_result(artifacts=payload),
        test_cmd=["python3", "-m", "pytest"], instance="verify-1", project="warden",
    )

    assert rerun.ran is True
    assert rerun.returncode == 0
    assert rerun.stdout == "4 passed"
    # thrown away after — a verification instance is not left behind
    assert client.instance_exists("verify-1", "warden") is False


def test_trusted_rerun_tears_down_even_when_extraction_fails():
    client = FakeIncusClient()
    client.exec_failures["tar -xzf"] = ExecResult(2, "", "tar: unexpected EOF")
    verifier = FunctionalVerifier(_app(client))
    payload = _tarball({"out.txt": b"x"})

    rerun = verifier.trusted_rerun(
        _build_result(artifacts=payload), test_cmd=["true"], instance="verify-1", project="warden"
    )

    assert rerun.ran is False
    assert "extraction failed" in rerun.skip_reason
    assert client.instance_exists("verify-1", "warden") is False
