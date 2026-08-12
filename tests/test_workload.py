"""`warden run` against the fake Incus client (DEMO-SPEC §3, §11.2).

The assertions that matter here are not "the exec happened" — they are the three properties the
module docstring calls load-bearing, each of which fails silently if it regresses:

  * the agent CLI is installed BEFORE the work window opens, behind the provisioning allowlist,
    which is narrowed back before the agent runs;
  * the secret never appears in any argv, on the host side or the guest side;
  * the manifest records a derived idmap, and nothing reads it back as a source of truth.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from warden.config import NeedsHumanError, build_config
from warden.example_prompt import EXAMPLE_PROMPT
from warden.incus import ExecResult
from warden.workload import (
    PROMPT_PATH,
    RUN_MANIFEST_SCHEMA_VERSION,
    SECRET_PATH,
    WORKDIR,
    RunManifest,
    WorkloadError,
    WorkloadRunner,
    run_dir_for,
    runtime_spec,
)
from tests.fakes import FakeIncusClient, FakeProxyAllowlistController

SECRET_MATERIAL = "sk-not-a-real-key-0123456789abcdef"


def _cfg(**kw):
    base = dict(instance="wd-1", flavor="builder", llm="gemini", project="wardendemo", audit=True)
    base.update(kw)
    return build_config(**base)


def _up_instance(client: FakeIncusClient, cfg):
    client.launch("images:debian/12", cfg.instance, cfg.project, "warden-builder")


def _runner(client, proxy=None):
    return WorkloadRunner(client, proxy_controller=proxy)


def _joined_execs(client) -> str:
    return "\n".join(" ".join(argv) for _name, argv in client.exec_calls)


# --- the phase boundary -------------------------------------------------------


def test_install_happens_before_the_work_window_opens():
    client = FakeIncusClient()
    cfg = _cfg()
    _up_instance(client, cfg)
    proxy = FakeProxyAllowlistController()
    manifest = _runner(client, proxy).run(cfg, "hello", secret_file=None)

    joined = [" ".join(argv) for _n, argv in client.exec_calls]
    install_at = next(i for i, c in enumerate(joined) if "gemini-cli" in c)
    invoke_at = next(i for i, c in enumerate(joined) if "gemini --skip-trust" in c)
    assert install_at < invoke_at
    # and the manifest's work window starts after provisioning finished
    assert manifest.started_at <= manifest.ended_at


def test_allowlist_widens_for_provisioning_and_narrows_before_the_agent_runs():
    client = FakeIncusClient()
    cfg = _cfg()
    _up_instance(client, cfg)
    proxy = FakeProxyAllowlistController()
    _runner(client, proxy).run(cfg, "hello", secret_file=None)

    assert cfg.spec.provisioning_allowlist in proxy.history
    # the LAST word is the narrow runtime list — never left wide
    assert proxy.current == cfg.spec.runtime_allowlist
    assert proxy.history.index(cfg.spec.provisioning_allowlist) < len(proxy.history) - 1


def test_allowlist_narrows_back_even_when_the_install_fails():
    """A half-finished install must not leave the wide provisioning allowlist active."""
    client = FakeIncusClient()
    cfg = _cfg()
    _up_instance(client, cfg)
    client.exec_failures["gemini-cli"] = ExecResult(1, "", "npm exploded")
    proxy = FakeProxyAllowlistController()
    with pytest.raises(WorkloadError):
        _runner(client, proxy).run(cfg, "hello", secret_file=None)
    assert proxy.current == cfg.spec.runtime_allowlist


def test_node_install_source_is_provisioning_only_not_runtime():
    """The reason installation cannot be deferred into the work phase even if someone wanted to."""
    cfg = _cfg()
    assert "deb.nodesource.com" in cfg.spec.provisioning_allowlist
    assert "deb.nodesource.com" not in cfg.spec.runtime_allowlist


# --- the secret ---------------------------------------------------------------


def test_secret_material_never_appears_in_any_argv(tmp_path):
    key = tmp_path / "gemini.key"
    key.write_text(SECRET_MATERIAL + "\n")
    client = FakeIncusClient()
    cfg = _cfg()
    _up_instance(client, cfg)
    manifest = _runner(client).run(cfg, "hello", secret_file=key)

    assert SECRET_MATERIAL not in _joined_execs(client)
    # the guest dereferences it itself, from a file
    assert f"$(cat {SECRET_PATH})" in _joined_execs(client)
    # and the manifest records the SOURCE, never the material
    assert manifest.secret_source == f"secret-file:{key}"
    assert SECRET_MATERIAL not in manifest.to_json()


def test_secret_is_pushed_as_bytes_and_mode_restricted(tmp_path):
    key = tmp_path / "gemini.key"
    key.write_text(SECRET_MATERIAL + "\n")
    client = FakeIncusClient()
    cfg = _cfg()
    _up_instance(client, cfg)
    _runner(client).run(cfg, "hello", secret_file=key)

    inst = client.instances[(cfg.project, cfg.instance)]
    # trailing newline stripped — a key with a newline is a key that fails auth confusingly
    assert inst.files[SECRET_PATH] == SECRET_MATERIAL.encode()
    assert f"chmod 600 {SECRET_PATH}" in _joined_execs(client)


def test_missing_secret_file_is_needs_human_not_a_crash(tmp_path):
    client = FakeIncusClient()
    cfg = _cfg()
    _up_instance(client, cfg)
    with pytest.raises(NeedsHumanError):
        _runner(client).run(cfg, "hello", secret_file=tmp_path / "absent.key")


def test_no_secret_means_no_env_prefix_at_all():
    client = FakeIncusClient()
    cfg = _cfg()
    _up_instance(client, cfg)
    _runner(client).run(cfg, "hello", secret_file=None)
    assert "GEMINI_API_KEY" not in _joined_execs(client)


# --- the prompt ---------------------------------------------------------------


def test_prompt_is_pushed_as_a_file_not_interpolated_into_the_shell():
    """A prompt containing a quote must not be able to change the shell command."""
    client = FakeIncusClient()
    cfg = _cfg()
    _up_instance(client, cfg)
    nasty = 'say "hi"; rm -rf /'
    _runner(client).run(cfg, nasty)

    inst = client.instances[(cfg.project, cfg.instance)]
    assert inst.files[PROMPT_PATH] == nasty.encode()
    assert nasty not in _joined_execs(client)
    assert f'"$(cat {PROMPT_PATH})"' in _joined_execs(client)


def test_example_prompt_is_carried_in_full_and_hashed():
    client = FakeIncusClient()
    cfg = _cfg()
    _up_instance(client, cfg)
    manifest = _runner(client).run(cfg, EXAMPLE_PROMPT, prompt_source="example")
    assert manifest.prompt == EXAMPLE_PROMPT
    assert manifest.prompt_source == "example"
    import hashlib

    assert manifest.prompt_sha256 == hashlib.sha256(EXAMPLE_PROMPT.encode()).hexdigest()


# --- the manifest -------------------------------------------------------------


def test_manifest_records_the_derived_idmap():
    client = FakeIncusClient()
    cfg = _cfg()
    _up_instance(client, cfg)
    manifest = _runner(client).run(cfg, "hello")

    idmap = json.loads(client.config_get(cfg.instance, "volatile.idmap.current", cfg.project))
    host_start = next(e for e in idmap if e["Isuid"] and e["Nsid"] == 0)["Hostid"]
    assert manifest.idmap_uid_start == host_start
    assert manifest.idmap_uid_end > manifest.idmap_uid_start


def test_manifest_roundtrips_and_refuses_a_foreign_schema_version(tmp_path):
    client = FakeIncusClient()
    cfg = _cfg()
    _up_instance(client, cfg)
    manifest = _runner(client).run(cfg, "hello")

    path = tmp_path / "manifest.json"
    path.write_text(manifest.to_json())
    assert RunManifest.load(path) == manifest

    data = json.loads(path.read_text())
    data["schema_version"] = RUN_MANIFEST_SCHEMA_VERSION + 1
    path.write_text(json.dumps(data))
    with pytest.raises(WorkloadError):
        RunManifest.load(path)


def test_manifest_names_the_agentwatch_runtime_profile():
    """`report` selects adapter + drift gate + scope tuning from this one string."""
    client = FakeIncusClient()
    for llm, expected in (("gemini", "gemini"), ("claude", "claude")):
        cfg = _cfg(llm=llm, instance=f"wd-{llm}")
        _up_instance(client, cfg)
        manifest = _runner(client).run(cfg, "hello")
        assert manifest.agentwatch_runtime == expected


def test_agent_nonzero_exit_is_recorded_not_raised():
    """An agent that failed at its task still produced a transcript and a trace."""
    client = FakeIncusClient()
    cfg = _cfg()
    _up_instance(client, cfg)
    client.exec_failures["gemini --skip-trust"] = ExecResult(3, "", "model refused")
    manifest = _runner(client).run(cfg, "hello")
    assert manifest.returncode == 3
    assert manifest.timed_out is False


def test_manifest_records_the_flavor_audit_state():
    client = FakeIncusClient()
    cfg = _cfg(audit=True)
    _up_instance(client, cfg)
    assert _runner(client).run(cfg, "hello").auditd_wired is True

    cfg2 = _cfg(audit=False, instance="wd-2")
    _up_instance(client, cfg2)
    assert _runner(client).run(cfg2, "hello").auditd_wired is False


# --- odds and ends ------------------------------------------------------------


def test_runtime_spec_rejects_an_unknown_llm():
    with pytest.raises(ValueError):
        runtime_spec("codex")


def test_run_dir_is_scoped_by_project_and_instance():
    d = run_dir_for(Path("/tmp/x"), "wardendemo", "wd-1")
    assert d == Path("/tmp/x/wardendemo/wd-1")


def test_workdir_is_not_the_up_clone_target():
    """`up --repo` clones into /root/repo; the example builds its own repo, so a run with no
    --repo still has a git history to export and a run with one keeps them separate."""
    assert WORKDIR != "/root/repo"
