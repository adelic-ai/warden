from pathlib import Path

import pytest

from warden.config import NeedsHumanError, build_config, resolve_llm_auth


def test_claude_needs_no_key_material():
    source = resolve_llm_auth("claude", env={})
    assert "oauth" in source


def test_gemini_without_key_anywhere_raises_needs_human():
    with pytest.raises(NeedsHumanError):
        resolve_llm_auth("gemini", env={})


def test_gemini_with_env_key_resolves():
    source = resolve_llm_auth("gemini", env={"GEMINI_API_KEY": "sk-fake-for-test"})
    assert source == "env:GEMINI_API_KEY"


def test_gemini_secret_file_must_exist(tmp_path):
    missing = tmp_path / "nope.secret"
    with pytest.raises(NeedsHumanError):
        resolve_llm_auth("gemini", env={}, secret_file=missing)


def test_gemini_secret_file_resolves_when_present(tmp_path):
    secret = tmp_path / "gemini.secret"
    secret.write_text("sk-fake-for-test")
    source = resolve_llm_auth("gemini", env={}, secret_file=secret)
    assert str(secret) in source


def test_build_config_wires_flavor_spec():
    cfg = build_config(instance="cap-1", flavor="monitored", llm="gemini", project="warden")
    assert cfg.spec.auditd_wired is True
    assert cfg.instance == "cap-1"
