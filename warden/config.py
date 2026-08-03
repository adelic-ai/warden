"""CLI input -> resolved `WardenConfig` (§3)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

from warden.flavors import Flavor, FlavorSpec, resolve as resolve_flavor


class NeedsHumanError(RuntimeError):
    """The wizard correctly refusing to proceed — a secret it can't
    conjure, a decision only a human should make. Not a bug: see
    NEEDS-HUMAN.md, this is that channel's programmatic counterpart."""


@dataclass(frozen=True)
class WardenConfig:
    instance: str
    flavor: Flavor
    llm: str
    host: str
    project: str
    mem: str
    cpu: str
    spec: FlavorSpec
    repo_url: str | None = None


def resolve_llm_auth(
    llm: str,
    *,
    env: Mapping[str, str] | None = None,
    secret_file: Path | None = None,
) -> str:
    """Returns a description of *where* the secret came from — never the
    secret material itself, so this is always safe to log. Raises
    `NeedsHumanError` when a real run can't proceed without a human
    supplying a key (§3: "the wizard stops before a real run without it")."""
    env = os.environ if env is None else env
    if llm == "claude":
        return "oauth/subscription (interactive `claude login`; no key material handled by warden)"
    if llm == "gemini":
        if secret_file is not None:
            if not secret_file.exists():
                raise NeedsHumanError(f"--secret-file {secret_file} does not exist")
            return f"secret-file:{secret_file}"
        if env.get("GEMINI_API_KEY"):
            return "env:GEMINI_API_KEY"
        raise NeedsHumanError(
            "gemini flavor needs GEMINI_API_KEY (env var or --secret-file) to inject as a "
            "container secret. Never committed. See NEEDS-HUMAN.md — refusing to launch a "
            "real run without it."
        )
    raise ValueError(f"unknown llm {llm!r}")


def build_config(
    *,
    instance: str,
    flavor: str,
    llm: str,
    host: str = "local",
    project: str = "warden",
    mem: str = "4GiB",
    cpu: str = "2",
    extra_allow: Iterable[str] = (),
    repo_url: str | None = None,
    audit: bool = False,
) -> WardenConfig:
    flavor_enum = Flavor(flavor)
    spec = resolve_flavor(flavor_enum, llm, extra_allow, audit=audit)
    return WardenConfig(
        instance=instance,
        flavor=flavor_enum,
        llm=llm,
        host=host,
        project=project,
        mem=mem,
        cpu=cpu,
        spec=spec,
        repo_url=repo_url,
    )
