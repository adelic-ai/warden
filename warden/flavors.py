"""The §2 table, as data — one codepath, two flavors.

`--flavor` is the only difference at the config layer (§0): everything in
`warden/app.py` is flavor-agnostic and just reads a `FlavorSpec`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable


class Flavor(str, Enum):
    MONITORED = "monitored"
    BUILDER = "builder"


# Domain allowlists, not CIDRs — verified against the LLM's actual
# endpoints per §3, never a stale/broad IP range.
LLM_ENDPOINTS: dict[str, tuple[str, ...]] = {
    "claude": ("api.anthropic.com",),
    "gemini": ("generativelanguage.googleapis.com",),
}

# One-time setup domains — needed to install the LLM CLI and its
# dependencies, not needed once the instance is actually running.
DEBIAN_SETUP: tuple[str, ...] = ("deb.debian.org", "security.debian.org")
NODE_SETUP: tuple[str, ...] = ("deb.nodesource.com",)

# A builder keeps these at runtime too (it's *building*, on an ongoing
# basis, not just once at provisioning) — this is the "+GitHub/npm/
# registries" row of the §2 table.
BUILDER_REGISTRIES: tuple[str, ...] = (
    "github.com",
    "objects.githubusercontent.com",
    "codeload.github.com",
    "registry.npmjs.org",
)


@dataclass(frozen=True)
class FlavorSpec:
    name: str
    llm: str
    provisioning_allowlist: tuple[str, ...]
    runtime_allowlist: tuple[str, ...]
    repo_git: bool
    auditd_wired: bool
    permission_mode: str  # "gated" | "skip-permissions"
    snapshot: bool = True


def resolve(flavor: Flavor, llm: str, extra_allow: Iterable[str] = ()) -> FlavorSpec:
    if llm not in LLM_ENDPOINTS:
        raise ValueError(f"unknown llm {llm!r}; expected one of {tuple(LLM_ENDPOINTS)}")
    llm_hosts = LLM_ENDPOINTS[llm]
    extra = tuple(extra_allow)

    if flavor is Flavor.MONITORED:
        provisioning = tuple(sorted(set(DEBIAN_SETUP) | set(llm_hosts) | set(extra)))
        runtime = tuple(sorted(set(llm_hosts) | set(extra)))
        return FlavorSpec(
            name="monitored",
            llm=llm,
            provisioning_allowlist=provisioning,
            runtime_allowlist=runtime,
            repo_git=False,
            auditd_wired=True,
            permission_mode="gated",
        )

    if flavor is Flavor.BUILDER:
        provisioning = tuple(sorted(
            set(DEBIAN_SETUP) | set(NODE_SETUP) | set(BUILDER_REGISTRIES) | set(llm_hosts) | set(extra)
        ))
        runtime = tuple(sorted(set(BUILDER_REGISTRIES) | set(llm_hosts) | set(extra)))
        return FlavorSpec(
            name="builder",
            llm=llm,
            provisioning_allowlist=provisioning,
            runtime_allowlist=runtime,
            repo_git=True,
            auditd_wired=False,
            permission_mode="skip-permissions",
        )

    raise ValueError(f"unknown flavor {flavor!r}")
