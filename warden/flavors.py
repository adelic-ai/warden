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
    DEV = "dev"


# Domain allowlists, not CIDRs — verified against the LLM's actual
# endpoints per §3, never a stale/broad IP range.
LLM_ENDPOINTS: dict[str, tuple[str, ...]] = {
    "claude": ("api.anthropic.com",),
    "gemini": ("generativelanguage.googleapis.com",),
}

# Interactive-login endpoints for the `dev` flavor. The operator authenticates their OWN account
# (`gemini` "Login with Google" / `claude` subscription login) — warden injects no key — so egress
# must reach the OAuth login + token hosts and the account-tier API the CLI talks to under that auth.
# These are runtime hosts (login happens when the operator runs the agent), unlike DEBIAN/NODE_SETUP.
# Determined empirically against the CLI login flow: deny-by-default egress surfaces any missing host.
LLM_AUTH_ENDPOINTS: dict[str, tuple[str, ...]] = {
    # gemini free-tier OAuth talks to Code Assist (cloudcode-pa), not the API-key endpoint.
    "gemini": (
        "accounts.google.com",
        "oauth2.googleapis.com",
        "www.googleapis.com",
        "cloudcode-pa.googleapis.com",
    ),
    "claude": ("claude.ai", "console.anthropic.com"),
}

# One-time setup domains — needed to install the LLM CLI and its
# dependencies, not needed once the instance is actually running.
DEBIAN_SETUP: tuple[str, ...] = ("deb.debian.org", "security.debian.org")
# The node-CLI install path needs BOTH the NodeSource apt repo (node itself) and the npm registry
# the CLI package is pulled from (`npm install -g @google/gemini-cli` / `@anthropic-ai/claude-code`).
# Both are one-time provisioning domains, removed from the runtime allowlist afterwards.
NODE_SETUP: tuple[str, ...] = ("deb.nodesource.com", "registry.npmjs.org")

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
    # False for `dev`: it is the operator's interactive home — they authenticate their own agent, so
    # warden injects no key and `up` does not gate on `resolve_llm_auth`.
    needs_secret: bool = True
    # True for `dev`: the persistent daily home. Marked on the instance so a stray `warden down`
    # refuses to delete it without --force (Fork P). Workload/monitored instances stay throwaway.
    persistent: bool = False
    # True for `dev`: install the agent CLI (node + gemini/claude) at provisioning. Workload/monitored
    # install it at *run* time; `dev` has no run step (it's interactive), so the home must come
    # furnished — and node's apt source is provisioning-only, so it can't be added after the fact.
    provision_agent_cli: bool = False


def resolve(flavor: Flavor, llm: str, extra_allow: Iterable[str] = (), audit: bool = False) -> FlavorSpec:
    """`audit` (DEMO-SPEC §2/§11.1) turns the ground-truth plane on for a
    flavor that does not have it by default.

    It is a **config toggle, not new architecture** — deliberately. The whole
    point of the flavor table being data is that "a builder that is also
    audited" is one boolean, not a third flavor and not a branch in `app.py`.
    Reconciliation needs *both* planes, and `builder` (the flavor that has a
    repo and a git history worth reconciling against) shipped with only the
    self-report one, so the demo's `report` verb had nothing to check against.

    On `monitored` it is already true and the flag is a no-op rather than an
    error: "make sure this is audited" is a reasonable thing to say about an
    instance that already is.
    """
    if llm not in LLM_ENDPOINTS:
        raise ValueError(f"unknown llm {llm!r}; expected one of {tuple(LLM_ENDPOINTS)}")
    llm_hosts = LLM_ENDPOINTS[llm]
    extra = tuple(extra_allow)

    if flavor is Flavor.MONITORED:
        # NODE_SETUP so the node-based LLM CLI can actually be installed at provisioning. monitored
        # is the audited flavor `report` reconciles against, so it MUST be able to stand its agent
        # up — the old set omitted the node/npm sources and 403'd the install. Narrowed away at
        # runtime (below): node/npm are provisioning-only, the agent only reaches the LLM endpoint.
        provisioning = tuple(sorted(set(DEBIAN_SETUP) | set(NODE_SETUP) | set(llm_hosts) | set(extra)))
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
            auditd_wired=audit,
            permission_mode="skip-permissions",
        )

    if flavor is Flavor.DEV:
        # The free-form daily HOME (ROADMAP step 1). Interactive: the operator drives their own agent
        # with their own auth — NO injected key (needs_secret=False). Audited (auditd_wired=True): the
        # dev container is where agentwatch earns trust, the unforgeable plane in the VM around it.
        # Egress-locked to the LLM endpoint + the registries a dev genuinely needs (clone/install),
        # like builder — kept at runtime because dev work is ongoing, not one provisioning burst.
        # PERSISTENT: it survives, and a stray `down` won't delete it.
        # AUTH hosts are runtime (the operator logs in with their own account while working), and kept
        # in provisioning too so the set only ever narrows. The agent CLI is installed at provisioning.
        auth_hosts = LLM_AUTH_ENDPOINTS.get(llm, ())
        provisioning = tuple(sorted(
            set(DEBIAN_SETUP) | set(NODE_SETUP) | set(BUILDER_REGISTRIES)
            | set(llm_hosts) | set(auth_hosts) | set(extra)
        ))
        runtime = tuple(sorted(
            set(BUILDER_REGISTRIES) | set(llm_hosts) | set(auth_hosts) | set(extra)
        ))
        return FlavorSpec(
            name="dev",
            llm=llm,
            provisioning_allowlist=provisioning,
            runtime_allowlist=runtime,
            repo_git=False,
            auditd_wired=True,
            permission_mode="skip-permissions",
            needs_secret=False,
            persistent=True,
            provision_agent_cli=True,
        )

    raise ValueError(f"unknown flavor {flavor!r}")
