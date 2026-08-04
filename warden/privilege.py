"""How warden reaches root-requiring host tools, without warden itself being root.

DEMO-SPEC §9 asks for "scoped sudo if run hands-off (incus/auditctl/ausearch/nft)". This is that,
in one place, because the alternative — `sudo warden up` — is worse in a way that is easy to miss:
running the whole wizard as root moves `Path.home()` to `/root`, so the allowlist file, the run
directory and every exported artifact silently relocate, and the *monitor* (which holds
prompt-bearing data and is a lot of code) ends up running with the privilege DESIGN §4 exists to
keep it away from.

So the process stays unprivileged and only the individual root-requiring invocations are elevated.

`sudo -n` — never prompt. A hands-off run that blocks on a password is a hang with no output,
which reads exactly like a broken plane; failing immediately with sudo's own message is the more
useful outcome. The sudoers grant should be scoped to the specific binaries, not to `ALL`.

Elevation is skipped when already root (a nested/CI context may legitimately run as root), and can
be forced either way with `WARDEN_SUDO=always|never` for hosts where the operator is in the
`incus` group and needs no elevation for the daemon socket.
"""

from __future__ import annotations

import os
from typing import Sequence

SUDO = ("sudo", "-n")

_ENV_VAR = "WARDEN_SUDO"
_ALWAYS = {"1", "always", "yes", "true"}
_NEVER = {"0", "never", "no", "false"}


def elevation_prefix(env: dict | None = None) -> tuple[str, ...]:
    """`("sudo", "-n")`, or `()` when elevation is unnecessary or disabled."""
    env = os.environ if env is None else env
    override = env.get(_ENV_VAR, "").strip().lower()
    if override in _NEVER:
        return ()
    if override in _ALWAYS:
        return SUDO
    return () if os.geteuid() == 0 else SUDO


def elevate(argv: Sequence[str], env: dict | None = None) -> list[str]:
    """Prefix `argv` with the elevation prefix. Returns a new list; never mutates the input."""
    return [*elevation_prefix(env), *argv]
