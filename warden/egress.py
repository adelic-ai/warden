"""Bridge egress ACL — default-drop, no interception (§1).

- `drop`, never `reject`, on the bridge ACLs (silent drop; a `reject`
  hands a scanning workload a clean, fast signal about what's closed).
- No explicit broad rule (e.g. a `10.0.0.0/8` drop) ahead of the specific
  allow — that's exactly the kind of rule that can *shadow* a later `/32`
  allow depending on evaluation order. Instead: chain policy is `drop`,
  full stop, and the only rules added are narrow `accept`s for established/
  related traffic and the one path to the host-side proxy. Nothing needs
  to explicitly drop the LAN; the policy already does that for everything
  not explicitly allowed.
"""

from __future__ import annotations

TABLE_NAME = "warden"


def generate_nft_ruleset(bridge: str, proxy_port: int) -> str:
    """Guest instances may only reach the host-side proxy port on the
    bridge gateway — never anything else, guest-to-guest included. All
    real egress is mediated by `warden/proxy.py`'s allowlist; this
    ruleset's job is only to make sure nothing can route around it.
    """
    return (
        f"table inet {TABLE_NAME} {{\n"
        f"    chain forward {{\n"
        f"        type filter hook forward priority 0; policy drop;\n"
        f"        ct state established,related accept\n"
        f'        iifname "{bridge}" oifname "{bridge}" drop\n'
        f"    }}\n"
        f"    chain input {{\n"
        f"        type filter hook input priority 0; policy accept;\n"
        f'        iifname "{bridge}" tcp dport {proxy_port} accept\n'
        f'        iifname "{bridge}" drop\n'
        f"    }}\n"
        f"}}\n"
    )


def assert_no_reject_and_correct_ordering(ruleset: str, bridge: str, proxy_port: int) -> None:
    """A guard a caller can run before loading the ruleset. Not exhaustive
    nftables validation — just the two footguns the spec calls out."""
    if "reject" in ruleset:
        raise ValueError("ruleset uses `reject` — bridge ACLs must use `drop`")
    accept_line = f'iifname "{bridge}" tcp dport {proxy_port} accept'
    drop_line = f'iifname "{bridge}" drop'
    accept_idx = ruleset.find(accept_line)
    drop_idx = ruleset.find(drop_line)
    if accept_idx == -1:
        raise ValueError("ruleset is missing the proxy-port accept rule")
    if drop_idx != -1 and drop_idx < accept_idx:
        raise ValueError(
            "a generic drop rule appears before the specific proxy-port accept — "
            "this would shadow it depending on nft evaluation order"
        )
