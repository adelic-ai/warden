"""Real, unfaked tests for the CONNECT-allowlist proxy.

Unlike the rest of this build, this component needs no root (a userspace
listener on a high port) so it's exercised against live egress instead of
a fake — see README.md / DECISIONS.md.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import ssl

import pytest

from warden.proxy import AllowlistProxy, write_allowlist

ALLOWED_HOST = "github.com"  # confirmed reachable from this VM
DISALLOWED_HOST = "example.com"


async def _run_with_proxy(allowlist_path, client_fn, *args):
    proxy = AllowlistProxy(allowlist_path)
    port = await proxy.start()
    serve_task = asyncio.create_task(proxy.serve_forever())
    try:
        return await asyncio.to_thread(client_fn, port, *args)
    finally:
        await proxy.stop()
        serve_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await serve_task


def _connect_and_tls_handshake(proxy_port: int, target_host: str) -> bool:
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=10)
    sock.sendall(f"CONNECT {target_host}:443 HTTP/1.1\r\nHost: {target_host}\r\n\r\n".encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(4096)
        if not chunk:
            break
        resp += chunk
    if b"200" not in resp.split(b"\r\n")[0]:
        return False
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(sock, server_hostname=target_host) as tls:
        tls.do_handshake()
        return tls.cipher() is not None


def _connect_and_read_status(proxy_port: int, target_host: str) -> bytes:
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=10)
    sock.sendall(f"CONNECT {target_host}:443 HTTP/1.1\r\nHost: {target_host}\r\n\r\n".encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(4096)
        if not chunk:
            break
        resp += chunk
    sock.close()
    return resp.split(b"\r\n")[0]


@pytest.mark.network
def test_proxy_allows_allowlisted_host_and_completes_real_tls(tmp_path):
    allowlist = tmp_path / "allow.txt"
    write_allowlist(allowlist, [ALLOWED_HOST])
    ok = asyncio.run(_run_with_proxy(allowlist, _connect_and_tls_handshake, ALLOWED_HOST))
    assert ok is True


def test_proxy_rejects_non_allowlisted_host(tmp_path):
    allowlist = tmp_path / "allow.txt"
    write_allowlist(allowlist, [ALLOWED_HOST])
    status = asyncio.run(_run_with_proxy(allowlist, _connect_and_read_status, DISALLOWED_HOST))
    assert b"403" in status


def test_proxy_allows_subdomain_of_allowlisted_host(tmp_path):
    allowlist = tmp_path / "allow.txt"
    write_allowlist(allowlist, ["github.com"])
    proxy = AllowlistProxy(allowlist)
    proxy._reload_if_changed()
    assert proxy.is_allowed("api.github.com")
    assert proxy.is_allowed("github.com")


def test_proxy_does_not_match_lookalike_domain(tmp_path):
    allowlist = tmp_path / "allow.txt"
    write_allowlist(allowlist, ["github.com"])
    proxy = AllowlistProxy(allowlist)
    proxy._reload_if_changed()
    assert not proxy.is_allowed("evilgithub.com")
    assert not proxy.is_allowed("github.com.evil.example")


def test_provisioning_to_runtime_narrowing_reloads_without_restart(tmp_path):
    """§1: 'swapping the list is not disabling the ACL' — the running
    proxy must pick up a narrower list without being restarted."""
    allowlist = tmp_path / "allow.txt"
    write_allowlist(allowlist, ["deb.debian.org", "registry.npmjs.org", "github.com"])
    proxy = AllowlistProxy(allowlist)
    proxy._reload_if_changed()
    assert proxy.is_allowed("deb.debian.org")

    write_allowlist(allowlist, ["github.com"])  # narrow to runtime list
    assert proxy.is_allowed("github.com")
    assert not proxy.is_allowed("deb.debian.org")


# --- proxy chaining (VANTAGE-PLAN.md phase 5) --------------------------------------------------
# A proxy running inside a vantage VM is itself behind the outer proxy. Real-host incident: without
# this, a nested proxy's direct connection attempt sat for 522s before finally returning a 502 -
# the outer bridge's default-drop ACL doesn't refuse fast, it just silently drops, and TCP's own
# retry/timeout behavior is what eventually gave up. These tests stand up two REAL proxy instances
# (not mocked) locally - an upstream and a downstream configured to relay through it - matching
# this file's existing "real, unfaked" convention.


async def _run_with_chained_proxies(allowlist_path, upstream_allowlist_path, client_fn, *args):
    upstream = AllowlistProxy(upstream_allowlist_path)
    upstream_port = await upstream.start()
    upstream_task = asyncio.create_task(upstream.serve_forever())
    downstream = AllowlistProxy(allowlist_path, upstream_proxy=f"127.0.0.1:{upstream_port}")
    downstream_port = await downstream.start()
    downstream_task = asyncio.create_task(downstream.serve_forever())
    try:
        return await asyncio.to_thread(client_fn, downstream_port, *args)
    finally:
        for p, t in ((upstream, upstream_task), (downstream, downstream_task)):
            await p.stop()
            t.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await t


@pytest.mark.network
def test_chained_proxy_completes_real_tls_through_upstream(tmp_path):
    allowlist = tmp_path / "allow.txt"
    write_allowlist(allowlist, [ALLOWED_HOST])
    upstream_allowlist = tmp_path / "upstream_allow.txt"
    write_allowlist(upstream_allowlist, [ALLOWED_HOST])  # upstream must ALSO allow it
    ok = asyncio.run(
        _run_with_chained_proxies(
            allowlist, upstream_allowlist, _connect_and_tls_handshake, ALLOWED_HOST
        )
    )
    assert ok is True


@pytest.mark.network
def test_chained_proxy_relays_plain_http_through_upstream(tmp_path):
    allowlist = tmp_path / "allow.txt"
    write_allowlist(allowlist, ["deb.debian.org"])
    upstream_allowlist = tmp_path / "upstream_allow.txt"
    write_allowlist(upstream_allowlist, ["deb.debian.org"])

    def _plain_http_via_proxy(proxy_port: int) -> bytes:
        sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=10)
        sock.sendall(
            b"GET http://deb.debian.org/debian/dists/bookworm/InRelease HTTP/1.1\r\n"
            b"Host: deb.debian.org\r\nConnection: close\r\n\r\n"
        )
        resp = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp += chunk
        sock.close()
        return resp.split(b"\r\n")[0]

    status = asyncio.run(
        _run_with_chained_proxies(allowlist, upstream_allowlist, _plain_http_via_proxy)
    )
    assert b"200" in status


def test_chained_proxy_reports_bad_gateway_when_upstream_refuses(tmp_path):
    # The downstream allows the host; the upstream does not - the downstream must not hang
    # waiting on a connection the upstream was always going to refuse, and must not silently
    # treat the upstream's refusal as its own success.
    allowlist = tmp_path / "allow.txt"
    write_allowlist(allowlist, [ALLOWED_HOST])
    upstream_allowlist = tmp_path / "upstream_allow.txt"
    write_allowlist(upstream_allowlist, [])  # upstream allows nothing

    status = asyncio.run(
        _run_with_chained_proxies(
            allowlist, upstream_allowlist, _connect_and_read_status, ALLOWED_HOST
        )
    )
    assert b"502" in status
