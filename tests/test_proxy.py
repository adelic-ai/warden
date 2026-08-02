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
