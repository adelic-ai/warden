"""Host-side forward proxy — the egress gotcha from §1.

Default-drop egress plus a **host-side** forward proxy (SNI/CONNECT
allowlist, no interception, not in-guest). Since this is an *explicit*
proxy the guest is configured to use (never a transparent intercept —
see DECISIONS.md on why that means no SNI-sniffing is needed), the
target hostname is already sitting in plaintext on the CONNECT request
line. The proxy allowlists on that, then just relays bytes: it never
terminates or inspects the TLS stream, so it structurally can't MITM
even by accident.

Provisioning-vs-runtime narrowing (§1): the allowlist lives in a file
that's reloaded whenever its content changes, so `warden` can swap a wide
provisioning list for a narrow runtime one by rewriting the file — the
ACL is never disabled, just re-scoped.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Protocol

CONNECT_OK = b"HTTP/1.1 200 Connection Established\r\n\r\n"
CONNECT_FORBIDDEN = b"HTTP/1.1 403 Forbidden\r\n\r\n"
CONNECT_BAD_METHOD = b"HTTP/1.1 405 Method Not Allowed\r\n\r\n"
CONNECT_BAD_GATEWAY = b"HTTP/1.1 502 Bad Gateway\r\n\r\n"

_CHUNK = 65536


def write_allowlist(path: Path, domains: list[str]) -> None:
    path.write_text("\n".join(sorted(set(d.lower() for d in domains))) + "\n")


def _domain_match(host: str, allowed: str) -> bool:
    return host == allowed or host.endswith("." + allowed)


class ProxyAllowlistController(Protocol):
    """What `warden/app.py` needs to swap the allowlist — provisioning-
    wide during setup, narrowed to runtime after (§1)."""

    def set_allowlist(self, domains: tuple[str, ...]) -> None: ...


class RealProxyAllowlistController:
    """Rewrites the allowlist file the running `AllowlistProxy` watches.
    No root needed — the file just needs to be under a path the proxy
    process and `warden` both have access to."""

    def __init__(self, allowlist_path: Path):
        self.allowlist_path = Path(allowlist_path)

    def set_allowlist(self, domains: tuple[str, ...]) -> None:
        write_allowlist(self.allowlist_path, list(domains))


class AllowlistProxy:
    """A CONNECT-only forward proxy that allows a request iff the target
    host matches (exactly, or as a subdomain of) an entry in the allowlist
    file. Never binds < 1024 (no root needed) unless explicitly asked to."""

    def __init__(self, allowlist_path: Path, host: str = "127.0.0.1", port: int = 0):
        self.allowlist_path = Path(allowlist_path)
        self.host = host
        self.port = port
        self._allowlist: frozenset[str] = frozenset()
        self._raw: bytes | None = None
        self._server: asyncio.base_events.Server | None = None

    def _reload_if_changed(self) -> None:
        try:
            raw = self.allowlist_path.read_bytes()
        except FileNotFoundError:
            self._allowlist = frozenset()
            self._raw = None
            return
        # Compare raw content, not mtime: a rapid provisioning->runtime
        # rewrite can land within one filesystem timestamp tick (some
        # filesystems here round to whole seconds), which would make an
        # mtime-based cache silently miss the change. Content comparison
        # is slightly more work but is the only thing that's actually
        # correct, and these files are tiny.
        if raw == self._raw:
            return
        lines = raw.decode().splitlines()
        self._allowlist = frozenset(
            line.strip().lower() for line in lines if line.strip() and not line.strip().startswith("#")
        )
        self._raw = raw

    def is_allowed(self, host: str) -> bool:
        self._reload_if_changed()
        host = host.lower()
        return any(_domain_match(host, allowed) for allowed in self._allowlist)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request_line = await reader.readline()
            if not request_line:
                return
            try:
                method, target, _version = request_line.decode().strip().split()
            except ValueError:
                writer.write(CONNECT_BAD_METHOD)
                await writer.drain()
                return
            # drain headers to the blank line
            while True:
                header = await reader.readline()
                if header in (b"\r\n", b""):
                    break
            if method.upper() != "CONNECT":
                writer.write(CONNECT_BAD_METHOD)
                await writer.drain()
                return
            host, _, port_s = target.rpartition(":")
            try:
                port = int(port_s)
            except ValueError:
                writer.write(CONNECT_BAD_METHOD)
                await writer.drain()
                return
            if not self.is_allowed(host):
                writer.write(CONNECT_FORBIDDEN)
                await writer.drain()
                return
            try:
                remote_reader, remote_writer = await asyncio.open_connection(host, port)
            except OSError:
                writer.write(CONNECT_BAD_GATEWAY)
                await writer.drain()
                return
            writer.write(CONNECT_OK)
            await writer.drain()
            await asyncio.gather(
                self._pump(reader, remote_writer),
                self._pump(remote_reader, writer),
            )
        finally:
            writer.close()

    @staticmethod
    async def _pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
        try:
            while True:
                data = await src.read(_CHUNK)
                if not data:
                    break
                dst.write(data)
                await dst.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            dst.close()

    async def start(self) -> int:
        """Start listening; returns the bound port (useful when `port=0`)."""
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        self.port = self._server.sockets[0].getsockname()[1]
        return self.port

    async def serve_forever(self) -> None:
        assert self._server is not None, "call start() first"
        async with self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
