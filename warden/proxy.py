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
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Protocol

CONNECT_OK = b"HTTP/1.1 200 Connection Established\r\n\r\n"
CONNECT_FORBIDDEN = b"HTTP/1.1 403 Forbidden\r\n\r\n"
CONNECT_BAD_METHOD = b"HTTP/1.1 405 Method Not Allowed\r\n\r\n"
CONNECT_BAD_GATEWAY = b"HTTP/1.1 502 Bad Gateway\r\n\r\n"

_CHUNK = 65536


class UpstreamRefused(Exception):
    """The upstream proxy (`AllowlistProxy.upstream_proxy`) declined a CONNECT relay — its own
    allowlist doesn't cover the target, or it's unreachable. Caller reports CONNECT_BAD_GATEWAY,
    the same outcome a direct-connect failure produces; the client can't tell which hop failed
    and doesn't need to."""


def write_allowlist(path: Path, domains: list[str]) -> None:
    path.write_text("\n".join(sorted(set(d.lower() for d in domains))) + "\n")


def _domain_match(host: str, allowed: str) -> bool:
    return host == allowed or host.endswith("." + allowed)


def _parse_absolute_uri(target: str) -> tuple[str, int, str] | None:
    """`http://host[:port]/path` -> (host, port, origin-form path).

    Returns None for anything that isn't absolute-form http, including
    https:// (which a client must reach via CONNECT, not this path).
    """
    if not target.lower().startswith("http://"):
        return None
    rest = target[len("http://"):]
    authority, slash, path = rest.partition("/")
    path = f"/{path}" if slash else "/"
    host, _, port_s = authority.rpartition(":")
    if not host:  # no colon at all -> rpartition put everything in port_s
        host, port = port_s, 80
    else:
        try:
            port = int(port_s)
        except ValueError:
            return None
    if not host:
        return None
    return host, port, path


class ProxyAllowlistController(Protocol):
    """What `warden/app.py` needs to swap the allowlist — provisioning-
    wide during setup, narrowed to runtime after (§1) — and to guarantee
    something is actually serving it."""

    def set_allowlist(self, domains: tuple[str, ...]) -> None: ...
    def ensure_running(self) -> bool: ...


class RealProxyAllowlistController:
    """Rewrites the allowlist file the running `AllowlistProxy` watches,
    and starts that proxy if it isn't up.

    Writing the file was previously the whole of it, which is how the
    first real run ended up with a carefully-narrowed allowlist that no
    process was reading and egress that was never enforced."""

    def __init__(
        self,
        allowlist_path: Path,
        bind: str = "127.0.0.1",
        port: int = 3128,
        upstream_proxy: str | None = None,
    ):
        self.allowlist_path = Path(allowlist_path)
        self.bind = bind
        self.port = port
        self.upstream_proxy = upstream_proxy

    def set_allowlist(self, domains: tuple[str, ...]) -> None:
        write_allowlist(self.allowlist_path, list(domains))

    def ensure_running(self) -> bool:
        # Write an empty allowlist first if there is none: the proxy must
        # never start out permissive by virtue of a missing file.
        if not self.allowlist_path.exists():
            self.allowlist_path.parent.mkdir(parents=True, exist_ok=True)
            write_allowlist(self.allowlist_path, [])
        return ensure_running(
            self.allowlist_path, self.bind, self.port, upstream_proxy=self.upstream_proxy
        )


class AllowlistProxy:
    """A CONNECT-only forward proxy that allows a request iff the target
    host matches (exactly, or as a subdomain of) an entry in the allowlist
    file. Never binds < 1024 (no root needed) unless explicitly asked to."""

    def __init__(
        self,
        allowlist_path: Path,
        host: str = "127.0.0.1",
        port: int = 0,
        upstream_proxy: str | None = None,
    ):
        self.allowlist_path = Path(allowlist_path)
        self.host = host
        self.port = port
        #: "host:port" of a parent proxy this one relays through, instead of connecting to
        #: targets directly. Needed the moment warden's own proxy runs nested more than one
        #: level deep (VANTAGE-PLAN.md phase 5): a proxy running inside a vantage VM, serving a
        #: container inside it, is itself behind the outer proxy — without this it just tries a
        #: direct connection, which the outer bridge's default-drop ACL blocks, and the request
        #: hangs until TCP gives up rather than failing fast. None (the default) is a flat
        #: single-hop proxy, unchanged from before this existed.
        self.upstream_proxy: tuple[str, int] | None = None
        if upstream_proxy is not None:
            up_host, _, up_port = upstream_proxy.rpartition(":")
            self.upstream_proxy = (up_host, int(up_port))
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
                method, target, version = request_line.decode().strip().split()
            except ValueError:
                writer.write(CONNECT_BAD_METHOD)
                await writer.drain()
                return
            # Collect, don't discard: a plain-HTTP request has to be
            # replayed to the origin server, headers and all.
            headers: list[bytes] = []
            while True:
                header = await reader.readline()
                if header in (b"\r\n", b""):
                    break
                headers.append(header)

            if method.upper() == "CONNECT":
                await self._handle_connect(target, reader, writer)
            else:
                await self._handle_plain(method, target, version, headers, reader, writer)
        finally:
            writer.close()

    async def _handle_connect(
        self, target: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
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
            remote_reader, remote_writer = await self._dial(host, port)
        except (OSError, UpstreamRefused):
            writer.write(CONNECT_BAD_GATEWAY)
            await writer.drain()
            return
        writer.write(CONNECT_OK)
        await writer.drain()
        await asyncio.gather(
            self._pump(reader, remote_writer),
            self._pump(remote_reader, writer),
        )

    async def _dial(
        self, host: str, port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Connect to `host:port` — directly, or by asking `self.upstream_proxy` to CONNECT
        there on our behalf when one is configured. Shared by both handlers' CONNECT/tunnel
        path; `_handle_plain`'s non-CONNECT relay case has its own, simpler upstream branch,
        since a plain HTTP request needs no handshake before sending it."""
        if self.upstream_proxy is None:
            return await asyncio.open_connection(host, port)
        reader, writer = await asyncio.open_connection(*self.upstream_proxy)
        target = f"{host}:{port}"
        writer.write(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        await writer.drain()
        status_line = await reader.readline()
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b""):
                break
        if b" 200 " not in status_line:
            writer.close()
            raise UpstreamRefused(f"upstream refused CONNECT {target}: {status_line!r}")
        return reader, writer

    async def _handle_plain(
        self,
        method: str,
        target: str,
        version: str,
        headers: list[bytes],
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Absolute-form plain HTTP (`GET http://host/path HTTP/1.1`).

        Needed because Debian's apt repositories are plain http, so a
        CONNECT-only proxy cannot provision a container at all — the
        first real-Incus run's `git` install had no path out. Allowlisting
        is on the same hostname, so http and https are governed by one
        list; there is still no interception of the https path.
        """
        parsed = _parse_absolute_uri(target)
        if parsed is None:
            # Origin-form request: the client didn't think it was talking
            # to a proxy, so there's no hostname to authorize against.
            writer.write(CONNECT_BAD_METHOD)
            await writer.drain()
            return
        host, port, path = parsed
        if not self.is_allowed(host):
            writer.write(CONNECT_FORBIDDEN)
            await writer.drain()
            return
        try:
            if self.upstream_proxy is None:
                remote_reader, remote_writer = await asyncio.open_connection(host, port)
            else:
                # No CONNECT handshake needed here, unlike _dial's tunnel case — a plain HTTP
                # request relays to an upstream proxy exactly like it would to the origin,
                # just sent to a different address.
                remote_reader, remote_writer = await asyncio.open_connection(*self.upstream_proxy)
        except OSError:
            writer.write(CONNECT_BAD_GATEWAY)
            await writer.drain()
            return
        # Rewrite absolute-form to origin-form for a direct connection (what an origin server
        # expects); an upstream proxy gets the original absolute-form request untouched (what a
        # proxy expects). Hop-by-hop proxy headers are dropped either way.
        request_line = f"{method} {target} {version}\r\n" if self.upstream_proxy else f"{method} {path} {version}\r\n"
        out = [request_line.encode()]
        out += [h for h in headers if not h.lower().startswith(b"proxy-")]
        out.append(b"\r\n")
        remote_writer.write(b"".join(out))
        await remote_writer.drain()
        await asyncio.gather(
            self._pump(reader, remote_writer),
            self._pump(remote_reader, writer),
        )

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


# ---------------------------------------------------------------------------
# running it for real — `warden up` self-provisions the proxy the same way it
# self-provisions the bridge, so there is no "…and separately start the proxy"
# step for an operator to forget (which is how the first real run ended up
# with an allowlist file nothing was reading).
# ---------------------------------------------------------------------------

def is_listening(host: str, port: int, timeout: float = 0.5) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0


def run_forever(
    allowlist_path: Path, host: str, port: int, upstream_proxy: str | None = None
) -> None:
    """Foreground proxy — the body of `warden proxy`."""
    proxy = AllowlistProxy(allowlist_path, host=host, port=port, upstream_proxy=upstream_proxy)

    async def _main() -> None:
        await proxy.start()
        await proxy.serve_forever()

    asyncio.run(_main())


def ensure_running(
    allowlist_path: Path,
    host: str,
    port: int,
    log_path: Path | None = None,
    timeout: float = 10.0,
    upstream_proxy: str | None = None,
) -> bool:
    """Start a detached proxy if nothing is already listening.

    Returns True if this call started one. Idempotent: a re-run of
    `warden up` finds the existing proxy and leaves it alone.
    """
    if is_listening(host, port):
        return False
    log_path = Path(log_path) if log_path else Path(allowlist_path).parent / "proxy.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(log_path, "ab")
    argv = [
        sys.executable, "-m", "warden.cli", "proxy",
        "--allowlist-file", str(allowlist_path),
        "--bind", host,
        "--port", str(port),
    ]
    if upstream_proxy is not None:
        argv += ["--upstream-proxy", upstream_proxy]
    subprocess.Popen(
        argv,
        stdout=handle,
        stderr=handle,
        stdin=subprocess.DEVNULL,
        start_new_session=True,  # survives the `warden up` that spawned it
        cwd=str(Path(__file__).resolve().parent.parent),
    )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if is_listening(host, port):
            return True
        time.sleep(0.2)
    raise RuntimeError(
        f"allowlist proxy did not come up on {host}:{port} within {timeout}s — see {log_path}"
    )
