"""SSH gateway: bridges a Mini App terminal (WebSocket) to a real SSH session.

Security properties:
  * host-key pinning: the server's SHA256 fingerprint must match what the user confirmed (TOFU on first use);
    on mismatch the connection is dropped BEFORE any credential is sent
  * credentials (password / private key) arrive per session from the user's own encrypted vault and are only
    held in memory for the handshake; CA mode needs no stored secret at all (ephemeral key + 5-minute cert)
  * sessions are recorded (asciinema) and can be watched live read-only through expiring share tokens
"""
from __future__ import annotations

import asyncio
import logging
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable

import asyncssh

from . import knock as knocking
from .ca import CA
from .record import Recorder

log = logging.getLogger("nullbyte.ops")
Send = Callable[[dict], Awaitable[None]]

SESSION_MAX = 4 * 3600          # hard cap on any session
IDLE_MAX = 30 * 60              # no input for 30 min -> close
CA_SESSION_TTL = 300            # gateway certs only need to survive the handshake


class GatewayError(Exception):
    pass


class HostKeyMismatch(GatewayError):
    def __init__(self, seen: str, expected: str | None):
        self.seen, self.expected = seen, expected
        super().__init__("unknown host key" if not expected else "HOST KEY CHANGED")


@dataclass
class Target:
    host: str
    port: int = 22
    user: str = "root"
    fingerprint: str | None = None
    auth: str = "ca"                    # ca | password | key
    password: str | None = None
    key: str | None = None              # private key text (OpenSSH/PEM)
    key_pass: str | None = None
    knock: list[int] = field(default_factory=list)
    name: str = ""

    @property
    def label(self) -> str:
        return self.name or f"{self.user}@{self.host}:{self.port}"

    def wipe(self) -> None:
        self.password = self.key = self.key_pass = None


class _PinnedClient(asyncssh.SSHClient):
    def __init__(self, expected: str | None):
        self.expected = expected
        self.seen: str | None = None

    def validate_host_public_key(self, host, addr, port, key) -> bool:
        self.seen = key.get_fingerprint("sha256")
        return bool(self.expected) and self.seen == self.expected


async def probe_fingerprint(host: str, port: int = 22, knock: list[int] | None = None, timeout: float = 12) -> str:
    """Learn a server's host-key fingerprint without authenticating (we abort right after key exchange)."""
    if knock:
        await knocking.knock(host, knock)
    client = _PinnedClient(None)
    try:
        conn = await asyncio.wait_for(asyncssh.connect(
            host, port, known_hosts=(), client_factory=lambda: client, username="probe",
            password=None, client_keys=None, agent_path=None, preferred_auth="none"), timeout)
        conn.close()
    except (asyncssh.HostKeyNotVerifiable, asyncssh.PermissionDenied, asyncssh.DisconnectError):
        pass
    except (OSError, asyncio.TimeoutError) as e:
        raise GatewayError(f"can't reach {host}:{port} ({type(e).__name__})") from e
    if not client.seen:
        raise GatewayError("no host key received")
    return client.seen


async def connect(t: Target, ca: CA | None, key_id: str, force_command: str | None = None,
                  ttl: float = CA_SESSION_TTL, timeout: float = 15, port_forwarding: bool = False) -> asyncssh.SSHClientConnection:
    if t.knock:
        await knocking.knock(t.host, t.knock)
    client = _PinnedClient(t.fingerprint)
    opts: dict = dict(known_hosts=(), client_factory=lambda: client, username=t.user, agent_path=None,
                      connect_timeout=timeout, keepalive_interval=30)
    if t.auth == "ca":
        if not ca:
            raise GatewayError("CA not available")
        k, cert = ca.ephemeral(t.user, ttl, key_id, force_command, port_forwarding)
        opts.update(client_keys=[(k, cert)], password=None, preferred_auth="publickey")
    elif t.auth == "password":
        opts.update(password=t.password or "", client_keys=None, preferred_auth="password,keyboard-interactive")
    elif t.auth == "key":
        try:
            pk = asyncssh.import_private_key(t.key or "", t.key_pass or None)
        except (asyncssh.KeyImportError, ValueError) as e:
            raise GatewayError(f"bad private key: {e}") from e
        opts.update(client_keys=[pk], password=None, preferred_auth="publickey")
    else:
        raise GatewayError(f"unknown auth {t.auth}")
    try:
        return await asyncssh.connect(t.host, t.port, **opts)
    except asyncssh.HostKeyNotVerifiable as e:
        raise HostKeyMismatch(client.seen or "?", t.fingerprint) from e
    except asyncssh.PermissionDenied as e:
        raise GatewayError("permission denied" + (" · is the NULLBYTE CA trusted on this server?" if t.auth == "ca" else "")) from e
    except (OSError, asyncio.TimeoutError, asyncssh.Error) as e:
        raise GatewayError(f"{type(e).__name__}: {e}") from e
    finally:
        t.wipe()


async def run(t: Target, ca: CA, command: str, timeout: float = 25, key_id: str = "nullbyte-runbook") -> tuple[int, str]:
    """One-shot command with a cert whose force-command IS the command: the cert can't be reused for anything else."""
    conn = await connect(t, ca, key_id, force_command=command, ttl=120)
    try:
        r = await asyncio.wait_for(conn.run(command, check=False), timeout)
        out = (r.stdout or "") + (r.stderr or "")
        return (r.exit_status if r.exit_status is not None else -1), out
    finally:
        conn.close()


class Session:
    def __init__(self, sid: int, user_id: int, target: Target, conn: asyncssh.SSHClientConnection,
                 cast_path: Path | None, cols: int, rows: int, expires: float | None = None, readonly: bool = False):
        self.id, self.user_id, self.target, self.conn = sid, user_id, target, conn
        self.cols, self.rows = cols, rows
        self.expires = min(expires or 9e18, time.time() + SESSION_MAX)
        self.readonly = readonly
        self.owner: Send | None = None
        self.watchers: dict[str, Send] = {}
        self.recorder = Recorder(cast_path, cols, rows, target.label) if cast_path else None
        self.process: asyncssh.SSHClientProcess | None = None
        self.last_input = time.time()
        self.closed = asyncio.Event()
        self.nbytes = 0
        self.scrollback: list[str] = []          # recent output, so late watchers see the screen
        self._tasks: list[asyncio.Task] = []

    async def start(self) -> None:
        self.process = await self.conn.create_process(term_type="xterm-256color", term_size=(self.cols, self.rows),
                                                      encoding="utf-8", errors="replace")
        self._tasks = [asyncio.create_task(self._pump(self.process.stdout)),
                       asyncio.create_task(self._pump(self.process.stderr)),
                       asyncio.create_task(self._watchdog())]

    async def _emit(self, msg: dict) -> None:
        targets = ([self.owner] if self.owner else []) + list(self.watchers.values())
        for send in targets:
            try:
                await send(msg)
            except Exception:  # noqa: BLE001  a dead watcher must not kill the session
                pass

    async def _pump(self, stream) -> None:
        try:
            while True:
                data = await stream.read(8192)
                if not data:
                    break
                self.nbytes += len(data)
                if self.recorder:
                    self.recorder.output(data)
                self.scrollback.append(data)
                if len(self.scrollback) > 400:
                    self.scrollback = self.scrollback[-300:]
                await self._emit({"t": "o", "d": data})
        except (asyncssh.Error, OSError, asyncio.CancelledError):
            pass
        finally:
            if stream is self.process.stdout:
                await self.close("remote closed")

    async def _watchdog(self) -> None:
        try:
            while not self.closed.is_set():
                await asyncio.sleep(5)
                if time.time() >= self.expires:
                    await self._emit({"t": "o", "d": "\r\n\x1b[31m[efferent] access expired · session closed\x1b[0m\r\n"})
                    await self.close("expired")
                elif time.time() - self.last_input > IDLE_MAX:
                    await self.close("idle")
        except asyncio.CancelledError:
            pass

    def write(self, data: str) -> None:
        if self.readonly or not self.process or self.closed.is_set():
            return
        self.last_input = time.time()
        self.process.stdin.write(data)

    def resize(self, cols: int, rows: int) -> None:
        cols, rows = max(20, min(cols, 400)), max(5, min(rows, 200))
        self.cols, self.rows = cols, rows
        if self.process:
            self.process.change_terminal_size(cols, rows)
        if self.recorder:
            self.recorder.resize(cols, rows)

    async def close(self, reason: str = "closed") -> None:
        if self.closed.is_set():
            return
        self.closed.set()
        for t in self._tasks:
            if t is not asyncio.current_task():
                t.cancel()
        try:
            if self.process:
                self.process.close()
            self.conn.close()
        except Exception:  # noqa: BLE001
            pass
        if self.recorder:
            self.recorder.close()
        await self._emit({"t": "exit", "reason": reason})


class Gateway:
    def __init__(self, ca: CA, rec_dir: Path):
        self.ca = ca
        self.rec_dir = Path(rec_dir)
        self.sessions: dict[int, Session] = {}
        self.shares: dict[str, tuple[int, float]] = {}       # token -> (session id, expires)

    async def open(self, sid: int, user_id: int, t: Target, cols: int, rows: int, record: bool = True,
                   expires: float | None = None, readonly: bool = False) -> Session:
        conn = await connect(t, self.ca, key_id=f"tg{user_id}-s{sid}")
        cast = self.rec_dir / f"session_{sid}.cast" if record else None
        s = Session(sid, user_id, t, conn, cast, cols, rows, expires, readonly)
        await s.start()
        self.sessions[sid] = s
        asyncio.create_task(self._reap(s))
        return s

    async def _reap(self, s: Session) -> None:
        await s.closed.wait()
        self.sessions.pop(s.id, None)
        for tok, (sid, _) in list(self.shares.items()):
            if sid == s.id:
                self.shares.pop(tok, None)

    def share(self, sid: int, ttl: float = 3600) -> str:
        tok = secrets.token_urlsafe(9)
        self.shares[tok] = (sid, time.time() + ttl)
        return tok

    def watch(self, token: str) -> Session | None:
        entry = self.shares.get(token)
        if not entry or entry[1] < time.time():
            self.shares.pop(token, None)
            return None
        return self.sessions.get(entry[0])

    async def close_all(self) -> None:
        for s in list(self.sessions.values()):
            await s.close("gateway shutdown")
