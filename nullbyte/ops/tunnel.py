"""Tunnels: reach Jupyter / TensorBoard / any web UI on a server from your phone.

  phone ──HTTPS──▶ gateway /t/<name>/… ──SSH direct-tcpip──▶ server 127.0.0.1:<port>

* the tunnel cert allows port forwarding but its force-command blocks shells
* the remote side is always 127.0.0.1 on that server: no pivoting into other hosts
* every request needs a signed, HttpOnly cookie minted after Telegram initData verification (operators only)
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import re
import time
from dataclasses import dataclass, field

import asyncssh

from .ca import CA
from .gateway import Target, connect

log = logging.getLogger("nullbyte.ops.tunnel")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,23}$")
TUNNEL_TTL = 12 * 3600


@dataclass
class Tunnel:
    name: str
    owner_id: int
    server: str
    remote_port: int
    strip: bool
    conn: asyncssh.SSHClientConnection
    listener: asyncssh.SSHListener
    local_port: int
    created: float = field(default_factory=time.time)
    expires: float = field(default_factory=lambda: time.time() + TUNNEL_TTL)
    requests: int = 0

    def close(self) -> None:
        try:
            self.listener.close()
            self.conn.close()
        except Exception:  # noqa: BLE001
            pass


class Tunnels:
    def __init__(self, ca: CA, secret: str):
        self.ca = ca
        self.key = hashlib.sha256(b"efferent-tunnel-cookie" + secret.encode()).digest()
        self.by_name: dict[str, Tunnel] = {}

    async def open(self, name: str, owner_id: int, t: Target, remote_port: int, strip: bool = False) -> Tunnel:
        if not NAME_RE.match(name):
            raise ValueError("name: a-z 0-9 - (max 24)")
        self.close(name)
        conn = await connect(t, self.ca, key_id=f"tg{owner_id}-tunnel-{name}", force_command="echo efferent-tunnel",
                             ttl=300, port_forwarding=True)
        listener = await conn.forward_local_port("127.0.0.1", 0, "127.0.0.1", remote_port)
        tun = Tunnel(name, owner_id, t.label, remote_port, strip, conn, listener, listener.get_port())
        self.by_name[name] = tun
        return tun

    def close(self, name: str) -> bool:
        tun = self.by_name.pop(name, None)
        if tun:
            tun.close()
        return bool(tun)

    def reap(self) -> list[str]:
        gone = [n for n, t in self.by_name.items() if t.expires < time.time() or t.conn.is_closed()]
        for n in gone:
            self.close(n)
        return gone

    def close_all(self) -> None:
        for n in list(self.by_name):
            self.close(n)

    # ------------------------------------------------------------------ access cookies
    def cookie(self, name: str, uid: int, ttl: float = TUNNEL_TTL) -> str:
        exp = int(time.time() + ttl)
        sig = hmac.new(self.key, f"{name}.{uid}.{exp}".encode(), hashlib.sha256).hexdigest()[:32]
        return f"{uid}.{exp}.{sig}"

    def check(self, name: str, value: str) -> int | None:
        try:
            uid_s, exp_s, sig = value.split(".")
            uid, exp = int(uid_s), int(exp_s)
        except (ValueError, AttributeError):
            return None
        good = hmac.new(self.key, f"{name}.{uid}.{exp}".encode(), hashlib.sha256).hexdigest()[:32]
        if exp < time.time() or not hmac.compare_digest(good, sig):
            return None
        return uid
