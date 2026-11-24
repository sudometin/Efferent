"""aiohttp server: serves the Mini App and speaks a small JSON protocol over WebSocket.

client -> server                                   server -> client
  {t:hello}                                          {t:hi, user, role, servers, grants, ca}
  {t:probe, host, port, knock}                       {t:fp, fp}
  {t:open, target, cols, rows, device, grant?}       {t:2fa} … {t:opened, sid, label} | {t:error, msg, code}
  {t:i, d}  {t:r, cols, rows}  {t:close}             {t:o, d}  {t:exit, reason}
  {t:share}                                          {t:shared, link, ttl}
  {t:watch, token}                                   {t:watching, label} + output stream (read-only)
  {t:enroll, name, host, port, user, fp, knock}      {t:enrolled, id}
  {t:card, server}                                   {t:card, link}
  {t:knock, host, ports}                             {t:knocked, n}
"""
from __future__ import annotations

import asyncio
import json
import logging
import secrets
import time
from pathlib import Path
from typing import Awaitable, Callable

import aiohttp
from aiohttp import WSMsgType, web

from . import knock as knocking
from . import tgauth
from .gateway import Gateway, GatewayError, HostKeyMismatch, Target, probe_fingerprint
from .store import OpsStore
from .tunnel import Tunnels

HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding",
       "upgrade", "content-length"}

log = logging.getLogger("nullbyte.ops.web")
STATIC = Path(__file__).parent / "webapp"
TWO_FA_TIMEOUT = 90


class OpsWeb:
    def __init__(self, *, token: str, store: OpsStore, gateway: Gateway, operators: Callable[[int], bool],
                 ask_2fa: Callable[[int, str, str], Awaitable[str]], bot_username: Callable[[], str],
                 honeypot_port: int = 0, honeypot_fp: str = "", tunnels: Tunnels | None = None):
        self.token, self.store, self.gw = token, store, gateway
        self.is_operator = operators
        self.ask_2fa = ask_2fa                # (user_id, label, device) -> "deny" | "once" | "trust"
        self.bot_username = bot_username
        self.honeypot = (honeypot_port, honeypot_fp)
        self.rate: dict[int, list[float]] = {}
        self.tunnels = tunnels
        self._http: aiohttp.ClientSession | None = None
        self.app = web.Application(client_max_size=256 * 1024)
        self.app.add_routes([web.get("/", self.index), web.get("/ws", self.ws),
                             web.get("/healthz", lambda r: web.Response(text="ok")),
                             web.post("/api/tunnel-auth", self.tunnel_auth),
                             web.get("/t/{name}", self.tunnel_redirect),
                             web.route("*", "/t/{name}/{tail:.*}", self.tunnel_proxy),
                             web.static("/vendor", STATIC / "vendor", show_index=False)])
        self.app.on_response_prepare.append(self._headers)
        self.runner: web.AppRunner | None = None

    async def _headers(self, request, response):
        if request.path.startswith("/t/"):
            return                                   # tunnelled apps keep their own headers (Jupyter needs its CSP)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline' https://telegram.org; "
            "style-src 'self' 'unsafe-inline'; connect-src 'self' wss: ws:; img-src 'self' data:; frame-ancestors *")

    async def start(self, host: str, port: int) -> None:
        self.runner = web.AppRunner(self.app, access_log=None)
        await self.runner.setup()
        await web.TCPSite(self.runner, host, port).start()
        log.info("ops web on http://%s:%s", host, port)

    async def stop(self) -> None:
        await self.gw.close_all()
        if self.tunnels:
            self.tunnels.close_all()
        if self._http:
            await self._http.close()
        if self.runner:
            await self.runner.cleanup()

    async def index(self, request: web.Request) -> web.Response:
        return web.FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-cache"})

    def _limited(self, uid: int, n: int = 40, window: float = 60) -> bool:
        now = time.time()
        hits = [t for t in self.rate.get(uid, []) if now - t < window]
        hits.append(now)
        self.rate[uid] = hits
        return len(hits) > n

    # ------------------------------------------------------------------ websocket
    async def ws(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(heartbeat=25, max_msg_size=256 * 1024)
        await ws.prepare(request)
        try:
            auth = tgauth.verify(request.query.get("tg", ""), self.token)
        except tgauth.AuthError as e:
            await ws.send_json({"t": "error", "msg": f"auth: {e}", "code": "auth"})
            await ws.close()
            return ws
        user = auth["user"]
        uid = int(user["id"])
        name = user.get("username") and "@" + user["username"] or user.get("first_name", "user")
        lock = asyncio.Lock()

        async def send(msg: dict) -> None:
            async with lock:
                if not ws.closed:
                    await ws.send_json(msg)

        session = None
        watch_key = secrets.token_hex(4)
        watching = None
        try:
            async for msg in ws:
                if msg.type != WSMsgType.TEXT:
                    continue
                try:
                    m = json.loads(msg.data)
                except ValueError:
                    continue
                t = m.get("t")
                if t == "i" and session:
                    session.write(str(m.get("d", ""))[:65536])
                    continue
                if t == "r" and session:
                    session.resize(int(m.get("cols", 80)), int(m.get("rows", 24)))
                    continue
                if self._limited(uid):
                    await send({"t": "error", "msg": "slow down", "code": "rate"})
                    continue
                if t == "hello":
                    await send(self._hello(uid, name))
                elif t == "probe":
                    if not self.is_operator(uid):
                        await send({"t": "error", "msg": "operators only", "code": "perm"})
                        continue
                    try:
                        fp = await probe_fingerprint(str(m["host"]), int(m.get("port", 22)),
                                                     knocking.parse(str(m.get("knock", ""))))
                        await send({"t": "fp", "fp": fp, "host": m["host"], "port": int(m.get("port", 22))})
                    except GatewayError as e:
                        await send({"t": "error", "msg": str(e), "code": "probe"})
                elif t == "open":
                    if session and not session.closed.is_set():
                        await session.close("replaced")
                    session = await self._open(m, uid, name, send)
                elif t == "close" and session:
                    await session.close("closed by user")
                    session = None
                elif t == "share" and session:
                    tok = self.gw.share(session.id, ttl=3600)
                    self.store.audit(uid, "share", session.target.label, "read-only 1h")
                    link = f"https://t.me/{self.bot_username()}?start=w_{tok}"
                    await send({"t": "shared", "link": link, "ttl": 3600})
                elif t == "watch":
                    s = self.gw.watch(str(m.get("token", "")))
                    if not s:
                        await send({"t": "error", "msg": "share link expired or session ended", "code": "watch"})
                        continue
                    watching = s
                    s.watchers[watch_key] = send
                    self.store.audit(uid, "watch", s.target.label, name)
                    await send({"t": "watching", "label": s.target.label, "cols": s.cols, "rows": s.rows})
                    await send({"t": "o", "d": "".join(s.scrollback[-200:])})
                    if s.owner:
                        try:
                            await s.owner({"t": "o", "d": f"\r\n\x1b[35m[efferent] 👁 {name} is watching (read-only)\x1b[0m\r\n"})
                        except Exception:  # noqa: BLE001
                            pass
                elif t == "enroll":
                    await send(self._enroll(m, uid))
                elif t == "card":
                    srv = m.get("server") or {}
                    cid = self.store.create_card(uid, srv)
                    self.store.audit(uid, "card", f"{srv.get('user')}@{srv.get('host')}")
                    await send({"t": "card", "link": f"https://t.me/{self.bot_username()}?start=c_{cid}"})
                elif t == "knock":
                    if not self.is_operator(uid):
                        continue
                    n = await knocking.knock(str(m["host"]), knocking.parse(str(m.get("ports", ""))))
                    self.store.audit(uid, "knock", str(m["host"]), str(m.get("ports")))
                    await send({"t": "knocked", "n": n})
        finally:
            if watching:
                watching.watchers.pop(watch_key, None)
            if session and not session.closed.is_set():
                session.owner = None
                await session.close("client disconnected")
        return ws

    def _hello(self, uid: int, name: str) -> dict:
        op = self.is_operator(uid)
        servers = [{"id": r["id"], "name": r["name"], "host": r["host"], "port": r["port"], "user": r["user"],
                    "fp": r["fingerprint"], "knock": r["knock"], "status": "down" if r["alert_state"] == "down" else
                    ("warn" if r["alert_state"] else "ok")} for r in self.store.servers(uid)] if op else []
        grants = [{"id": g["id"], "name": g["name"], "host": g["host"], "port": g["port"], "user": g["principal"],
                   "expires": g["expires"], "readonly": bool(g["readonly"])} for g in self.store.grants_for(uid)]
        hp = None
        if op and self.honeypot[0]:
            hp = {"host": "127.0.0.1", "port": self.honeypot[0], "fp": self.honeypot[1]}
        return {"t": "hi", "user": name, "role": "operator" if op else "guest", "servers": servers,
                "grants": grants, "honeypot": hp, "bot": self.bot_username()}

    def _enroll(self, m: dict, uid: int) -> dict:
        if not self.is_operator(uid):
            return {"t": "error", "msg": "operators only", "code": "perm"}
        name = str(m.get("name") or m.get("host"))[:40]
        if not m.get("fp"):
            return {"t": "error", "msg": "probe the host key first", "code": "enroll"}
        sid = self.store.upsert_server(uid, name, str(m["host"]), int(m.get("port", 22)), str(m.get("user", "root")),
                                       str(m["fp"]), str(m.get("knock", "")))
        self.store.audit(uid, "enroll", name, f"{m.get('user')}@{m['host']}:{m.get('port', 22)}")
        return {"t": "enrolled", "id": sid, "name": name}

    async def _open(self, m: dict, uid: int, name: str, send):
        device = str(m.get("device", ""))[:64] or "unknown"
        cols, rows = int(m.get("cols", 80)), int(m.get("rows", 24))
        expires, readonly = None, False
        if m.get("grant"):
            g = next((g for g in self.store.grants_for(uid) if g["id"] == int(m["grant"])), None)
            if not g:
                await send({"t": "error", "msg": "grant expired or revoked", "code": "grant"})
                return None
            tgt = Target(g["host"], g["port"], g["principal"], g["fingerprint"], "ca",
                         knock=knocking.parse(g["knock"]), name=f"{g['name']} (grant)")
            expires, readonly = g["expires"], bool(g["readonly"])
        else:
            if not self.is_operator(uid):
                await send({"t": "error", "msg": "operators only", "code": "perm"})
                return None
            x = m.get("target") or {}
            tgt = Target(str(x.get("host", "")), int(x.get("port", 22)), str(x.get("user", "root")),
                         x.get("fp") or None, str(x.get("auth", "ca")), x.get("password"), x.get("key"),
                         x.get("key_pass"), knocking.parse(str(x.get("knock", ""))), str(x.get("name", ""))[:40])
            if not tgt.host:
                await send({"t": "error", "msg": "no host", "code": "open"})
                return None
        # 2FA: confirm in the bot chat unless this device is trusted
        if not self.store.trusted(uid, device):
            await send({"t": "2fa"})
            verdict = await self.ask_2fa(uid, tgt.label, device)
            if verdict == "deny":
                tgt.wipe()
                self.store.audit(uid, "2fa-deny", tgt.label, device)
                await send({"t": "error", "msg": "connection denied in bot", "code": "2fa"})
                return None
            if verdict == "trust":
                self.store.trust(uid, device, 12 * 3600)
        sid = self.store.session_start(uid, tgt.label, "grant" if m.get("grant") else tgt.auth)
        try:
            s = await self.gw.open(sid, uid, tgt, cols, rows, record=True, expires=expires, readonly=readonly)
        except HostKeyMismatch as e:
            self.store.audit(uid, "hostkey-" + ("changed" if e.expected else "unknown"), tgt.label, e.seen)
            self.store.session_end(sid, 0, None)
            await send({"t": "error", "code": "hostkey", "msg": str(e), "seen": e.seen, "expected": e.expected})
            return None
        except GatewayError as e:
            self.store.audit(uid, "connect-fail", tgt.label, str(e))
            self.store.session_end(sid, 0, None)
            await send({"t": "error", "msg": str(e), "code": "connect"})
            return None
        s.owner = send
        self.store.audit(uid, "connect", tgt.label, f"session {sid} via {'grant' if m.get('grant') else tgt.auth}")

        async def finish():
            await s.closed.wait()
            self.store.session_end(sid, s.nbytes, str(s.recorder.path) if s.recorder else None)
            self.store.audit(uid, "disconnect", tgt.label, f"session {sid} · {s.nbytes} bytes")
        asyncio.create_task(finish())
        await send({"t": "opened", "sid": sid, "label": tgt.label, "readonly": readonly,
                    "expires": expires})
        return s

    # ------------------------------------------------------------------ tunnels (HTTP + WebSocket reverse proxy over SSH)
    async def tunnel_auth(self, request: web.Request) -> web.Response:
        """Mini App posts its initData here; we answer with a signed HttpOnly cookie scoped to /t/<name>/."""
        try:
            body = await request.json()
            auth = tgauth.verify(str(body.get("tg", "")), self.token)
        except (ValueError, tgauth.AuthError) as e:
            return web.json_response({"ok": False, "error": str(e)}, status=403)
        uid, name = int(auth["user"]["id"]), str(body.get("name", ""))
        tun = self.tunnels.by_name.get(name) if self.tunnels else None
        if not tun or not (self.is_operator(uid) or uid == tun.owner_id):
            return web.json_response({"ok": False, "error": "no such tunnel"}, status=404)
        secure = request.headers.get("X-Forwarded-Proto", request.scheme) == "https"
        resp = web.json_response({"ok": True, "url": f"/t/{name}/"})
        resp.set_cookie(f"efx_{name}", self.tunnels.cookie(name, uid), path=f"/t/{name}/", httponly=True,
                        secure=secure, samesite="None" if secure else "Lax", max_age=int(tun.expires - time.time()))
        self.store.audit(uid, "tunnel-open", name, f"{tun.server}:{tun.remote_port}")
        return resp

    async def tunnel_redirect(self, request: web.Request) -> web.Response:
        raise web.HTTPFound(f"/t/{request.match_info['name']}/")

    async def tunnel_proxy(self, request: web.Request):
        name = request.match_info["name"]
        tun = self.tunnels.by_name.get(name) if self.tunnels else None
        uid = self.tunnels.check(name, request.cookies.get(f"efx_{name}", "")) if tun else None
        if not tun or uid is None:
            return web.Response(status=401, text="EFFERENT-008 · tunnel locked · open it from the bot (/fx_tunnels)",
                                content_type="text/plain")
        tun.requests += 1
        path = "/" + request.match_info["tail"] if tun.strip else request.path
        url = f"http://127.0.0.1:{tun.local_port}{path}" + (f"?{request.query_string}" if request.query_string else "")
        cookies = "; ".join(f"{k}={v}" for k, v in request.cookies.items() if not k.startswith("efx_"))
        headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP | {"cookie"}}
        if cookies:
            headers["Cookie"] = cookies
        if self._http is None:
            self._http = aiohttp.ClientSession(auto_decompress=False, timeout=aiohttp.ClientTimeout(total=None, sock_connect=15))
        if request.headers.get("Upgrade", "").lower() == "websocket":
            return await self._proxy_ws(request, url, headers)
        try:
            async with self._http.request(request.method, url, headers=headers, data=request.content,
                                          allow_redirects=False) as up:
                resp = web.StreamResponse(status=up.status)
                for k, v in up.headers.items():
                    if k.lower() not in HOP:
                        resp.headers.add(k, v)
                await resp.prepare(request)
                async for chunk in up.content.iter_chunked(64 * 1024):
                    await resp.write(chunk)
                await resp.write_eof()
                return resp
        except aiohttp.ClientError as e:
            return web.Response(status=502, text=f"EFFERENT-008 · tunnel '{name}': upstream error ({type(e).__name__}).\n"
                                                 f"Is anything listening on 127.0.0.1:{tun.remote_port} on {tun.server}?",
                                content_type="text/plain")

    async def _proxy_ws(self, request: web.Request, url: str, headers: dict):
        protocols = [p.strip() for p in request.headers.get("Sec-WebSocket-Protocol", "").split(",") if p.strip()]
        fwd = {k: v for k, v in headers.items() if k.lower() in ("origin", "cookie", "authorization", "user-agent")}
        try:
            up = await self._http.ws_connect(url.replace("http://", "ws://"), headers=fwd, protocols=protocols,
                                             max_msg_size=0, autoping=True)
        except aiohttp.ClientError:
            return web.Response(status=502, text="upstream websocket refused")
        down = web.WebSocketResponse(protocols=protocols, max_msg_size=0)
        await down.prepare(request)

        async def pipe(src, dst):
            async for m in src:
                if m.type == WSMsgType.TEXT:
                    await dst.send_str(m.data)
                elif m.type == WSMsgType.BINARY:
                    await dst.send_bytes(m.data)
                else:
                    break
            await dst.close()
        await asyncio.gather(pipe(down, up), pipe(up, down), return_exceptions=True)
        return down
