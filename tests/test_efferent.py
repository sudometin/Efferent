"""EFFERENT-008 features against an SSH server that REALLY executes commands (bash in a temp HOME):
training watch (+kill, +loss curve, +GPU-idle alert), GPU afferent, reflex arcs, authenticated tunnels."""
import asyncio, json, os, re, stat, sys, tempfile, time

sys.path.insert(0, os.path.dirname(__file__))
import test_ops as T                                   # reuse the mock Bot API + helpers

import aiohttp
import asyncssh
from aiohttp import web
from telegram import Update

B = T.B
HOME = tempfile.mkdtemp()
FAKEBIN = os.path.join(HOME, "fakebin")


def _fake_tools():
    os.makedirs(FAKEBIN, exist_ok=True)
    tools = {
        # df: disk at whatever $HOME/disk says (default 95%) -> triggers the disk alert + reflex
        "df": '#!/bin/sh\necho "Filesystem 1024-blocks Used Available Capacity Mounted"\n'
              'echo "/dev/sda1 100 95 5 $(cat $HOME/disk 2>/dev/null || echo 95)% /"\n',
        "nvidia-smi": '#!/bin/sh\ncat $HOME/gpu.csv\n',
        "sudo": '#!/bin/sh\nexec "$@"\n',
        "journalctl": '#!/bin/sh\necho vacuumed\n',
    }
    for name, body in tools.items():
        path = os.path.join(FAKEBIN, name)
        with open(path, "w") as f:
            f.write(body)
        os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
    with open(os.path.join(HOME, "gpu.csv"), "w") as f:
        f.write("0, NVIDIA RTX 4090, 0, 900, 24564, 45\n1, NVIDIA RTX 4090, 2, 900, 24564, 44\n")


async def exec_server(ca_line: str):
    hk = asyncssh.generate_private_key("ssh-ed25519")
    auth = asyncssh.import_authorized_keys(f'cert-authority,principals="matin" {ca_line}\n')
    env = {**os.environ, "HOME": HOME, "PATH": FAKEBIN + os.pathsep + os.environ["PATH"]}

    async def handle(p):
        cmd = p.command or "true"
        proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE,
                                                     stderr=asyncio.subprocess.STDOUT, env=env, cwd=HOME)
        out, _ = await proc.communicate()
        p.stdout.write(out.decode(errors="replace"))
        p.exit(proc.returncode or 0)

    class S(asyncssh.SSHServer):
        def connection_requested(self, dest_host, dest_port, orig_host, orig_port):
            return dest_host == "127.0.0.1"           # direct-tcpip for tunnels

    srv = await asyncssh.create_server(S, "127.0.0.1", 0, server_host_keys=[hk], authorized_client_keys=auth,
                                       process_factory=handle)
    return srv, srv.sockets[0].getsockname()[1], hk.get_fingerprint("sha256")


async def upstream_app():
    """A stand-in for Jupyter: lives under /t/jupyter/ (base_url) and has a websocket."""
    async def page(r):
        return web.Response(text=f"hello from jupyter {r.path}", headers={"Content-Security-Policy": "jupyter-own"})

    async def root(r):
        return web.Response(text=f"root app {r.path}")

    async def ws(r):
        w = web.WebSocketResponse()
        await w.prepare(r)
        async for m in w:
            await w.send_str("echo:" + m.data)
        return w
    app = web.Application()
    app.add_routes([web.get("/t/jupyter/", page), web.get("/t/jupyter/api/kernels/ws", ws), web.get("/{tail:.*}", root)])
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    return runner, site._server.sockets[0].getsockname()[1]


def test_efferent_features():
    saved = {k: getattr(B.CFG, k) for k in T.OVERRIDES}
    for k, v in T.OVERRIDES.items():
        setattr(B.CFG, k, v)
    B.CFG.data_dir = __import__("pathlib").Path(tempfile.mkdtemp())
    try:
        asyncio.run(_run())
    finally:
        for k, v in saved.items():
            setattr(B.CFG, k, v)


async def _run():
    _fake_tools()
    SENT = T.SENT
    app = B.Application.builder().token(T.TOKEN).request(T.FakeAPI()).get_updates_request(T.FakeAPI()) \
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
    upd, alltext, since, txt = T.upd, T.alltext, T.since, T.txt
    srv, sport, sfp = await exec_server(ops.ca.public_line)
    sid = ops.store.upsert_server(T.OWNER, "lab", "127.0.0.1", sport, "matin", sfp)

    # ---------------- GPU afferent
    n = len(SENT); await go(upd(text="/fx_gpu lab"))
    t = alltext(n); assert "GPU AFFERENT" in t and "gpu0" in t and "RTX" not in t or "gpu1" in t, t

    # ---------------- training watch: runs detached, reports with exit code + loss curve
    script = ("for e in 1 2 3 4 5; do echo \"Epoch $e/5 - loss: $(python3 -c \"print(2.0/$e)\") "
              "- val_loss: $(python3 -c \"print(2.2/$e)\") - accuracy: 0.$((5+e))\"; sleep 0.15; done")
    n = len(SENT); await go(upd(text=f"/fx_watch lab cd=/tmp {script}"))
    t = alltext(n); assert "JOB #1 LAUNCHED" in t, t
    job = ops.store.job(1)
    assert job["state"] == "running"
    await asyncio.sleep(2.2)
    n = len(SENT); await ops.job_watch(None)
    photos = since(n, "sendPhoto", T.OWNER)
    assert photos and "JOB #1 DONE" in T.strip(txt(photos[0])) and "exit    0" in T.strip(txt(photos[0])), alltext(n)
    assert "Epoch 5/5" in alltext(n)
    assert ops.store.job(1)["state"] == "done"

    # kill a running job (confirm step, then kill the whole process group)
    n = len(SENT); await go(upd(text="/fx_watch lab sleep 300"))
    jid = int(re.search(r"JOB #(\d+) LAUNCHED", alltext(n)).group(1))
    n = len(SENT); await go(upd(cb=f"ops:jk:{jid}"))
    assert "kill job" in alltext(n)
    n = len(SENT); await go(upd(cb=f"ops:jkk:{jid}"))
    assert ops.store.job(jid)["state"] == "killed", alltext(n)
    await asyncio.sleep(0.3)
    assert "sleep 300" not in os.popen("ps -e -o cmd").read()

    # ---------------- GPU idle while a job runs → "stuck?" alert
    n = len(SENT); await go(upd(text="/fx_watch lab sleep 120"))
    jid2 = int(re.search(r"JOB #(\d+) LAUNCHED", alltext(n)).group(1))
    ops.store.update_job(jid2, started=time.time() - 1200)
    open(os.path.join(HOME, "disk"), "w").write("40")          # keep disk healthy for this part
    await ops.job_health(None)
    await ops.job_health(None)
    n = len(SENT); await ops.job_watch(None)
    assert "GPUs IDLE" in alltext(n), alltext(n)
    n = len(SENT); await ops.job_watch(None)
    assert "GPUs IDLE" not in alltext(n), "alert once"
    await go(upd(cb=f"ops:jkk:{jid2}"))

    # ---------------- reflex arcs: disk 95% → ask → "always" → auto next time
    n = len(SENT); await go(upd(text="/fx_reflex lab disk clean"))
    rid = int(re.search(r"REFLEX ARC #(\d+)", alltext(n)).group(1))
    open(os.path.join(HOME, "disk"), "w").write("95")
    n = len(SENT); await ops.job_health(None)
    t = alltext(n); assert "disk 95%" in t and f"REFLEX #{rid}" in t and "fire it?" in t, t
    n = len(SENT); await go(upd(cb=f"ops:rxa:{rid}"))
    t = alltext(n); assert "free disk" in t and "95% /" in t, t
    assert ops.store.reflex(rid)["trusted"] == 1
    # recover, then break again → fires automatically (cooldown reset for the test)
    open(os.path.join(HOME, "disk"), "w").write("40")
    await ops.job_health(None)
    ops.store.update_reflex(rid, last_fired=0)
    open(os.path.join(HOME, "disk"), "w").write("96")
    n = len(SENT); await ops.job_health(None)
    t = alltext(n); assert f"reflex #{rid} fired" in t and "free disk" in t, t
    # cooldown: no re-fire
    ops.store.set_alert_state(sid, "")
    n = len(SENT); await ops.job_health(None)
    assert "fired" not in alltext(n)
    n = len(SENT); await go(upd(text="/fx_reflexes"))
    assert "REFLEX ARCS" in alltext(n) and "auto" in alltext(n)

    # ---------------- tunnels: locked without the signed cookie, open with it, WS too, strip mode, close
    up_runner, up_port = await upstream_app()
    n = len(SENT); await go(upd(text=f"/fx_tunnel lab {up_port} jupyter"))
    t = alltext(n); assert "TUNNEL UP" in t, t
    assert "tunnel=jupyter" in json.dumps(since(n, "sendMessage")[0]["params"]["reply_markup"])
    base = f"http://127.0.0.1:{ops.web.runner.addresses[0][1]}"
    async with aiohttp.ClientSession() as anon:
        r = await anon.get(base + "/t/jupyter/")
        assert r.status == 401
        r = await anon.post(base + "/api/tunnel-auth", json={"tg": T.init_data(T.FRIEND, "Ali"), "name": "jupyter"})
        assert r.status == 404, "guests can't mint tunnel cookies"
    async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as http:
        r = await http.post(base + "/api/tunnel-auth", json={"tg": T.init_data(T.OWNER, "Matin"), "name": "jupyter"})
        assert r.status == 200 and (await r.json())["ok"]
        r = await http.get(base + "/t/jupyter/")
        body = await r.text()
        assert r.status == 200 and "hello from jupyter /t/jupyter/" in body, body
        assert r.headers.get("Content-Security-Policy") == "jupyter-own", "upstream headers preserved"
        ws = await http.ws_connect(base.replace("http", "ws") + "/t/jupyter/api/kernels/ws")
        await ws.send_str("ping")
        m = await asyncio.wait_for(ws.receive(), 5)
        assert m.data == "echo:ping"
        await ws.close()
        # the cookie is scoped: it doesn't open other tunnels
        await go(upd(text=f"/fx_tunnel lab {up_port} plain strip"))
        r = await http.get(base + "/t/plain/x")
        assert r.status == 401
        await http.post(base + "/api/tunnel-auth", json={"tg": T.init_data(T.OWNER, "Matin"), "name": "plain"})
        r = await http.get(base + "/t/plain/hello")
        assert r.status == 200 and "root app /hello" in await r.text(), "strip mode removes the prefix"
        n = len(SENT); await go(upd(text="/fx_tunnels"))
        assert "jupyter" in alltext(n) and "plain" in alltext(n)
        await go(upd(cb="ops:tc:jupyter"))
        r = await http.get(base + "/t/jupyter/")
        assert r.status == 401, "closed tunnel is locked"
    # non-operators
    n = len(SENT); await go(upd(user=T.FRIEND, text="/fx_watch lab id"))
    assert "operators" in alltext(n)
    audit = alltext(0)
    acts = [r["action"] for r in ops.store.audit_tail(60)]
    for a in ("job-start", "job-kill", "reflex-fire", "reflex-trust", "tunnel-create", "tunnel-open", "tunnel-close"):
        assert a in acts, a

    await up_runner.cleanup()
    srv.close()
    await ops.stop()
