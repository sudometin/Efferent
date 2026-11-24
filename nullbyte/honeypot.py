"""A low-interaction SSH honeypot.

Accepts (almost) any login, then drops the visitor into a fake Ubuntu shell.
NOTHING they type is executed: every command is answered from canned output,
logged, and streamed to the bot owner. `wget`/`curl` URLs are recorded, never fetched.
"""
from __future__ import annotations

import asyncio
import logging
import random
import shlex
import time
from collections import Counter
from pathlib import Path
from typing import Awaitable, Callable

import asyncssh
import httpx

from .db import DB

log = logging.getLogger("nullbyte.honeypot")

HOSTNAME = "prod-db-02"
BANNER_VERSION = "OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
SESSION_IDLE = 180
SESSION_MAX = 600

MOTD = """Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-105-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

  System information as of {date}

  System load:  0.08               Processes:             141
  Usage of /:   61.4% of 77.35GB   Users logged in:       0
  Memory usage: 37%                IPv4 address for eth0: 10.0.4.17
  Swap usage:   0%

Last login: {last} from 10.0.4.2
"""

FS = {
    "/": ["bin", "boot", "dev", "etc", "home", "lib", "opt", "proc", "root", "srv", "tmp", "usr", "var"],
    "/root": [".bash_history", ".ssh", "backup.sql.gz", "notes.txt"],
    "/home": ["deploy", "ubuntu"],
    "/tmp": [".X11-unix", "systemd-private-3f1c"],
    "/etc": ["passwd", "shadow", "hostname", "hosts", "ssh", "crontab", "os-release"],
    "/var/www": ["html"],
}

FILES = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                   "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nmysql:x:112:117:MySQL Server,,,:/nonexistent:/bin/false\n"
                   "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\ndeploy:x:1001:1001::/home/deploy:/bin/bash\n",
    "/etc/hostname": HOSTNAME + "\n",
    "/etc/os-release": 'PRETTY_NAME="Ubuntu 22.04.4 LTS"\nNAME="Ubuntu"\nVERSION_ID="22.04"\nID=ubuntu\n',
    "/root/notes.txt": "TODO: rotate db creds before audit\nmysql root pw is in vault (NOT here!!)\n",
    "/proc/cpuinfo": "".join(
        f"processor\t: {i}\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) Gold 6248R CPU @ 3.00GHz\ncpu MHz\t\t: 2999.998\ncpu cores\t: 8\n\n"
        for i in range(8)),
    "/etc/shadow": None,  # permission theatre handled below
}

Notifier = Callable[[str], Awaitable[None]]


class GeoCache:
    def __init__(self) -> None:
        self.cache: dict[str, dict] = {}

    async def lookup(self, ip: str) -> dict:
        if ip in self.cache:
            return self.cache[ip]
        info = {"country": "?", "countryCode": "", "city": "", "as": ""}
        if ip.startswith(("127.", "10.", "192.168.", "172.16.", "::1")):
            info.update(country="Localhost", countryCode="", city="lab")
        else:
            try:
                async with httpx.AsyncClient(timeout=4) as client:
                    r = await client.get(f"http://ip-api.com/json/{ip}",
                                         params={"fields": "status,country,countryCode,city,as"})
                    data = r.json()
                    if data.get("status") == "success":
                        info.update(data)
            except Exception:  # noqa: BLE001
                pass
        self.cache[ip] = info
        return info


class Honeypot:
    def __init__(self, db: DB, port: int, host_key_path: str | Path, notify: Notifier,
                 live_ref: Callable[[], bool]):
        self.db = db
        self.port = port
        self.host_key_path = Path(host_key_path)
        self.notify = notify
        self.is_live = live_ref
        self.geo = GeoCache()
        self.server: asyncssh.SSHAcceptor | None = None
        self.active: dict[int, dict] = {}
        self.stream: Callable[[dict, str], None] | None = None     # optional live feed (Ops -> channel)

    # ------------------------------------------------------------------ lifecycle
    async def start(self) -> None:
        if not self.host_key_path.exists():
            self.host_key_path.parent.mkdir(parents=True, exist_ok=True)
            key = asyncssh.generate_private_key("ssh-ed25519")
            key.write_private_key(str(self.host_key_path))
        hp = self

        class Server(asyncssh.SSHServer):
            def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
                self.conn = conn
                peer = conn.get_extra_info("peername") or ("?", 0)
                self.ip, self.port = peer[0], peer[1]
                self.attempts = 0

            def begin_auth(self, username: str) -> bool:
                return True

            def password_auth_supported(self) -> bool:
                return True

            def validate_password(self, username: str, password: str) -> bool:
                self.attempts += 1
                hp.db.x("INSERT INTO hp_auth(ip,username,password,ts) VALUES(?,?,?,?)",
                        (self.ip, username, password, time.time()))
                # Feel real: reject the first try sometimes, then let them in.
                ok = self.attempts >= 2 or random.random() < 0.6
                if ok:
                    self.conn.set_extra_info(hp_password=password)
                return ok

            def kbdint_auth_supported(self) -> bool:
                return False

            def public_key_auth_supported(self) -> bool:
                return False

        self.server = await asyncssh.create_server(
            Server, "", self.port,
            server_host_keys=[str(self.host_key_path)],
            process_factory=self.handle,
            server_version=BANNER_VERSION,
            login_timeout=60,
            keepalive_interval=0,
        )
        log.info("honeypot listening on :%s", self.port)

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    # ------------------------------------------------------------------ session
    async def handle(self, process: asyncssh.SSHServerProcess) -> None:
        conn = process.channel.get_connection()
        ip, port = (process.get_extra_info("peername") or ("?", 0))[:2]
        username = process.get_extra_info("username") or "?"
        password = conn.get_extra_info("hp_password") or ""
        client = conn.get_extra_info("client_version") or ""
        geo = await self.geo.lookup(ip)
        sid = self.db.x(
            "INSERT INTO hp_sessions(ip,port,client,username,password,country,cc,city,asn,started) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (ip, port, client, username, password, geo.get("country"), geo.get("countryCode"),
             geo.get("city"), geo.get("as"), time.time()))
        state = {"cwd": "/root" if username == "root" else f"/home/{username}", "user": username,
                 "sid": sid, "ip": ip, "geo": geo, "cmds": 0}
        self.active[sid] = state
        await self.notify(self._fmt_login(sid, ip, username, password, client, geo))

        try:
            if process.command:  # `ssh host "cmd"` exec request
                out = self.run_line(state, process.command)
                process.stdout.write(out)
                process.exit(0)
                return
            process.stdout.write(MOTD.format(
                date=time.strftime("%a %b %d %H:%M:%S UTC %Y", time.gmtime()),
                last=time.strftime("%a %b %d %H:%M:%S %Y", time.gmtime(time.time() - 86400 * 3 - 4711))
            ).replace("\n", "\r\n"))
            started = time.time()
            while time.time() - started < SESSION_MAX:
                process.stdout.write(self.prompt(state))
                try:
                    line = await asyncio.wait_for(process.stdin.readline(), SESSION_IDLE)
                except asyncssh.TerminalSizeChanged:
                    continue
                except (asyncssh.BreakReceived, asyncio.TimeoutError, asyncssh.DisconnectError,
                        asyncssh.ConnectionLost, BrokenPipeError):
                    break
                if line == "":
                    break
                line = line.rstrip("\r\n")
                if not line.strip():
                    continue
                if line.strip() in ("exit", "logout", "quit"):
                    process.stdout.write("logout\r\n")
                    break
                out = self.run_line(state, line)
                if out:
                    process.stdout.write(out.replace("\n", "\r\n"))
            process.exit(0)
        except Exception:  # noqa: BLE001
            log.exception("session %s crashed", sid)
        finally:
            self.db.x("UPDATE hp_sessions SET ended=? WHERE id=?", (time.time(), sid))
            self.active.pop(sid, None)
            await self.notify(self._fmt_end(sid))

    def prompt(self, st: dict) -> str:
        home = "/root" if st["user"] == "root" else f"/home/{st['user']}"
        cwd = "~" + st["cwd"][len(home):] if st["cwd"].startswith(home) else st["cwd"]
        sigil = "#" if st["user"] == "root" else "$"
        return f"{st['user']}@{HOSTNAME}:{cwd}{sigil} "

    # ------------------------------------------------------------------ fake shell
    def run_line(self, st: dict, line: str) -> str:
        self.db.x("INSERT INTO hp_commands(session_id,ts,cmd) VALUES(?,?,?)", (st["sid"], time.time(), line[:2000]))
        st["cmds"] += 1
        if self.stream:
            try:
                self.stream(st, line)
            except Exception:  # noqa: BLE001
                pass
        if self.is_live():
            asyncio.get_event_loop().create_task(self.notify(
                f"<code>{_e(st['ip'])}</code> ⟫ <code>{_e(line[:300])}</code>"))
        outputs = []
        for part in _split_commands(line):
            outputs.append(self.run_cmd(st, part))
        return "".join(outputs)

    def run_cmd(self, st: dict, cmd: str) -> str:
        try:
            argv = shlex.split(cmd)
        except ValueError:
            argv = cmd.split()
        if not argv:
            return ""
        name, args = argv[0], argv[1:]
        if name == "sudo" and args:
            name, args = args[0], args[1:]
        user = st["user"]

        for tok in argv:
            if tok.startswith(("http://", "https://", "ftp://")) or (name in ("wget", "curl", "tftp") and "." in tok and "/" in tok):
                self.db.x("INSERT INTO hp_urls(session_id,ts,url) VALUES(?,?,?)", (st["sid"], time.time(), tok[:500]))
                asyncio.get_event_loop().create_task(self.notify(
                    f"📦 <b>payload URL captured</b> from <code>{_e(st['ip'])}</code>\n<code>{_e(tok[:300])}</code>\n"
                    f"<i>(recorded, never fetched)</i>"))

        simple = {
            "whoami": f"{user}\n",
            "id": "uid=0(root) gid=0(root) groups=0(root)\n" if user == "root"
                  else f"uid=1000({user}) gid=1000({user}) groups=1000({user}),27(sudo)\n",
            "hostname": HOSTNAME + "\n",
            "pwd": st["cwd"] + "\n",
            "nproc": "8\n",
            "uptime": " 21:14:05 up 47 days,  3:12,  0 users,  load average: 0.08, 0.11, 0.09\n",
            "w": " 21:14:05 up 47 days,  3:12,  0 users,  load average: 0.08, 0.11, 0.09\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n",
            "free": "               total        used        free      shared  buff/cache   available\n"
                    "Mem:        32776432    12139332     4120000       12016    16517100    20131552\n"
                    "Swap:              0           0           0\n",
            "history": "    1  apt update\n    2  systemctl restart mysql\n    3  vim /etc/mysql/my.cnf\n",
            "arch": "x86_64\n",
            "lscpu": "Architecture:            x86_64\nCPU(s):                  8\nModel name:              Intel(R) Xeon(R) Gold 6248R CPU @ 3.00GHz\n",
            "ps": "    PID TTY          TIME CMD\n   4711 pts/0    00:00:00 bash\n   4790 pts/0    00:00:00 ps\n",
            "crontab": "no crontab for root\n",
            "ifconfig": "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.4.17  netmask 255.255.255.0  broadcast 10.0.4.255\n",
        }
        if name in simple:
            if name == "free" and "-m" in args:
                return "               total        used        free\nMem:           32008       11854        4023\n"
            return simple[name]
        if name == "uname":
            if "-a" in args:
                return f"Linux {HOSTNAME} 5.15.0-105-generic #115-Ubuntu SMP Mon Apr 15 09:52:04 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux\n"
            return "Linux\n"
        if name == "echo":
            return " ".join(args) + "\n"
        if name == "cd":
            target = args[0] if args else ("/root" if user == "root" else f"/home/{user}")
            if target in ("~",):
                target = "/root" if user == "root" else f"/home/{user}"
            if not target.startswith("/"):
                target = (st["cwd"].rstrip("/") + "/" + target)
            st["cwd"] = _norm(target)
            return ""
        if name in ("ls", "dir", "ll"):
            path = _norm(next((a for a in args if not a.startswith("-")), st["cwd"]) if args else st["cwd"])
            if not path.startswith("/"):
                path = _norm(st["cwd"] + "/" + path)
            entries = FS.get(path, [])
            show_all = any("a" in a for a in args if a.startswith("-"))
            entries = [e for e in entries if show_all or not e.startswith(".")]
            if any("l" in a for a in args if a.startswith("-")) or name == "ll":
                return "".join(f"-rw-r--r-- 1 root root {random.randint(220, 90000):>6} Nov 19 03:12 {e}\n" for e in entries)
            return "  ".join(entries) + ("\n" if entries else "")
        if name == "cat":
            out = []
            for a in args:
                p = a if a.startswith("/") else _norm(st["cwd"] + "/" + a)
                if p == "/etc/shadow" and user != "root":
                    out.append(f"cat: {a}: Permission denied\n")
                elif p in FILES and FILES[p] is not None:
                    out.append(FILES[p])
                elif p == "/etc/shadow":
                    out.append("root:$6$Zq8x$JXv0.fake.hash.nice.try:19675:0:99999:7:::\n")
                else:
                    out.append(f"cat: {a}: No such file or directory\n")
            return "".join(out)
        if name in ("wget", "curl"):
            if name == "wget":
                return ("Resolving host... done.\nConnecting... connected.\nHTTP request sent, awaiting response... 200 OK\n"
                        "Length: 1337 (1.3K) [application/octet-stream]\nSaving to: 'x'\n\n"
                        "x                   100%[===================>]   1.31K  --.-KB/s    in 0s\n\n")
            return ""
        if name in ("chmod", "chown", "rm", "mkdir", "touch", "export", "unset", "kill", "pkill", "systemctl",
                    "service", "mv", "cp", "nohup", "history", "clear"):
            return ""
        if name in ("python", "python3", "perl", "bash", "sh"):
            return ""
        if name.startswith("./"):
            return f"bash: {name}: Permission denied\n"
        if name in ("apt", "apt-get", "yum"):
            return "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\n"
        return f"{name}: command not found\n"

    # ------------------------------------------------------------------ formatting
    def _fmt_login(self, sid, ip, user, pw, client, geo) -> str:
        from . import ui
        fl = ui.flag(geo.get("countryCode"))
        place = ", ".join(x for x in (geo.get("city"), geo.get("country")) if x)
        return (f"🍯 <b>INTRUDER #{sid} IS IN</b>\n"
                + ui.box("SESSION", ui.kv([
                    ("ip", ip), ("geo", f"{place}"), ("asn", ui.clip(geo.get("as") or "?", 20)),
                    ("login", ui.clip(f"{user} / {pw}", 20)), ("client", ui.clip(client, 20)),
                ], 6)) + f"{fl} <i>/hp_replay {sid} for the transcript</i>")

    def _fmt_end(self, sid) -> str:
        n = self.db.q("SELECT COUNT(*) c FROM hp_commands WHERE session_id=?", (sid,))[0]["c"]
        row = self.db.q("SELECT started, ended FROM hp_sessions WHERE id=?", (sid,))[0]
        dur = (row["ended"] or time.time()) - row["started"]
        return f"🔌 session #{sid} closed · {n} commands · {int(dur)}s · /hp_replay {sid}"

    # ------------------------------------------------------------------ analytics
    def stats(self, since: float = 0) -> dict:
        sess = self.db.q("SELECT * FROM hp_sessions WHERE started>=?", (since,))
        auth = self.db.q("SELECT username, password FROM hp_auth WHERE ts>=?", (since,))
        cmds = self.db.q("SELECT cmd FROM hp_commands c JOIN hp_sessions s ON s.id=c.session_id WHERE s.started>=?", (since,))
        urls = self.db.q("SELECT url FROM hp_urls WHERE ts>=?", (since,))
        return {
            "sessions": len(sess),
            "ips": len({s["ip"] for s in sess}),
            "auth": len(auth),
            "commands": len(cmds),
            "urls": len(urls),
            "countries": Counter((s["cc"] or "", s["country"] or "?") for s in sess).most_common(6),
            "users": Counter(a["username"] for a in auth).most_common(5),
            "passwords": Counter(a["password"] for a in auth).most_common(5),
            "top_cmds": Counter(c["cmd"].split()[0] if c["cmd"].split() else "" for c in cmds).most_common(6),
            "clients": Counter(s["client"] for s in sess).most_common(3),
        }

    def transcript(self, sid: int) -> tuple[dict | None, list]:
        rows = self.db.q("SELECT * FROM hp_sessions WHERE id=?", (sid,))
        if not rows:
            return None, []
        cmds = self.db.q("SELECT ts, cmd FROM hp_commands WHERE session_id=? ORDER BY id", (sid,))
        return dict(rows[0]), cmds

    def kiddie_of_the_day(self) -> int | None:
        rows = self.db.q(
            "SELECT s.id, COUNT(c.id) n FROM hp_sessions s LEFT JOIN hp_commands c ON c.session_id=s.id "
            "WHERE s.started>=? GROUP BY s.id ORDER BY n DESC LIMIT 1", (time.time() - 86400,))
        return rows[0]["id"] if rows and rows[0]["n"] > 0 else None


def _split_commands(line: str) -> list[str]:
    parts, buf, quote = [], "", None
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            buf += ch
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
            buf += ch
        elif line.startswith("&&", i) or line.startswith("||", i):
            parts.append(buf); buf = ""; i += 1
        elif ch in ";|":
            parts.append(buf); buf = ""
        else:
            buf += ch
        i += 1
    parts.append(buf)
    return [p.strip() for p in parts if p.strip()]


def _norm(path: str) -> str:
    out: list[str] = []
    for seg in path.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if out:
                out.pop()
        else:
            out.append(seg)
    return "/" + "/".join(out)


def _e(s: str) -> str:
    import html
    return html.escape(str(s), quote=False)
