"""Telegram side of UNFINITUM // EFFERENT-008 (motor pathway: commands out to the fleet): commands, 2FA approvals, grants, cards, runbooks, health pings, recordings,
Shamir break-glass for the CA, and the honeypot -> channel live stream."""
from __future__ import annotations

import asyncio
import base64
import datetime as dt
import html
import io
import json
import logging
import os
import re
import secrets
import time
from pathlib import Path

from telegram import (InlineKeyboardButton, InlineKeyboardMarkup, InputFile, LinkPreviewOptions, MenuButtonWebApp,
                      Update, WebAppInfo)
from telegram.error import TelegramError
from telegram.ext import (Application, ApplicationHandlerStop, CallbackQueryHandler, CommandHandler, ContextTypes,
                          filters)

from .. import shamir, ui
from . import health as healthmod
from . import jobs as jobmod
from . import knock as knocking
from .admin import AdminMixin
from .ca import CA
from .gateway import Gateway, GatewayError, Target, run as ssh_run
from .record import cast_to_gif
from .store import OpsStore
from .tunnel import NAME_RE, Tunnels
from .web import OpsWeb

log = logging.getLogger("nullbyte.ops")
NO_PREVIEW = LinkPreviewOptions(is_disabled=True)
TTL_RE = re.compile(r"^(\d+)(m|h|d)$")

RUNBOOKS: dict[str, tuple[str, str, bool]] = {          # key: (label, command, needs-confirm)
    "disk":   ("💽 disk",        "df -h -x tmpfs -x devtmpfs", False),
    "mem":    ("🧠 memory",      "free -h", False),
    "load":   ("📈 load",        "uptime; echo; ps -eo pcpu,pmem,comm --sort=-pcpu | head -8", False),
    "logs":   ("📜 logs",        "journalctl -n 30 --no-pager -o short", False),
    "ports":  ("🔌 ports",       "ss -tulpn 2>/dev/null | head -25", False),
    "docker": ("🐳 docker",      "docker ps --format 'table {{.Names}}\\t{{.Status}}\\t{{.Ports}}'", False),
    "nginx":  ("♻️ restart nginx", "sudo systemctl restart nginx && systemctl is-active nginx", True),
    "clean":  ("🧹 free disk",   "sudo journalctl --vacuum-size=200M >/dev/null 2>&1; sudo apt-get clean 2>/dev/null; "
                                "docker system prune -f 2>/dev/null | tail -1; df -h /", True),
    "gpu":    ("🎛 gpu",         "nvidia-smi 2>/dev/null || echo 'no NVIDIA GPU'", False),
    "update": ("📦 updates",     "apt list --upgradable 2>/dev/null | tail -n +2 | head -20 || dnf check-update | head -20", False),
}


def parse_ttl(s: str) -> int | None:
    m = TTL_RE.match(s.strip().lower())
    if not m:
        return None
    n, u = int(m.group(1)), m.group(2)
    secs = n * {"m": 60, "h": 3600, "d": 86400}[u]
    return secs if 60 <= secs <= 7 * 86400 else None


class Ops(AdminMixin):
    def __init__(self, cfg, db, app: Application):
        self.cfg, self.app = cfg, app
        self.store = OpsStore(db)
        self._admin_init()
        self.ca = CA(cfg.data_dir / "ops_ca_ed25519", cfg.ops_ca_passphrase)
        self.gw = Gateway(self.ca, cfg.data_dir / "recordings")
        self.tunnels = Tunnels(self.ca, cfg.token)
        self.pending_2fa: dict[str, tuple[asyncio.Future, int]] = {}
        self._2fa_by_dev: dict[tuple[int, str], asyncio.Future] = {}
        self.username = ""
        hp_fp = ""
        if cfg.host_key.exists():
            try:
                import asyncssh
                hp_fp = asyncssh.read_private_key(str(cfg.host_key)).get_fingerprint("sha256")
            except Exception:  # noqa: BLE001
                pass
        self.web = OpsWeb(token=cfg.token, store=self.store, gateway=self.gw, operators=self.is_operator,
                          ask_2fa=self.ask_2fa, bot_username=lambda: self.username,
                          honeypot_port=cfg.honeypot_port if cfg.honeypot_enabled else 0, honeypot_fp=hp_fp,
                          tunnels=self.tunnels)
        self.hp_queue: list[str] = []

    # ------------------------------------------------------------------ roles
    def webapp_button(self, label: str, query: str = "") -> InlineKeyboardButton | None:
        if not self.cfg.webapp_url:
            return None
        return InlineKeyboardButton(label, web_app=WebAppInfo(self.cfg.webapp_url.rstrip("/") + "/" + (("?" + query) if query else "")))

    # ------------------------------------------------------------------ lifecycle
    async def start(self) -> None:
        me = await self.app.bot.get_me()
        self.username = me.username
        await self.web.start(self.cfg.webapp_host, self.cfg.webapp_port)
        if self.cfg.webapp_url and self.cfg.owner_id:
            try:
                btn = MenuButtonWebApp("⟶ terminal", WebAppInfo(self.cfg.webapp_url))
                await self.app.bot.set_chat_menu_button(menu_button=btn)                      # everyone
                await self.app.bot.set_chat_menu_button(self.cfg.owner_id, btn)               # owner override
                log.info("menu button → %s", self.cfg.webapp_url)
            except TelegramError as e:
                log.warning("menu button: %s", e)
        jq = self.app.job_queue
        if jq:
            jq.run_repeating(self.job_health, interval=max(1, self.cfg.ops_health_min) * 60, first=45, name="ops_health")
            jq.run_repeating(self.job_hp_stream, interval=6, first=10, name="hp_stream")
            jq.run_repeating(self.job_watch, interval=max(15, self.cfg.ops_job_poll), first=20, name="fx_jobs")
            jq.run_repeating(self.job_tunnels, interval=300, first=300, name="fx_tunnels")

    async def stop(self) -> None:
        await self.web.stop()

    def register(self) -> None:
        add = self.app.add_handler
        self.register_admin()
        add(CommandHandler("start", self.cmd_start_deeplink, filters=filters.Regex(r"^/start\s+(g|c|w)_")), group=-1)
        for name, fn in [("efferent", self.cmd_ops), ("fx", self.cmd_ops), ("fx_ca", self.cmd_ca), ("fx_grant", self.cmd_grant),
                         ("fx_grants", self.cmd_grants), ("fx_cert", self.cmd_cert), ("fx_card", self.cmd_card),
                         ("fx_audit", self.cmd_audit), ("fx_sessions", self.cmd_sessions), ("fx_signal", self.cmd_run),
                         ("fx_afferent", self.cmd_health), ("fx_knock", self.cmd_knock),
                         ("fx_breakglass", self.cmd_breakglass), ("fx_recover", self.cmd_recover),
                         ("hp_stream", self.cmd_hp_stream),
                         ("fx_watch", self.cmd_watch), ("fx_jobs", self.cmd_jobs), ("fx_gpu", self.cmd_gpu),
                         ("fx_tunnel", self.cmd_tunnel), ("fx_tunnels", self.cmd_tunnels),
                         ("fx_reflex", self.cmd_reflex), ("fx_reflexes", self.cmd_reflexes),
                         # legacy aliases
                         ("ops", self.cmd_ops)]:
            add(CommandHandler(name, fn))
        add(CallbackQueryHandler(self.on_callback, pattern=r"^ops"))

    # ------------------------------------------------------------------ helpers
    async def _deny(self, update: Update) -> bool:
        if not self.is_operator(update.effective_user.id):
            uid = update.effective_user.id
            if self.locked:
                txt = "🚨 EFFERENT-008 is in lockdown. Try again later."
                kb = None
            else:
                txt = ("EPERM :: EFFERENT-008 is for operators.\n"
                       f"your id: {uid}\ntap below and the owner gets a one-tap approve.")
                kb = self.request_button()
            await update.effective_message.reply_text(ui.pre(txt), reply_markup=kb)
            return True
        return False

    def _server(self, uid: int, ref: str):
        if ref.isdigit():
            s = self.store.server(int(ref))
            return s if s and s["owner_id"] == uid else None
        return self.store.server_by_name(uid, ref)

    def _target(self, s) -> Target:
        return Target(s["host"], s["port"], s["user"], s["fingerprint"], "ca", knock=knocking.parse(s["knock"]), name=s["name"])

    # ------------------------------------------------------------------ 2FA
    async def ask_2fa(self, uid: int, label: str, device: str) -> str:
        # same device asking again while a prompt is still open (app was backgrounded → reconnected):
        # share the existing prompt instead of spamming a second one
        waiting = self._2fa_by_dev.get((uid, device))
        if waiting and not waiting.done():
            try:
                return await asyncio.wait_for(asyncio.shield(waiting), 95)
            except asyncio.TimeoutError:
                return "deny"
        tok = secrets.token_hex(5)
        fut = asyncio.get_running_loop().create_future()
        self.pending_2fa[tok] = (fut, uid)
        self._2fa_by_dev[(uid, device)] = fut
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("✓ allow once", callback_data=f"ops2fa:{tok}:once"),
                                    InlineKeyboardButton("✓ trust device 12h", callback_data=f"ops2fa:{tok}:trust")],
                                   [InlineKeyboardButton("✕ deny", callback_data=f"ops2fa:{tok}:deny")]])
        try:
            msg = await self.app.bot.send_message(uid, ui.box("🔐 LOGIN APPROVAL", [
                f"target  {ui.clip(label, 22)}", f"device  {device[:12]}…", f"time    {time.strftime('%H:%M:%S')}",
                "", "Not you? Deny, then rotate your vault passphrase."]), reply_markup=kb)
        except TelegramError:
            self.pending_2fa.pop(tok, None)
            return "deny"
        try:
            verdict = await asyncio.wait_for(asyncio.shield(fut), 90)
        except asyncio.TimeoutError:
            verdict = "deny"
        self.pending_2fa.pop(tok, None)
        self._2fa_by_dev.pop((uid, device), None)
        if not fut.done():
            fut.set_result(verdict)
        if verdict == "once":
            # grace window: approving usually means leaving the Mini App to tap the button, which can drop the
            # socket on iOS — let the same device reconnect for a couple of minutes without asking again
            self.store.trust(uid, device, 180)
        try:
            await msg.edit_text(ui.pre({"once": "✓ approved (once)", "trust": "✓ approved · device trusted 12h",
                                        "deny": "✕ denied"}[verdict] + f"\n{label}"))
        except TelegramError:
            pass
        return verdict

    # ------------------------------------------------------------------ /ops dashboard
    async def cmd_ops(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        uid = update.effective_user.id
        rows: list[list[InlineKeyboardButton]] = []
        b = self.webapp_button("⟶ open terminal")
        if b:
            rows.append([b])
        grants = self.store.grants_for(uid)
        if not self.is_operator(uid):
            if not grants:
                await self._deny(update)
                return
            lines = [f"⏳ {ui.clip(g['name'], 14):<14} until {dt.datetime.fromtimestamp(g['expires']):%H:%M}" for g in grants]
            await update.message.reply_text(ui.box("EFFERENT-008 // SHARED WITH YOU", lines), reply_markup=InlineKeyboardMarkup(rows) if rows else None)
            return
        servers = self.store.servers(uid)
        lines = []
        for s in servers:
            last = self.store.health(s["id"], time.time() - 3600)
            dot = "🔴" if s["alert_state"] == "down" else "🟡" if s["alert_state"] else "🟢" if last else "⚪"
            if last and last[-1]["ok"]:
                h = last[-1]
                lines.append(f"{dot} {ui.clip(s['name'], 12):<12} L{h['load']:.1f} m{h['mem']:.0f}% d{h['disk']:.0f}%")
            else:
                lines.append(f"{dot} {ui.clip(s['name'], 12):<12} {s['user']}@{ui.clip(s['host'], 14)}")
            rows.append([InlineKeyboardButton(f"⚡ {s['name'][:12]}", callback_data=f"ops:rb:{s['id']}"),
                         InlineKeyboardButton("📈", callback_data=f"ops:hc:{s['id']}"),
                         InlineKeyboardButton("🚪", callback_data=f"ops:kn:{s['id']}"),
                         InlineKeyboardButton("🪪", callback_data=f"ops:cd:{s['id']}")])
        if not servers:
            lines = ["no monitored servers yet", "", "1. /fx_ca → trust the CA on a server", "2. ⟶ open terminal → ＋ add",
                     "   (CA auth + monitor = health + runbooks)"]
        if not self.cfg.webapp_url:
            lines += ["", "⚠ WEBAPP_URL not set: Mini App offline"]
        lines += ["", f"live sessions {len(self.gw.sessions)} · grants {len(self.store.active_grants(uid))}"]
        await update.message.reply_text(ui.box("EFFERENT-008 // FLEET", lines), reply_markup=InlineKeyboardMarkup(rows) if rows else None)

    async def cmd_ca(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if await self._deny(update):
            return
        await update.message.reply_text(
            ui.box("SSH CERTIFICATE AUTHORITY", [f"fp {ui.clip(self.ca.fingerprint, 32)}", "",
                                                  "paste on each server once ↓", "then: keyless, expiring logins"])
            + "\n" + ui.pre(self.ca.install_snippet())
            + "\n<i>Principals = usernames. A cert for <code>deploy</code> only logs in as deploy.</i>")

    # ------------------------------------------------------------------ deep links: grants, cards, watch
    async def cmd_start_deeplink(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        arg = ctx.args[0] if ctx.args else ""
        u = update.effective_user
        name = f"@{u.username}" if u.username else (u.first_name or str(u.id))
        if arg.startswith("g_"):
            g = self.store.claim_grant(arg[2:], u.id, name)
            if not g:
                await update.message.reply_text(ui.pre("✕ grant expired, revoked, or already claimed"))
                raise ApplicationHandlerStop
            s = self.store.server(g["server_id"])
            self.store.audit(u.id, "grant-claim", s["name"], f"grant {g['id']} by {name}")
            until = dt.datetime.fromtimestamp(g["expires"])
            b = self.webapp_button("⟶ open terminal")
            await update.message.reply_text(
                ui.box("ACCESS GRANTED", [f"server  {ui.clip(s['name'], 22)}", f"login   {g['principal']}",
                                          f"until   {until:%Y-%m-%d %H:%M}", f"mode    {'read-only' if g['readonly'] else 'shell'}",
                                          "", "expires on its own · can't be reused"])
                + f"\n<i>Own SSH client?</i> <code>/fx_cert {g['id']} ssh-ed25519 AAAA…</code> <i>gets you a cert for your key.</i>",
                reply_markup=InlineKeyboardMarkup([[b]]) if b else None)
            try:
                await self.app.bot.send_message(g["created_by"], ui.pre(f"[ OK ] {name} claimed grant #{g['id']} → {s['name']}"))
            except TelegramError:
                pass
        elif arg.startswith("c_"):
            card = self.store.card(arg[2:])
            if not card:
                await update.message.reply_text(ui.pre("✕ card not found"))
                raise ApplicationHandlerStop
            q = "card=" + base64.b64encode(json.dumps({"name": card.get("name"), "host": card.get("host"), "port": card.get("port"),
                                                       "user": card.get("user"), "fp": card.get("fingerprint"),
                                                       "knock": card.get("knock") or "", "auth": "ca"}).encode()).decode()
            b = self.webapp_button("＋ add to my servers", q)
            await update.message.reply_text(self.card_text(card), reply_markup=InlineKeyboardMarkup([[b]]) if b else None)
        elif arg.startswith("w_"):
            b = self.webapp_button("👁 watch live", "watch=" + arg[2:])
            s = self.gw.watch(arg[2:])
            await update.message.reply_text(
                ui.box("LIVE SESSION", [f"target  {ui.clip(s.target.label, 22)}" if s else "session ended",
                                        "mode    read-only", "you can't type, only watch"]),
                reply_markup=InlineKeyboardMarkup([[b]]) if (b and s) else None)
        raise ApplicationHandlerStop

    @staticmethod
    def card_text(card: dict) -> str:
        return ui.box("🪪 CONNECTION CARD", [
            f"name  {ui.clip(card.get('name') or '-', 24)}", f"host  {ui.clip(card.get('host') or '', 24)}",
            f"port  {card.get('port') or 22}", f"user  {card.get('user') or 'root'}",
            f"knock {card.get('knock') or '-'}", "", "host key (verify before trusting):",
            ui.clip(card.get("fingerprint") or "-", 34), "", "no passwords · no keys · nothing secret"])

    async def cmd_card(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if await self._deny(update):
            return
        s = self._server(update.effective_user.id, " ".join(ctx.args)) if ctx.args else None
        if not s:
            await update.message.reply_text(ui.pre("usage: /fx_card <server name>"))
            return
        await self._send_card(update.effective_chat.id, update.effective_user.id, s)

    async def _send_card(self, chat_id: int, uid: int, s) -> None:
        card = {"name": s["name"], "host": s["host"], "port": s["port"], "user": s["user"],
                "fingerprint": s["fingerprint"], "knock": s["knock"]}
        cid = self.store.create_card(uid, card)
        link = f"https://t.me/{self.username}?start=c_{cid}"
        await self.app.bot.send_message(chat_id, self.card_text(card) + f"\n{html.escape(link)}",
                                        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(
                                            "↗ share card", url=f"https://t.me/share/url?url={link}")]]),
                                        link_preview_options=NO_PREVIEW)

    # ------------------------------------------------------------------ grants + certs
    async def cmd_grant(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if await self._deny(update):
            return
        a = ctx.args
        if len(a) < 2:
            await update.message.reply_text(ui.pre("usage: /fx_grant <server> <30m|2h|1d> [user=deploy] [ro]\n"
                                                    "→ a one-time link; whoever opens it first gets access until it expires"))
            return
        uid = update.effective_user.id
        s = self._server(uid, a[0])
        ttl = parse_ttl(a[1])
        if not s or not ttl:
            await update.message.reply_text(ui.pre("✕ unknown server or bad duration (1m … 7d)"))
            return
        principal = next((x.split("=", 1)[1] for x in a[2:] if x.startswith("user=")), s["user"])
        ro = "ro" in a[2:]
        tok = self.store.create_grant(s["id"], principal, uid, ttl, ro)
        self.store.audit(uid, "grant-create", s["name"], f"{principal} {a[1]} {'ro' if ro else 'rw'}")
        link = f"https://t.me/{self.username}?start=g_{tok}"
        await update.message.reply_text(
            ui.box("GRANT MINTED", [f"server  {s['name']}", f"login   {principal}", f"ttl     {a[1]}",
                                    f"mode    {'read-only' if ro else 'shell'}", "", "one claim · auto-expires · revocable"])
            + f"\n{html.escape(link)}",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("↗ send to a friend",
                                                                     url=f"https://t.me/share/url?url={link}")]]),
            link_preview_options=NO_PREVIEW)

    async def cmd_grants(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if await self._deny(update):
            return
        gs = self.store.active_grants(update.effective_user.id)
        if not gs:
            await update.message.reply_text(ui.pre("no active grants"))
            return
        lines = [f"#{g['id']:<3} {ui.clip(g['name'], 10):<10} {ui.clip(g['grantee_name'] or 'unclaimed', 11):<11} "
                 f"{dt.datetime.fromtimestamp(g['expires']):%H:%M}" for g in gs]
        kb = [[InlineKeyboardButton(f"✕ revoke #{g['id']}", callback_data=f"ops:rv:{g['id']}")] for g in gs[:8]]
        await update.message.reply_text(ui.box("ACTIVE GRANTS", lines), reply_markup=InlineKeyboardMarkup(kb))

    async def cmd_cert(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        uid = update.effective_user.id
        if len(ctx.args) < 3 or not ctx.args[0].isdigit():
            await update.message.reply_text(ui.pre("usage: /fx_cert <grant id> <ssh-ed25519 AAAA… your public key>"))
            return
        g = next((g for g in self.store.grants_for(uid) if g["id"] == int(ctx.args[0])), None)
        if not g:
            await update.message.reply_text(ui.pre("✕ no such active grant for you"))
            return
        try:
            cert = self.ca.sign_openssh_pubkey(" ".join(ctx.args[1:3]), g["principal"], g["expires"] - time.time(),
                                               f"grant{g['id']}-tg{uid}")
        except Exception as e:  # noqa: BLE001
            await update.message.reply_text(ui.pre(f"✕ couldn't read that public key ({type(e).__name__})"))
            return
        self.store.audit(uid, "cert-issue", g["name"], f"grant {g['id']}")
        await update.message.reply_document(
            InputFile(io.BytesIO((cert + "\n").encode()), filename="id_ed25519-cert.pub"),
            caption=ui.pre(f"save next to your key as  ~/.ssh/id_ed25519-cert.pub\nssh {g['principal']}@{g['host']} -p {g['port']}\n"
                           f"valid until {dt.datetime.fromtimestamp(g['expires']):%Y-%m-%d %H:%M}"))

    # ------------------------------------------------------------------ runbooks
    def _runbooks(self) -> dict:
        rb = dict(RUNBOOKS)
        try:
            for k, v in json.loads(self.store.db.get("ops_runbooks", "{}")).items():
                rb[k] = (v.get("label", k), v["cmd"], bool(v.get("confirm")))
        except (ValueError, KeyError):
            pass
        return rb

    async def cmd_run(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if await self._deny(update):
            return
        a = ctx.args
        if a and a[0] == "add" and len(a) >= 3:
            rb = json.loads(self.store.db.get("ops_runbooks", "{}"))
            rb[a[1]] = {"label": "⚙️ " + a[1], "cmd": " ".join(a[2:]), "confirm": True}
            self.store.db.set("ops_runbooks", json.dumps(rb))
            self.store.audit(update.effective_user.id, "runbook-add", a[1], " ".join(a[2:]))
            await update.message.reply_text(ui.pre(f"[ OK ] runbook '{a[1]}' saved (asks before running)"))
            return
        if len(a) < 2:
            await update.message.reply_text(ui.pre("usage: /fx_signal <server> <" + "|".join(self._runbooks()) + ">\n"
                                                    "       /fx_signal add <name> <command…>"))
            return
        s = self._server(update.effective_user.id, a[0])
        if not s:
            await update.message.reply_text(ui.pre("✕ unknown server"))
            return
        await self._run_book(update.effective_chat.id, update.effective_user.id, s, a[1])

    async def _run_book(self, chat_id: int, uid: int, s, key: str) -> None:
        rb = self._runbooks().get(key)
        if not rb:
            await self.app.bot.send_message(chat_id, ui.pre("✕ unknown runbook"))
            return
        label, cmd, _ = rb
        msg = await self.app.bot.send_message(chat_id, ui.pre(f"[....] {label} @ {s['name']}"))
        try:
            code, out = await ssh_run(self._target(s), self.ca, cmd, key_id=f"tg{uid}-rb-{key}")
        except GatewayError as e:
            self.store.audit(uid, "runbook-fail", s["name"], f"{key}: {e}")
            await msg.edit_text(ui.pre(f"[FAIL] {label} @ {s['name']}\n{e}"))
            return
        self.store.audit(uid, "runbook", s["name"], f"{key} → exit {code}")
        out = out.strip() or "(no output)"
        if len(out) > 3300:
            out = "…\n" + out[-3300:]
        await msg.edit_text(f"<b>{html.escape(label)}</b> @ <code>{html.escape(s['name'])}</code> "
                            f"<code>exit {code}</code>\n" + ui.pre(out),
                            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("↻ again", callback_data=f"ops:go:{s['id']}:{key}")]]))

    # ------------------------------------------------------------------ health
    async def probe(self, s) -> dict | None:
        try:
            code, out = await ssh_run(self._target(s), self.ca, healthmod.PROBE, timeout=20, key_id="nullbyte-health")
            m = healthmod.parse(out)
            self.store.add_health(s["id"], True, m["load"], m["cpus"], m["mem"], m["disk"], m["uptime"], m.get("gpu"))
            return m
        except (GatewayError, ValueError, asyncio.TimeoutError) as e:
            log.info("health %s: %s", s["name"], e)
            self.store.add_health(s["id"], False)
            return None

    async def job_health(self, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        for s in self.store.servers():
            if not s["monitor"]:
                continue
            m = await self.probe(s)
            if m is None:
                fails = self.store.health(s["id"], time.time() - 3600)[-2:]
                state = "down" if len(fails) == 2 and not any(f["ok"] for f in fails) else s["alert_state"]
                issues = ["unreachable (2 probes in a row)"] if state == "down" else []
            else:
                issues = healthmod.problems(m)
                state = ",".join(sorted(i.split()[0] for i in issues))
            if state != (s["alert_state"] or ""):
                self.store.set_alert_state(s["id"], state)
                await self._alert(s, issues, recovered=not state)
                if m is not None and issues:
                    await self._reflexes(s, issues)

    async def _alert(self, s, issues: list[str], recovered: bool) -> None:
        rows = self.store.health(s["id"], time.time() - 6 * 3600)
        png = await asyncio.to_thread(healthmod.chart, s["name"], rows)
        cap = (ui.pre(f"[ OK ] {s['name']} recovered") if recovered else
               ui.box(f"⚠ {s['name']}", issues + ["", "/efferent → ⚡ signals"]))
        try:
            await self.app.bot.send_photo(s["owner_id"], png, caption=cap,
                                          reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(
                                              "⚡ signals", callback_data=f"ops:rb:{s['id']}")]]))
        except TelegramError as e:
            log.warning("alert: %s", e)

    async def cmd_health(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if await self._deny(update):
            return
        s = self._server(update.effective_user.id, " ".join(ctx.args)) if ctx.args else None
        if not s:
            await update.message.reply_text(ui.pre("usage: /fx_afferent <server>"))
            return
        await self._send_health(update.effective_chat.id, s)

    async def _send_health(self, chat_id: int, s) -> None:
        m = await self.probe(s)
        rows = self.store.health(s["id"], time.time() - 24 * 3600)
        png = await asyncio.to_thread(healthmod.chart, s["name"], rows)
        if m:
            cap = ui.box(f"⟵ afferent · {s['name']}", [f"load   {m['load']:.2f} / {m['cpus']} cpu", f"mem    {ui.bar(m['mem'] / 100, 12)} {m['mem']:.0f}%",
                                            f"disk   {ui.bar(m['disk'] / 100, 12)} {m['disk']:.0f}%",
                                            f"uptime {ui.human_duration(m['uptime'])}"] + healthmod.gpu_lines(m.get("gpu") or []))
        else:
            cap = ui.pre(f"[FAIL] {s['name']} unreachable")
        await self.app.bot.send_photo(chat_id, png, caption=cap)

    # ------------------------------------------------------------------ knock
    async def cmd_knock(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if await self._deny(update):
            return
        s = self._server(update.effective_user.id, " ".join(ctx.args)) if ctx.args else None
        if not s:
            await update.message.reply_text(ui.pre("usage: /fx_knock <server>\nknockd config:\n" + knocking.knockd_snippet([])))
            return
        await self._knock(update.effective_chat.id, update.effective_user.id, s)

    async def _knock(self, chat_id: int, uid: int, s) -> None:
        ports = knocking.parse(s["knock"])
        if not ports:
            await self.app.bot.send_message(chat_id, ui.pre("no knock sequence for this server · set one in the Mini App\n\n"
                                                            + knocking.knockd_snippet([7000, 8000, 9000], s["port"])))
            return
        n = await knocking.knock(s["host"], ports)
        self.store.audit(uid, "knock", s["name"], ",".join(map(str, ports)))
        await self.app.bot.send_message(chat_id, ui.pre(f"🚪 knocked {n}× on {s['name']} · door open ~60s for the gateway"))

    # ------------------------------------------------------------------ audit + recordings
    async def cmd_audit(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if await self._deny(update):
            return
        rows = self.store.audit_tail(20)
        lines = [f"{time.strftime('%m-%d %H:%M', time.localtime(r['ts']))} {ui.clip(r['action'], 13):<13} {ui.clip(r['target'] or '', 12)}"
                 for r in rows] or ["(empty)"]
        await update.message.reply_text(ui.box("AUDIT LOG", lines))

    async def cmd_sessions(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if await self._deny(update):
            return
        rows = [r for r in self.store.sessions(update.effective_user.id, 10) if r["cast"]]
        if not rows:
            await update.message.reply_text(ui.pre("no recorded sessions yet"))
            return
        lines = [f"#{r['id']:<4} {ui.clip(r['target'], 14):<14} {ui.human_duration((r['ended'] or time.time()) - r['started'])}"
                 for r in rows]
        kb = [[InlineKeyboardButton(f"▶ GIF #{r['id']}", callback_data=f"ops:gif:{r['id']}"),
               InlineKeyboardButton("📄 .cast", callback_data=f"ops:cast:{r['id']}")] for r in rows[:6]]
        await update.message.reply_text(ui.box("RECORDINGS", lines), reply_markup=InlineKeyboardMarkup(kb))

    async def _send_recording(self, chat_id: int, uid: int, sid: int, gif: bool) -> None:
        r = self.store.session(sid)
        if not r or r["user_id"] != uid or not r["cast"] or not Path(r["cast"]).exists():
            await self.app.bot.send_message(chat_id, ui.pre("✕ recording not found"))
            return
        if gif:
            data = await asyncio.to_thread(cast_to_gif, Path(r["cast"]), 90, 6, 100, 32, 1.5, r["target"])
            await self.app.bot.send_animation(chat_id, InputFile(io.BytesIO(data), filename=f"session_{sid}.gif"),
                                              caption=ui.pre(f"▶ session #{sid} · {r['target']}\nidle gaps squashed · max 90s"))
        else:
            await self.app.bot.send_document(chat_id, InputFile(Path(r["cast"]).read_bytes(), filename=f"session_{sid}.cast"),
                                             caption=ui.pre("asciinema play session.cast"))

    # ------------------------------------------------------------------ break-glass (Shamir over the CA key)
    async def cmd_breakglass(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if update.effective_user.id != self.cfg.owner_id:
            await update.message.reply_text(ui.pre("EPERM :: owner only"))
            return
        try:
            k, n = (int(x) for x in ctx.args[:2]) if len(ctx.args) >= 2 else (2, 3)
            shares = shamir.split(self.ca.export_private(), k, n)
        except (ValueError, shamir.ShamirError) as e:
            await update.message.reply_text(ui.pre(f"usage: /fx_breakglass <k> <n>   e.g. 2 3\n{e}"))
            return
        self.store.audit(update.effective_user.id, "breakglass-split", "ca", f"{k}-of-{n}")
        await update.message.reply_text(ui.box("BREAK-GLASS KEY", [
            f"CA key split {k}-of-{n}", f"ca fp {ui.clip(self.ca.fingerprint, 26)}", "",
            "forward ONE share to each guardian", "delete these messages afterwards",
            f"any {k} can restore the CA:", "/fx_recover <share> <share>"]))
        for s in shares:
            await update.message.reply_text(f"🛡 <b>guardian share {s.x}/{n}</b> · NULLBYTE CA\n" + ui.pre(s.encode()))

    async def cmd_recover(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if update.effective_user.id != self.cfg.owner_id:
            await update.message.reply_text(ui.pre("EPERM :: owner only"))
            return
        text = update.message.text or ""
        found = re.findall(r"sss1-[0-9a-f]{6}-\d{1,2}-\d{1,2}-[a-z2-7]+-[0-9a-f]{4}", text, re.I)
        try:
            secret = shamir.combine([shamir.Share.decode(x) for x in found])
        except shamir.ShamirError as e:
            await update.message.reply_text(ui.pre(f"✕ {e}"))
            return
        path = self.ca.path
        if path.exists():
            path.rename(path.with_suffix(f".bak{int(time.time())}"))
        self.ca = CA.restore(path, secret, self.cfg.ops_ca_passphrase)
        self.gw.ca = self.ca
        self.store.audit(update.effective_user.id, "breakglass-recover", "ca", self.ca.fingerprint)
        try:
            await update.message.delete()
        except TelegramError:
            pass
        await self.app.bot.send_message(update.effective_chat.id, ui.pre(f"[ OK ] CA restored from {len(found)} shares\n     fp {self.ca.fingerprint}"))

    # ------------------------------------------------------------------ honeypot -> channel live stream
    def hp_push(self, st: dict, line: str) -> None:
        if self.store.db.get("hp_stream", "0") != "1" or not self.cfg.hp_stream_chat:
            return
        safe = re.sub(r"(https?|ftp)://", lambda m: m.group(1).replace("t", "x") + "://", line)
        safe = re.sub(r"(\d+)\.(\d+)\.(\d+)\.(\d+)", r"\1.\2.\3[.]\4", safe)
        ip = st.get("ip", "?")
        masked = re.sub(r"\.\d+$", ".x", ip) if "." in ip else ip[:8] + "…"
        cc = (st.get("geo") or {}).get("countryCode")
        if len(self.hp_queue) < 60:
            self.hp_queue.append(f"{ui.flag(cc)} <code>{html.escape(masked)}</code> ⟫ <code>{html.escape(safe[:180])}</code>")

    async def job_hp_stream(self, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if not self.hp_queue or not self.cfg.hp_stream_chat:
            return
        batch, self.hp_queue = self.hp_queue[:20], self.hp_queue[20:]
        try:
            await self.app.bot.send_message(self.cfg.hp_stream_chat, "🍯 <b>live from the honeypot</b> <code>⟵ afferent</code>\n" + "\n".join(batch),
                                            link_preview_options=NO_PREVIEW, disable_notification=True)
        except TelegramError as e:
            log.warning("hp stream: %s", e)

    async def cmd_hp_stream(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if update.effective_user.id != self.cfg.owner_id:
            return
        on = (ctx.args[0].lower() if ctx.args else "") in ("on", "1", "yes")
        self.store.db.set("hp_stream", "1" if on else "0")
        where = self.cfg.hp_stream_chat or "(set HP_STREAM_CHAT)"
        await update.message.reply_text(ui.pre(f"honeypot → {where}: {'STREAMING 📡' if on else 'off'}\n"
                                               "IPs masked · URLs defanged · batched every 6s"))

    # ------------------------------------------------------------------ callbacks
    async def on_callback(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        q = update.callback_query
        uid = q.from_user.id
        parts = q.data.split(":")
        if parts[0] == "ops2fa":
            tok, verdict = parts[1], parts[2]
            entry = self.pending_2fa.get(tok)
            if not entry or entry[1] != uid:
                await q.answer("expired")
                return
            if not entry[0].done():
                entry[0].set_result(verdict)
            await q.answer({"deny": "denied", "once": "approved", "trust": "approved + trusted"}[verdict])
            return
        if not self.is_operator(uid):
            await q.answer("operators only")
            return
        await q.answer()
        act = parts[1]
        chat = q.message.chat_id
        if act == "rv":
            ok = self.store.revoke_grant(int(parts[2]), uid)
            if ok:
                self.store.audit(uid, "grant-revoke", f"#{parts[2]}")
                for s in list(self.gw.sessions.values()):
                    if s.target.name.endswith("(grant)") and s.user_id != uid:
                        g = self.store.grant(int(parts[2]))
                        if g and s.user_id == g["grantee_id"]:
                            await s.close("grant revoked")
            await self.app.bot.send_message(chat, ui.pre(f"{'[ OK ] revoked' if ok else '✕ not yours'} #{parts[2]}"))
            return
        if act == "gif" or act == "cast":
            await self._send_recording(chat, uid, int(parts[2]), act == "gif")
            return
        if act in ("jp", "jt", "jk", "jkk"):
            j = self.store.job(int(parts[2]))
            if not j or j["owner_id"] != uid:
                return
            if act == "jk":
                await self.app.bot.send_message(chat, ui.pre(f"kill job #{j['id']} ({j['label'][:40]})?"),
                                                reply_markup=InlineKeyboardMarkup([[
                                                    InlineKeyboardButton("✕ kill it", callback_data=f"ops:jkk:{j['id']}"),
                                                    InlineKeyboardButton("keep running", callback_data="ops:noop:0")]]))
                return
            s = self.store.server(j["server_id"])
            try:
                if act == "jkk":
                    await ssh_run(self._target(s), self.ca, jobmod.kill_cmd(j["token"]), key_id=f"tg{uid}-jobkill")
                    self.store.audit(uid, "job-kill", s["name"], f"#{j['id']}")
                code, log_text = await self._poll_job(j)
            except GatewayError as e:
                await self.app.bot.send_message(chat, ui.pre(f"[FAIL] {e}"))
                return
            if code is not None and j["state"] == "running":
                self.store.update_job(j["id"], state="done" if code == 0 else ("killed" if code in (143, 137) else "failed"),
                                      exit=code, finished=time.time())
                j = self.store.job(j["id"])
            if act == "jt":
                await self.app.bot.send_message(chat, f"<b>📜 job #{j['id']}</b>\n" + ui.pre("\n".join(log_text.splitlines()[-40:])[-3500:] or "(empty)"))
            else:
                await self._job_report(chat, j, log_text, final=j["state"] != "running")
            return
        if act == "tc":
            ok = self.tunnels.close(parts[2])
            if ok:
                self.store.audit(uid, "tunnel-close", parts[2])
            await self.app.bot.send_message(chat, ui.pre(f"{'[ OK ] closed' if ok else '✕ not open'} tunnel {parts[2]}"))
            return
        if act.startswith("rx"):
            r = self.store.reflex(int(parts[2]))
            if not r or r["owner_id"] != uid:
                return
            if act == "rxd":
                self.store.delete_reflex(r["id"], uid)
                await self.app.bot.send_message(chat, ui.pre(f"reflex #{r['id']} removed"))
            elif act == "rxe":
                self.store.update_reflex(r["id"], enabled=0 if r["enabled"] else 1)
                await self.app.bot.send_message(chat, ui.pre(f"reflex #{r['id']} {'paused' if r['enabled'] else 'active'}"))
            elif act == "rxt":
                self.store.update_reflex(r["id"], trusted=0 if r["trusted"] else 1)
                self.store.audit(uid, "reflex-trust", r["server"], f"#{r['id']} {'ask' if r['trusted'] else 'auto'}")
                await self.app.bot.send_message(chat, ui.pre(f"reflex #{r['id']} → {'asks first' if r['trusted'] else 'fires automatically'}"))
            elif act in ("rxf", "rxa"):
                if act == "rxa":
                    self.store.update_reflex(r["id"], trusted=1)
                    self.store.audit(uid, "reflex-trust", r["server"], f"#{r['id']} auto")
                s = self.store.server(r["server_id"])
                self.store.audit(uid, "reflex-fire", s["name"], f"{r['trigger']} → {r['signal']}")
                await self._run_book(chat, uid, s, r["signal"])
            return
        s = self.store.server(int(parts[2]))
        if not s or s["owner_id"] != uid:
            return
        if act == "rb":
            books = self._runbooks()
            kb, row = [], []
            for key, (label, _, _) in books.items():
                row.append(InlineKeyboardButton(label, callback_data=f"ops:go:{s['id']}:{key}"))
                if len(row) == 2:
                    kb.append(row)
                    row = []
            if row:
                kb.append(row)
            await self.app.bot.send_message(chat, ui.pre(f"⚡ efferent signals → {s['name']}"), reply_markup=InlineKeyboardMarkup(kb))
        elif act == "go":
            key = parts[3]
            label, cmd, confirm = self._runbooks().get(key, ("?", "", False))
            if confirm and (len(parts) < 5 or parts[4] != "y"):
                await self.app.bot.send_message(chat, ui.pre(f"run on {s['name']}?\n$ {cmd}"),
                                                reply_markup=InlineKeyboardMarkup([[
                                                    InlineKeyboardButton("✓ run", callback_data=f"ops:go:{s['id']}:{key}:y"),
                                                    InlineKeyboardButton("✕ cancel", callback_data="ops:noop:0")]]))
                return
            await self._run_book(chat, uid, s, key)
        elif act == "hc":
            await self._send_health(chat, s)
        elif act == "kn":
            await self._knock(chat, uid, s)
        elif act == "cd":
            await self._send_card(chat, uid, s)

    # ================================================================== training watch
    async def cmd_watch(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if await self._deny(update):
            return
        uid = update.effective_user.id
        raw = (update.message.text or "").split(None, 2)
        if len(raw) < 3:
            await update.message.reply_text(ui.pre("usage: /fx_watch <server> [cd=~/dir] <command…>\n"
                                                    "e.g.  /fx_watch lab cd=~/odor python train.py --epochs 50\n"
                                                    "runs detached · survives disconnects · pings you when done"))
            return
        s = self._server(uid, raw[1])
        if not s:
            await update.message.reply_text(ui.pre("✕ unknown server (monitored CA servers only)"))
            return
        rest = raw[2].strip()
        cwd = ""
        if rest.startswith("cd="):
            cwd, _, rest = rest[3:].partition(" ")
            cwd = cwd.replace("~", "$HOME", 1) if cwd.startswith("~") else cwd
        label = re.sub(r"\s+", " ", rest)[:60]
        jid, tok = self.store.add_job(uid, s["id"], label, rest)
        try:
            code, out = await ssh_run(self._target(s), self.ca, jobmod.launch_cmd(tok, rest, cwd), key_id=f"tg{uid}-job{jid}")
        except GatewayError as e:
            self.store.update_job(jid, state="failed", finished=time.time(), exit=-1)
            await update.message.reply_text(ui.pre(f"[FAIL] couldn't launch on {s['name']}\n{e}"))
            return
        self.store.audit(uid, "job-start", s["name"], rest[:200])
        await update.message.reply_text(
            ui.box(f"⟶ JOB #{jid} LAUNCHED", [f"server  {s['name']}", f"cmd     {ui.clip(label, 24)}",
                                             f"pgid    {out.strip().split()[-1] if out.strip() else '?'}",
                                             "", "detached · I'll ping you when it ends", "with exit code, log tail + curves"]),
            reply_markup=self._job_kb(jid))

    def _job_kb(self, jid: int, running: bool = True) -> InlineKeyboardMarkup:
        row = [InlineKeyboardButton("📈 progress", callback_data=f"ops:jp:{jid}"),
               InlineKeyboardButton("📜 tail", callback_data=f"ops:jt:{jid}")]
        if running:
            row.append(InlineKeyboardButton("✕ kill", callback_data=f"ops:jk:{jid}"))
        return InlineKeyboardMarkup([row])

    async def cmd_jobs(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if await self._deny(update):
            return
        rows = self.store.jobs(update.effective_user.id, state=None)[:10]
        if not rows:
            await update.message.reply_text(ui.pre("no jobs yet · /fx_watch <server> <command>"))
            return
        icon = {"running": "◐", "done": "✓", "failed": "✗", "killed": "■"}
        lines = [f"{icon.get(r['state'], '?')} #{r['id']:<3} {ui.clip(r['server'], 8):<8} "
                 f"{ui.human_duration((r['finished'] or time.time()) - r['started']):>7}  {ui.clip(r['label'], 14)}" for r in rows]
        kb = [[InlineKeyboardButton(f"#{r['id']} 📈", callback_data=f"ops:jp:{r['id']}"),
               InlineKeyboardButton("📜", callback_data=f"ops:jt:{r['id']}")]
              + ([InlineKeyboardButton("✕", callback_data=f"ops:jk:{r['id']}")] if r["state"] == "running" else [])
              for r in rows[:6]]
        await update.message.reply_text(ui.box("⟶ JOBS", lines), reply_markup=InlineKeyboardMarkup(kb))

    async def _poll_job(self, j) -> tuple[int | None, str]:
        s = self.store.server(j["server_id"])
        code, out = await ssh_run(self._target(s), self.ca, jobmod.poll_cmd(j["token"]), key_id="efferent-jobpoll")
        return jobmod.parse_poll(out)

    async def job_watch(self, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        for j in self.store.jobs(state="running"):
            try:
                code, log_text = await self._poll_job(j)
            except GatewayError as e:
                log.info("job %s poll: %s", j["id"], e)
                continue
            self.store.update_job(j["id"], last_poll=time.time())
            if code is None:
                await self._gpu_idle_check(j)
                continue
            state = "done" if code == 0 else ("killed" if code in (143, 137) else "failed")
            self.store.update_job(j["id"], state=state, exit=code, finished=time.time())
            await self._job_report(j["owner_id"], self.store.job(j["id"]), log_text, final=True)

    async def _gpu_idle_check(self, j) -> None:
        """Running for >10 min but every GPU idle on the last two probes → probably stuck (or CPU-bound)."""
        if j["gpu_idle"] or time.time() - j["started"] < 600:
            return
        rows = [r for r in self.store.health(j["server_id"], time.time() - 1800) if r["ok"]][-2:]
        gpus = [healthmod._gpus(r) for r in rows]
        if len(gpus) == 2 and all(gpus) and all(g["util"] < 5 for gs in gpus for g in gs):
            self.store.update_job(j["id"], gpu_idle=1)
            await self.app.bot.send_message(j["owner_id"], ui.box(f"⚠ JOB #{j['id']} · GPUs IDLE", [
                f"server {j['server']}", f"cmd    {ui.clip(j['label'], 24)}", "", "job is running but every GPU",
                "sat at <5% for the last 2 probes", "stuck dataloader? CPU-only? deadlock?"]), reply_markup=self._job_kb(j["id"]))

    async def _job_report(self, chat_id: int, j, log_text: str, final: bool) -> None:
        dur = ui.human_duration((j["finished"] or time.time()) - j["started"])
        tail = "\n".join(log_text.rstrip().splitlines()[-15:]) or "(empty log)"
        if len(tail) > 2500:
            tail = "…" + tail[-2500:]
        if final:
            ok = j["exit"] == 0
            head = ui.box(f"{'✓' if ok else '✗'} JOB #{j['id']} {j['state'].upper()}", [
                f"server  {j['server']}", f"cmd     {ui.clip(j['label'], 24)}", f"exit    {j['exit']}", f"took    {dur}"])
        else:
            prog = jobmod.progress(log_text)
            head = ui.box(f"◐ JOB #{j['id']} RUNNING", [f"server  {j['server']}", f"cmd     {ui.clip(j['label'], 24)}",
                                                       f"elapsed {dur}"] + ([f"at      {prog}"] if prog else []))
        series = jobmod.metrics(log_text)
        kb = self._job_kb(j["id"], running=not final)
        if series:
            png = await asyncio.to_thread(jobmod.curve, f"#{j['id']} · {j['server']} · {j['label'][:30]}", series)
            await self.app.bot.send_photo(chat_id, png, caption=head[:1000], reply_markup=kb)
            await self.app.bot.send_message(chat_id, ui.pre(tail))
        else:
            await self.app.bot.send_message(chat_id, head + "\n" + ui.pre(tail), reply_markup=kb)

    # ================================================================== GPU afferent
    async def cmd_gpu(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if await self._deny(update):
            return
        uid = update.effective_user.id
        servers = [self._server(uid, " ".join(ctx.args))] if ctx.args else [s for s in self.store.servers(uid) if s["monitor"]]
        lines = []
        for s in servers:
            if not s:
                continue
            m = await self.probe(s)
            gl = healthmod.gpu_lines(m.get("gpu") or []) if m else []
            lines += [f"▸ {s['name']}"] + (gl or ["  (no NVIDIA GPU)" if m else "  ✕ unreachable"])
        await update.message.reply_text(ui.box("⟵ GPU AFFERENT", lines or ["no monitored servers"]))

    # ================================================================== tunnels
    async def cmd_tunnel(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if await self._deny(update):
            return
        a = ctx.args
        if len(a) < 2 or not a[1].isdigit():
            await update.message.reply_text(ui.pre(
                "usage: /fx_tunnel <server> <port> [name] [strip]\n"
                "  /fx_tunnel lab 8888 jupyter\n  /fx_tunnel lab 6006 tb\n\n"
                "start the app with a matching base path:\n"
                "  jupyter lab --ServerApp.base_url=/t/jupyter/\n"
                "  tensorboard --logdir runs --path_prefix=/t/tb\n"
                "apps without base-path support: add 'strip'"))
            return
        if not self.cfg.webapp_url:
            await update.message.reply_text(ui.pre("✕ WEBAPP_URL not set: tunnels ride on the Mini App's HTTPS"))
            return
        uid = update.effective_user.id
        s = self._server(uid, a[0])
        port = int(a[1])
        name = (a[2] if len(a) > 2 and a[2] != "strip" else f"{s['name'] if s else 'x'}-{port}").lower()
        if not s or not (0 < port < 65536) or not NAME_RE.match(name):
            await update.message.reply_text(ui.pre("✕ unknown server, bad port, or bad name (a-z 0-9 -)"))
            return
        try:
            tun = await self.tunnels.open(name, uid, self._target(s), port, strip="strip" in a)
        except (GatewayError, ValueError, OSError) as e:
            await update.message.reply_text(ui.pre(f"[FAIL] tunnel: {e}"))
            return
        self.store.audit(uid, "tunnel-create", s["name"], f"{name} → 127.0.0.1:{port}")
        b = self.webapp_button(f"⟶ open {name}", "tunnel=" + name)
        await update.message.reply_text(
            ui.box("⟶ TUNNEL UP", [f"name    {name}", f"target  {s['name']} 127.0.0.1:{port}",
                                   f"path    /t/{name}/" + (" (stripped)" if tun.strip else ""),
                                   "expires 12h · operators only", "", "SSH direct-tcpip · no ports opened"]),
            reply_markup=InlineKeyboardMarkup([[b], [InlineKeyboardButton("✕ close", callback_data=f"ops:tc:{name}")]]))

    async def cmd_tunnels(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if await self._deny(update):
            return
        self.tunnels.reap()
        ts = list(self.tunnels.by_name.values())
        if not ts:
            await update.message.reply_text(ui.pre("no open tunnels · /fx_tunnel <server> <port> [name]"))
            return
        lines = [f"{ui.clip(t.name, 12):<12} {ui.clip(t.server, 10):<10} :{t.remote_port:<5} {t.requests} req" for t in ts]
        kb = [[b for b in (self.webapp_button(f"⟶ {t.name}", "tunnel=" + t.name),) if b] +
              [InlineKeyboardButton("✕", callback_data=f"ops:tc:{t.name}")] for t in ts[:8]]
        await update.message.reply_text(ui.box("⟶ TUNNELS", lines), reply_markup=InlineKeyboardMarkup(kb))

    async def job_tunnels(self, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        for name in self.tunnels.reap():
            log.info("tunnel %s expired", name)

    # ================================================================== reflex arcs
    TRIGGERS = ("disk", "mem", "load", "gpu", "rebooted")

    async def cmd_reflex(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if await self._deny(update):
            return
        a = ctx.args
        books = self._runbooks()
        if len(a) < 3 or a[1] not in self.TRIGGERS or a[2] not in books:
            await update.message.reply_text(ui.pre(
                "usage: /fx_reflex <server> <trigger> <signal>\n"
                f"triggers: {' '.join(self.TRIGGERS)}\nsignals:  {' '.join(books)}\n\n"
                "e.g. /fx_reflex lab disk clean\n     /fx_reflex web load nginx\n"
                "asks before firing until you tap 'always'"))
            return
        uid = update.effective_user.id
        s = self._server(uid, a[0])
        if not s:
            await update.message.reply_text(ui.pre("✕ unknown server"))
            return
        rid = self.store.add_reflex(uid, s["id"], a[1], a[2])
        self.store.audit(uid, "reflex-add", s["name"], f"{a[1]} → {a[2]}")
        await update.message.reply_text(ui.box(f"⚡ REFLEX ARC #{rid}", [
            f"server   {s['name']}", f"stimulus {a[1]}", f"response {books[a[2]][0]}", "mode     ask first",
            "cooldown 30 min", "", "afferent ⟵ alert  ⟶ efferent signal"]))

    async def cmd_reflexes(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if await self._deny(update):
            return
        rs = self.store.reflexes(update.effective_user.id)
        if not rs:
            await update.message.reply_text(ui.pre("no reflex arcs · /fx_reflex <server> <trigger> <signal>"))
            return
        lines = [f"#{r['id']:<3} {'●' if r['enabled'] else '○'} {ui.clip(r['server'], 9):<9} {r['trigger']:<6}⟶ {r['signal']:<7}"
                 f"{'auto' if r['trusted'] else 'ask'}" for r in rs]
        kb = [[InlineKeyboardButton(f"#{r['id']} {'pause' if r['enabled'] else 'resume'}", callback_data=f"ops:rxe:{r['id']}"),
               InlineKeyboardButton("auto" if not r["trusted"] else "ask", callback_data=f"ops:rxt:{r['id']}"),
               InlineKeyboardButton("✕", callback_data=f"ops:rxd:{r['id']}")] for r in rs[:8]]
        await update.message.reply_text(ui.box("⚡ REFLEX ARCS", lines), reply_markup=InlineKeyboardMarkup(kb))

    async def _reflexes(self, s, issues: list[str]) -> None:
        fired = {healthmod.trigger_of(i) for i in issues}
        for r in self.store.reflexes(server_id=s["id"]):
            if not r["enabled"] or r["trigger"] not in fired or time.time() - r["last_fired"] < r["cooldown"]:
                continue
            self.store.update_reflex(r["id"], last_fired=time.time())
            label = self._runbooks().get(r["signal"], ("?",))[0]
            if r["trusted"]:
                self.store.audit(r["owner_id"], "reflex-fire", s["name"], f"{r['trigger']} → {r['signal']} (auto)")
                await self.app.bot.send_message(r["owner_id"], ui.pre(f"⚡ reflex #{r['id']} fired: {r['trigger']} ⟶ {label} @ {s['name']}"))
                await self._run_book(r["owner_id"], r["owner_id"], s, r["signal"])
            else:
                await self.app.bot.send_message(
                    r["owner_id"], ui.box(f"⚡ REFLEX #{r['id']} · STIMULUS", [
                        f"server   {s['name']}", f"stimulus {r['trigger']}", f"response {label}", "", "fire it?"]),
                    reply_markup=InlineKeyboardMarkup([[
                        InlineKeyboardButton("⟶ fire", callback_data=f"ops:rxf:{r['id']}"),
                        InlineKeyboardButton("⟶ always", callback_data=f"ops:rxa:{r['id']}"),
                        InlineKeyboardButton("✕ skip", callback_data="ops:noop:0")]]))
