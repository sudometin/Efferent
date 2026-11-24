"""CORTEX — owner control plane for EFFERENT-008.

Everything here is owner-only and lives in the bot's SQLite DB (no .env edits, no restarts):
  access mode (private / open), dynamic operators with optional expiry, bans, lockdown,
  access requests with one-tap approval, live session list with kick, user directory, broadcast.
"""
from __future__ import annotations

import asyncio
import html
import json
import re
import secrets
import time

from telegram import InlineKeyboardButton as B
from telegram import InlineKeyboardMarkup as M
from telegram import Update
from telegram.error import TelegramError
from telegram.ext import ApplicationHandlerStop, CallbackQueryHandler, CommandHandler, ContextTypes, TypeHandler

from .. import ui

USERS_SQL = """CREATE TABLE IF NOT EXISTS fx_users (uid INTEGER PRIMARY KEY, name TEXT, username TEXT,
  first_seen REAL, last_seen REAL, hits INTEGER DEFAULT 0)"""
DUR_RE = re.compile(r"^(\d+)\s*([mhdw])$")
REQ_COOLDOWN = 3600


def parse_duration(s: str | None) -> float | None:
    """'30m' '12h' '7d' '2w' → seconds · 'forever'/None → 0 · garbage → None."""
    if not s or s.lower() in ("forever", "perm", "permanent", "inf", "∞"):
        return 0
    m = DUR_RE.match(s.strip().lower())
    if not m:
        return None
    secs = int(m.group(1)) * {"m": 60, "h": 3600, "d": 86400, "w": 604800}[m.group(2)]
    return secs if 60 <= secs <= 366 * 86400 else None


def ago(ts: float | None) -> str:
    if not ts:
        return "never"
    d = time.time() - ts
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if d >= n:
            return f"{int(d // n)}{unit} ago"
    return "just now"


def left(until: float) -> str:
    if not until:
        return "∞"
    d = until - time.time()
    if d <= 0:
        return "expired"
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if d >= n:
            return f"{int(d // n)}{unit} left"
    return "<1m left"


class AdminMixin:
    """Mixed into Ops. Expects self.cfg, self.app, self.store, self.gw, self.tunnels."""

    # ------------------------------------------------------------------ state (kv-backed)
    def _admin_init(self) -> None:
        self.store.db.x(USERS_SQL)
        self._req_last: dict[int, float] = {}
        self._bcast: dict[str, str] = {}

    def _kv(self, key: str, default):
        raw = self.store.db.get(key)
        try:
            return json.loads(raw) if raw is not None else default
        except ValueError:
            return default

    def _kv_set(self, key: str, value) -> None:
        self.store.db.set(key, json.dumps(value))

    @property
    def access_mode(self) -> str:
        return self._kv("fx_mode", "private")

    @property
    def locked(self) -> bool:
        return bool(self._kv("fx_locked", False))

    def dyn_ops(self) -> dict[str, dict]:
        ops = self._kv("fx_ops", {})
        now = time.time()
        live = {k: v for k, v in ops.items() if not v.get("until") or v["until"] > now}
        if len(live) != len(ops):
            self._kv_set("fx_ops", live)
        return live

    def banned(self) -> set[int]:
        return set(self._kv("fx_banned", []))

    def is_banned(self, uid: int) -> bool:
        return uid != self.cfg.owner_id and uid in self.banned()

    def is_owner(self, uid: int) -> bool:
        return uid == self.cfg.owner_id

    def is_operator(self, uid: int) -> bool:
        if self.is_owner(uid):
            return True
        if self.locked or self.is_banned(uid):
            return False
        if uid in self.cfg.ops_users or str(uid) in self.dyn_ops():
            return True
        return self.access_mode == "open"

    def role(self, uid: int) -> str:
        if self.is_owner(uid):
            return "♛ owner"
        if self.is_banned(uid):
            return "⛔ banned"
        if uid in self.cfg.ops_users:
            return "● operator (.env)"
        d = self.dyn_ops().get(str(uid))
        if d:
            return f"● operator · {left(d.get('until', 0))}"
        if self.access_mode == "open" and not self.locked:
            return "◐ public"
        return "○ guest"

    # ------------------------------------------------------------------ user directory
    async def _track(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        u = update.effective_user
        if not u or u.is_bot:
            return
        now = time.time()
        self.store.db.x("""INSERT INTO fx_users(uid,name,username,first_seen,last_seen,hits) VALUES(?,?,?,?,?,1)
                           ON CONFLICT(uid) DO UPDATE SET name=excluded.name, username=excluded.username,
                           last_seen=excluded.last_seen, hits=hits+1""",
                        (u.id, u.full_name, u.username or "", now, now))
        if self.is_banned(u.id):
            if update.callback_query:
                try:
                    await update.callback_query.answer("⛔ banned")
                except TelegramError:
                    pass
            raise ApplicationHandlerStop

    def user(self, uid: int):
        return self.store.one("SELECT * FROM fx_users WHERE uid=?", (uid,))

    def who(self, uid: int) -> str:
        u = self.user(uid)
        if not u:
            return str(uid)
        return f"{u['name']}" + (f" @{u['username']}" if u["username"] else "") + f" · {uid}"

    def resolve(self, update: Update, ref: str | None) -> int | None:
        """id, @username (must have used the bot), or reply to a forwarded/quoted message."""
        msg = update.effective_message
        if not ref and msg.reply_to_message:
            r = msg.reply_to_message
            if r.forward_origin and getattr(r.forward_origin, "sender_user", None):
                return r.forward_origin.sender_user.id
            if r.from_user and not r.from_user.is_bot:
                return r.from_user.id
        if not ref:
            return None
        ref = ref.strip()
        if ref.lstrip("-").isdigit():
            return int(ref)
        row = self.store.one("SELECT uid FROM fx_users WHERE lower(username)=?", (ref.lstrip("@").lower(),))
        return row["uid"] if row else None

    # ------------------------------------------------------------------ mutations
    def grant_op(self, uid: int, secs: float, by: int) -> None:
        ops = self.dyn_ops()
        ops[str(uid)] = {"until": time.time() + secs if secs else 0, "added": time.time(), "by": by}
        self._kv_set("fx_ops", ops)
        b = self.banned()
        if uid in b:
            b.discard(uid)
            self._kv_set("fx_banned", sorted(b))
        self.store.audit(by, "op-add", str(uid), f"{int(secs)}s" if secs else "forever")

    async def drop_op(self, uid: int, by: int, reason: str = "access revoked") -> int:
        ops = self.dyn_ops()
        ops.pop(str(uid), None)
        self._kv_set("fx_ops", ops)
        self.store.audit(by, "op-remove", str(uid))
        return await self.kick(uid, reason)

    async def kick(self, uid: int, reason: str = "kicked by owner") -> int:
        n = 0
        for s in list(self.gw.sessions.values()):
            if s.user_id == uid:
                await s.close(reason)
                n += 1
        for name, t in list(self.tunnels.by_name.items()):
            if t.owner_id == uid:
                self.tunnels.close(name)
                n += 1
        return n

    # ------------------------------------------------------------------ registration
    def register_admin(self) -> None:
        add = self.app.add_handler
        add(TypeHandler(Update, self._track), group=-5)
        for name, fn in [("fx_admin", self.cmd_admin), ("cortex", self.cmd_admin), ("fx_allow", self.cmd_allow),
                         ("fx_revoke", self.cmd_revoke), ("fx_ban", self.cmd_ban), ("fx_unban", self.cmd_unban),
                         ("fx_mode", self.cmd_mode), ("fx_users", self.cmd_users), ("fx_live", self.cmd_live),
                         ("fx_kick", self.cmd_kick), ("fx_lockdown", self.cmd_lockdown),
                         ("fx_broadcast", self.cmd_broadcast), ("fx_whois", self.cmd_whois)]:
            add(CommandHandler(name, fn))
        add(CallbackQueryHandler(self.on_admin_cb, pattern=r"^fxa:"))

    async def _owner_only(self, update: Update) -> bool:
        if not self.is_owner(update.effective_user.id):
            await update.effective_message.reply_text(ui.pre("EPERM :: CORTEX answers to the owner only."))
            return True
        return False

    # ------------------------------------------------------------------ panel
    def panel(self) -> tuple[str, M]:
        mode, locked = self.access_mode, self.locked
        ops = self.dyn_ops()
        n_users = self.store.one("SELECT COUNT(*) c FROM fx_users")["c"]
        n_active = self.store.one("SELECT COUNT(*) c FROM fx_users WHERE last_seen>?", (time.time() - 86400,))["c"]
        n_srv = self.store.one("SELECT COUNT(*) c FROM ops_servers")["c"]
        n_jobs = self.store.one("SELECT COUNT(*) c FROM ops_jobs WHERE state='running'")["c"]
        state = "🚨 LOCKDOWN" if locked else ("🔓 OPEN · anyone" if mode == "open" else "🔒 PRIVATE · invite only")
        body = ui.pre("\n".join([
            "♛ CORTEX // owner control plane",
            "────────────────────────────",
            f"access    {state}",
            f"operators {len(ops) + len(self.cfg.ops_users)}   banned {len(self.banned())}",
            f"users     {n_users}   active 24h {n_active}",
            f"sessions  {len(self.gw.sessions)} live   tunnels {len(self.tunnels.by_name)}",
            f"fleet     {n_srv} servers   jobs {n_jobs}",
        ]))
        body += ("\n<b>commands</b>\n"
                 "› /fx_allow ID|@user [7d] — make operator\n"
                 "› /fx_revoke ID — remove + kick\n"
                 "› /fx_ban · /fx_unban ID — block from the whole bot\n"
                 "› /fx_mode open|private — who can use EFFERENT\n"
                 "› /fx_live — live sessions · /fx_kick ID\n"
                 "› /fx_users — directory · /fx_whois ID\n"
                 "› /fx_broadcast text — message every user\n"
                 "› /fx_lockdown — panic button")
        rows = []
        if locked:
            rows.append([B("🟢 Lift lockdown", callback_data="fxa:unlock")])
        else:
            rows.append([B("🔒 Make private" if mode == "open" else "🔓 Open to everyone",
                           callback_data="fxa:mode:" + ("private" if mode == "open" else "open"))])
        rows.append([B("👥 Operators", callback_data="fxa:ops"), B("🧑‍💻 Users", callback_data="fxa:users"),
                     B("📡 Live", callback_data="fxa:live")])
        rows.append([B("↻ Refresh", callback_data="fxa:panel")] +
                    ([] if locked else [B("🚨 LOCKDOWN", callback_data="fxa:lockask")]))
        return body, M(rows)

    async def cmd_admin(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if await self._owner_only(update):
            return
        text, kb = self.panel()
        await update.effective_message.reply_text(text, reply_markup=kb)

    # ------------------------------------------------------------------ operators
    async def cmd_allow(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if await self._owner_only(update):
            return
        args = list(ctx.args or [])
        dur = None
        if args and not args[-1].lstrip("-").isdigit() and not args[-1].startswith("@") \
                and parse_duration(args[-1]) is not None:
            dur = args.pop()
        uid = self.resolve(update, args[0] if args else None)
        secs = parse_duration(dur)
        if not uid or secs is None:
            await update.effective_message.reply_text(ui.pre(
                "usage: /fx_allow <id | @username> [30m|12h|7d|2w|forever]\n"
                "tip: or reply to a message forwarded from them\n"
                "@username only works if they've opened the bot once"))
            return
        if self.is_owner(uid):
            await update.effective_message.reply_text(ui.pre("you're already root 👑"))
            return
        self.grant_op(uid, secs, update.effective_user.id)
        await update.effective_message.reply_text(ui.pre(f"[ OK ] operator ← {self.who(uid)}\n         expires: {left(time.time() + secs) if secs else '∞ never'}"))
        await self._notify(uid, "⟶ <b>EFFERENT-008 unlocked</b>\nThe owner made you an operator"
                           + (f" for <b>{html.escape(dur)}</b>" if secs else "") + ". Send /efferent to start.")

    async def cmd_revoke(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if await self._owner_only(update):
            return
        uid = self.resolve(update, ctx.args[0] if ctx.args else None)
        if not uid:
            await update.effective_message.reply_text(ui.pre("usage: /fx_revoke <id | @username>"))
            return
        n = await self.drop_op(uid, update.effective_user.id)
        note = "\n(still in OPS_USERS in .env — remove it there too)" if uid in self.cfg.ops_users else ""
        await update.effective_message.reply_text(ui.pre(f"[ OK ] revoked {self.who(uid)} · closed {n} live{note}"))

    async def cmd_ban(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if await self._owner_only(update):
            return
        uid = self.resolve(update, ctx.args[0] if ctx.args else None)
        if not uid or self.is_owner(uid):
            await update.effective_message.reply_text(ui.pre("usage: /fx_ban <id | @username>"))
            return
        await self._ban(uid, update.effective_user.id)
        await update.effective_message.reply_text(ui.pre(f"⛔ banned {self.who(uid)} · bot ignores them now"))

    async def _ban(self, uid: int, by: int) -> None:
        b = self.banned()
        b.add(uid)
        self._kv_set("fx_banned", sorted(b))
        await self.drop_op(uid, by, "banned")
        self.store.audit(by, "ban", str(uid))

    async def cmd_unban(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if await self._owner_only(update):
            return
        uid = self.resolve(update, ctx.args[0] if ctx.args else None)
        if not uid:
            await update.effective_message.reply_text(ui.pre("usage: /fx_unban <id | @username>"))
            return
        b = self.banned()
        b.discard(uid)
        self._kv_set("fx_banned", sorted(b))
        self.store.audit(update.effective_user.id, "unban", str(uid))
        await update.effective_message.reply_text(ui.pre(f"[ OK ] unbanned {self.who(uid)}"))

    async def cmd_mode(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if await self._owner_only(update):
            return
        want = (ctx.args[0].lower() if ctx.args else "")
        if want not in ("open", "private"):
            await update.effective_message.reply_text(ui.pre(
                f"mode: {self.access_mode}\nusage: /fx_mode open     anyone can use EFFERENT (own fleet each)\n"
                "       /fx_mode private  only you + operators"))
            return
        self._kv_set("fx_mode", want)
        self.store.audit(update.effective_user.id, "mode", want)
        await update.effective_message.reply_text(ui.pre(
            f"[ OK ] access → {want.upper()}" + ("\nanyone who opens the bot can add their own servers.\n"
                                                 "they never see yours · /fx_ban still works" if want == "open" else "")))

    # ------------------------------------------------------------------ directory
    def users_text(self, limit: int = 25) -> str:
        rows = self.store.db.q("SELECT * FROM fx_users ORDER BY last_seen DESC LIMIT ?", (limit,))
        if not rows:
            return ui.pre("no users yet")
        lines = ["🧑‍💻 USERS // last seen", "────────────────────────────"]
        for r in rows:
            tag = f"@{r['username']}" if r["username"] else r["name"][:16]
            lines.append(f"{self.role(r['uid'])[:1]} {tag[:18]:<18} {ago(r['last_seen']):>8}")
            lines.append(f"  {r['uid']}")
        lines.append("────────────────────────────\n♛ owner ● op ◐ public ○ guest ⛔ banned")
        return ui.pre("\n".join(lines))

    async def cmd_users(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if await self._owner_only(update):
            return
        await update.effective_message.reply_text(self.users_text())

    async def cmd_whois(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if await self._owner_only(update):
            return
        uid = self.resolve(update, ctx.args[0] if ctx.args else None)
        u = self.user(uid) if uid else None
        if not u:
            await update.effective_message.reply_text(ui.pre("usage: /fx_whois <id | @username> (must have used the bot)"))
            return
        n_srv = self.store.one("SELECT COUNT(*) c FROM ops_servers WHERE owner_id=?", (uid,))["c"]
        n_ses = self.store.one("SELECT COUNT(*) c FROM ops_sessions WHERE user_id=?", (uid,))["c"]
        text = ui.box("WHOIS", ui.kv([("name", u["name"]), ("user", f"@{u['username']}" if u["username"] else "-"),
                                      ("uid", uid), ("role", self.role(uid)), ("first", ago(u["first_seen"])),
                                      ("last", ago(u["last_seen"])), ("hits", u["hits"]), ("servers", n_srv),
                                      ("sessions", n_ses)], 8))
        await update.effective_message.reply_text(text, reply_markup=self._user_kb(uid))

    def _user_kb(self, uid: int) -> M:
        if self.is_owner(uid):
            return M([])
        op = str(uid) in self.dyn_ops()
        return M([[B("✕ Revoke" if op else "✓ Operator 7d", callback_data=f"fxa:{'rev' if op else 'ok7'}:{uid}"),
                   B("✓ Forever", callback_data=f"fxa:okf:{uid}")],
                  [B("⏏ Kick", callback_data=f"fxa:kick:{uid}"),
                   B("♻ Unban" if self.is_banned(uid) else "⛔ Ban", callback_data=f"fxa:{'unban' if self.is_banned(uid) else 'ban'}:{uid}")]])

    # ------------------------------------------------------------------ live sessions
    def live_text(self) -> tuple[str, M]:
        ss = list(self.gw.sessions.values())
        ts = list(self.tunnels.by_name.values())
        if not ss and not ts:
            return ui.pre("📡 nothing live right now"), M([[B("↻ Refresh", callback_data="fxa:live")]])
        lines, rows = ["📡 LIVE", "────────────────────────────"], []
        for s in ss:
            lines.append(f"▶ {self.who(s.user_id)[:26]}\n  → {getattr(s.target, 'label', s.target)}")
        for t in ts:
            lines.append(f"🚇 {self.who(t.owner_id)[:26]}\n  → {t.name} :{t.remote_port}")
        for uid in sorted({s.user_id for s in ss} | {t.owner_id for t in ts}):
            if not self.is_owner(uid):
                rows.append([B(f"⏏ kick {self.who(uid)[:24]}", callback_data=f"fxa:kick:{uid}")])
        rows.append([B("↻ Refresh", callback_data="fxa:live")])
        return ui.pre("\n".join(lines)), M(rows)

    async def cmd_live(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if await self._owner_only(update):
            return
        text, kb = self.live_text()
        await update.effective_message.reply_text(text, reply_markup=kb)

    async def cmd_kick(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if await self._owner_only(update):
            return
        uid = self.resolve(update, ctx.args[0] if ctx.args else None)
        if not uid:
            await update.effective_message.reply_text(ui.pre("usage: /fx_kick <id | @username>"))
            return
        n = await self.kick(uid)
        self.store.audit(update.effective_user.id, "kick", str(uid))
        await update.effective_message.reply_text(ui.pre(f"⏏ closed {n} session(s)/tunnel(s) of {self.who(uid)}"))

    # ------------------------------------------------------------------ lockdown
    async def lockdown(self, by: int) -> str:
        self._kv_set("fx_locked", True)
        n_s = 0
        for s in list(self.gw.sessions.values()):
            if not self.is_owner(s.user_id):
                await s.close("🚨 lockdown")
                n_s += 1
        n_t = 0
        for name, t in list(self.tunnels.by_name.items()):
            if not self.is_owner(t.owner_id):
                self.tunnels.close(name)
                n_t += 1
        now = time.time()
        n_g = self.store.one("SELECT COUNT(*) c FROM ops_grants WHERE revoked=0 AND expires>?", (now,))["c"]
        self.store.db.x("UPDATE ops_grants SET revoked=1 WHERE revoked=0 AND expires>?", (now,))
        self.store.audit(by, "lockdown", "", f"sessions={n_s} tunnels={n_t} grants={n_g}")
        return (f"🚨 LOCKDOWN ENGAGED\n────────────────────────────\n"
                f"sessions closed  {n_s}\ntunnels closed   {n_t}\ngrants revoked   {n_g}\n"
                f"operators        frozen (only you)\n\nlift: /fx_lockdown off")

    async def cmd_lockdown(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if await self._owner_only(update):
            return
        if ctx.args and ctx.args[0].lower() in ("off", "lift", "0"):
            self._kv_set("fx_locked", False)
            self.store.audit(update.effective_user.id, "lockdown-lift")
            await update.effective_message.reply_text(ui.pre("🟢 lockdown lifted · operators restored (grants stay revoked)"))
            return
        await update.effective_message.reply_text(
            ui.pre("🚨 LOCKDOWN?\nkills every non-owner session + tunnel,\nrevokes all grants, freezes operators."),
            reply_markup=M([[B("🚨 ENGAGE", callback_data="fxa:lock"), B("cancel", callback_data="fxa:x")]]))

    # ------------------------------------------------------------------ broadcast
    async def cmd_broadcast(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if await self._owner_only(update):
            return
        text = update.effective_message.text.partition(" ")[2].strip()
        if not text:
            await update.effective_message.reply_text(ui.pre("usage: /fx_broadcast <message>  (HTML ok)"))
            return
        n = self.store.one("SELECT COUNT(*) c FROM fx_users WHERE uid!=?", (self.cfg.owner_id,))["c"]
        tok = secrets.token_hex(4)
        self._bcast[tok] = text
        await update.effective_message.reply_text(
            f"<b>📣 preview</b> → {n} users\n────────────\n{text}",
            reply_markup=M([[B(f"📣 Send to {n}", callback_data=f"fxa:bc:{tok}"), B("cancel", callback_data="fxa:x")]]))

    async def _broadcast(self, text: str) -> tuple[int, int]:
        ok = fail = 0
        banned = self.banned()
        for r in self.store.db.q("SELECT uid FROM fx_users WHERE uid!=?", (self.cfg.owner_id,)):
            if r["uid"] in banned:
                continue
            try:
                await self.app.bot.send_message(r["uid"], f"📣 <b>UNFINITUM // EFFERENT-008</b>\n\n{text}")
                ok += 1
            except TelegramError:
                fail += 1
            await asyncio.sleep(0.06)          # stay under Telegram's ~30 msg/s
        return ok, fail

    # ------------------------------------------------------------------ access requests
    def request_button(self) -> M:
        return M([[B("📨 Request access", callback_data="fxa:req")]])

    async def _notify(self, uid: int, text: str) -> None:
        try:
            await self.app.bot.send_message(uid, text)
        except TelegramError:
            pass

    async def on_admin_cb(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        q = update.callback_query
        uid = q.from_user.id
        parts = q.data.split(":")
        act = parts[1]

        if act == "req":                                   # anyone
            if self.is_operator(uid):
                await q.answer("you already have access → /efferent", show_alert=True)
                return
            if time.time() - self._req_last.get(uid, 0) < REQ_COOLDOWN:
                await q.answer("request already sent · hang tight", show_alert=True)
                return
            self._req_last[uid] = time.time()
            u = q.from_user
            try:
                await self.app.bot.send_message(
                    self.cfg.owner_id,
                    ui.pre("📨 ACCESS REQUEST // EFFERENT-008\n────────────────────────────\n"
                           f"name  {u.full_name}\nuser  {'@' + u.username if u.username else '-'}\nuid   {u.id}"),
                    reply_markup=M([[B("✓ 24h", callback_data=f"fxa:ok1:{u.id}"), B("✓ 7d", callback_data=f"fxa:ok7:{u.id}"),
                                     B("✓ forever", callback_data=f"fxa:okf:{u.id}")],
                                    [B("✕ deny", callback_data=f"fxa:no:{u.id}"), B("⛔ ban", callback_data=f"fxa:ban:{u.id}")]]))
            except TelegramError:
                pass
            await q.answer("sent to the owner ✓", show_alert=True)
            return

        if not self.is_owner(uid):
            await q.answer("owner only")
            return
        await q.answer()
        msg = q.message

        async def edit(text: str, kb: M | None = None) -> None:
            try:
                await msg.edit_text(text, reply_markup=kb)
            except TelegramError:
                await msg.reply_text(text, reply_markup=kb)

        if act == "x":
            await edit(ui.pre("cancelled"))
        elif act == "open":
            await msg.reply_text(*self.panel()[:1], reply_markup=self.panel()[1])
        elif act == "panel":
            await edit(*self.panel())
        elif act == "mode":
            self._kv_set("fx_mode", parts[2])
            self.store.audit(uid, "mode", parts[2])
            await edit(*self.panel())
        elif act == "unlock":
            self._kv_set("fx_locked", False)
            self.store.audit(uid, "lockdown-lift")
            await edit(*self.panel())
        elif act == "lockask":
            await edit(ui.pre("🚨 LOCKDOWN?\nkills every non-owner session + tunnel,\nrevokes all grants, freezes operators."),
                       M([[B("🚨 ENGAGE", callback_data="fxa:lock"), B("cancel", callback_data="fxa:panel")]]))
        elif act == "lock":
            await edit(ui.pre(await self.lockdown(uid)), M([[B("🟢 Lift lockdown", callback_data="fxa:unlock")]]))
        elif act == "users":
            await edit(self.users_text(), M([[B("← panel", callback_data="fxa:panel")]]))
        elif act == "live":
            await edit(*self.live_text())
        elif act == "ops":
            ops = self.dyn_ops()
            lines = ["👥 OPERATORS", "────────────────────────────"]
            rows = []
            for k in self.cfg.ops_users:
                lines.append(f"● {self.who(k)[:28]}\n  .env · permanent")
            for k, v in ops.items():
                lines.append(f"● {self.who(int(k))[:28]}\n  {left(v.get('until', 0))}")
                rows.append([B(f"✕ {self.who(int(k))[:26]}", callback_data=f"fxa:rev:{k}")])
            if len(lines) == 2:
                lines.append("none · /fx_allow ID [7d]")
            rows.append([B("← panel", callback_data="fxa:panel")])
            await edit(ui.pre("\n".join(lines)), M(rows))
        elif act in ("ok1", "ok7", "okf"):
            target = int(parts[2])
            secs = {"ok1": 86400, "ok7": 7 * 86400, "okf": 0}[act]
            self.grant_op(target, secs, uid)
            label = {"ok1": "24h", "ok7": "7 days", "okf": "forever"}[act]
            await edit(ui.pre(f"[ OK ] operator ← {self.who(target)} · {label}"))
            await self._notify(target, f"⟶ <b>Access granted</b> · EFFERENT-008 is yours for <b>{label}</b>.\nSend /efferent to begin.")
        elif act == "no":
            target = int(parts[2])
            await edit(ui.pre(f"✕ denied {self.who(target)}"))
            await self._notify(target, "✕ Your EFFERENT-008 access request was declined.")
        elif act == "rev":
            target = int(parts[2])
            n = await self.drop_op(target, uid)
            await edit(ui.pre(f"[ OK ] revoked {self.who(target)} · closed {n} live"), M([[B("← panel", callback_data="fxa:panel")]]))
        elif act == "ban":
            target = int(parts[2])
            await self._ban(target, uid)
            await edit(ui.pre(f"⛔ banned {self.who(target)}"))
        elif act == "unban":
            target = int(parts[2])
            b = self.banned()
            b.discard(target)
            self._kv_set("fx_banned", sorted(b))
            await edit(ui.pre(f"[ OK ] unbanned {self.who(target)}"))
        elif act == "kick":
            target = int(parts[2])
            n = await self.kick(target)
            self.store.audit(uid, "kick", str(target))
            await edit(ui.pre(f"⏏ closed {n} of {self.who(target)}"), M([[B("📡 Live", callback_data="fxa:live")]]))
        elif act == "bc":
            text = self._bcast.pop(parts[2], None)
            if not text:
                await edit(ui.pre("✕ broadcast expired · run /fx_broadcast again"))
                return
            await edit(ui.pre("📣 sending…"))
            ok, fail = await self._broadcast(text)
            self.store.audit(uid, "broadcast", "", f"ok={ok} fail={fail}")
            await edit(ui.pre(f"📣 delivered {ok} · failed {fail}\n(failed = they blocked the bot)"))
