"""NULLBYTE: a nerdy security-lab Telegram bot.

Modules: steganography (hide / reveal / detect), photo metadata forensics,
drand time-lock capsules, Shamir secret sharing ceremonies, and an SSH honeypot.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import functools
import html
import io
from types import SimpleNamespace
import logging
import re
import secrets
import time
from typing import Any, Awaitable, Callable

import httpx
from telegram import (BotCommand, InlineKeyboardButton, InlineKeyboardMarkup, InputFile, LinkPreviewOptions,
                      Message, Update)
from telegram.constants import ChatAction, ChatType, ParseMode
from telegram.error import BadRequest, Forbidden, NetworkError, TimedOut
from telegram.request import HTTPXRequest
from telegram.ext import (Application, CallbackQueryHandler, CommandHandler, ContextTypes, Defaults,
                          MessageHandler, filters)

from . import capsule, exif_tools, shamir, stego, ui
from .config import Config
from .db import DB
from .honeypot import Honeypot

try:                                    # Ops needs aiohttp + pyte; the rest of the bot works without them
    from .ops.bot_ops import Ops
except ImportError as _e:               # pragma: no cover
    Ops = None
    logging.getLogger("nullbyte").warning("ops disabled: %s", _e)

log = logging.getLogger("nullbyte")
CFG = Config()
MAX_DOWNLOAD = 20 * 1024 * 1024  # Bot API download limit
SHARE_RE = re.compile(r"sss1-[0-9a-f]{6}-\d{1,2}-\d{1,2}-[a-z2-7]+-[0-9a-f]{4}", re.I)
CEREMONY_TTL = 3600
NO_PREVIEW = LinkPreviewOptions(is_disabled=True)

Handler = Callable[[Update, ContextTypes.DEFAULT_TYPE], Awaitable[Any]]


# ============================================================================ plumbing


def guarded(fn: Handler) -> Handler:
    @functools.wraps(fn)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        user = update.effective_user
        if not CFG.can_use(user.id if user else None):
            if update.effective_message:
                await update.effective_message.reply_text(
                    ui.pre("ERR 403 :: you are not in /etc/sudoers.\nThis incident will be reported. 🙃"))
            return
        return await fn(update, context)
    return wrapper


def owner_only(fn: Handler) -> Handler:
    @functools.wraps(fn)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        user = update.effective_user
        if not user or user.id != CFG.owner_id:
            await update.effective_message.reply_text(ui.pre("EPERM :: honeypot console is owner-only."))
            return
        return await fn(update, context)
    return wrapper


def db(context: ContextTypes.DEFAULT_TYPE) -> DB:
    return context.application.bot_data["db"]


def hp(context: ContextTypes.DEFAULT_TYPE) -> Honeypot | None:
    return context.application.bot_data.get("honeypot")


def set_mode(context: ContextTypes.DEFAULT_TYPE, mode: str | None, **data: Any) -> None:
    ud = context.user_data
    if mode is None:
        for k in [k for k in ud if k.startswith("m_")]:
            ud.pop(k)
        ud.pop("mode", None)
    else:
        ud["mode"] = mode
        for k, v in data.items():
            ud[f"m_{k}"] = v


async def try_delete(msg: Message | None) -> bool:
    if not msg:
        return False
    try:
        await msg.delete()
        return True
    except (BadRequest, Forbidden):
        return False


async def progress(msg: Message, steps: list[str], delay: float = 0.35) -> None:
    """Fake-terminal boot sequence: edits one message through several lines."""
    shown: list[str] = []
    for step in steps:
        shown.append(step)
        try:
            await msg.edit_text(ui.pre("\n".join(shown)))
        except BadRequest:
            pass
        await asyncio.sleep(delay)


async def download(context: ContextTypes.DEFAULT_TYPE, file_id: str) -> bytes:
    f = await context.bot.get_file(file_id)
    return bytes(await f.download_as_bytearray())


def doc_file(data: bytes, name: str) -> InputFile:
    return InputFile(io.BytesIO(data), filename=name)


def kb(rows: list[list[tuple[str, str]]]) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[InlineKeyboardButton(t, callback_data=d) for t, d in row] for row in rows])


# ============================================================================ start / help

NB_SECTIONS = """<b>🕳 STEGANOGRAPHY</b>
› /hide — bury an AES-256 message in a PNG or WAV
› /reveal — dig it back out with the passphrase
› /detect — chi-square steganalysis + EOF scan

<b>🔬 METADATA FORENSICS</b>
› /exif — what your photo leaks (GPS, serials…)
<i>tip: just send any image as a <b>file</b></i>

<b>⏳ TIME CAPSULES</b> <i>drand tlock</i>
› /capsule — seal a message until a future date
› /capsules — your sealed capsules
› /unseal — open a .age capsule anywhere

<b>🧩 SHAMIR SECRET SHARING</b>
› /split — k-of-n shares over GF(2⁸)
› /combine — rebuild a secret from shares
› /ceremony — group recovery ritual
› /contribute CODE share — join a ceremony

<b>🍯 HONEYPOT</b> <i>owner</i>
› /hp · /hp_stats · /hp_live · /hp_replay ID · /hp_kiddie"""

FX_SECTIONS = """<b>⟶ MOTOR</b> · <i>reach your machines</i>
› /efferent — terminal, fleet, quick signals
› /fx_signal — fire one command, no shell
› /fx_grant — time-boxed access for a friend
› /fx_ca — keyless logins, 5-minute certs

<b>⟵ AFFERENT</b> · <i>feel their state</i>
› /fx_afferent — health chart for a server
› /fx_gpu — temp · VRAM · utilisation
› /fx_reflex — auto-respond when an alert fires

<b>◉ PLASTICITY</b> · <i>long-running work</i>
› /fx_watch — run training, get pinged + loss curve
› /fx_jobs — what's running right now
› /fx_tunnel — Jupyter / TensorBoard on your phone

<b>⛨ MYELIN</b> · <i>insulation &amp; audit</i>
› /fx_knock — port-knock before connecting
› /fx_sessions — recordings as GIF / cast
› /fx_audit — who did what, when
› /fx_breakglass · /fx_recover — emergency CA"""

CORTEX_SECTION = """<b>♛ CORTEX</b> · <i>owner only</i>
› /fx_admin — control panel (mode · ops · live · lockdown)
› /fx_allow ID|@user [7d] — make someone an operator
› /fx_revoke · /fx_ban · /fx_unban — take it back
› /fx_mode open|private — open EFFERENT to everyone
› /fx_live · /fx_kick — who's connected right now
› /fx_users · /fx_whois — user directory
› /fx_broadcast — message every user
› /fx_lockdown — panic button"""

FOOTER = "<code>────────────────────────────</code>\n/cancel abort · /id whoami · /help this menu"


def _fx_vitals(context: ContextTypes.DEFAULT_TYPE, uid: int) -> str:
    ops = context.application.bot_data.get("ops")
    if not ops:
        return "○ ops offline"
    try:
        n_srv = len(ops.store.servers(uid))
        n_job = len(ops.store.jobs(uid, state="running"))
        n_tun = len(ops.tunnels.by_name)
        n_arc = len(ops.store.reflexes(uid))
    except Exception:  # noqa: BLE001 — the menu must never fail
        return "○ vitals unavailable"
    cell = lambda label, n: f"{'●' if n else '○'} {label:<8}{n:>2}"  # noqa: E731
    return (f"{cell('fleet', n_srv)}    {cell('jobs', n_job)}\n"
            f"{cell('tunnels', n_tun)}    {cell('arcs', n_arc)}")


def help_text(context: ContextTypes.DEFAULT_TYPE, uid: int) -> str:
    if CFG.brand == "nullbyte":
        return f"{ui.pre(ui.BANNER + chr(10) + ui.TAGLINE)}\n{NB_SECTIONS}\n\n{FX_SECTIONS}\n\n{FOOTER}"
    ops = context.application.bot_data.get("ops")
    operator = bool(ops and ops.is_operator(uid))
    head = [ui.FX_BANNER, ui.FX_TAGLINE, "efferent (adj.) · carrying signals", "outward, from core to periphery"]
    if operator:
        head += ["", _fx_vitals(context, uid)]
    body = FX_SECTIONS if operator else ("<i>EFFERENT-008 is operator-only.</i> Tap <b>📨 Request access</b> below — "
                                         "the owner can approve you in one tap. The NULLBYTE toolkit is yours already.")
    if ops and ops.is_owner(uid):
        body += "\n\n" + CORTEX_SECTION
    return (f"{ui.pre(chr(10).join(head))}\n{body}\n\n"
            f"<blockquote expandable><b>⌬ NULLBYTE MODULES</b> · <i>tap to expand</i>\n\n{NB_SECTIONS}</blockquote>\n"
            f"{FOOTER}")


NB_KB = [[InlineKeyboardButton("🕳 Hide", callback_data="go:hide"), InlineKeyboardButton("🔓 Reveal", callback_data="go:reveal"),
          InlineKeyboardButton("🧪 Detect", callback_data="go:detect")],
         [InlineKeyboardButton("🔬 EXIF", callback_data="go:exif"), InlineKeyboardButton("⏳ Capsule", callback_data="go:capsule"),
          InlineKeyboardButton("🧩 Split", callback_data="go:split")]]


def help_keyboard(context: ContextTypes.DEFAULT_TYPE, uid: int) -> InlineKeyboardMarkup:
    nb = NB_KB
    ops = context.application.bot_data.get("ops")
    if CFG.brand == "nullbyte":
        return InlineKeyboardMarkup(nb)
    if not (ops and ops.is_operator(uid)):
        req = [] if (not ops or ops.locked) else [[InlineKeyboardButton("📨 Request EFFERENT access", callback_data="fxa:req")]]
        return InlineKeyboardMarkup(req + nb)
    rows: list[list[InlineKeyboardButton]] = []
    term = ops.webapp_button("⟶  OPEN TERMINAL")
    if term:
        rows.append([term])
    rows.append([InlineKeyboardButton("🛰 Fleet", callback_data="nav:fleet"), InlineKeyboardButton("🌡 GPU", callback_data="nav:gpu"),
                 InlineKeyboardButton("◉ Jobs", callback_data="nav:jobs")])
    rows.append([InlineKeyboardButton("🚇 Tunnels", callback_data="nav:tunnels"), InlineKeyboardButton("⚡ Arcs", callback_data="nav:arcs"),
                 InlineKeyboardButton("🎞 Sessions", callback_data="nav:sessions")])
    last = [InlineKeyboardButton("⌬ NULLBYTE tools", callback_data="nav:nb")]
    if ops.is_owner(uid):
        last.insert(0, InlineKeyboardButton("♛ CORTEX", callback_data="fxa:open"))
    rows.append(last)
    return InlineKeyboardMarkup(rows)


BOOT_NB = ["[ OK ] mounting /dev/entropy", "[ OK ] loading AES-NI · scrypt · GF(2^8)",
           "[ OK ] syncing with drand League of Entropy"]


@guarded
async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    set_mode(context, None)
    uid = update.effective_user.id
    name = update.effective_user.first_name or "operator"
    honey = "[ OK ] honeypot " + ("armed on :%d" % CFG.honeypot_port if hp(context) else "offline")
    if CFG.brand == "nullbyte":
        first, steps = "[    ] booting nullbyte kernel…", BOOT_NB + [honey, f"[ OK ] welcome, {name}."]
    else:
        ops = context.application.bot_data.get("ops")
        ca = ops.ca.fingerprint.split(":")[-1][:10] if ops else "offline"
        first = "[    ] depolarising EFFERENT-008…"
        steps = ["[ OK ] axon hillock · threshold −55 mV",
                 f"[ OK ] myelin · CA {ca}…",
                 f"[ OK ] afferent probes · every {CFG.ops_health_min} min",
                 honey,
                 f"[ OK ] action potential → {name}"]
    msg = await update.message.reply_text(ui.pre(first))
    await progress(msg, steps, 0.3)
    await msg.edit_text(help_text(context, uid), reply_markup=help_keyboard(context, uid))


@guarded
async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    uid = update.effective_user.id
    await update.message.reply_text(help_text(context, uid), reply_markup=help_keyboard(context, uid))


async def on_nav(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Menu buttons → reuse the real command handlers with a lightweight update shim."""
    q = update.callback_query
    await q.answer()
    what = q.data.split(":", 1)[1]
    if what == "nb":
        await q.message.reply_text(f"<b>⌬ NULLBYTE MODULES</b>\n\n{NB_SECTIONS}", reply_markup=InlineKeyboardMarkup(NB_KB))
        return
    ops = context.application.bot_data.get("ops")
    if not ops:
        return
    fn = {"fleet": ops.cmd_ops, "gpu": ops.cmd_gpu, "jobs": ops.cmd_jobs, "tunnels": ops.cmd_tunnels,
          "arcs": ops.cmd_reflexes, "sessions": ops.cmd_sessions}.get(what)
    if not fn:
        return
    shim = SimpleNamespace(message=q.message, effective_message=q.message, effective_user=q.from_user,
                           effective_chat=q.message.chat, callback_query=None)
    context.args = []
    await fn(shim, context)


async def cmd_id(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    u = update.effective_user
    await update.message.reply_text(ui.box("WHOAMI", ui.kv([
        ("uid", u.id), ("user", f"@{u.username}" if u.username else "-"), ("chat", update.effective_chat.id),
        ("owner", "yes ✓" if u.id == CFG.owner_id else "no"),
    ], 6)))


@guarded
async def cmd_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    set_mode(context, None)
    await update.message.reply_text(ui.pre("^C\nprocess terminated. state wiped."))


async def on_go(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    q = update.callback_query
    await q.answer()
    if not CFG.can_use(q.from_user.id):
        return
    action = q.data.split(":", 1)[1]
    fake = {"hide": start_hide, "reveal": start_reveal, "detect": start_detect, "exif": start_exif,
            "capsule": start_capsule, "split": start_split}
    await fake[action](q.message, context)


# ============================================================================ file intake

FILE_MENU_IMG = [[("🔬 Expose metadata", "f:exif"), ("🧪 Scan for stego", "f:detect")],
                 [("🕳 Hide a message", "f:hide"), ("🔓 Reveal message", "f:reveal")]]
FILE_MENU_WAV = [[("🧪 Scan for stego", "f:detect")], [("🕳 Hide a message", "f:hide"), ("🔓 Reveal", "f:reveal")]]


@guarded
async def on_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    doc = update.message.document
    if doc.file_size and doc.file_size > MAX_DOWNLOAD:
        await update.message.reply_text(ui.pre("E2BIG :: Telegram lets bots fetch files ≤ 20 MB."))
        return
    name = doc.file_name or "file"
    mode = context.user_data.get("mode")
    if name.lower().endswith(".age") and mode in (None, "unseal"):
        data = await download(context, doc.file_id)
        await do_unseal(update.message, context, data.decode(errors="replace"))
        return
    entry = {"id": doc.file_id, "name": name, "size": doc.file_size or 0}
    if mode == "hide_cover":
        context.user_data["m_file"] = entry
        context.user_data["mode"] = "hide_msg"
        await update.message.reply_text(ui.pre(f"> carrier locked: {ui.clip(name, 24)}\n> now send the SECRET MESSAGE (text)"))
        return
    if mode == "reveal_file":
        context.user_data["m_file"] = entry
        context.user_data["mode"] = "reveal_pass"
        await update.message.reply_text(ui.pre("> carrier loaded.\n> enter passphrase:") + "\n<i>I'll delete it right after.</i>")
        return
    if mode == "detect_file":
        set_mode(context, None)
        await run_detect(update.message, context, entry)
        return
    if mode == "exif_file":
        set_mode(context, None)
        await run_exif(update.message, context, entry)
        return
    # No active mode: offer the menu.
    context.user_data["last_file"] = entry
    is_wav = name.lower().endswith(".wav")
    await update.message.reply_text(
        ui.pre(f"> file received: {ui.clip(name, 22)}\n> size: {ui.human_bytes(entry['size'])}\n> select operation_"),
        reply_markup=kb(FILE_MENU_WAV if is_wav else FILE_MENU_IMG))


@guarded
async def on_photo(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        ui.box("LOSSY INPUT DETECTED", [
            "Telegram re-encoded this photo:",
            "· all EXIF metadata stripped",
            "· JPEG recompression destroyed",
            "  every LSB (stego is gone)",
            "",
            "Resend it as a FILE:",
            "📎 → File → pick the image",
        ]) + "<i>Ironically, Telegram just scrubbed it for you.</i>")


@guarded
async def on_audio(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(ui.pre(
        "Voice notes / music are lossy (Opus/MP3).\nLSB stego needs uncompressed 16-bit WAV,\nsent as a FILE."))


async def on_file_action(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    q = update.callback_query
    await q.answer()
    if not CFG.can_use(q.from_user.id):
        return
    entry = context.user_data.get("last_file")
    if not entry:
        await q.message.reply_text(ui.pre("ENOENT :: file expired from cache, send it again."))
        return
    action = q.data.split(":", 1)[1]
    if action == "exif":
        await run_exif(q.message, context, entry)
    elif action == "detect":
        await run_detect(q.message, context, entry)
    elif action == "hide":
        set_mode(context, "hide_msg", file=entry)
        await q.message.reply_text(ui.pre("> carrier locked.\n> now send the SECRET MESSAGE (text)"))
    elif action == "reveal":
        set_mode(context, "reveal_pass", file=entry)
        await q.message.reply_text(ui.pre("> enter passphrase:") + "\n<i>I'll delete it right after.</i>")


# ============================================================================ text router


@guarded
async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = update.message.text or ""
    mode = context.user_data.get("mode")
    routes = {
        "hide_msg": text_hide_msg, "hide_pass": text_hide_pass, "reveal_pass": text_reveal_pass,
        "capsule_dur": text_capsule_dur, "capsule_msg": text_capsule_msg,
        "split_kn": text_split_kn, "split_secret": text_split_secret, "combine": text_combine,
        "unseal": text_unseal,
    }
    if mode in routes:
        await routes[mode](update, context, text)
        return
    if mode in ("hide_cover", "reveal_file", "detect_file", "exif_file"):
        await update.message.reply_text(ui.pre("> waiting for a FILE (📎 → File). /cancel to abort."))
        return
    if SHARE_RE.search(text):
        set_mode(context, "combine", shares={})
        await text_combine(update, context, text)
        return
    if "BEGIN AGE ENCRYPTED FILE" in text:
        await do_unseal(update.message, context, text)
        return
    if update.effective_chat.type == ChatType.PRIVATE:
        await update.message.reply_text(ui.pre(f"bash: {ui.clip(text.split()[0] if text.split() else text, 18)}: command not found\ntry /help"))


# ============================================================================ STEGO


async def start_hide(msg: Message, context: ContextTypes.DEFAULT_TYPE) -> None:
    set_mode(context, "hide_cover")
    await msg.reply_text(ui.box("STEGO :: EMBED", [
        "1. send a carrier as FILE",
        "   PNG/JPG/WebP → PNG out",
        "   16-bit WAV   → WAV out",
        "2. send the secret text",
        "3. send a passphrase",
        "",
        "crypto: scrypt → AES-256-GCM",
        "bits scattered by keyed PRNG",
    ]))


@guarded
async def cmd_hide(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await start_hide(update.message, context)


async def text_hide_msg(update: Update, context: ContextTypes.DEFAULT_TYPE, text: str) -> None:
    context.user_data["m_secret"] = text
    context.user_data["mode"] = "hide_pass"
    await try_delete(update.message)
    await update.effective_chat.send_message(
        ui.pre(f"> secret buffered ({len(text.encode())} B), your message wiped.\n> choose a passphrase:"))


async def text_hide_pass(update: Update, context: ContextTypes.DEFAULT_TYPE, passphrase: str) -> None:
    ud = context.user_data
    entry, secret = ud.get("m_file"), ud.get("m_secret")
    set_mode(context, None)
    await try_delete(update.message)
    chat = update.effective_chat
    status = await chat.send_message(ui.pre("[....] initialising"))
    await context.bot.send_chat_action(chat.id, ChatAction.UPLOAD_DOCUMENT)
    try:
        data = await download(context, entry["id"])
        task = asyncio.create_task(asyncio.to_thread(stego.hide, data, entry["name"], secret, passphrase))
        await progress(status, [
            "[ OK ] carrier decoded",
            "[ OK ] salt ← /dev/urandom (128 bit)",
            "[ OK ] scrypt N=2^15 r=8 p=1 → k",
            "[ OK ] zlib → AES-256-GCM seal",
            "[ OK ] PCG64(HMAC(k)) scatter map",
            "[ OK ] flipping least-significant bits",
        ], 0.25)
        rep = await task
    except stego.StegoError as e:
        await status.edit_text(ui.pre(f"[FAIL] {e}"))
        return
    usage = rep.payload_bytes / max(1, rep.capacity)
    lines = ui.kv([
        ("carrier", rep.carrier_kind), ("payload", f"{rep.payload_bytes} B"),
        ("capacity", f"{ui.human_bytes(rep.capacity)}"), ("used", f"{ui.bar(usage, 12)} {usage:.1%}"),
        ("bits Δ", f"{rep.changed_bits:,}"),
    ], 8)
    if rep.psnr is not None:
        lines.append(f"{'PSNR':<8} {rep.psnr:.1f} dB (invisible)")
    await status.edit_text(ui.box("PAYLOAD EMBEDDED", lines)
                           + "⚠️ <i>Send it on as a <b>file</b>. Any recompression destroys the payload.</i>")
    stem = re.sub(r"\.[^.]+$", "", entry["name"]) or "image"
    await chat.send_document(doc_file(rep.file, f"{stem}.{rep.ext}"),
                             caption="🕳 looks innocent. isn't.")


async def start_reveal(msg: Message, context: ContextTypes.DEFAULT_TYPE) -> None:
    set_mode(context, "reveal_file")
    await msg.reply_text(ui.pre("STEGO :: EXTRACT\n> send the carrier as a FILE"))


@guarded
async def cmd_reveal(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await start_reveal(update.message, context)


async def text_reveal_pass(update: Update, context: ContextTypes.DEFAULT_TYPE, passphrase: str) -> None:
    entry = context.user_data.get("m_file")
    set_mode(context, None)
    await try_delete(update.message)
    chat = update.effective_chat
    status = await chat.send_message(ui.pre("[....] reading LSB plane"))
    try:
        data = await download(context, entry["id"])
        task = asyncio.create_task(asyncio.to_thread(stego.reveal, data, entry["name"], passphrase))
        await progress(status, ["[ OK ] salt recovered from bits 0-127", "[ .. ] scrypt key stretch",
                                "[ .. ] rebuilding scatter map"], 0.3)
        rep = await task
    except stego.WrongKey:
        await status.edit_text(ui.pre(
            "[FAIL] GCM authentication tag mismatch\n\n"
            "  ⛔  A C C E S S   D E N I E D  ⛔\n\n"
            "wrong passphrase, or nothing is hidden.\n(indistinguishable by design)"))
        return
    except stego.StegoError as e:
        await status.edit_text(ui.pre(f"[FAIL] {e}"))
        return
    await status.edit_text(
        ui.box("ACCESS GRANTED", ui.kv([
            ("carrier", rep.carrier_kind), ("payload", f"{rep.payload_bytes} B ciphertext"),
            ("salt", rep.salt.hex()[:16] + "…"), ("auth", "GCM tag valid ✓"),
        ], 8)) + f"🔓 <b>decrypted:</b>\n{ui.spoiler(rep.message)}")


async def start_detect(msg: Message, context: ContextTypes.DEFAULT_TYPE) -> None:
    set_mode(context, "detect_file")
    await msg.reply_text(ui.pre("STEGANALYSIS\n> send an image or WAV as a FILE"))


@guarded
async def cmd_detect(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await start_detect(update.message, context)


async def run_detect(msg: Message, context: ContextTypes.DEFAULT_TYPE, entry: dict) -> None:
    status = await msg.reply_text(ui.pre("[....] loading sample"))
    try:
        data = await download(context, entry["id"])
        task = asyncio.create_task(asyncio.to_thread(stego.analyze, data, entry["name"]))
        await progress(status, ["[ OK ] histogram of value pairs (2k,2k+1)",
                                "[ OK ] χ² Westfeld–Pfitzmann attack",
                                "[ OK ] scanning past EOF marker"], 0.3)
        a = await task
    except stego.StegoError as e:
        await status.edit_text(ui.pre(f"[FAIL] {e}"))
        return
    icon, verdict = a.verdict
    lines = [f"{icon} {verdict}", ""]
    if a.kind == "image":
        lines.append(f"{a.width}×{a.height} {a.fmt}")
    for ch, p in a.p_channels.items():
        lines.append(f"χ² {ch:<4}{ui.bar(p, 14)} {p:5.1%}")
    lines.append(f"curve {ui.sparkline(a.curve)}")
    lines.append(f"LSB=1 ratio  {a.lsb_ones_ratio:.4f}")
    lines.append(f"EOF tail     {len(a.trailing)} B" + (f" · {a.trailing_sig.split()[0]}" if a.trailing_sig else ""))
    text = ui.box("STEGANALYSIS", lines)
    if a.trailing:
        text += "<b>bytes after end-of-file:</b>\n" + ui.pre(ui.hexdump(a.trailing, 4))
    text += ("<i>χ² ≈ how equal the (2k,2k+1) pairs are. LSB replacement flattens them. "
             "Light, scattered payloads (like NULLBYTE's) can slip under it, which is the point.</i>")
    await status.edit_text(text)
    if a.lsb_plane_png:
        await msg.reply_photo(a.lsb_plane_png, caption="▦ LSB plane ×255. Noise = normal. Blocks/stripes/text = 👀")
    if len(a.trailing) > 16:
        ext = {"ZIP": "zip", "RAR": "rar", "7-Zip": "7z", "PDF": "pdf", "PNG": "png", "JPEG": "jpg"}
        guess = next((v for k, v in ext.items() if a.trailing_sig and a.trailing_sig.startswith(k)), "bin")
        await msg.reply_document(doc_file(a.trailing, f"carved_tail.{guess}"),
                                 caption="🪚 carved the appended bytes for you")


# ============================================================================ EXIF


async def start_exif(msg: Message, context: ContextTypes.DEFAULT_TYPE) -> None:
    set_mode(context, "exif_file")
    await msg.reply_text(ui.pre("METADATA FORENSICS\n> send a photo as a FILE (not as photo)"))


@guarded
async def cmd_exif(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await start_exif(update.message, context)


async def reverse_geocode(lat: float, lon: float) -> str | None:
    try:
        async with httpx.AsyncClient(timeout=5, headers={"User-Agent": "nullbyte-bot/1.0"}) as c:
            r = await c.get("https://nominatim.openstreetmap.org/reverse",
                            params={"lat": lat, "lon": lon, "format": "jsonv2", "zoom": 16})
            return r.json().get("display_name")
    except Exception:  # noqa: BLE001
        return None


async def run_exif(msg: Message, context: ContextTypes.DEFAULT_TYPE, entry: dict) -> None:
    status = await msg.reply_text(ui.pre("[....] parsing IFD0 / ExifIFD / GPS IFD"))
    try:
        data = await download(context, entry["id"])
        leak = await asyncio.to_thread(exif_tools.inspect, data)
    except Exception:  # noqa: BLE001
        await status.edit_text(ui.pre("[FAIL] not an image Pillow can parse"))
        return
    context.user_data["last_file"] = entry
    score = leak.threat_score
    meter = ui.bar(score / 100, 10)
    lines = ["DOXX-O-METER", f"[{meter}] {score}% doxxable", ""]
    rows = []
    if leak.make or leak.model:
        rows.append(("device", " ".join(x for x in (leak.make, leak.model) if x)))
    if leak.lens:
        rows.append(("lens", ui.clip(leak.lens, 21)))
    if leak.software:
        rows.append(("software", ui.clip(leak.software, 21)))
    if leak.taken:
        rows.append(("taken", leak.taken[:16].replace(":", "-", 2)))
        age = exif_tools.taken_age(leak.taken)
        extra = " · ".join(x for x in ((f"UTC{leak.tz_offset}" if leak.tz_offset else None), age) if x)
        if extra:
            rows.append(("", ui.clip(extra, 21)))
    if leak.settings:
        rows.append(("exposure", leak.settings))
    if leak.has_gps:
        rows.append(("GPS", f"{leak.lat:.5f}, {leak.lon:.5f}"))
        if leak.alt is not None:
            rows.append(("altitude", f"{leak.alt:.0f} m"))
        if leak.heading is not None:
            rows.append(("facing", exif_tools.heading_arrow(leak.heading)))
    rows.append(("pixels", f"{leak.width}×{leak.height} {leak.fmt}"))
    rows.append(("tags", f"{leak.tag_count} EXIF" + (" +XMP" if leak.has_xmp else "") + (" +IPTC" if leak.has_iptc else "")))
    lines += ui.kv(rows, 8)
    for key, val, why in leak.spicy:
        lines += ["", f"🌶 {key}", f"  {ui.clip(val, 26)}", f"  ↳ {ui.clip(why, 26)}"]
    text = ui.box("EXIF DUMP", lines)
    if score == 0 and leak.tag_count == 0:
        text += "✅ <i>Clean: no EXIF at all. Already scrubbed, or a screenshot.</i>"
    elif leak.has_gps:
        place = await reverse_geocode(leak.lat, leak.lon)
        text += f"📍 <b>this photo knows where it was taken</b>\n{ui.esc(place or '')}"
    await status.edit_text(text, reply_markup=kb([[("🧹 Scrub it", "x:scrub"), ("📜 Raw tags", "x:raw")]]),
                           link_preview_options=NO_PREVIEW)
    context.user_data["last_leak_raw"] = leak.raw
    if leak.has_gps:
        await msg.reply_location(leak.lat, leak.lon)
    if leak.thumbnail:
        await msg.reply_photo(leak.thumbnail, caption=(
            "🖼 embedded EXIF thumbnail. Editors sometimes forget to update it, so it can show "
            "the photo <b>before</b> cropping."))


async def on_exif_action(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    q = update.callback_query
    await q.answer()
    if not CFG.can_use(q.from_user.id):
        return
    action = q.data.split(":", 1)[1]
    if action == "raw":
        raw = context.user_data.get("last_leak_raw") or {}
        if not raw:
            await q.message.reply_text(ui.pre("(no readable tags)"))
            return
        body = "\n".join(f"{k[:18]:<18} {ui.clip(v, 30)}" for k, v in raw.items())
        await q.message.reply_text(ui.pre(body[:3900]))
        return
    entry = context.user_data.get("last_file")
    if not entry:
        await q.message.reply_text(ui.pre("ENOENT :: send the file again."))
        return
    data = await download(context, entry["id"])
    clean, ext = await asyncio.to_thread(exif_tools.scrub, data)
    after = await asyncio.to_thread(exif_tools.inspect, clean)
    stem = re.sub(r"\.[^.]+$", "", entry["name"]) or "photo"
    await q.message.reply_document(doc_file(clean, f"{stem}_clean.{ext}"), caption=(
        ui.pre(f"SCRUB COMPLETE\nEXIF tags   → {after.tag_count}\nGPS         → {'gone ✓' if not after.has_gps else 'STILL THERE?!'}\n"
               f"size        {ui.human_bytes(len(data))} → {ui.human_bytes(len(clean))}\npixels re-encoded, orientation baked in")))


# ============================================================================ CAPSULES


async def start_capsule(msg: Message, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not capsule.available():
        await msg.reply_text(ui.pre("ENOSYS :: `tle` binary not found on server.\nSee README → time capsules."))
        return
    set_mode(context, "capsule_dur")
    await msg.reply_text(ui.box("TIME CAPSULE", [
        "Encrypt to a FUTURE drand round.",
        "The key is a threshold BLS sig",
        "the League of Entropy only makes",
        "when that round arrives.",
        "Not you, not me: nobody opens",
        "it early.",
        "",
        "> unlock in? e.g. 90s 2h 7d 1y",
    ]))


@guarded
async def cmd_capsule(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if context.args:
        if not capsule.available():
            await update.message.reply_text(ui.pre("ENOSYS :: `tle` not installed."))
            return
        set_mode(context, "capsule_dur")
        await text_capsule_dur(update, context, context.args[0])
        return
    await start_capsule(update.message, context)


async def text_capsule_dur(update: Update, context: ContextTypes.DEFAULT_TYPE, text: str) -> None:
    try:
        seconds, tle_dur = capsule.parse_duration(text)
    except capsule.CapsuleError as e:
        await update.message.reply_text(ui.pre(f"EINVAL :: {e}"))
        return
    context.user_data.update(mode="capsule_msg", m_seconds=seconds, m_tle=tle_dur)
    unlock = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=seconds)
    await update.message.reply_text(ui.pre(
        f"> unlock: {unlock:%Y-%m-%d %H:%M} UTC\n> (in {ui.human_duration(seconds)})\n> write the message to seal:"))


async def text_capsule_msg(update: Update, context: ContextTypes.DEFAULT_TYPE, text: str) -> None:
    ud = context.user_data
    seconds, tle_dur = ud.get("m_seconds"), ud.get("m_tle")
    set_mode(context, None)
    await try_delete(update.message)
    chat = update.effective_chat
    status = await chat.send_message(ui.pre("[....] contacting drand"))
    try:
        task = asyncio.create_task(capsule.seal(text, tle_dur))
        await progress(status, [
            "[ OK ] GET /chains/quicknet/info",
            "[ OK ] target round = now + Δ/3s",
            "[ OK ] ID = H(round) on BLS12-381 G1",
            "[ OK ] Boneh–Franklin IBE wrap",
            "[ OK ] age payload · ChaCha20-Poly1305",
        ], 0.3)
        armored = await task
    except capsule.CapsuleError as e:
        await status.edit_text(ui.pre(f"[FAIL] {e}"))
        return
    hdr = capsule.parse_header(armored)
    unlock_at = capsule.round_time(hdr.round) if hdr.round else time.time() + seconds
    cid = db(context).add_capsule(chat.id, update.effective_user.id, None, unlock_at, hdr.round, armored)
    when = dt.datetime.fromtimestamp(unlock_at, dt.timezone.utc)
    await status.edit_text(ui.box(f"CAPSULE #{cid} SEALED", ui.kv([
        ("round", f"{hdr.round:,}" if hdr.round else "?"),
        ("unlocks", f"{when:%Y-%m-%d %H:%M:%S}"), ("", "UTC"),
        ("in", ui.human_duration(unlock_at - time.time())),
        ("size", f"{len(armored)} B armored"),
        ("chain", (hdr.chain or "")[:12] + "…"),
    ], 7)) + "🔒 <i>Your plaintext was wiped from this chat. I'll deliver it here when the round lands.</i>")
    await chat.send_document(doc_file(armored.encode(), f"capsule_{cid}.age"),
                             caption=(f"Backup. Opens anywhere after unlock, even if this bot dies:\n"
                                      f"<code>tle -d capsule_{cid}.age</code>"))


@guarded
async def cmd_capsules(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    rows = db(context).pending_capsules(update.effective_user.id)
    if not rows:
        await update.message.reply_text(ui.pre("no sealed capsules. /capsule to make one."))
        return
    lines = []
    now = time.time()
    for r in rows[:12]:
        total = max(1, r["unlock_at"] - r["created_at"])
        frac = (now - r["created_at"]) / total
        lines += [f"#{r['id']:<4} {ui.bar(frac, 14)} {frac:4.0%}", f"      T-{ui.human_duration(r['unlock_at'] - now)}"]
    await update.message.reply_text(ui.box("SEALED", lines))


@guarded
async def cmd_unseal(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    set_mode(context, "unseal")
    await update.message.reply_text(ui.pre("> paste the armored capsule\n  or send the .age file"))


async def text_unseal(update: Update, context: ContextTypes.DEFAULT_TYPE, text: str) -> None:
    set_mode(context, None)
    await do_unseal(update.message, context, text)


async def do_unseal(msg: Message, context: ContextTypes.DEFAULT_TYPE, armored: str) -> None:
    set_mode(context, None)
    hdr = capsule.parse_header(armored)
    status = await msg.reply_text(ui.pre(f"[....] fetching round {hdr.round or '?'} signature"))
    try:
        plain = await capsule.unseal(armored)
    except capsule.TooEarly:
        wait = capsule.round_time(hdr.round) - time.time() if hdr.round else 0
        await status.edit_text(ui.pre(
            f"[LOCK] round {hdr.round:,} hasn't happened yet.\n"
            f"       T-{ui.human_duration(wait)}\n"
            "the key does not exist anywhere in the universe. patience." if hdr.round else
            "[LOCK] too early."))
        return
    except capsule.CapsuleError as e:
        await status.edit_text(ui.pre(f"[FAIL] {e}"))
        return
    await status.edit_text(ui.box("UNSEALED", [f"round {hdr.round or '?'} · BLS sig verified"])
                           + ui.spoiler(plain))


async def job_capsules(context: ContextTypes.DEFAULT_TYPE) -> None:
    store = db(context)
    for r in store.due_capsules():
        try:
            plain = await capsule.unseal(r["armored"])
        except capsule.TooEarly:
            store.postpone(r["id"], 15)
            continue
        except capsule.CapsuleError as e:
            log.warning("capsule %s: %s", r["id"], e)
            store.postpone(r["id"], 300)
            continue
        sealed = dt.datetime.fromtimestamp(r["created_at"], dt.timezone.utc)
        try:
            m = await context.bot.send_message(r["chat_id"], ui.pre("📡 drand round landed…"))
            await progress(m, [
                f"[ OK ] round {r['drand_round'] or '?'} beacon received",
                "[ OK ] BLS threshold signature verified",
                "[ OK ] IBE private key = σ_round",
                "[ OK ] decrypting…",
            ], 0.6)
            await m.edit_text(
                ui.box(f"CAPSULE #{r['id']} UNSEALED", ui.kv([
                    ("sealed", f"{sealed:%Y-%m-%d %H:%M} UTC"),
                    ("waited", ui.human_duration(time.time() - r["created_at"])),
                ], 7)) + f"📬 <b>message from the past:</b>\n{ui.esc(plain)}")
        except (BadRequest, Forbidden) as e:
            log.warning("deliver capsule %s failed: %s", r["id"], e)
        store.mark_opened(r["id"])


# ============================================================================ SHAMIR


async def start_split(msg: Message, context: ContextTypes.DEFAULT_TYPE) -> None:
    set_mode(context, "split_kn")
    await msg.reply_text(ui.box("SHAMIR :: SPLIT", [
        "Secret → n shares. Any k rebuild",
        "it; k-1 shares reveal exactly",
        "zero bits (information-theoretic).",
        "",
        "> threshold as k/n, e.g. 3/5",
    ]))


@guarded
async def cmd_split(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if len(context.args) == 2 and all(a.isdigit() for a in context.args):
        set_mode(context, "split_kn")
        await text_split_kn(update, context, "/".join(context.args))
        return
    await start_split(update.message, context)


async def text_split_kn(update: Update, context: ContextTypes.DEFAULT_TYPE, text: str) -> None:
    m = re.match(r"^\s*(\d{1,2})\s*[/ ,of-]+\s*(\d{1,2})\s*$", text)
    if not m or not (2 <= int(m.group(1)) <= int(m.group(2)) <= 16):
        await update.message.reply_text(ui.pre("EINVAL :: format k/n with 2 ≤ k ≤ n ≤ 16"))
        return
    k, n = int(m.group(1)), int(m.group(2))
    context.user_data.update(mode="split_secret", m_k=k, m_n=n)
    await update.message.reply_text(ui.pre(f"> {k}-of-{n} scheme armed\n> send the secret (≤1 KB).\n  I'll delete your message."))


async def text_split_secret(update: Update, context: ContextTypes.DEFAULT_TYPE, text: str) -> None:
    k, n = context.user_data.get("m_k"), context.user_data.get("m_n")
    set_mode(context, None)
    await try_delete(update.message)
    chat = update.effective_chat
    try:
        shares = shamir.split(text.encode("utf-8"), k, n)
    except shamir.ShamirError as e:
        await chat.send_message(ui.pre(f"[FAIL] {e}"))
        return
    status = await chat.send_message(ui.pre("[....] sampling random polynomials"))
    await progress(status, [
        f"[ OK ] f(x) = s + a₁x + … + a{_sub(k - 1)}x^{k - 1}",
        "[ OK ] coefficients ← CSPRNG",
        f"[ OK ] evaluating at x = 1…{n} in GF(2⁸)",
        "[ OK ] appended SHA-256 check (4 B)",
    ], 0.3)
    await status.edit_text(ui.box("SECRET SHATTERED", ui.kv([
        ("scheme", f"{k}-of-{n}"), ("set id", shares[0].set_id), ("field", "GF(2^8) / 0x11B"),
        ("secret", "wiped from chat ✓"),
    ], 7)))
    for s in shares:
        await chat.send_message(
            ui.pre(f"🗝 SHARE {s.x}/{n} · NEED {k}\nset {s.set_id} · fp {s.fingerprint}") + "\n" + ui.code(s.encode()))
    await chat.send_message(
        "<b>Now:</b> forward each share to a <i>different</i> guardian, then delete them here.\n"
        f"Recovery: /combine, or a group ritual with /ceremony.")


def _sub(n: int) -> str:
    return str(n).translate(str.maketrans("0123456789", "₀₁₂₃₄₅₆₇₈₉"))


@guarded
async def cmd_combine(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    set_mode(context, "combine", shares={})
    await update.message.reply_text(ui.pre("SHAMIR :: COMBINE\n> paste shares (one or many per message)"))


async def text_combine(update: Update, context: ContextTypes.DEFAULT_TYPE, text: str) -> None:
    found = SHARE_RE.findall(text)
    await try_delete(update.message)
    chat = update.effective_chat
    if not found:
        await chat.send_message(ui.pre("no sss1-… share found in that. /cancel to stop."))
        return
    bag: dict = context.user_data.setdefault("m_shares", {})
    errors = []
    for raw in found:
        try:
            s = shamir.Share.decode(raw)
            bag[(s.set_id, s.x)] = s
        except shamir.ShamirError as e:
            errors.append(str(e))
    if not bag:
        await chat.send_message(ui.pre("[FAIL] " + "; ".join(errors)))
        return
    any_share = next(iter(bag.values()))
    same = [s for s in bag.values() if s.set_id == any_share.set_id]
    k = any_share.k
    got = len(same)
    if got < k:
        await chat.send_message(ui.pre(
            f"[{ui.bar(got / k, 12)}] {got}/{k} shares\nset {any_share.set_id}" + ("\n! " + errors[0] if errors else "")))
        return
    set_mode(context, None)
    try:
        secret = shamir.combine(same)
    except shamir.ShamirError as e:
        await chat.send_message(ui.pre(f"[FAIL] {e}"))
        return
    m = await chat.send_message(ui.pre("[....] Lagrange interpolation at x=0"))
    await progress(m, [f"[ OK ] {k} points on a degree-{k - 1} curve", "[ OK ] f(0) recovered byte-by-byte",
                       "[ OK ] SHA-256 check matches ✓"], 0.35)
    await m.edit_text(ui.box("SECRET RECONSTRUCTED", [f"set {any_share.set_id} · {k}-of-?"])
                      + ui.spoiler(secret.decode("utf-8", errors="replace")))


@guarded
async def cmd_ceremony(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    code = secrets.token_hex(3).upper()
    sessions = context.application.bot_data.setdefault("ceremonies", {})
    sessions[code] = {"owner": update.effective_user.id, "chat": update.effective_chat.id,
                      "shares": {}, "created": time.time(), "done": False, "result": None}
    me = (await context.bot.get_me()).username
    await update.message.reply_text(
        ui.box("RECOVERY CEREMONY", [
            f"code      {code}",
            f"summoner  {update.effective_user.first_name}",
            "expires   60 min",
            "",
            "Guardians: DM the bot",
            f"/contribute {code} <share>",
            "",
            "The secret is revealed ONLY to",
            "the summoner, privately.",
        ]) + f"👉 <a href=\"https://t.me/{me}\">open @{ui.esc(me)}</a>", link_preview_options=NO_PREVIEW)


@guarded
async def cmd_contribute(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg = update.message
    if update.effective_chat.type != ChatType.PRIVATE:
        await try_delete(msg)
        await update.effective_chat.send_message(ui.pre("!! never post shares in a group. DM me instead."))
        return
    parts = (msg.text or "").split(maxsplit=2)
    if len(parts) < 3:
        await msg.reply_text(ui.pre("usage: /contribute CODE sss1-…"))
        return
    code, raw = parts[1].upper(), parts[2]
    await try_delete(msg)
    sessions = context.application.bot_data.get("ceremonies", {})
    sess = sessions.get(code)
    if not sess or sess["done"] or time.time() - sess["created"] > CEREMONY_TTL:
        await update.effective_chat.send_message(ui.pre(f"ENOENT :: ceremony {code} not active"))
        return
    try:
        share = shamir.Share.decode(raw)
    except shamir.ShamirError as e:
        await update.effective_chat.send_message(ui.pre(f"[FAIL] {e}"))
        return
    sets = {s.set_id for s in sess["shares"].values()}
    if sets and share.set_id not in sets:
        await update.effective_chat.send_message(ui.pre("[FAIL] share belongs to a different secret"))
        return
    sess["shares"][share.x] = share
    got, k = len(sess["shares"]), share.k
    who = update.effective_user.first_name or "a guardian"
    await update.effective_chat.send_message(ui.pre(f"✓ share x={share.x} accepted into {code}\n[{ui.bar(got / k, 12)}] {got}/{k}"))
    await context.bot.send_message(sess["chat"], ui.pre(
        f"🗝 {who} contributed to {code}\n[{ui.bar(got / k, 12)}] {got}/{k}"))
    if got >= k:
        sess["done"] = True
        try:
            secret = shamir.combine(list(sess["shares"].values()))
        except shamir.ShamirError as e:
            await context.bot.send_message(sess["chat"], ui.pre(f"[FAIL] ceremony {code}: {e}"))
            return
        sess["shares"].clear()
        text = ui.box(f"CEREMONY {code} COMPLETE", ["threshold reached", "Lagrange @ x=0 ✓", "integrity ✓"]) + \
            ui.spoiler(secret.decode("utf-8", errors="replace"))
        try:
            await context.bot.send_message(sess["owner"], text)
            await context.bot.send_message(sess["chat"], ui.pre(f"🔓 {code}: secret delivered privately to the summoner."))
        except Forbidden:
            sess["result"] = text
            await context.bot.send_message(sess["chat"], ui.pre(
                f"🔓 {code} complete, but I can't DM the summoner.\nSummoner: open a DM with me and send /claim {code}"))


@guarded
async def cmd_claim(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    code = (context.args[0] if context.args else "").upper()
    sess = context.application.bot_data.get("ceremonies", {}).get(code)
    if not sess or sess["owner"] != update.effective_user.id or not sess.get("result"):
        await update.message.reply_text(ui.pre("nothing to claim."))
        return
    await update.message.reply_text(sess["result"])
    sess["result"] = None


# ============================================================================ HONEYPOT


@owner_only
async def cmd_hp(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    pot = hp(context)
    if not pot:
        await update.message.reply_text(ui.pre("honeypot disabled (HONEYPOT_ENABLED=0)"))
        return
    day = pot.stats(time.time() - 86400)
    live = db(context).get("hp_live", "0") == "1"
    await update.message.reply_text(ui.box("HONEYPOT CONSOLE", ui.kv([
        ("status", f"● armed :{CFG.honeypot_port}"), ("disguise", "prod-db-02 · U22.04"),
        ("live", "streaming ✓" if live else "off (/hp_live on)"), ("in jail", f"{len(pot.active)} active"),
        ("24h", f"{day['sessions']} sessions · {day['ips']} IPs"), ("", f"{day['auth']} logins · {day['commands']} cmds"),
        ("payloads", f"{day['urls']} URLs captured"),
    ], 8)))


@owner_only
async def cmd_hp_live(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    on = (context.args[0].lower() if context.args else "") in ("on", "1", "yes")
    db(context).set("hp_live", "1" if on else "0")
    await update.message.reply_text(ui.pre(f"live keystroke stream: {'ON 📡' if on else 'OFF'}"))


@owner_only
async def cmd_hp_stats(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    pot = hp(context)
    if not pot:
        return
    arg = context.args[0] if context.args else "7d"
    windows = {"24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400, "all": time.time()}
    since = time.time() - windows.get(arg, 7 * 86400)
    st = pot.stats(since)

    def top(items, width=11):
        if not items:
            return ["  (nothing yet)"]
        mx = items[0][1]
        return [f"{ui.clip(str(k) or '∅', width):<{width}} {ui.bar(v / mx, 9)} {v}" for k, v in items]

    lines = [f"window {arg} · {st['sessions']} sessions", f"{st['ips']} IPs · {st['auth']} logins", ""]
    lines += ["▸ origins"] + [f"{ui.flag(cc)} {ui.clip(name, 12):<12} {ui.bar(n / st['countries'][0][1], 8)} {n}"
                              for (cc, name), n in st["countries"]] if st["countries"] else ["▸ origins", "  (nothing yet)"]
    lines += ["", "▸ usernames"] + top(st["users"])
    lines += ["", "▸ passwords"] + top(st["passwords"])
    lines += ["", "▸ commands"] + top(st["top_cmds"])
    await update.message.reply_text(ui.box("THREAT INTEL", lines))


def render_transcript(sess: dict, cmds: list, limit: int | None = None) -> str:
    user = sess["username"] or "root"
    prompt = f"{user}@prod-db-02:~{'#' if user == 'root' else '$'}"
    t0 = sess["started"] or 0
    lines = []
    for c in cmds[:limit]:
        rel = c["ts"] - t0
        lines.append(f"[{int(rel // 60):02d}:{int(rel % 60):02d}] {prompt} {c['cmd']}")
    return "\n".join(lines) or "(connected, typed nothing, left. a shy one.)"


def transcript_header(sess: dict) -> str:
    dur = (sess["ended"] or time.time()) - sess["started"]
    return ui.box(f"SESSION #{sess['id']}", ui.kv([
        ("from", f"{sess['ip']}"), ("geo", ui.clip(f"{sess['city'] or ''} {sess['country'] or ''}".strip(), 22)),
        ("creds", ui.clip(f"{sess['username']} / {sess['password']}", 22)),
        ("client", ui.clip(sess["client"] or "?", 22)), ("lasted", ui.human_duration(dur)),
    ], 6))


@owner_only
async def cmd_hp_replay(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    pot = hp(context)
    if not pot or not context.args or not context.args[0].isdigit():
        await update.message.reply_text(ui.pre("usage: /hp_replay <session id>"))
        return
    await send_replay(update.effective_chat.id, context, int(context.args[0]))


async def send_replay(chat_id: int, context: ContextTypes.DEFAULT_TYPE, sid: int, title: str = "") -> None:
    pot = hp(context)
    sess, cmds = pot.transcript(sid)
    if not sess:
        await context.bot.send_message(chat_id, ui.pre("ENOENT :: no such session"))
        return
    body = render_transcript(sess, cmds)
    head = (f"<b>{title}</b>\n" if title else "") + f"{ui.flag(sess['cc'])} " + transcript_header(sess)
    if len(body) < 3000:
        await context.bot.send_message(chat_id, head + ui.pre(body),
                                       reply_markup=kb([[("▶️ Play it back", f"hp:play:{sid}")]]) if cmds else None)
    else:
        await context.bot.send_message(chat_id, head)
        await context.bot.send_document(chat_id, doc_file(body.encode(), f"session_{sid}.log"))


async def on_hp_action(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    q = update.callback_query
    if q.from_user.id != CFG.owner_id:
        await q.answer("owner only")
        return
    await q.answer("▶ replaying…")
    sid = int(q.data.rsplit(":", 1)[1])
    sess, cmds = hp(context).transcript(sid)
    if not sess:
        return
    user = sess["username"] or "root"
    prompt = f"{user}@prod-db-02:~{'#' if user == 'root' else '$'} "
    m = await q.message.reply_text(ui.pre(prompt + "▌"))
    screen: list[str] = []
    prev_ts = cmds[0]["ts"] if cmds else 0
    for c in cmds[:30]:
        gap = min(2.0, max(0.5, (c["ts"] - prev_ts) / 3))
        prev_ts = c["ts"]
        await asyncio.sleep(gap)
        typed = ""
        cmd = c["cmd"][:120]
        for chunk in _chunks(cmd, max(4, len(cmd) // 3)):  # typewriter in a few frames
            typed += chunk
            view = "\n".join(screen[-14:] + [prompt + typed + "▌"])
            try:
                await m.edit_text(ui.pre(view))
            except BadRequest:
                pass
            await asyncio.sleep(0.35)
        screen.append(prompt + cmd)
    screen.append("Connection to prod-db-02 closed.")
    try:
        await m.edit_text(ui.pre("\n".join(screen[-16:])))
    except BadRequest:
        pass


def _chunks(s: str, n: int) -> list[str]:
    return [s[i:i + n] for i in range(0, len(s), n)] or [""]


@owner_only
async def cmd_hp_kiddie(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await announce_kiddie(context, update.effective_chat.id, force=True)


async def announce_kiddie(context: ContextTypes.DEFAULT_TYPE, chat_id: int, force: bool = False) -> None:
    pot = hp(context)
    if not pot:
        return
    sid = pot.kiddie_of_the_day()
    if not sid:
        if force:
            await context.bot.send_message(chat_id, ui.pre("no visitors in the last 24h. the internet is quiet. suspicious."))
        return
    await send_replay(chat_id, context, sid, title="🏆 SCRIPT KIDDIE OF THE DAY")


async def job_kiddie(context: ContextTypes.DEFAULT_TYPE) -> None:
    if CFG.owner_id:
        await announce_kiddie(context, CFG.owner_id)


# ============================================================================ notifier + app


class OwnerNotifier:
    """Rate-limited queue so a busy honeypot never trips Telegram flood limits."""

    def __init__(self, app: Application):
        self.app = app
        self.q: asyncio.Queue[str] = asyncio.Queue(maxsize=200)
        self.task: asyncio.Task | None = None

    async def __call__(self, text: str) -> None:
        if not CFG.owner_id:
            return
        is_live_line = "⟫" in text
        if is_live_line and db_from_app(self.app).get("hp_live", "0") != "1":
            return
        try:
            self.q.put_nowait(text)
        except asyncio.QueueFull:
            pass

    def start(self) -> None:
        self.task = asyncio.create_task(self._run())

    async def _run(self) -> None:
        while True:
            text = await self.q.get()
            batch = [text]
            while not self.q.empty() and len(batch) < 15 and "⟫" in text:
                nxt = self.q.get_nowait()
                batch.append(nxt)
            try:
                await self.app.bot.send_message(CFG.owner_id, "\n".join(batch), link_preview_options=NO_PREVIEW)
            except Exception as e:  # noqa: BLE001
                log.warning("notify failed: %s", e)
            await asyncio.sleep(1.2)


def db_from_app(app: Application) -> DB:
    return app.bot_data["db"]


async def post_init(app: Application) -> None:
    store = app.bot_data["ops"].store.db if "ops" in app.bot_data else DB(CFG.db_path)
    app.bot_data["db"] = store
    notifier = OwnerNotifier(app)
    notifier.start()
    app.bot_data["notifier"] = notifier
    if CFG.honeypot_enabled and CFG.honeypot_port:
        pot = Honeypot(store, CFG.honeypot_port, CFG.host_key, notifier,
                       lambda: store.get("hp_live", "0") == "1")
        try:
            await pot.start()
            app.bot_data["honeypot"] = pot
        except OSError as e:
            log.error("honeypot failed to bind :%s (%s)", CFG.honeypot_port, e)
    fx_cmds = [
        BotCommand("efferent", "⟶ terminal · fleet · signals"), BotCommand("fx_signal", "fire one command on a server"),
        BotCommand("fx_afferent", "⟵ health chart for a server"), BotCommand("fx_gpu", "GPU temp · VRAM · util"),
        BotCommand("fx_watch", "◉ watch a training job"), BotCommand("fx_jobs", "running jobs"),
        BotCommand("fx_tunnel", "Jupyter / TensorBoard tunnel"), BotCommand("fx_reflex", "⚡ reflex arc on alert"),
        BotCommand("fx_grant", "time-boxed access for a friend"), BotCommand("fx_ca", "keyless logins · trust the CA"),
        BotCommand("fx_sessions", "session recordings"), BotCommand("fx_knock", "port-knock a server"),
        BotCommand("fx_audit", "audit log"), BotCommand("fx_admin", "♛ owner control panel"),
    ]
    nb_cmds = [
        BotCommand("hide", "hide a message in an image/WAV"), BotCommand("reveal", "extract a hidden message"),
        BotCommand("detect", "steganalysis"), BotCommand("exif", "photo metadata forensics"),
        BotCommand("capsule", "seal a time capsule"), BotCommand("capsules", "your sealed capsules"),
        BotCommand("unseal", "open a .age capsule"), BotCommand("split", "Shamir k-of-n split"),
        BotCommand("combine", "rebuild from shares"), BotCommand("ceremony", "group recovery ritual"),
        BotCommand("hp", "honeypot console"),
    ]
    head = [BotCommand("start", "boot + menu"), BotCommand("help", "command map")]
    tail = [BotCommand("cancel", "abort"), BotCommand("id", "your user id")]
    order = fx_cmds + nb_cmds if CFG.brand != "nullbyte" else nb_cmds + fx_cmds
    await app.bot.set_my_commands(head + order + tail)
    ops = app.bot_data.get("ops")
    if ops:
        await ops.start()
        if "honeypot" in app.bot_data:
            app.bot_data["honeypot"].stream = ops.hp_push
    if app.job_queue:
        app.job_queue.run_repeating(job_capsules, interval=20, first=5, name="capsules")
        app.job_queue.run_daily(job_kiddie, time=dt.time(CFG.kiddie_hour_utc, 0, tzinfo=dt.timezone.utc),
                                name="kiddie")
    log.info("NULLBYTE online · owner=%s · honeypot=%s", CFG.owner_id, "on" if "honeypot" in app.bot_data else "off")


async def post_shutdown(app: Application) -> None:
    ops = app.bot_data.get("ops")
    if ops:
        await ops.stop()
    pot = app.bot_data.get("honeypot")
    if pot:
        await pot.stop()


async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    log.exception("handler error", exc_info=context.error)
    if isinstance(update, Update) and update.effective_message:
        try:
            await update.effective_message.reply_text(ui.pre(
                f"Segmentation fault (core dumped)\n{type(context.error).__name__}: {ui.clip(str(context.error), 60)}"))
        except Exception:  # noqa: BLE001
            pass


class ResilientRequest(HTTPXRequest):
    """Retries requests that never reached Telegram (connect timeout / connect error), so a flaky VPN or
    filtered network doesn't crash handlers. Safe: a request that failed to connect wasn't delivered."""

    async def do_request(self, *args, **kwargs):
        delay = 1.5
        for attempt in range(4):
            try:
                return await super().do_request(*args, **kwargs)
            except (TimedOut, NetworkError) as e:
                cause = e.__cause__
                if attempt == 3 or not isinstance(cause, (httpx.ConnectTimeout, httpx.ConnectError)):
                    raise
                log.warning("telegram unreachable (%s), retry %d/3 in %.1fs", type(cause).__name__, attempt + 1, delay)
                await asyncio.sleep(delay)
                delay *= 2


def build_app() -> Application:
    if not CFG.token:
        raise SystemExit("BOT_TOKEN is not set. Copy .env.example to .env and fill it in.")
    net = dict(connect_timeout=15, read_timeout=30, write_timeout=30, pool_timeout=15, media_write_timeout=60,
               proxy=CFG.proxy or None)
    app = (Application.builder().token(CFG.token)
           .request(ResilientRequest(connection_pool_size=16, **net))
           .get_updates_request(ResilientRequest(**net))
           .defaults(Defaults(parse_mode=ParseMode.HTML))
           .post_init(post_init).post_shutdown(post_shutdown)
           .concurrent_updates(True)
           .build())
    add = app.add_handler
    add(CommandHandler("start", cmd_start))
    add(CommandHandler("help", cmd_help))
    add(CallbackQueryHandler(on_nav, pattern=r"^nav:"))
    add(CommandHandler("id", cmd_id))
    add(CommandHandler("cancel", cmd_cancel))
    add(CommandHandler("hide", cmd_hide))
    add(CommandHandler("reveal", cmd_reveal))
    add(CommandHandler("detect", cmd_detect))
    add(CommandHandler("exif", cmd_exif))
    add(CommandHandler("capsule", cmd_capsule))
    add(CommandHandler("capsules", cmd_capsules))
    add(CommandHandler("unseal", cmd_unseal))
    add(CommandHandler("split", cmd_split))
    add(CommandHandler("combine", cmd_combine))
    add(CommandHandler("ceremony", cmd_ceremony))
    add(CommandHandler("contribute", cmd_contribute))
    add(CommandHandler("claim", cmd_claim))
    add(CommandHandler("hp", cmd_hp))
    add(CommandHandler("hp_live", cmd_hp_live))
    add(CommandHandler("hp_stats", cmd_hp_stats))
    add(CommandHandler("hp_replay", cmd_hp_replay))
    add(CommandHandler("hp_kiddie", cmd_hp_kiddie))
    if Ops and CFG.ops_enabled:
        CFG.data_dir.mkdir(parents=True, exist_ok=True)
        ops = Ops(CFG, DB(CFG.db_path), app)
        app.bot_data["ops"] = ops
        ops.register()
    add(CallbackQueryHandler(on_go, pattern=r"^go:"))
    add(CallbackQueryHandler(on_file_action, pattern=r"^f:"))
    add(CallbackQueryHandler(on_exif_action, pattern=r"^x:"))
    add(CallbackQueryHandler(on_hp_action, pattern=r"^hp:play:"))
    add(MessageHandler(filters.Document.ALL, on_document))
    add(MessageHandler(filters.PHOTO, on_photo))
    add(MessageHandler(filters.AUDIO | filters.VOICE, on_audio))
    add(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))
    app.add_error_handler(on_error)
    return app


def main() -> None:
    logging.basicConfig(format="%(asctime)s %(levelname)s %(name)s: %(message)s", level=logging.INFO)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("asyncssh").setLevel(logging.WARNING)
    CFG.data_dir.mkdir(parents=True, exist_ok=True)
    build_app().run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)


if __name__ == "__main__":
    main()
