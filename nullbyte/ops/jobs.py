"""Training watch: launch a long command detached on a server, poll it, and report back with a loss curve.

On the server everything lives in ~/.efferent/jobs/<token>.{log,exit,pid}. The job runs in its own session
(setsid), so closing the SSH connection doesn't kill it, and /fx_jobs → ✕ kills the whole process group.
"""
from __future__ import annotations

import io
import re
import shlex

from PIL import Image, ImageDraw, ImageFont

DIR = "$HOME/.efferent/jobs"


def launch_cmd(token: str, command: str, cwd: str = "") -> str:
    """setsid -f puts the job in its own session; the inner bash writes its own pid (= process-group id).
    The user's command is passed as $0, so there are no nested quoting games."""
    inner = (f'echo $$ > {DIR}/{token}.pid; bash -lc "$0" > {DIR}/{token}.log 2>&1 < /dev/null; '
             f'echo $? > {DIR}/{token}.exit')
    cd = f" && cd {shlex.quote(cwd)}" if cwd else ""
    return (f"mkdir -p {DIR}{cd} && setsid -f bash -c {shlex.quote(inner)} {shlex.quote(command)} "
            f"> /dev/null 2>&1 < /dev/null; sleep 0.3; echo started $(cat {DIR}/{token}.pid 2>/dev/null)")


def poll_cmd(token: str, lines: int = 400) -> str:
    return (f"cat {DIR}/{token}.exit 2>/dev/null || echo RUNNING; echo '--log--'; "
            f"tail -n {lines} {DIR}/{token}.log 2>/dev/null")


def kill_cmd(token: str) -> str:
    """POSIX-sh safe (servers may run commands through dash): `kill -SIG -PGID` hits the whole job tree."""
    return (f"p=$(cat {DIR}/{token}.pid 2>/dev/null) && kill -TERM -$p 2>/dev/null; sleep 1; "
            f"kill -0 -$p 2>/dev/null && kill -KILL -$p 2>/dev/null; echo 143 > {DIR}/{token}.exit; echo killed")


def parse_poll(out: str) -> tuple[int | None, str]:
    head, _, log = out.partition("--log--")
    status = head.strip().splitlines()[-1].strip() if head.strip() else "RUNNING"
    code = None if status == "RUNNING" else (int(status) if status.lstrip("-").isdigit() else -1)
    return code, log.lstrip("\n")


# ------------------------------------------------------------------ metrics from logs
# matches: "loss: 0.123", "loss=0.12", "val_loss 0.3", "train/loss: 1e-3", "accuracy: 0.91", "acc=91.2%"
METRIC_RE = re.compile(
    r"(?<![A-Za-z])((?:train[_/ ])?(?:val(?:id(?:ation)?)?[_/ ])?(?:loss|acc(?:uracy)?|f1|auc))"
    r"\s*[:=]?\s*(-?\d+(?:\.\d+)?(?:e-?\d+)?)\s*(%?)", re.I)
EPOCH_RE = re.compile(r"epoch\s*[:=]?\s*(\d+)(?:\s*/\s*(\d+))?", re.I)


def metrics(log: str) -> dict[str, list[float]]:
    series: dict[str, list[float]] = {}
    for line in log.splitlines():
        for name, val, pct in METRIC_RE.findall(line):
            key = re.sub(r"[ /]", "_", name.lower()).replace("validation", "val").replace("valid", "val")
            key = key.replace("accuracy", "acc").replace("train_", "")
            try:
                v = float(val)
            except ValueError:
                continue
            if pct:
                v /= 100
            series.setdefault(key, []).append(v)
    return {k: v for k, v in series.items() if len(v) >= 2}


def progress(log: str) -> str | None:
    last = None
    for m in EPOCH_RE.finditer(log):
        last = m
    if not last:
        return None
    return f"epoch {last.group(1)}" + (f"/{last.group(2)}" if last.group(2) else "")


def _font(size: int, bold: bool = False):
    for p in ([f"/usr/share/fonts/truetype/dejavu/DejaVuSansMono{'-Bold' if bold else ''}.ttf",
               "/System/Library/Fonts/Menlo.ttc"]):
        try:
            return ImageFont.truetype(p, size)
        except OSError:
            continue
    return ImageFont.load_default()


PALETTE = [(255, 122, 26), (61, 220, 255), (178, 140, 255), (61, 245, 166), (255, 209, 102), (255, 79, 216)]


def curve(title: str, series: dict[str, list[float]], width: int = 900, height: int = 420) -> bytes:
    """Loss/metric curves: losses on the left panel, accuracies on the right (each auto-scaled)."""
    img = Image.new("RGB", (width, height), (6, 7, 11))
    d = ImageDraw.Draw(img)
    for x in range(0, width, 24):
        d.line([(x, 0), (x, height)], fill=(14, 32, 28))
    for y in range(0, height, 24):
        d.line([(0, y), (width, y)], fill=(14, 32, 28))
    d.text((24, 16), f"EFFERENT-008 ▸ {title}"[:70], font=_font(18, True), fill=(255, 122, 26))
    groups = [("loss", {k: v for k, v in series.items() if "loss" in k}),
              ("metrics", {k: v for k, v in series.items() if "loss" not in k})]
    groups = [g for g in groups if g[1]]
    if not groups:
        d.text((24, 80), "no loss / accuracy lines found in the log", font=_font(15), fill=(140, 150, 165))
    panel_w = (width - 48) // max(1, len(groups))
    ci = 0
    for gi, (gname, ser) in enumerate(groups):
        x0, x1, y0, y1 = 24 + gi * panel_w + 46, 24 + (gi + 1) * panel_w - 16, 64, height - 70
        allv = [v for vals in ser.values() for v in vals]
        lo, hi = min(allv), max(allv)
        if hi - lo < 1e-12:
            hi = lo + 1
        d.rectangle([x0, y0, x1, y1], outline=(30, 40, 52))
        for frac, lab in ((0, hi), (1, lo)):
            d.text((x0 - 44, y0 + (y1 - y0) * frac - 8), f"{lab:.3g}", font=_font(12), fill=(92, 107, 122))
        d.text((x0, y0 - 18), gname, font=_font(13, True), fill=(140, 150, 165))
        ly = y1 + 10
        for name, vals in ser.items():
            col = PALETTE[ci % len(PALETTE)]
            ci += 1
            pts = [(x0 + (x1 - x0) * j / max(1, len(vals) - 1), y1 - (y1 - y0) * (v - lo) / (hi - lo)) for j, v in enumerate(vals)]
            d.line(pts, fill=col, width=3, joint="curve")
            d.text((x0, ly), f"■ {name} {vals[-1]:.4g} ({'↓' if vals[-1] < vals[0] else '↑'} from {vals[0]:.3g})",
                   font=_font(13), fill=col)
            ly += 18
    buf = io.BytesIO()
    img.save(buf, "PNG", optimize=True)
    return buf.getvalue()
