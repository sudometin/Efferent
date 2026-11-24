"""Session recording: asciinema v2 casts, rendered to animated GIFs for replay (and for the UNFINITUM channel).

A cast is JSON lines: header {"version":2,"width":W,"height":H,"timestamp":T} then [t, "o", data] events.
The GIF renderer replays events through pyte (a VT100 emulator) and paints the screen with Pillow.
"""
from __future__ import annotations

import io
import json
import time
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

FONT_PATHS = ["/usr/share/fonts/truetype/jetbrains-mono/JetBrainsMono-Regular.ttf",
              str(Path.home() / "Library/Fonts/JetBrainsMono-Regular.ttf"),
              "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
              "/System/Library/Fonts/Menlo.ttc"]
BG = (6, 7, 11)
FG = (205, 214, 224)
ANSI = {"black": (40, 44, 52), "red": (255, 77, 109), "green": (61, 245, 166), "brown": (255, 209, 102),
        "yellow": (255, 209, 102), "blue": (122, 162, 255), "magenta": (255, 79, 216), "cyan": (61, 220, 255),
        "white": (215, 224, 234), "default": FG}


class Recorder:
    def __init__(self, path: Path, cols: int, rows: int, title: str = ""):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.t0 = time.monotonic()
        self.f = open(self.path, "w", encoding="utf-8")
        self.f.write(json.dumps({"version": 2, "width": cols, "height": rows, "timestamp": int(time.time()),
                                 "title": title, "env": {"TERM": "xterm-256color"}}) + "\n")
        self.bytes = 0

    def output(self, data: str) -> None:
        if self.f.closed:
            return
        self.f.write(json.dumps([round(time.monotonic() - self.t0, 4), "o", data]) + "\n")
        self.bytes += len(data)

    def resize(self, cols: int, rows: int) -> None:
        if not self.f.closed:
            self.f.write(json.dumps([round(time.monotonic() - self.t0, 4), "r", f"{cols}x{rows}"]) + "\n")

    def close(self) -> None:
        if not self.f.closed:
            self.f.close()


def _font(size: int):
    for p in FONT_PATHS:
        try:
            return ImageFont.truetype(p, size)
        except OSError:
            continue
    return ImageFont.load_default()


def _color(name: str, default):
    if not name or name == "default":
        return default
    if name in ANSI:
        return ANSI[name]
    if len(name) == 6:
        try:
            return tuple(int(name[i:i + 2], 16) for i in (0, 2, 4))
        except ValueError:
            pass
    return default


def cast_to_gif(cast_path: Path, max_seconds: float = 60, fps: float = 6, max_cols: int = 100,
                max_rows: int = 32, idle_cap: float = 1.5, title: str = "") -> bytes:
    """Render a cast to GIF. Long idle gaps are squashed to `idle_cap` seconds so replays stay snappy."""
    import pyte

    lines = Path(cast_path).read_text(encoding="utf-8").splitlines()
    header = json.loads(lines[0])
    cols, rows = min(header.get("width", 80), max_cols), min(header.get("height", 24), max_rows)
    screen = pyte.Screen(cols, rows)
    stream = pyte.Stream(screen)
    events = []
    for ln in lines[1:]:
        try:
            t, kind, data = json.loads(ln)
        except ValueError:
            continue
        if kind == "o":
            events.append((float(t), data))
    # compress idle time
    out, last, shift = [], 0.0, 0.0
    for t, data in events:
        gap = t - last
        if gap > idle_cap:
            shift += gap - idle_cap
        last = t
        out.append((t - shift, data))
    events = [(t, d) for t, d in out if t <= max_seconds]

    font = _font(15)
    cw = int(font.getlength("M")) or 9
    ch = 19
    pad, bar = 14, 30
    W, H = cols * cw + pad * 2, rows * ch + pad * 2 + bar

    def paint() -> Image.Image:
        img = Image.new("RGB", (W, H), BG)
        d = ImageDraw.Draw(img)
        d.rectangle([0, 0, W, bar], fill=(14, 16, 22))
        for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
            d.ellipse([12 + i * 18, 10, 23 + i * 18, 21], fill=c)
        d.text((76, 7), f"EFFERENT-008 ▸ {title}"[:80], font=_font(13), fill=(61, 245, 166))
        for y in range(rows):
            line = screen.buffer[y]
            for x in range(cols):
                cell = line[x]
                if cell.data == " " and cell.bg == "default" and not cell.reverse:
                    continue
                fg, bg = _color(cell.fg, FG), _color(cell.bg, None)
                if cell.reverse:
                    fg, bg = (bg or BG), fg
                px, py = pad + x * cw, bar + pad + y * ch
                if bg:
                    d.rectangle([px, py, px + cw, py + ch], fill=bg)
                if cell.data.strip():
                    d.text((px, py), cell.data, font=font, fill=fg)
        cx, cy = screen.cursor.x, screen.cursor.y
        if 0 <= cx < cols and 0 <= cy < rows:
            px, py = pad + cx * cw, bar + pad + cy * ch
            d.rectangle([px, py + ch - 4, px + cw, py + ch - 1], fill=(61, 245, 166))
        return img

    frames, durations = [], []
    step = 1.0 / fps
    t_frame, i = 0.0, 0
    end = events[-1][0] if events else 0
    while t_frame <= end + step and len(frames) < int(max_seconds * fps) + 2:
        while i < len(events) and events[i][0] <= t_frame:
            stream.feed(events[i][1])
            i += 1
        frames.append(paint().convert("P", palette=Image.ADAPTIVE, colors=64))
        durations.append(int(step * 1000))
        t_frame += step
    if not frames:
        frames, durations = [paint().convert("P", palette=Image.ADAPTIVE, colors=64)], [1000]
    durations[-1] = 2500
    # drop consecutive identical frames (merge their durations): big size win
    dedup, ddur = [frames[0]], [durations[0]]
    for f, dur in zip(frames[1:], durations[1:]):
        if f.tobytes() == dedup[-1].tobytes():
            ddur[-1] += dur
        else:
            dedup.append(f)
            ddur.append(dur)
    buf = io.BytesIO()
    dedup[0].save(buf, "GIF", save_all=True, append_images=dedup[1:], duration=ddur, loop=0, optimize=True)
    return buf.getvalue()
