"""Terminal-flavoured message styling. Everything renders with Telegram HTML parse mode.

Telegram on a phone fits ~32-36 monospace columns, so boxes are kept narrow.
"""
from __future__ import annotations

import html
import math
import random
import unicodedata

W = 32  # inner width of boxes


def esc(text: object) -> str:
    return html.escape(str(text), quote=False)


def pre(text: str) -> str:
    return f"<pre>{esc(text)}</pre>"


def code(text: object) -> str:
    return f"<code>{esc(text)}</code>"


def spoiler(text: object) -> str:
    return f"<tg-spoiler>{esc(text)}</tg-spoiler>"


def clip(text: str, width: int) -> str:
    text = str(text)
    return text if len(text) <= width else text[: width - 1] + "…"


def dwidth(text: str) -> int:
    """Display width in a monospace block: emoji and CJK take two cells."""
    w = 0
    for ch in text:
        o = ord(ch)
        if unicodedata.combining(ch) or o in (0x200D, 0xFE0F):
            continue
        if 0x1F1E6 <= o <= 0x1F1FF:      # regional indicator: a flag pair = 2 cells
            w += 1
        elif o >= 0x1F000 or unicodedata.east_asian_width(ch) in ("W", "F") or o in (0x26A0, 0x2705, 0x26D4):
            w += 2
        else:
            w += 1
    return w


def ljust_d(text: str, width: int) -> str:
    return text + " " * max(0, width - dwidth(text))


def box(title: str, lines: list[str], width: int = W) -> str:
    """A box-drawing panel, returned already wrapped in <pre>."""
    top = f"┌─[ {title} ]" + "─" * max(0, width - len(title) - 5) + "┐"
    out = [top]
    for line in lines:
        for chunk in _wrap(line, width - 2):
            out.append("│ " + ljust_d(chunk, width - 2) + " │")
    out.append("└" + "─" * (width) + "┘")
    return pre("\n".join(out))


def _wrap(line: str, width: int) -> list[str]:
    if line == "":
        return [""]
    chunks = []
    while dwidth(line) > width:
        limit = width
        while dwidth(line[:limit]) > width:
            limit -= 1
        cut = line.rfind(" ", 0, limit)
        cut = cut if cut > limit // 3 else limit
        chunks.append(line[:cut])
        line = line[cut:].lstrip()
    chunks.append(line)
    return chunks


def kv(rows: list[tuple[str, object]], key_width: int = 10) -> list[str]:
    return [f"{k:<{key_width}} {v}" for k, v in rows]


def bar(fraction: float, width: int = 16, full: str = "█", empty: str = "░") -> str:
    fraction = max(0.0, min(1.0, fraction))
    n = round(fraction * width)
    return full * n + empty * (width - n)


SPARK = "▁▂▃▄▅▆▇█"


def sparkline(values: list[float], lo: float = 0.0, hi: float = 1.0) -> str:
    span = (hi - lo) or 1.0
    return "".join(SPARK[min(7, max(0, int((v - lo) / span * 7.999)))] for v in values)


def hexdump(data: bytes, rows: int = 4, width: int = 8) -> str:
    lines = []
    for i in range(0, min(len(data), rows * width), width):
        chunk = data[i : i + width]
        hexes = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:04x}  {hexes}  {asc}")
    return "\n".join(lines)


def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def human_duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    parts = []
    for unit, size in (("y", 31_536_000), ("d", 86_400), ("h", 3_600), ("m", 60), ("s", 1)):
        if seconds >= size:
            parts.append(f"{seconds // size}{unit}")
            seconds %= size
        if len(parts) == 2:
            break
    return " ".join(parts) or "0s"


def flag(country_code: str | None) -> str:
    if not country_code or len(country_code) != 2:
        return "🏴"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in country_code.upper())


def glitch(text: str, rate: float = 0.12) -> str:
    """Sprinkle a few block glyphs into a string for loading screens."""
    glyphs = "▓▒░█▚▞"
    return "".join(random.choice(glyphs) if c != " " and random.random() < rate else c for c in text)


BANNER = (
    "░█▀█░█░█░█░░░█░░░█▀▄░█░█░▀█▀░█▀▀\n"
    "░█░█░█░█░█░░░█░░░█▀▄░░█░░░█░░█▀▀\n"
    "░▀░▀░▀▀▀░▀▀▀░▀▀▀░▀▀░░░▀░░░▀░░▀▀▀"
)

TAGLINE = "0x00 // stego·exif·tlock·sss·hp"

FX_BANNER = (
    "░█▀▀░█▀▀░█▀▀░█▀▀░█▀▄░█▀▀░█▀█░▀█▀\n"
    "░█▀▀░█▀▀░█▀▀░█▀▀░█▀▄░█▀▀░█░█░░█░\n"
    "░▀▀▀░▀░░░▀░░░▀▀▀░▀░▀░▀▀▀░▀░▀░░▀░"
)
FX_TAGLINE = "UNFINITUM ▸ SUBSYSTEM 008"
