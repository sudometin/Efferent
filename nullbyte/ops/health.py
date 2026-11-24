"""Health probes over SSH (with a CA-minted, forced-command cert) + alert rules + sparkline charts."""
from __future__ import annotations

import io
import json
import time

from PIL import Image, ImageDraw, ImageFont

PROBE = ("cat /proc/loadavg; nproc; "
         "awk '/MemTotal/{t=$2}/MemAvailable/{a=$2}END{print (t-a)/t*100}' /proc/meminfo; "
         "df -P / | awk 'NR==2{gsub(\"%\",\"\",$5); print $5}'; cut -d' ' -f1 /proc/uptime; "
         "echo '--gpu--'; command -v nvidia-smi >/dev/null && nvidia-smi "
         "--query-gpu=index,name,utilization.gpu,memory.used,memory.total,temperature.gpu "
         "--format=csv,noheader,nounits 2>/dev/null; true")

LIMITS = {"disk": 90.0, "mem": 92.0, "load_per_cpu": 1.5, "gpu_temp": 85.0}


def parse(out: str) -> dict:
    head, _, gpu_part = out.partition("--gpu--")
    lines = [ln.strip() for ln in head.strip().splitlines() if ln.strip()]
    if len(lines) < 5:
        raise ValueError("unexpected probe output")
    load = float(lines[0].split()[0])
    return {"load": load, "cpus": int(lines[1]), "mem": float(lines[2]), "disk": float(lines[3]),
            "uptime": float(lines[4]), "gpu": parse_gpus(gpu_part)}


def parse_gpus(text: str) -> list[dict]:
    gpus = []
    for ln in text.strip().splitlines():
        parts = [p.strip() for p in ln.split(",")]
        if len(parts) < 6:
            continue
        try:
            gpus.append({"i": int(parts[0]), "name": parts[1].replace("NVIDIA ", "")[:22], "util": float(parts[2]),
                         "mem": float(parts[3]), "mem_total": float(parts[4]), "temp": float(parts[5])})
        except ValueError:
            continue
    return gpus


def problems(m: dict) -> list[str]:
    out = []
    if m["disk"] >= LIMITS["disk"]:
        out.append(f"disk {m['disk']:.0f}%")
    if m["mem"] >= LIMITS["mem"]:
        out.append(f"mem {m['mem']:.0f}%")
    if m["cpus"] and m["load"] / m["cpus"] >= LIMITS["load_per_cpu"]:
        out.append(f"load {m['load']:.2f} on {m['cpus']} cpu")
    if m["uptime"] < 600:
        out.append(f"rebooted {m['uptime'] / 60:.0f} min ago")
    for g in m.get("gpu") or []:
        if g["temp"] >= LIMITS["gpu_temp"]:
            out.append(f"gpu{g['i']} {g['temp']:.0f}°C")
    return out


def trigger_of(issue: str) -> str:
    """Map an issue line to a reflex trigger name."""
    w = issue.split()[0]
    return "gpu" if w.startswith("gpu") else w            # disk | mem | load | rebooted | gpu


def _gpus(row) -> list:
    try:
        return json.loads(row["gpu"]) if "gpu" in row.keys() and row["gpu"] else []
    except (ValueError, TypeError):
        return []


def chart(name: str, rows: list, width: int = 900, height: int = 360) -> bytes:
    """Neon sparklines: load/cpu, mem, disk (+ GPU util when the server has NVIDIA GPUs)."""
    ok = [r for r in rows if r["ok"]]
    series = [("load/cpu %", [min(100.0, (r["load"] / max(1, r["cpus"])) * 100) for r in ok], (61, 220, 255)),
              ("mem %", [r["mem"] for r in ok], (178, 140, 255)),
              ("disk %", [r["disk"] for r in ok], (255, 209, 102))]
    gpu_util = [sum(g["util"] for g in gs) / len(gs) for gs in map(_gpus, ok) if gs]
    if gpu_util:
        series.append(("gpu util %", gpu_util, (255, 122, 26)))
        height += 95
    img = Image.new("RGB", (width, height), (6, 7, 11))
    d = ImageDraw.Draw(img)
    for x in range(0, width, 24):
        d.line([(x, 0), (x, height)], fill=(14, 32, 28))
    for y in range(0, height, 24):
        d.line([(0, y), (width, y)], fill=(14, 32, 28))
    f, fs = _font(True, 18), _font(False, 14)
    d.text((24, 16), f"EFFERENT-008 ▸ {name}  ⟵ afferent", font=f, fill=(255, 122, 26))
    top, lane = 56, (height - 76) // len(series)
    for i, (label, vals, color) in enumerate(series):
        y0 = top + i * lane
        d.text((24, y0), label, font=fs, fill=(140, 150, 165))
        last = f"{vals[-1]:.0f}" if vals else "—"
        d.text((width - 24 - d.textlength(last, font=f), y0 - 2), last, font=f, fill=color)
        x0, x1, ya, yb = 150, width - 90, y0 + 4, y0 + lane - 18
        d.line([(x0, yb), (x1, yb)], fill=(30, 40, 52))
        if len(vals) >= 2:
            pts = [(x0 + (x1 - x0) * j / (len(vals) - 1), yb - (yb - ya) * max(0, min(100, v)) / 100)
                   for j, v in enumerate(vals)]
            d.line(pts, fill=color, width=3, joint="curve")
    down = sum(1 for r in rows if not r["ok"])
    d.text((24, height - 26), f"{len(rows)} probes · {down} failed · {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}",
           font=fs, fill=(92, 107, 122))
    buf = io.BytesIO()
    img.save(buf, "PNG", optimize=True)
    return buf.getvalue()


def _font(bold: bool, size: int):
    for p in (["/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"] if bold else
              ["/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"]) + ["/System/Library/Fonts/Menlo.ttc"]:
        try:
            return ImageFont.truetype(p, size)
        except OSError:
            continue
    return ImageFont.load_default()


def gpu_lines(gpus: list[dict]) -> list[str]:
    out = []
    for g in gpus:
        bar = "█" * round(g["util"] / 10) + "░" * (10 - round(g["util"] / 10))
        out.append(f"gpu{g['i']} {bar} {g['util']:>3.0f}% {g['temp']:.0f}°C {g['mem'] / 1024:.0f}/{g['mem_total'] / 1024:.0f}G")
    return out
