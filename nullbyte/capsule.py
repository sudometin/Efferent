"""Time-lock encryption via drand's `tle` (tlock).

The message is encrypted to a *future drand round* using identity-based
encryption on BLS12-381. The decryption key is that round's threshold BLS
signature, which the drand League of Entropy network only produces when the
round arrives. Nobody can open it early: not you, not this bot.
"""
from __future__ import annotations

import asyncio
import base64
import os
import re
import shutil
import time
from dataclasses import dataclass

TLE = os.environ.get("TLE_BIN", "tle")
NETWORK = os.environ.get("DRAND_NETWORK", "")   # empty = tle default (api.drand.sh)
CHAIN = os.environ.get("DRAND_CHAIN", "")       # empty = tle default (quicknet)
QUICKNET_GENESIS = 1692803367                   # quicknet: 3s period
QUICKNET_PERIOD = 3

UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800, "M": 2_592_000, "y": 31_536_000}
DUR_RE = re.compile(r"^(\d{1,4})\s*([smhdwMy])$")


class CapsuleError(Exception):
    pass


def available() -> bool:
    return shutil.which(TLE) is not None


def parse_duration(text: str) -> tuple[int, str]:
    """'2h' -> (7200, '2h'). Weeks are converted to days for tle."""
    m = DUR_RE.match(text.strip())
    if not m:
        raise CapsuleError("Format: <number><unit>, units s m h d w M y (e.g. 90s, 2h, 7d, 1y).")
    n, unit = int(m.group(1)), m.group(2)
    if n == 0:
        raise CapsuleError("Zero seconds is just a message.")
    seconds = n * UNITS[unit]
    if seconds > 10 * 31_536_000:
        raise CapsuleError("Max 10 years. drand is sturdy, but let's be reasonable.")
    tle_dur = f"{n * 7}d" if unit == "w" else f"{n}{unit}"
    return seconds, tle_dur


def _base_args() -> list[str]:
    args = [TLE]
    if NETWORK:
        args += ["-n", NETWORK]
    if CHAIN:
        args += ["-c", CHAIN]
    return args


async def _run(args: list[str], data: bytes, timeout: float = 60) -> bytes:
    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)
    except FileNotFoundError as exc:
        raise CapsuleError("`tle` isn't installed on the server.") from exc
    try:
        out, err = await asyncio.wait_for(proc.communicate(data), timeout)
    except asyncio.TimeoutError as exc:
        proc.kill()
        raise CapsuleError("drand network timed out.") from exc
    if proc.returncode != 0:
        msg = err.decode(errors="replace").strip()
        if "too early" in msg.lower():
            raise TooEarly(msg)
        raise CapsuleError(msg or f"tle exited with {proc.returncode}")
    return out


class TooEarly(CapsuleError):
    pass


async def seal(message: str, tle_duration: str) -> str:
    out = await _run(_base_args() + ["-e", "-a", "-D", tle_duration], message.encode())
    return out.decode()


async def unseal(armored: str) -> str:
    out = await _run(_base_args() + ["-d"], armored.encode())
    return out.decode("utf-8", errors="replace")


@dataclass
class Header:
    round: int | None
    chain: str | None


def parse_header(armored: str) -> Header:
    """Peek inside the age armor at the tlock stanza: '-> tlock <round> <chainhash>'."""
    try:
        body = "".join(line for line in armored.strip().splitlines() if not line.startswith("-----"))
        raw = base64.b64decode(body + "=" * (-len(body) % 4))
        m = re.search(rb"-> tlock (\d+) ([0-9a-f]{64})", raw)
        if m:
            return Header(int(m.group(1)), m.group(2).decode())
    except Exception:  # noqa: BLE001
        pass
    return Header(None, None)


def round_time(rnd: int) -> float:
    """Unix time of a quicknet round."""
    return QUICKNET_GENESIS + (rnd - 1) * QUICKNET_PERIOD


def current_round(now: float | None = None) -> int:
    now = time.time() if now is None else now
    return int((now - QUICKNET_GENESIS) // QUICKNET_PERIOD) + 1
