"""Shamir's Secret Sharing over GF(2^8), byte-wise (the same field AES uses).

A secret is split into n shares; any k reconstruct it, k-1 reveal nothing.
Before splitting we append 4 bytes of SHA-256(secret) so reconstruction is
verified, which catches wrong or mismatched shares instead of returning garbage.

Share string:  sss1-<setid>-<k>-<x>-<base32 data>-<crc>
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import zlib
from dataclasses import dataclass

# ---- GF(256) arithmetic, polynomial x^8 + x^4 + x^3 + x + 1 (0x11B), generator 3
EXP = [0] * 512
LOG = [0] * 256
_x = 1
for _i in range(255):
    EXP[_i] = _x
    LOG[_x] = _i
    _x ^= (_x << 1) ^ (0x11B if _x & 0x80 else 0)  # multiply by 3
    _x &= 0xFF
for _i in range(255, 512):
    EXP[_i] = EXP[_i - 255]


def gmul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return EXP[LOG[a] + LOG[b]]


def gdiv(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError
    if a == 0:
        return 0
    return EXP[(LOG[a] - LOG[b]) % 255]


class ShamirError(Exception):
    pass


@dataclass(frozen=True)
class Share:
    set_id: str
    k: int
    x: int
    data: bytes

    def encode(self) -> str:
        b32 = base64.b32encode(self.data).decode().rstrip("=").lower()
        core = f"sss1-{self.set_id}-{self.k}-{self.x}-{b32}"
        crc = f"{zlib.crc32(core.encode()) & 0xFFFF:04x}"
        return f"{core}-{crc}"

    @staticmethod
    def decode(text: str) -> "Share":
        text = "".join(text.split()).lower()
        parts = text.split("-")
        if len(parts) != 6 or parts[0] != "sss1":
            raise ShamirError("Not a NULLBYTE share (expected sss1-…).")
        core = "-".join(parts[:5])
        if f"{zlib.crc32(core.encode()) & 0xFFFF:04x}" != parts[5]:
            raise ShamirError("Checksum mismatch: a character is wrong or missing.")
        _, set_id, k, x, b32 = parts[:5]
        pad = "=" * (-len(b32) % 8)
        data = base64.b32decode(b32.upper() + pad)
        return Share(set_id, int(k), int(x), data)

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.encode().encode()).hexdigest()[:8]


def split(secret: bytes, k: int, n: int) -> list[Share]:
    if not (2 <= k <= n <= 16):
        raise ShamirError("Need 2 ≤ k ≤ n ≤ 16.")
    if not secret:
        raise ShamirError("Secret is empty.")
    if len(secret) > 1024:
        raise ShamirError("Secret too long (1 KB max).")
    payload = secret + hashlib.sha256(secret).digest()[:4]
    set_id = secrets.token_hex(3)
    ys = [bytearray() for _ in range(n)]
    for byte in payload:
        coeffs = [byte] + [secrets.randbelow(256) for _ in range(k - 1)]
        for i in range(n):
            x = i + 1
            acc = 0
            for c in reversed(coeffs):  # Horner
                acc = gmul(acc, x) ^ c
            ys[i].append(acc)
    return [Share(set_id, k, i + 1, bytes(ys[i])) for i in range(n)]


def combine(shares: list[Share]) -> bytes:
    if not shares:
        raise ShamirError("No shares.")
    set_ids = {s.set_id for s in shares}
    if len(set_ids) > 1:
        raise ShamirError("These shares come from different secrets.")
    k = shares[0].k
    uniq = {s.x: s for s in shares}
    if len(uniq) < k:
        raise ShamirError(f"Need {k} distinct shares, have {len(uniq)}.")
    use = list(uniq.values())[:k]
    length = len(use[0].data)
    if any(len(s.data) != length for s in use):
        raise ShamirError("Share lengths differ.")
    out = bytearray()
    for idx in range(length):
        acc = 0
        for j, sj in enumerate(use):
            num, den = 1, 1
            for m, sm in enumerate(use):
                if m != j:
                    num = gmul(num, sm.x)            # (0 - x_m) == x_m in GF(2^8)
                    den = gmul(den, sj.x ^ sm.x)
            acc ^= gmul(sj.data[idx], gdiv(num, den))
        out.append(acc)
    secret, check = bytes(out[:-4]), bytes(out[-4:])
    if hashlib.sha256(secret).digest()[:4] != check:
        raise ShamirError("Reconstruction failed integrity check (bad or tampered share).")
    return secret
