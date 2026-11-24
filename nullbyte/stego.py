"""LSB steganography with real crypto, plus steganalysis.

Embedding format (all bits live in the least-significant bit of a carrier array):

  positions 0..127            salt (16 bytes), sequential
  keyed-random positions      [len:u32][nonce:12][ciphertext+tag]

  key   = scrypt(passphrase, salt, N=2^15, r=8, p=1) -> 32 bytes
  cipher= AES-256-GCM over zlib(plaintext)
  scatter positions = PCG64 seeded from HMAC(key, "scatter"), deduplicated

Without the passphrase the payload bits are indistinguishable from noise and are
scattered across the whole carrier, so there is no magic header to grep for.
Carriers: PNG/BMP/TIFF/WebP-lossless images (RGB channels) and 16-bit PCM WAV.
"""
from __future__ import annotations

import hashlib
import hmac
import io
import math
import os
import struct
import wave
import zlib
from dataclasses import dataclass, field

import numpy as np
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PIL import Image

SALT_LEN = 16
NONCE_LEN = 12
SALT_BITS = SALT_LEN * 8
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15, 8, 1


class StegoError(Exception):
    """User-facing error with a readable message."""


class WrongKey(StegoError):
    pass


# --------------------------------------------------------------------------- carriers


@dataclass
class Carrier:
    kind: str                     # "image" or "audio"
    flat: np.ndarray              # writable 1-D view of LSB-able samples
    meta: dict = field(default_factory=dict)

    @property
    def capacity_bits(self) -> int:
        return int(self.flat.size)


def load_carrier(data: bytes, filename: str = "") -> Carrier:
    name = filename.lower()
    if name.endswith(".wav") or data[:4] == b"RIFF" and data[8:12] == b"WAVE":
        return _load_wav(data)
    return _load_image(data)


def _load_image(data: bytes) -> Carrier:
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
    except Exception as exc:  # noqa: BLE001
        raise StegoError("That doesn't parse as an image or a WAV file.") from exc
    fmt = (img.format or "").upper()
    has_alpha = img.mode in ("RGBA", "LA") or (img.mode == "P" and "transparency" in img.info)
    rgba = img.convert("RGBA") if has_alpha else img.convert("RGB")
    arr = np.array(rgba, dtype=np.uint8)
    rgb = arr[..., :3].copy()
    alpha = arr[..., 3].copy() if has_alpha else None
    return Carrier("image", rgb.reshape(-1), {"shape": rgb.shape, "alpha": alpha, "format": fmt})


def _load_wav(data: bytes) -> Carrier:
    try:
        with wave.open(io.BytesIO(data)) as w:
            params = w.getparams()
            frames = w.readframes(params.nframes)
    except Exception as exc:  # noqa: BLE001
        raise StegoError("Couldn't read that WAV. It needs to be uncompressed PCM.") from exc
    if params.sampwidth != 2:
        raise StegoError("Only 16-bit PCM WAV is supported as an audio carrier.")
    samples = np.frombuffer(frames, dtype="<i2").copy()
    return Carrier("audio", samples, {"params": params})


def save_carrier(c: Carrier) -> tuple[bytes, str]:
    """Returns (file bytes, extension)."""
    if c.kind == "audio":
        buf = io.BytesIO()
        with wave.open(buf, "wb") as w:
            w.setparams(c.meta["params"])
            w.writeframes(c.flat.astype("<i2").tobytes())
        return buf.getvalue(), "wav"
    rgb = c.flat.reshape(c.meta["shape"])
    alpha = c.meta.get("alpha")
    if alpha is not None:
        img = Image.fromarray(np.dstack([rgb, alpha]), "RGBA")
    else:
        img = Image.fromarray(rgb, "RGB")
    buf = io.BytesIO()
    img.save(buf, "PNG", optimize=False, compress_level=6)
    return buf.getvalue(), "png"


# --------------------------------------------------------------------------- crypto + bits


def derive_key(passphrase: str, salt: bytes) -> bytes:
    return hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R,
                          p=SCRYPT_P, maxmem=128 * 1024 * 1024, dklen=32)


def _bits(data: bytes) -> np.ndarray:
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))


def _bytes(bits: np.ndarray) -> bytes:
    return np.packbits(bits.astype(np.uint8)).tobytes()


def _scatter(key: bytes, total: int, count: int) -> np.ndarray:
    """`count` distinct pseudo-random positions in [SALT_BITS, total).

    Drawn in fixed-size blocks so that asking for more positions always extends,
    never reshuffles, the sequence; extraction can read the length prefix first.
    """
    space = total - SALT_BITS
    if count > space:
        raise StegoError("Payload doesn't fit in this carrier.")
    seed = int.from_bytes(hmac.new(key, b"scatter", hashlib.sha256).digest()[:16], "big")
    rng = np.random.Generator(np.random.PCG64(seed))
    out: list[np.ndarray] = []
    seen: set[int] = set()
    have = 0
    block = 1 << 16
    while have < count:
        cand = rng.integers(0, space, size=block)
        fresh = []
        for v in cand.tolist():
            if v not in seen:
                seen.add(v)
                fresh.append(v)
                have += 1
                if have == count:
                    break
        out.append(np.array(fresh, dtype=np.int64))
    return np.concatenate(out) + SALT_BITS


MAX_PAYLOAD = 64 * 1024  # bytes of ciphertext; text secrets, not movies


def capacity_bytes(c: Carrier) -> int:
    # Use at most a quarter of the LSBs: keeps statistics quiet and scatter fast.
    usable = (c.capacity_bits - SALT_BITS) // 4 - 32 - (NONCE_LEN + 16) * 8
    return max(0, min(usable // 8, MAX_PAYLOAD))


@dataclass
class HideReport:
    file: bytes
    ext: str
    payload_bytes: int
    capacity: int
    changed_bits: int
    carrier_kind: str
    psnr: float | None


def hide(carrier_bytes: bytes, filename: str, message: str, passphrase: str) -> HideReport:
    if not passphrase:
        raise StegoError("Passphrase can't be empty.")
    c = load_carrier(carrier_bytes, filename)
    original = c.flat.copy()

    salt = os.urandom(SALT_LEN)
    key = derive_key(passphrase, salt)
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, zlib.compress(message.encode("utf-8"), 9), b"nullbyte-v1")
    body = struct.pack(">I", len(ct)) + nonce + ct

    cap = capacity_bytes(c)
    if len(ct) > cap:
        raise StegoError(f"Message too big: needs {len(ct)} B, carrier holds ~{cap} B.")

    salt_bits = _bits(salt)
    body_bits = _bits(body)
    pos = _scatter(key, c.capacity_bits, body_bits.size)

    flat = c.flat
    if c.kind == "audio":
        u = flat.view(np.uint16)
        u[:SALT_BITS] = (u[:SALT_BITS] & 0xFFFE) | salt_bits
        u[pos] = (u[pos] & 0xFFFE) | body_bits
    else:
        flat[:SALT_BITS] = (flat[:SALT_BITS] & 0xFE) | salt_bits
        flat[pos] = (flat[pos] & 0xFE) | body_bits

    changed = int(np.count_nonzero(original != c.flat))
    psnr = None
    if c.kind == "image":
        mse = np.mean((original.astype(np.float64) - c.flat.astype(np.float64)) ** 2)
        psnr = float("inf") if mse == 0 else 10 * math.log10(255**2 / mse)
    data, ext = save_carrier(c)
    return HideReport(data, ext, len(ct), cap, changed, c.kind, psnr)


@dataclass
class RevealReport:
    message: str
    payload_bytes: int
    carrier_kind: str
    salt: bytes


def reveal(carrier_bytes: bytes, filename: str, passphrase: str) -> RevealReport:
    c = load_carrier(carrier_bytes, filename)
    lsb = (c.flat.view(np.uint16) if c.kind == "audio" else c.flat) & 1
    if lsb.size < SALT_BITS + 32:
        raise WrongKey("Nothing here (carrier too small).")
    salt = _bytes(lsb[:SALT_BITS])
    key = derive_key(passphrase, salt)

    head = _scatter(key, c.capacity_bits, 32)
    (length,) = struct.unpack(">I", _bytes(lsb[head]))
    if length == 0 or length > capacity_bytes(c) + 16:
        raise WrongKey("ACCESS DENIED")
    total_bits = (4 + NONCE_LEN + length) * 8
    pos = _scatter(key, c.capacity_bits, total_bits)
    body = _bytes(lsb[pos])
    nonce, ct = body[4 : 4 + NONCE_LEN], body[4 + NONCE_LEN :]
    try:
        plain = zlib.decompress(AESGCM(key).decrypt(nonce, ct, b"nullbyte-v1"))
    except (InvalidTag, zlib.error) as exc:
        raise WrongKey("ACCESS DENIED") from exc
    return RevealReport(plain.decode("utf-8", errors="replace"), length, c.kind, salt)


# --------------------------------------------------------------------------- steganalysis


def _gammq(a: float, x: float) -> float:
    """Regularized upper incomplete gamma Q(a, x) (Numerical Recipes)."""
    if x <= 0:
        return 1.0
    gln = math.lgamma(a)
    if x < a + 1:  # series for P, return 1-P
        ap, s = a, 1.0 / a
        d = s
        for _ in range(1000):
            ap += 1
            d *= x / ap
            s += d
            if abs(d) < abs(s) * 1e-12:
                break
        return max(0.0, 1.0 - s * math.exp(-x + a * math.log(x) - gln))
    b = x + 1 - a  # continued fraction for Q
    c = 1 / 1e-300
    d = 1 / b
    h = d
    for i in range(1, 1000):
        an = -i * (i - a)
        b += 2
        d = an * d + b
        d = 1e-300 if abs(d) < 1e-300 else d
        c = b + an / c
        c = 1e-300 if abs(c) < 1e-300 else c
        d = 1 / d
        delta = d * c
        h *= delta
        if abs(delta - 1) < 1e-12:
            break
    return min(1.0, math.exp(-x + a * math.log(x) - gln) * h)


def chi_square_p(values: np.ndarray) -> float:
    """Westfeld-Pfitzmann chi-square attack. Returns the probability of embedding.

    LSB replacement equalises the counts of each pair of values (2k, 2k+1).
    High p means the pairs look suspiciously equal.
    """
    hist = np.bincount(values.astype(np.int64), minlength=256)[:256].astype(np.float64)
    even, odd = hist[0::2], hist[1::2]
    expected = (even + odd) / 2
    mask = expected > 4
    if mask.sum() < 2:
        return 0.0
    chi = float(np.sum((even[mask] - expected[mask]) ** 2 / expected[mask]))
    dof = int(mask.sum()) - 1
    return _gammq(dof / 2, chi / 2)


@dataclass
class Analysis:
    kind: str
    p_overall: float
    p_channels: dict[str, float]
    curve: list[float]
    lsb_ones_ratio: float
    trailing: bytes
    trailing_sig: str | None
    lsb_plane_png: bytes | None
    width: int = 0
    height: int = 0
    fmt: str = ""

    @property
    def verdict(self) -> tuple[str, str]:
        if self.trailing and len(self.trailing) > 16:
            return "🚨", "DATA HIDDEN AFTER EOF"
        p = self.p_overall
        if p > 0.95:
            return "🚨", "LSB EMBEDDING LIKELY"
        if p > 0.6:
            return "⚠️", "SUSPICIOUS LSB STATS"
        if p > 0.2:
            return "🤔", "INCONCLUSIVE"
        return "✅", "LOOKS CLEAN"


SIGNATURES = [
    (b"PK\x03\x04", "ZIP archive"), (b"Rar!", "RAR archive"), (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"%PDF", "PDF document"), (b"\x89PNG", "PNG image"), (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF8", "GIF image"), (b"\x1f\x8b", "gzip stream"), (b"-----BEGIN", "PEM/armored text"),
    (b"age-encryption", "age-encrypted file"), (b"MZ", "Windows executable"), (b"\x7fELF", "ELF executable"),
]


def find_trailing(data: bytes) -> bytes:
    """Bytes after the official end of a PNG (IEND) or JPEG (last EOI)."""
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        i = data.rfind(b"IEND")
        if i != -1:
            return data[i + 8 :]  # 4 type + 4 CRC
    if data[:2] == b"\xff\xd8":
        # Walk segments to the start of scan, then find the EOI after entropy-coded data.
        i = 2
        while i + 4 <= len(data):
            if data[i] != 0xFF:
                break
            marker = data[i + 1]
            if marker == 0xDA:  # SOS: find EOI not preceded by stuffing
                j = data.find(b"\xff\xd9", i)
                return data[j + 2 :] if j != -1 else b""
            seg_len = struct.unpack(">H", data[i + 2 : i + 4])[0]
            i += 2 + seg_len
    return b""


def identify(blob: bytes) -> str | None:
    head = blob[:64]
    for sig, name in SIGNATURES:
        idx = head.find(sig)
        if idx != -1:
            return name if idx == 0 else f"{name} (at +{idx})"
    return None


def analyze(data: bytes, filename: str = "") -> Analysis:
    trailing = find_trailing(data)
    c = load_carrier(data, filename)
    if c.kind == "audio":
        samples = c.flat.view(np.uint16)
        vals = (samples & 0xFF).astype(np.uint8)
        p = chi_square_p(vals)
        curve = _curve(vals)
        ones = float(np.mean(samples & 1))
        return Analysis("audio", p, {"PCM": p}, curve, ones, trailing, identify(trailing), None)

    rgb = c.flat.reshape(c.meta["shape"])
    h, w, _ = rgb.shape
    chans = {"R": rgb[..., 0].ravel(), "G": rgb[..., 1].ravel(), "B": rgb[..., 2].ravel()}
    p_ch = {k: chi_square_p(v) for k, v in chans.items()}
    p_all = float(np.mean(list(p_ch.values())))
    curve = _curve(c.flat)
    ones = float(np.mean(c.flat & 1))

    plane = ((rgb & 1) * 255).astype(np.uint8)
    img = Image.fromarray(plane, "RGB")
    if max(img.size) > 1280:
        img.thumbnail((1280, 1280), Image.NEAREST)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return Analysis("image", p_all, p_ch, curve, ones, trailing, identify(trailing), buf.getvalue(),
                    w, h, c.meta.get("format", ""))


def _curve(values: np.ndarray, steps: int = 20) -> list[float]:
    """Chi-square p over growing prefixes (catches sequential embedding)."""
    n = values.size
    out = []
    for i in range(1, steps + 1):
        sl = values[: max(512, n * i // steps)]
        out.append(chi_square_p(sl))
    return out
