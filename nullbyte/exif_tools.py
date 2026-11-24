"""Photo metadata forensics: what a picture leaks, and a scrubbed copy."""
from __future__ import annotations

import io
from dataclasses import dataclass, field
from datetime import datetime

from PIL import ExifTags, Image, ImageOps

try:  # iPhone HEIC support, optional
    from pillow_heif import register_heif_opener

    register_heif_opener()
    HEIF = True
except Exception:  # noqa: BLE001
    HEIF = False

try:
    import piexif
except Exception:  # noqa: BLE001
    piexif = None

EXIF_IFD = 0x8769
GPS_IFD = 0x8825

# Tags worth shouting about, with a "why it matters" note.
SPICY = {
    "BodySerialNumber": "camera serial: links every photo you take",
    "LensSerialNumber": "lens serial: same, for the lens",
    "CameraOwnerName": "literally your name",
    "Artist": "author field",
    "Copyright": "author/copyright field",
    "ImageUniqueID": "unique ID, can match copies",
    "HostComputer": "the computer/phone model that edited it",
    "Software": "editing app or OS version",
}


@dataclass
class Leak:
    make: str | None = None
    model: str | None = None
    lens: str | None = None
    software: str | None = None
    taken: str | None = None
    tz_offset: str | None = None
    lat: float | None = None
    lon: float | None = None
    alt: float | None = None
    heading: float | None = None
    speed: float | None = None
    width: int = 0
    height: int = 0
    fmt: str = ""
    settings: str | None = None
    spicy: list[tuple[str, str, str]] = field(default_factory=list)
    has_xmp: bool = False
    has_icc: bool = False
    has_iptc: bool = False
    thumbnail: bytes | None = None
    tag_count: int = 0
    raw: dict[str, str] = field(default_factory=dict)

    @property
    def has_gps(self) -> bool:
        return self.lat is not None and self.lon is not None

    @property
    def threat_score(self) -> int:
        """0-100, a playful 'how doxxable is this photo'."""
        score = 0
        score += 45 if self.has_gps else 0
        score += 10 if self.taken else 0
        score += 8 if self.model else 0
        score += 6 if self.software else 0
        score += 7 * min(3, len(self.spicy))
        score += 6 if self.thumbnail else 0
        score += 4 if self.has_xmp else 0
        return min(100, score)

    @property
    def maps_url(self) -> str | None:
        if not self.has_gps:
            return None
        return f"https://www.openstreetmap.org/?mlat={self.lat:.6f}&mlon={self.lon:.6f}#map=17/{self.lat:.6f}/{self.lon:.6f}"


def _rat(v) -> float:
    try:
        return float(v)
    except Exception:  # noqa: BLE001
        num, den = v
        return num / den if den else 0.0


def _dms(values, ref) -> float | None:
    try:
        d, m, s = (_rat(x) for x in values)
    except Exception:  # noqa: BLE001
        return None
    deg = d + m / 60 + s / 3600
    if ref in ("S", "W", b"S", b"W"):
        deg = -deg
    return deg


def _clean(v) -> str:
    if isinstance(v, bytes):
        v = v.rstrip(b"\x00").decode("utf-8", errors="replace")
    return str(v).strip()


def inspect(data: bytes) -> Leak:
    img = Image.open(io.BytesIO(data))
    leak = Leak(width=img.width, height=img.height, fmt=img.format or "?")
    exif = img.getexif()
    leak.has_icc = bool(img.info.get("icc_profile"))
    leak.has_xmp = bool(img.info.get("xmp") or img.info.get("XML:com.adobe.xmp")) or b"http://ns.adobe.com/xap" in data[:200_000]
    leak.has_iptc = b"Photoshop 3.0" in data[:200_000]

    flat: dict[str, object] = {}
    for tag, val in exif.items():
        flat[ExifTags.TAGS.get(tag, hex(tag))] = val
    try:
        for tag, val in exif.get_ifd(EXIF_IFD).items():
            flat[ExifTags.TAGS.get(tag, hex(tag))] = val
    except Exception:  # noqa: BLE001
        pass
    gps: dict[str, object] = {}
    try:
        for tag, val in exif.get_ifd(GPS_IFD).items():
            gps[ExifTags.GPSTAGS.get(tag, hex(tag))] = val
    except Exception:  # noqa: BLE001
        pass

    leak.tag_count = len(flat) + len(gps)
    leak.make = _clean(flat["Make"]) if "Make" in flat else None
    leak.model = _clean(flat["Model"]) if "Model" in flat else None
    leak.lens = _clean(flat["LensModel"]) if "LensModel" in flat else None
    leak.software = _clean(flat["Software"]) if "Software" in flat else None
    for key in ("DateTimeOriginal", "DateTimeDigitized", "DateTime"):
        if key in flat:
            leak.taken = _clean(flat[key])
            break
    for key in ("OffsetTimeOriginal", "OffsetTime"):
        if key in flat:
            leak.tz_offset = _clean(flat[key])
            break

    parts = []
    if "FNumber" in flat:
        parts.append(f"f/{_rat(flat['FNumber']):.1f}")
    if "ExposureTime" in flat:
        et = _rat(flat["ExposureTime"])
        parts.append(f"1/{round(1 / et)}s" if 0 < et < 1 else f"{et:g}s")
    if "ISOSpeedRatings" in flat:
        parts.append(f"ISO{_clean(flat['ISOSpeedRatings'])}")
    if "FocalLength" in flat:
        parts.append(f"{_rat(flat['FocalLength']):.1f}mm")
    leak.settings = " ".join(parts) or None

    for key, why in SPICY.items():
        if key in flat and _clean(flat[key]) and key != "Software":
            leak.spicy.append((key, _clean(flat[key]), why))

    if "GPSLatitude" in gps and "GPSLongitude" in gps:
        leak.lat = _dms(gps["GPSLatitude"], gps.get("GPSLatitudeRef", "N"))
        leak.lon = _dms(gps["GPSLongitude"], gps.get("GPSLongitudeRef", "E"))
        if leak.lat == 0 and leak.lon == 0:
            leak.lat = leak.lon = None
    if "GPSAltitude" in gps:
        alt = _rat(gps["GPSAltitude"])
        leak.alt = -alt if gps.get("GPSAltitudeRef") in (1, b"\x01") else alt
    if "GPSImgDirection" in gps:
        leak.heading = _rat(gps["GPSImgDirection"])
    if "GPSSpeed" in gps:
        leak.speed = _rat(gps["GPSSpeed"])

    for k, v in list(flat.items())[:60]:
        s = _clean(v)
        if s and len(s) < 80 and not k.startswith("0x") and k not in ("MakerNote", "UserComment"):
            leak.raw[k] = s

    if piexif is not None and leak.fmt == "JPEG":
        try:
            thumb = piexif.load(data).get("thumbnail")
            if thumb and len(thumb) > 200:
                leak.thumbnail = thumb
        except Exception:  # noqa: BLE001
            pass
    return leak


def taken_age(taken: str | None) -> str | None:
    if not taken:
        return None
    try:
        dt = datetime.strptime(taken[:19], "%Y:%m:%d %H:%M:%S")
    except ValueError:
        return None
    days = (datetime.now() - dt).days
    return dt.strftime("%a") + (f" · {days}d ago" if days >= 0 else "")


def heading_arrow(deg: float | None) -> str:
    if deg is None:
        return ""
    arrows = "↑↗→↘↓↙←↖"
    names = ["N", "NE", "E", "SE", "S", "SW", "W", "NW"]
    i = int(((deg % 360) + 22.5) // 45) % 8
    return f"{arrows[i]} {names[i]} ({deg:.0f}°)"


def scrub(data: bytes) -> tuple[bytes, str]:
    """Re-encode pixels only. Orientation is baked in so the photo still looks right."""
    img = Image.open(io.BytesIO(data))
    fmt = (img.format or "JPEG").upper()
    img = ImageOps.exif_transpose(img)
    buf = io.BytesIO()
    if fmt in ("PNG", "GIF", "BMP", "TIFF"):
        if img.mode not in ("RGB", "RGBA", "L", "LA"):
            img = img.convert("RGBA")
        clean = Image.new(img.mode, img.size)  # fresh image: no info dict, no chunks
        clean.paste(img)
        clean.save(buf, "PNG")
        return buf.getvalue(), "png"
    if img.mode not in ("RGB", "L"):
        img = img.convert("RGB")
    clean = Image.new(img.mode, img.size)
    clean.paste(img)
    clean.save(buf, "JPEG", quality=95, optimize=True, subsampling=0)
    return buf.getvalue(), "jpg"
