import io, os, sys, wave, time
import numpy as np
import pytest
from PIL import Image
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from nullbyte import stego, shamir, exif_tools, capsule, ui


def photo(w=640, h=480, fmt="PNG", seed=1):
    rng = np.random.default_rng(seed)
    # smooth-ish natural image: gradients + noise
    y, x = np.mgrid[0:h, 0:w]
    base = np.stack([(x * 255 / w), (y * 255 / h), ((x + y) * 127 / (w + h))], -1)
    arr = np.clip(base + rng.normal(0, 6, base.shape), 0, 255).astype(np.uint8)
    buf = io.BytesIO(); Image.fromarray(arr).save(buf, fmt); return buf.getvalue()


def wav(seconds=2, rate=44100):
    t = np.arange(seconds * rate) / rate
    s = (np.sin(2 * np.pi * 440 * t) * 8000 + np.random.default_rng(0).normal(0, 200, t.size)).astype("<i2")
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(rate); w.writeframes(s.tobytes())
    return buf.getvalue()


def test_image_roundtrip():
    msg = "the eagle lands at 0300 🦅 " * 20
    r = stego.hide(photo(), "a.png", msg, "hunter2")
    assert r.ext == "png" and r.psnr > 60
    out = stego.reveal(r.file, "x.png", "hunter2")
    assert out.message == msg


def test_jpeg_cover_becomes_png():
    r = stego.hide(photo(fmt="JPEG"), "a.jpg", "hi", "pw")
    assert r.ext == "png"
    assert stego.reveal(r.file, "a.png", "pw").message == "hi"


def test_wrong_pass():
    r = stego.hide(photo(), "a.png", "secret", "right")
    with pytest.raises(stego.WrongKey):
        stego.reveal(r.file, "a.png", "wrong")


def test_clean_image_has_no_message():
    with pytest.raises(stego.WrongKey):
        stego.reveal(photo(), "a.png", "anything")


def test_rgba_alpha_preserved():
    arr = np.zeros((100, 100, 4), np.uint8); arr[..., 3] = 128; arr[..., 0] = np.arange(100)
    buf = io.BytesIO(); Image.fromarray(arr, "RGBA").save(buf, "PNG")
    r = stego.hide(buf.getvalue(), "a.png", "alpha!", "k")
    img = Image.open(io.BytesIO(r.file)); assert img.mode == "RGBA"
    assert np.all(np.array(img)[..., 3] == 128)
    assert stego.reveal(r.file, "a.png", "k").message == "alpha!"


def test_wav_roundtrip():
    r = stego.hide(wav(), "a.wav", "audio secret", "pw")
    assert r.ext == "wav"
    assert stego.reveal(r.file, "a.wav", "pw").message == "audio secret"


def test_too_big():
    with pytest.raises(stego.StegoError):
        stego.hide(photo(40, 40), "a.png", os.urandom(4000).hex(), "pw")


def test_chi_square_detects_full_lsb_replacement():
    clean = photo(512, 512)
    a_clean = stego.analyze(clean, "c.png")
    arr = np.array(Image.open(io.BytesIO(clean)))
    rng = np.random.default_rng(5)
    arr = (arr & 0xFE) | rng.integers(0, 2, arr.shape, dtype=np.uint8)
    buf = io.BytesIO(); Image.fromarray(arr).save(buf, "PNG")
    a_dirty = stego.analyze(buf.getvalue(), "d.png")
    print("clean p", a_clean.p_overall, "dirty p", a_dirty.p_overall)
    assert a_dirty.p_overall > 0.9
    assert a_clean.p_overall < a_dirty.p_overall
    assert a_dirty.lsb_plane_png[:4] == b"\x89PNG"


def test_trailing_zip_detected():
    data = photo(fmt="JPEG") + b"PK\x03\x04" + os.urandom(200)
    a = stego.analyze(data, "x.jpg")
    assert len(a.trailing) == 204 and a.trailing_sig.startswith("ZIP")
    assert a.verdict[0] == "🚨"
    png = photo() + b"hidden text after iend"
    assert stego.find_trailing(png) == b"hidden text after iend"


def test_shamir_all_subsets():
    import itertools
    secret = "correct horse battery staple ✓".encode()
    shares = shamir.split(secret, 3, 5)
    encoded = [s.encode() for s in shares]
    decoded = [shamir.Share.decode(e) for e in encoded]
    for combo in itertools.combinations(decoded, 3):
        assert shamir.combine(list(combo)) == secret
    with pytest.raises(shamir.ShamirError):
        shamir.combine(decoded[:2])


def test_shamir_typo_and_mix():
    s = shamir.split(b"abc", 2, 3)
    bad = s[0].encode()
    bad = bad[:12] + ("a" if bad[12] != "a" else "b") + bad[13:]
    with pytest.raises(shamir.ShamirError):
        shamir.Share.decode(bad)
    other = shamir.split(b"xyz", 2, 3)
    with pytest.raises(shamir.ShamirError):
        shamir.combine([s[0], other[1]])


def test_exif_gps_and_scrub():
    import piexif
    img = Image.fromarray(np.full((200, 300, 3), 120, np.uint8))
    exif = {
        "0th": {piexif.ImageIFD.Make: b"Apple", piexif.ImageIFD.Model: b"iPhone 16 Pro",
                piexif.ImageIFD.Software: b"18.1", piexif.ImageIFD.Orientation: 6},
        "Exif": {piexif.ExifIFD.DateTimeOriginal: b"2026:11:20 21:14:05",
                 piexif.ExifIFD.BodySerialNumber: b"C02XK1ZZJGH5",
                 piexif.ExifIFD.FNumber: (178, 100), piexif.ExifIFD.ExposureTime: (1, 120)},
        "GPS": {piexif.GPSIFD.GPSLatitudeRef: b"N", piexif.GPSIFD.GPSLatitude: ((41, 1), (1, 1), (2280, 100)),
                piexif.GPSIFD.GPSLongitudeRef: b"E", piexif.GPSIFD.GPSLongitude: ((28, 1), (58, 1), (4080, 100)),
                piexif.GPSIFD.GPSImgDirection: (9000, 100)},
    }
    buf = io.BytesIO(); img.save(buf, "JPEG", exif=piexif.dump(exif)); data = buf.getvalue()
    leak = exif_tools.inspect(data)
    assert leak.model == "iPhone 16 Pro" and leak.make == "Apple"
    assert abs(leak.lat - 41.0230) < 1e-3 and abs(leak.lon - 28.9780) < 1e-3
    assert any(k == "BodySerialNumber" for k, _, _ in leak.spicy)
    assert leak.threat_score >= 60
    assert "→" in exif_tools.heading_arrow(leak.heading)
    clean, ext = exif_tools.scrub(data)
    c = exif_tools.inspect(clean)
    assert not c.has_gps and c.model is None and c.tag_count == 0
    assert Image.open(io.BytesIO(clean)).size == (200, 300)  # orientation baked in


def test_capsule_durations_and_rounds():
    assert capsule.parse_duration("2h") == (7200, "2h")
    assert capsule.parse_duration("2w") == (1209600, "14d")
    with pytest.raises(capsule.CapsuleError):
        capsule.parse_duration("soon")
    r = capsule.current_round(capsule.QUICKNET_GENESIS + 30)
    assert r == 11 and capsule.round_time(r) == capsule.QUICKNET_GENESIS + 30


def test_ui_helpers():
    assert ui.bar(0.5, 10) == "█████░░░░░"
    assert ui.flag("TR") == "🇹🇷"
    assert "0000" in ui.hexdump(b"hello world")
    assert 7.9 < ui.entropy(os.urandom(4096)) <= 8
    assert ui.box("T", ["x"]).startswith("<pre>")
