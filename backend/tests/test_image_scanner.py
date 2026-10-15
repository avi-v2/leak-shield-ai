"""
Automated unit tests for Image Detection and Privacy Scanner in Leak-Sheild-AI.
Verifies EXIF GPS leak detection, device metadata detection, embedded secret scanning,
image sanitization, and API endpoints.
"""

import io
import base64
from PIL import Image, PngImagePlugin
from app.security.image_scanner import scan_image_bytes, sanitize_image

def _create_clean_image_bytes() -> bytes:
    """Helper to generate a clean, unblemished PNG image in memory."""
    img = Image.new("RGB", (64, 64), color=(73, 109, 137))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()

def _create_png_with_secret_chunk() -> bytes:
    """Helper to generate a PNG with embedded secret token in text chunk."""
    img = Image.new("RGB", (64, 64), color=(255, 0, 0))
    target_info = PngImagePlugin.PngInfo()
    target_info.add_text("PromptConfig", "Authorization: Bearer sk-proj-1234567890123456789012345678901234567890")
    buf = io.BytesIO()
    img.save(buf, format="PNG", pnginfo=target_info)
    return buf.getvalue()

def _create_jpeg_with_exif_gps() -> bytes:
    """Helper to generate a JPEG with simulated EXIF GPS coordinates."""
    img = Image.new("RGB", (64, 64), color=(0, 255, 0))
    exif = img.getexif()
    # 0x8825 (34853) is GPSInfo
    # GPSLatitude: (37, 46, 29.8) -> 37.774944, GPSLongitude: (122, 25, 9.8) -> 122.419389
    gps_ifd = exif.get_ifd(0x8825)
    gps_ifd[1] = "N" # GPSLatitudeRef
    gps_ifd[2] = (37.0, 46.0, 29.8) # GPSLatitude
    gps_ifd[3] = "W" # GPSLongitudeRef
    gps_ifd[4] = (122.0, 25.0, 9.8) # GPSLongitude
    gps_ifd[6] = 15.0 # Altitude

    # Device tags
    exif[0x010F] = "Apple" # Make
    exif[0x0110] = "iPhone 15 Pro" # Model

    buf = io.BytesIO()
    img.save(buf, format="JPEG", exif=exif)
    return buf.getvalue()

def test_clean_image_scan():
    raw_bytes = _create_clean_image_bytes()
    resp = scan_image_bytes(raw_bytes, filename="clean_test.png")
    assert resp.action == "ALLOW"
    assert resp.risk_level == "low"
    assert len(resp.findings) == 0
    assert resp.metadata.width == 64
    assert resp.metadata.height == 64
    assert resp.sanitized_image_base64 is not None

def test_png_with_embedded_secret_detected():
    raw_bytes = _create_png_with_secret_chunk()
    resp = scan_image_bytes(raw_bytes, filename="leaky_prompt.png")
    assert resp.action == "BLOCK"
    assert resp.risk_level == "critical"
    # Should flag the embedded secret
    types = [f.type for f in resp.findings]
    assert any("CREDENTIAL" in t or "API_KEY" in t for t in types)

def test_jpeg_gps_leak_detected_and_sanitized():
    raw_bytes = _create_jpeg_with_exif_gps()
    resp = scan_image_bytes(raw_bytes, filename="vacation_photo.jpg")
    # GPS leak should be flagged
    types = [f.type for f in resp.findings]
    assert "RULE_IMAGE_EXIF_GPS_LEAK" in types
    assert resp.metadata.gps_coordinates is not None
    assert resp.metadata.gps_coordinates["latitude"] > 37.0
    assert resp.metadata.gps_coordinates["longitude"] < -122.0
    assert resp.action in ("REDACT", "BLOCK")
    assert resp.sanitized_image_base64 is not None
    assert resp.sanitized_image_base64.startswith("data:image/")

def test_empty_or_corrupt_image():
    resp_empty = scan_image_bytes(b"", filename="empty.png")
    assert resp_empty.action == "BLOCK"
    assert any(f.type == "RULE_IMAGE_EMPTY_PAYLOAD" for f in resp_empty.findings)

    resp_corrupt = scan_image_bytes(b"not_an_image_at_all_12345", filename="corrupt.png")
    assert resp_corrupt.action == "BLOCK"
    assert any("CORRUPT" in f.type or "INVALID" in f.type for f in resp_corrupt.findings)

def test_scan_image_api_endpoint(client):
    clean_bytes = _create_clean_image_bytes()
    b64_str = base64.b64encode(clean_bytes).decode("utf-8")

    # Test POST /scan/image JSON
    res = client.post("/scan/image", json={
        "image_base64": f"data:image/png;base64,{b64_str}",
        "filename": "clean_via_api.png"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["action"] == "ALLOW"
    assert "metadata" in data
    assert data["metadata"]["width"] == 64

def test_scan_image_upload_endpoint(client):
    clean_bytes = _create_clean_image_bytes()
    # Test POST /scan/image/upload multipart
    res = client.post(
        "/scan/image/upload",
        files={"file": ("upload_test.png", clean_bytes, "image/png")}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["action"] == "ALLOW"
    assert data["metadata"]["format"] == "PNG"
