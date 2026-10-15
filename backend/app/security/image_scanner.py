"""
Image Privacy and Sensitive Data Detection Engine for Leak-Sheild-AI.

Inspects images uploaded or passed to multimodal AI gateways:
1. Detects EXIF GPS location leaks (latitude/longitude coordinates revealing physical location).
2. Detects camera, device serials, and user fingerprinting metadata in EXIF headers.
3. Inspects embedded comments, PNG chunks (tEXt, iTXt), and prompts for secrets/credentials using regex engine.
4. Generates sanitized / redacted images by stripping all private metadata and EXIF tags.
"""

import io
import re
import base64
import uuid
from typing import Dict, Any, List, Optional, Tuple
from PIL import Image, ExifTags
from app.schemas import Finding, ImageMetadata, ImageScanResponse
from app.security.sensitive_data import scan_sensitive_data

def _get_exif_dict(img: Image.Image) -> Dict[str, Any]:
    """Safely extract readable EXIF key-value dictionary from Pillow Image."""
    exif_data = {}
    try:
        raw_exif = img.getexif()
        if raw_exif:
            for tag_id, value in raw_exif.items():
                tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                exif_data[tag_name] = value

            # Also check IFD for GPSInfo
            try:
                # In modern Pillow, GPSInfo is often in IFD
                gps_ifd = raw_exif.get_ifd(ExifTags.IFD.GPSInfo)
                if gps_ifd:
                    gps_data = {}
                    for k, v in gps_ifd.items():
                        sub_tag = ExifTags.GPSTAGS.get(k, str(k))
                        gps_data[sub_tag] = v
                    exif_data["GPSInfo"] = gps_data
            except Exception:
                pass
    except Exception:
        pass

    # Check legacy _getexif() if available
    if "GPSInfo" not in exif_data and hasattr(img, "_getexif"):
        try:
            legacy_exif = img._getexif()
            if legacy_exif:
                for tag_id, value in legacy_exif.items():
                    tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                    if tag_name == "GPSInfo" and isinstance(value, dict):
                        gps_data = {}
                        for k, v in value.items():
                            sub_tag = ExifTags.GPSTAGS.get(k, str(k))
                            gps_data[sub_tag] = v
                        exif_data["GPSInfo"] = gps_data
                    elif tag_name not in exif_data:
                        exif_data[tag_name] = value
        except Exception:
            pass

    return exif_data

def _convert_to_degrees(value: Any) -> Optional[float]:
    """Helper to convert GPS degree/minute/second tuples to decimal degrees."""
    try:
        if isinstance(value, (int, float)):
            return float(value)
        if hasattr(value, "__len__") and len(value) >= 3:
            d = float(value[0])
            m = float(value[1])
            s = float(value[2])
            return d + (m / 60.0) + (s / 3600.0)
    except Exception:
        return None
    return None

def _extract_gps_info(gps_dict: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Parse GPSInfo tag dictionary to extract decimal latitude and longitude."""
    if not isinstance(gps_dict, dict):
        return None

    lat_raw = gps_dict.get("GPSLatitude")
    lat_ref = gps_dict.get("GPSLatitudeRef", "N")
    lon_raw = gps_dict.get("GPSLongitude")
    lon_ref = gps_dict.get("GPSLongitudeRef", "E")
    altitude = gps_dict.get("GPSAltitude")

    if lat_raw is None or lon_raw is None:
        return None

    lat = _convert_to_degrees(lat_raw)
    lon = _convert_to_degrees(lon_raw)

    if lat is None or lon is None:
        return None

    if str(lat_ref).strip().upper() == "S":
        lat = -lat
    if str(lon_ref).strip().upper() == "W":
        lon = -lon

    alt_float = None
    if altitude is not None:
        try:
            alt_float = float(altitude)
        except Exception:
            pass

    return {
        "latitude": round(lat, 6),
        "longitude": round(lon, 6),
        "altitude_meters": alt_float,
        "lat_ref": str(lat_ref),
        "lon_ref": str(lon_ref),
        "formatted": f"Lat {round(lat, 5)}°, Lon {round(lon, 5)}°"
    }

def sanitize_image(img: Image.Image, output_format: str = "PNG") -> str:
    """
    Produce a clean, sanitized image by stripping all EXIF tags, GPS metadata,
    and comment chunks. Returns a clean base64 data URI.
    """
    # Create fresh image with raw RGB/RGBA pixels, completely devoid of EXIF
    mode = "RGBA" if img.mode in ("RGBA", "LA") or (img.mode == "P" and "transparency" in img.info) else "RGB"
    clean_img = Image.new(mode, img.size)
    
    # If source is RGBA or palette, convert safely
    converted = img.convert(mode)
    clean_img.paste(converted)

    buffer = io.BytesIO()
    # Save without metadata or exif
    fmt = "PNG" if output_format.upper() in ("PNG", "WEBP") else "JPEG"
    clean_img.save(buffer, format=fmt)
    buffer.seek(0)
    
    encoded = base64.b64encode(buffer.getvalue()).decode("utf-8")
    mime = "image/png" if fmt == "PNG" else "image/jpeg"
    return f"data:{mime};base64,{encoded}"

def scan_image_bytes(
    image_bytes: bytes,
    filename: str = "image.png",
    request_id: Optional[str] = None
) -> ImageScanResponse:
    """
    Main scanner function: Inspects image bytes for sensitive data, EXIF leaks,
    and metadata risks.
    """
    req_id = request_id or f"img_{uuid.uuid4().hex[:8]}"
    file_size = len(image_bytes)

    if not image_bytes:
        return ImageScanResponse(
            request_id=req_id,
            action="BLOCK",
            risk_level="critical",
            findings=[
                Finding(
                    type="RULE_IMAGE_EMPTY_PAYLOAD",
                    category="Malformed Payload",
                    description="Empty image payload received by security gateway.",
                    severity="high",
                    match_preview="0 bytes"
                )
            ],
            metadata=ImageMetadata(file_size_bytes=0),
            recommendation="Reject empty image submission.",
            sanitized_image_base64=None,
            scanned_at="now",
            explanation="The uploaded image contains 0 bytes."
        )

    try:
        img = Image.open(io.BytesIO(image_bytes))
        img.load()
    except Exception as e:
        return ImageScanResponse(
            request_id=req_id,
            action="BLOCK",
            risk_level="critical",
            findings=[
                Finding(
                    type="RULE_IMAGE_CORRUPTED_OR_INVALID",
                    category="Malformed Image",
                    description=f"Image could not be parsed or decoded: {str(e)}",
                    severity="high",
                    match_preview=str(e)[:80]
                )
            ],
            metadata=ImageMetadata(file_size_bytes=file_size),
            recommendation="Block unparseable image file to prevent gateway crash or exploit.",
            sanitized_image_base64=None,
            scanned_at="now",
            explanation=f"Malformed or unsupported image format: {str(e)}"
        )

    findings: List[Finding] = []
    exif_data = _get_exif_dict(img)
    has_exif = bool(exif_data)

    gps_coords = None
    device_info = {}

    # 1. Inspect GPS Metadata
    if "GPSInfo" in exif_data:
        gps_parsed = _extract_gps_info(exif_data["GPSInfo"])
        if gps_parsed:
            gps_coords = gps_parsed
            findings.append(Finding(
                type="RULE_IMAGE_EXIF_GPS_LEAK",
                category="Location Privacy Leak",
                description="Precise GPS coordinates detected in image EXIF headers, exposing physical location.",
                severity="high",
                match_preview=gps_parsed["formatted"]
            ))

    # 2. Inspect Device / Hardware Fingerprint Metadata
    device_fields = ["Make", "Model", "Software", "Artist", "Copyright", "CameraOwnerName", "BodySerialNumber"]
    for field in device_fields:
        if field in exif_data and exif_data[field]:
            val = str(exif_data[field]).strip()
            if val:
                device_info[field] = val

    if device_info:
        preview_text = ", ".join(f"{k}: {v}" for k, v in list(device_info.items())[:3])
        findings.append(Finding(
            type="RULE_IMAGE_DEVICE_METADATA",
            category="Hardware Fingerprinting",
            description="Hardware, camera model, or owner metadata detected in image headers.",
            severity="medium",
            match_preview=preview_text
        ))

    # 3. Inspect Embedded Text Chunks (PNG tEXt/iTXt, comments, AI generation parameters)
    extracted_text_blocks = []
    if hasattr(img, "info") and isinstance(img.info, dict):
        for k, v in img.info.items():
            if isinstance(v, str) and len(v.strip()) > 0:
                extracted_text_blocks.append(f"{k}: {v}")

    # Also scan text chunks in EXIF UserComment if any
    if "UserComment" in exif_data and isinstance(exif_data["UserComment"], (str, bytes)):
        try:
            uc = exif_data["UserComment"]
            if isinstance(uc, bytes):
                uc = uc.decode("utf-8", errors="ignore")
            if uc.strip():
                extracted_text_blocks.append(f"UserComment: {uc}")
        except Exception:
            pass

    # Run sensitive data regex engine over all extracted metadata text blocks
    for block in extracted_text_blocks:
        block_findings, _ = scan_sensitive_data(block)
        for f in block_findings:
            f_type = f.get("type", "UNKNOWN_TYPE")
            f_cat = f.get("category", "Sensitive Data")
            f_desc = f.get("description", "Exposed sensitive string")
            f_sev = f.get("severity", "medium")
            f_preview = f.get("match_preview")

            # Avoid duplicate rules
            if not any(existing.type == f"RULE_IMAGE_EMBEDDED_{f_type}" and existing.match_preview == f_preview for existing in findings):
                findings.append(Finding(
                    type=f"RULE_IMAGE_EMBEDDED_{f_type}",
                    category=f"Embedded {f_cat}",
                    description=f"Sensitive secret discovered inside image metadata/text chunk: {f_desc}",
                    severity=f_sev,
                    match_preview=f_preview
                ))

    # 4. Generate Sanitized Clean Image (Strip all EXIF and metadata)
    sanitized_b64 = None
    try:
        sanitized_b64 = sanitize_image(img, output_format=img.format or "PNG")
    except Exception:
        pass

    # 5. Evaluate Gateway Decision & Risk
    has_high_risk = any(f.severity in ("high", "critical") for f in findings)
    has_credential = any("CREDENTIAL" in f.type or "API_KEY" in f.type or "PASSWORD" in f.type for f in findings)

    if has_credential:
        action = "BLOCK"
        risk_level = "critical"
        rec = "Block image from being transmitted. Contained hardcoded secret or credential."
        explanation = "Image contains sensitive API keys or credentials embedded in metadata."
    elif has_high_risk or gps_coords is not None:
        action = "REDACT"
        risk_level = "high"
        rec = "Sanitize image metadata before transmitting to LLM or external service."
        explanation = "Image contains GPS location or hardware metadata. Sanitized version generated with stripped EXIF."
    elif findings:
        action = "REDACT"
        risk_level = "medium"
        rec = "Redact image headers and strip tracking metadata."
        explanation = "Minor metadata detected. Clean image produced."
    else:
        action = "ALLOW"
        risk_level = "low"
        rec = "Image is clean and safe for processing."
        explanation = "No EXIF leaks, GPS coordinates, or embedded secrets detected."

    from datetime import datetime, timezone
    now_iso = datetime.now(timezone.utc).isoformat()

    metadata = ImageMetadata(
        format=img.format,
        width=img.width,
        height=img.height,
        mode=img.mode,
        file_size_bytes=file_size,
        has_exif=has_exif,
        gps_coordinates=gps_coords,
        device_info=device_info if device_info else None
    )

    return ImageScanResponse(
        request_id=req_id,
        action=action,
        risk_level=risk_level,
        findings=findings,
        metadata=metadata,
        recommendation=rec,
        sanitized_image_base64=sanitized_b64,
        scanned_at=now_iso,
        explanation=explanation
    )
