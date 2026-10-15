"""
Image Content & Multimodal Security Scanner for Leak-Shield-AI.

Integrates:
1. Deep OCR text extraction (pytesseract) for visible credentials, PII, and adversarial prompt injections.
2. Complete EXIF and GPS geolocation extraction.
3. Hardware/camera fingerprinting metadata detection.
4. PNG chunks (tEXt, iTXt) and JPEG UserComment secret exfiltration inspection.
5. Image sanitization / metadata stripping.
6. Transparent reporting of OCR availability and limitations.
"""

import io
import re
import base64
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from PIL import Image, ExifTags

from app.schemas import Finding, ImageMetadata, ImageScanResponse
from app.database import load_policies
from app.security.sensitive_data import scan_sensitive_data
from app.security.injection_detector import detect_prompt_injection
from app.security.policy_engine import evaluate_security_policy
from app.security.ocr_utils import is_ocr_available, extract_text_from_image

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
    mode = "RGBA" if img.mode in ("RGBA", "LA") or (img.mode == "P" and "transparency" in img.info) else "RGB"
    clean_img = Image.new(mode, img.size)
    converted = img.convert(mode)
    clean_img.paste(converted)

    buffer = io.BytesIO()
    fmt = "PNG" if output_format.upper() in ("PNG", "WEBP") else "JPEG"
    clean_img.save(buffer, format=fmt)
    buffer.seek(0)

    encoded = base64.b64encode(buffer.getvalue()).decode("utf-8")
    mime = "image/png" if fmt == "PNG" else "image/jpeg"
    return f"data:{mime};base64,{encoded}"

def scan_image_content_and_metadata(
    image_bytes: bytes,
    filename: str = "image.png",
    request_id: Optional[str] = None
) -> ImageScanResponse:
    """
    Comprehensive image scanner:
    - Inspects metadata, GPS, EXIF headers, PNG chunks
    - Runs OCR visible text recognition
    - Evaluates extracted text for credentials, PII, and prompt injection attacks
    - Enforces central security policies
    """
    req_id = request_id or f"img_{uuid.uuid4().hex[:8]}"
    now_iso = datetime.now(timezone.utc).isoformat()
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
                    match_preview="0 bytes",
                    source_location="File Upload",
                    origin="image_metadata"
                )
            ],
            metadata=ImageMetadata(file_size_bytes=0),
            recommendation="Reject empty image submission.",
            sanitized_image_base64=None,
            scanned_at=now_iso,
            explanation="The uploaded image contains 0 bytes.",
            ocr_status="skipped",
            ocr_text_preview=None,
            finding_count=1,
            scanned_components=[]
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
                    match_preview=str(e)[:80],
                    source_location="Image Decoder",
                    origin="image_metadata"
                )
            ],
            metadata=ImageMetadata(file_size_bytes=file_size),
            recommendation="Block unparseable image file to prevent gateway crash or exploit.",
            sanitized_image_base64=None,
            scanned_at=now_iso,
            explanation=f"Malformed or unsupported image format: {str(e)}",
            ocr_status="failed",
            ocr_text_preview=None,
            finding_count=1,
            scanned_components=[]
        )

    findings: List[Finding] = []
    scanned_components: List[str] = []

    # 1. Inspect EXIF & GPS Metadata
    exif_data = _get_exif_dict(img)
    has_exif = bool(exif_data)
    gps_coords = None
    device_info = {}

    if has_exif:
        scanned_components.append("EXIF Metadata")

    if "GPSInfo" in exif_data:
        gps_parsed = _extract_gps_info(exif_data["GPSInfo"])
        if gps_parsed:
            gps_coords = gps_parsed
            findings.append(Finding(
                type="RULE_IMAGE_EXIF_GPS_LEAK",
                category="Location Privacy Leak",
                description="Precise GPS coordinates detected in image EXIF headers, exposing physical location.",
                severity="high",
                match_preview=gps_parsed["formatted"],
                source_location="EXIF GPSInfo Block",
                origin="image_metadata"
            ))

    # 2. Inspect Hardware / Camera Metadata
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
            match_preview=preview_text,
            source_location="EXIF Header Tags",
            origin="image_metadata"
        ))

    # 3. Inspect Embedded Text Chunks (PNG tEXt/iTXt, comments)
    policy = load_policies()
    extracted_text_blocks = []
    if hasattr(img, "info") and isinstance(img.info, dict):
        for k, v in img.info.items():
            if isinstance(v, str) and len(v.strip()) > 0:
                extracted_text_blocks.append((f"{k}: {v}", f"PNG Chunk '{k}'"))

    if "UserComment" in exif_data and isinstance(exif_data["UserComment"], (str, bytes)):
        try:
            uc = exif_data["UserComment"]
            if isinstance(uc, bytes):
                uc = uc.decode("utf-8", errors="ignore")
            if uc.strip():
                extracted_text_blocks.append((f"UserComment: {uc}", "EXIF UserComment"))
        except Exception:
            pass

    for block_str, block_loc in extracted_text_blocks:
        scanned_components.append(block_loc)
        b_findings, _ = scan_sensitive_data(block_str, policy)
        for f in b_findings:
            findings.append(Finding(
                type=f"RULE_IMAGE_EMBEDDED_{f['type']}",
                category=f"Embedded {f['category']}",
                description=f"Sensitive secret discovered inside image metadata: {f['description']}",
                severity=f["severity"],
                match_preview=f.get("match_preview"),
                source_location=block_loc,
                origin="image_metadata"
            ))

    # 4. OCR Visible Text Recognition
    ocr_status = "unavailable"
    ocr_raw_text = None
    ocr_preview = None

    if is_ocr_available():
        scanned_components.append("OCR Visible Text")
        ocr_raw_text, ocr_status = extract_text_from_image(img)
    else:
        ocr_status = "unavailable"

    if ocr_raw_text and ocr_raw_text.strip():
        # 4a. Sensitive Data Scan on OCR Text
        ocr_sens_findings, ocr_redacted = scan_sensitive_data(ocr_raw_text, policy)
        for sf in ocr_sens_findings:
            findings.append(Finding(
                type=f"RULE_OCR_{sf['type']}",
                category=sf["category"],
                description=f"OCR detected {sf['description']} in visible image text.",
                severity=sf["severity"],
                match_preview=sf.get("match_preview"),
                source_location="OCR Visible Text",
                origin="ocr"
            ))

        # 4b. Prompt Injection & Jailbreak Scan on OCR Text
        ocr_inj_findings, ocr_inj_risk, _, _ = detect_prompt_injection(ocr_raw_text, policy)
        for inf in ocr_inj_findings:
            findings.append(Finding(
                type=f"RULE_OCR_{inf['type']}",
                category=inf["category"],
                description=f"OCR detected adversarial directive in visible image text: {inf['description']}",
                severity=inf["severity"],
                match_preview=inf.get("match_preview"),
                source_location="OCR Visible Text",
                origin="ocr"
            ))

        # Safe OCR preview (truncated & redacted if sensitive)
        display_ocr = ocr_redacted if ocr_sens_findings else ocr_raw_text
        ocr_preview = (display_ocr[:157] + "...") if len(display_ocr) > 160 else display_ocr

    # 5. Generate Sanitized Clean Image (Strip all EXIF and metadata)
    sanitized_b64 = None
    try:
        sanitized_b64 = sanitize_image(img, output_format=img.format or "PNG")
    except Exception:
        pass

    # 6. Central Policy Evaluation
    sens_for_policy = [f.model_dump() for f in findings if "Injection" not in f.category and "Jailbreak" not in f.category and "Prompt" not in f.category]
    inj_for_policy = [f.model_dump() for f in findings if "Injection" in f.category or "Jailbreak" in f.category or "Prompt" in f.category]
    highest_inj_risk = "high" if any(f.get("severity") in ("high", "critical") for f in inj_for_policy) else "none"

    policy_verdict = evaluate_security_policy(
        sensitive_findings=sens_for_policy,
        injection_findings=inj_for_policy,
        injection_risk=highest_inj_risk,
        policy=policy
    )

    action = policy_verdict["action"]
    risk_level = policy_verdict["risk_level"]
    recommendation = policy_verdict["recommendation"]
    explanation = policy_verdict["explanation"]

    # If GPS or hardware metadata was detected without credentials, REDACT applies (sanitize image)
    if gps_coords is not None and action == "ALLOW":
        action = "REDACT"
        risk_level = "high"
        recommendation = "Sanitize image metadata before transmitting to LLM or external service."
        explanation = "Image contains GPS location coordinates. Sanitized version generated with stripped EXIF."

    # If OCR was unavailable and image has no findings, mention OCR limitation
    if ocr_status == "unavailable" and not findings:
        explanation = "No EXIF leaks or embedded metadata detected. Note: OCR engine was unavailable; visible text could not be verified."

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
        recommendation=recommendation,
        sanitized_image_base64=sanitized_b64,
        scanned_at=now_iso,
        explanation=explanation,
        ocr_status=ocr_status,
        ocr_text_preview=ocr_preview,
        finding_count=len(findings),
        scanned_components=list(set(scanned_components))
    )
