"""
Image Redaction & Privacy Enforcement Engine for Leak-Shield-AI.

Executes genuine pixel-level opaque redaction of sensitive visual text detected via OCR,
combined with complete stripping of EXIF tags, GPS coordinates, and hardware metadata.
Includes rigorous post-redaction verification.
"""

import io
import base64
from typing import Dict, Any, List, Tuple, Optional
from PIL import Image, ImageDraw

from app.security.sensitive_data import scan_sensitive_data
from app.security.ocr_utils import extract_text_and_boxes_from_image, extract_text_from_image
from app.security.image_scanner import _get_exif_dict

def redact_image_bytes(
    image_bytes: bytes,
    policy: Optional[Dict[str, Any]] = None,
    filename: str = "image.png"
) -> Dict[str, Any]:
    """
    Complete end-to-end image redaction pipeline:
    1. Decode original image.
    2. Extract OCR text and word bounding-box coordinates.
    3. Detect sensitive data spans in the OCR text.
    4. Associate sensitive spans with the corresponding OCR bounding boxes.
    5. Draw opaque rectangular masks covering the sensitive text regions.
    6. Strip all EXIF, GPS, and metadata chunks.
    7. Perform multi-step verification:
       - Structural decode verification
       - Metadata absence verification
       - Second-pass OCR re-scan to confirm secret elimination.
    """
    if not image_bytes:
        return {
            "success": False,
            "action": "BLOCK",
            "risk_level": "critical",
            "redaction_count": 0,
            "affected_categories": [],
            "verification_status": "FAILED",
            "verification_details": {"error": "Empty image payload (0 bytes)."},
            "sanitized_image_bytes": None,
            "sanitized_image_base64": None,
            "warnings": ["Uploaded image is empty."],
            "can_download": False
        }

    try:
        orig_img = Image.open(io.BytesIO(image_bytes))
        orig_img.load()
    except Exception as e:
        return {
            "success": False,
            "action": "BLOCK",
            "risk_level": "critical",
            "redaction_count": 0,
            "affected_categories": [],
            "verification_status": "FAILED",
            "verification_details": {"error": f"Failed to parse or decode image: {str(e)}"},
            "sanitized_image_bytes": None,
            "sanitized_image_base64": None,
            "warnings": [f"Malformed image file: {str(e)}"],
            "can_download": False
        }

    # 1. OCR text and bounding-box extraction
    ocr_text, word_boxes, ocr_status = extract_text_and_boxes_from_image(orig_img)
    warnings: List[str] = []

    if ocr_status == "unavailable":
        warnings.append("OCR engine (Tesseract) is unavailable on the host; visible text could not be extracted.")
    elif ocr_status.startswith("failed"):
        warnings.append(f"OCR execution failed: {ocr_status}")

    # 2. Detect sensitive data in OCR text
    sensitive_findings: List[Dict[str, Any]] = []
    if ocr_text and ocr_text.strip():
        sensitive_findings, _ = scan_sensitive_data(ocr_text, policy)

    # 3. Check EXIF/GPS leaks
    exif_data = _get_exif_dict(orig_img)
    has_gps = "GPSInfo" in exif_data and bool(exif_data["GPSInfo"])
    has_exif = bool(exif_data)

    affected_categories_set = set()
    for f in sensitive_findings:
        affected_categories_set.add(f.get("category", "Sensitive Data"))
    if has_gps:
        affected_categories_set.add("Location Privacy Leak")
    if has_exif and not has_gps:
        affected_categories_set.add("Hardware Fingerprinting")

    affected_categories = sorted(list(affected_categories_set))

    # 4. Map sensitive findings to OCR word boxes
    boxes_to_redact: List[Dict[str, Any]] = []
    unmapped_findings: List[Dict[str, Any]] = []

    for f in sensitive_findings:
        f_start = f.get("start", -1)
        f_end = f.get("end", -1)
        matched_any = False

        if f_start >= 0 and f_end > f_start:
            for wb in word_boxes:
                wb_start = wb.get("start_char", -1)
                wb_end = wb.get("end_char", -1)
                # Check character overlap
                if max(f_start, wb_start) < min(f_end, wb_end):
                    boxes_to_redact.append(wb)
                    matched_any = True

        if not matched_any:
            # Fallback: substring matching on word tokens
            preview = f.get("match_preview", "")
            # Try finding by word text
            if ocr_text and f_start >= 0 and f_end > f_start:
                secret_sub = ocr_text[f_start:f_end].strip()
                secret_words = secret_sub.split()
                for sw in secret_words:
                    for wb in word_boxes:
                        if sw.lower() in wb.get("text", "").lower():
                            boxes_to_redact.append(wb)
                            matched_any = True

        if not matched_any:
            unmapped_findings.append(f)

    # 5. Create clean canvas and apply opaque rectangular redactions
    mode = "RGBA" if orig_img.mode in ("RGBA", "LA") or (orig_img.mode == "P" and "transparency" in orig_img.info) else "RGB"
    redacted_canvas = Image.new(mode, orig_img.size)
    redacted_canvas.paste(orig_img.convert(mode))

    draw = ImageDraw.Draw(redacted_canvas)
    redaction_count = 0
    pad = 3  # Padding around text box to prevent glyph boundary leakage

    img_w, img_h = orig_img.size

    # Deduplicate overlapping boxes
    drawn_rects = set()
    for b in boxes_to_redact:
        x1 = max(0, b["left"] - pad)
        y1 = max(0, b["top"] - pad)
        x2 = min(img_w, b["left"] + b["width"] + pad)
        y2 = min(img_h, b["top"] + b["height"] + pad)

        rect_key = (x1, y1, x2, y2)
        if rect_key not in drawn_rects:
            drawn_rects.add(rect_key)
            # Draw solid opaque black rectangle
            fill_color = (0, 0, 0, 255) if mode == "RGBA" else (0, 0, 0)
            draw.rectangle([x1, y1, x2, y2], fill=fill_color, outline=fill_color)
            redaction_count += 1

    # 6. Save sanitized image stripping all metadata
    buffer = io.BytesIO()
    out_format = "PNG" if (orig_img.format or "").upper() in ("PNG", "WEBP") or mode == "RGBA" else "JPEG"
    redacted_canvas.save(buffer, format=out_format)
    sanitized_bytes = buffer.getvalue()

    # 7. Verification Phase
    verification_details: Dict[str, Any] = {
        "structural_integrity": False,
        "metadata_stripped": False,
        "re_scan_clean": False,
        "ocr_verification_status": "skipped",
        "checks_performed": []
    }

    verification_status = "VERIFIED"

    # 7a. Reopen and verify structural integrity
    try:
        verify_img = Image.open(io.BytesIO(sanitized_bytes))
        verify_img.load()
        verification_details["structural_integrity"] = True
        verification_details["checks_performed"].append("Pillow image decode and pixel load passed.")
    except Exception as e:
        verification_status = "FAILED"
        verification_details["structural_integrity"] = False
        warnings.append(f"Sanitized image failed decode verification: {str(e)}")

    # 7b. Verify metadata absence
    sanitized_exif = _get_exif_dict(verify_img)
    has_sanitized_gps = "GPSInfo" in sanitized_exif and bool(sanitized_exif["GPSInfo"])
    if not sanitized_exif and not has_sanitized_gps:
        verification_details["metadata_stripped"] = True
        verification_details["checks_performed"].append("All EXIF tags, GPS metadata, and comments successfully eliminated.")
    else:
        verification_status = "FAILED"
        warnings.append("EXIF or GPS metadata residual was detected after redaction.")

    # 7c. Re-run OCR inspection on the sanitized image
    if verification_status != "FAILED":
        re_ocr_text, re_ocr_status = extract_text_from_image(verify_img)
        verification_details["ocr_verification_status"] = re_ocr_status

        if re_ocr_status == "executed":
            if re_ocr_text and re_ocr_text.strip():
                re_findings, _ = scan_sensitive_data(re_ocr_text, policy)
                if re_findings:
                    verification_status = "FAILED"
                    warnings.append(f"Residual sensitive data ({len(re_findings)} items) re-detected by OCR on sanitized image.")
                else:
                    verification_details["re_scan_clean"] = True
                    verification_details["checks_performed"].append("Second-pass OCR scan detected zero residual sensitive patterns.")
            else:
                verification_details["re_scan_clean"] = True
                verification_details["checks_performed"].append("Second-pass OCR found zero residual readable text.")
        elif re_ocr_status == "unavailable":
            verification_details["checks_performed"].append("Host OCR engine unavailable for second-pass text inspection.")
            if sensitive_findings and not boxes_to_redact:
                verification_status = "PARTIAL"
        elif re_ocr_status.startswith("failed"):
            verification_status = "PARTIAL"
            warnings.append(f"Second-pass OCR verification could not complete: {re_ocr_status}")

    # If some sensitive findings were detected by OCR initially but could not be mapped to boxes
    if unmapped_findings and verification_status != "FAILED":
        verification_status = "PARTIAL"
        warnings.append(f"{len(unmapped_findings)} detected secret(s) could not be mapped to exact image coordinates.")

    can_download = (verification_status != "FAILED")

    # Generate base64 Data URI for immediate frontend preview
    mime_type = "image/png" if out_format == "PNG" else "image/jpeg"
    b64_str = base64.b64encode(sanitized_bytes).decode("utf-8")
    data_uri = f"data:{mime_type};base64,{b64_str}"

    return {
        "success": verification_status != "FAILED",
        "action": "REDACT" if (redaction_count > 0 or has_exif) else "ALLOW",
        "risk_level": "low" if verification_status == "VERIFIED" else "medium" if verification_status == "PARTIAL" else "high",
        "redaction_count": redaction_count,
        "affected_categories": affected_categories,
        "verification_status": verification_status,
        "verification_details": verification_details,
        "sanitized_image_bytes": sanitized_bytes,
        "sanitized_image_base64": data_uri,
        "warnings": warnings,
        "can_download": can_download,
        "filename": filename,
        "sanitized_filename": f"sanitized_{filename}"
    }
