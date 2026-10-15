"""
Image Scan Route for Leak-Sheild-AI Security Gateway.

Provides POST /scan/image to evaluate images for:
- EXIF GPS coordinates & location leaks
- Hardware and camera fingerprinting metadata
- Embedded credentials and secrets in image comments / chunks
- Image sanitization (stripping metadata to produce a clean version)
"""

import time
import base64
import uuid
from typing import Optional
from fastapi import APIRouter, File, UploadFile, HTTPException, Body
from app.schemas import ImageScanRequest, ImageScanResponse
from app.security.image_scanner import scan_image_bytes
from app.services.audit_service import record_audit_event

router = APIRouter()

@router.post("/scan/image", response_model=ImageScanResponse)
async def scan_image_json_endpoint(payload: ImageScanRequest):
    """
    POST /scan/image — Scan an image provided as a base64 encoded string or Data URI.
    Detects EXIF GPS leaks, device fingerprinting, and embedded secrets.
    """
    start_time = time.time()
    req_id = f"img_{uuid.uuid4().hex[:8]}"

    raw_b64 = payload.image_base64
    # Strip data URL prefix if present e.g. "data:image/jpeg;base64,..."
    if "," in raw_b64:
        raw_b64 = raw_b64.split(",", 1)[1]

    try:
        image_bytes = base64.b64decode(raw_b64)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid base64 image data: {str(e)}")

    response = scan_image_bytes(image_bytes, filename=payload.filename or "uploaded.png", request_id=req_id)
    latency_ms = int((time.time() - start_time) * 1000)

    # Persist audit record to SQLite
    matched_rules = [f.type for f in response.findings]
    summary_text = response.explanation or f"Image scan: {response.action}"
    preview = f"{payload.filename} ({response.metadata.format or 'IMG'} {response.metadata.width}x{response.metadata.height})"

    record_audit_event(
        request_id=req_id,
        threat_category=response.findings[0].category if response.findings else "Image Privacy Scan",
        severity=response.risk_level,
        source="Gateway /scan/image",
        action_taken=response.action,
        status="PROCESSED",
        summary=summary_text,
        matched_rules=matched_rules,
        latency_ms=latency_ms,
        sanitized_preview=preview,
        is_output_scan=False
    )

    return response

@router.post("/scan/image/upload", response_model=ImageScanResponse)
async def scan_image_upload_endpoint(file: UploadFile = File(...)):
    """
    POST /scan/image/upload — Scan an image file uploaded as multipart/form-data.
    """
    start_time = time.time()
    req_id = f"img_{uuid.uuid4().hex[:8]}"

    try:
        image_bytes = await file.read()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read uploaded file: {str(e)}")

    response = scan_image_bytes(image_bytes, filename=file.filename or "uploaded.png", request_id=req_id)
    latency_ms = int((time.time() - start_time) * 1000)

    matched_rules = [f.type for f in response.findings]
    summary_text = response.explanation or f"Image scan: {response.action}"
    preview = f"{file.filename} ({response.metadata.format or 'IMG'} {response.metadata.width}x{response.metadata.height})"

    record_audit_event(
        request_id=req_id,
        threat_category=response.findings[0].category if response.findings else "Image Privacy Scan",
        severity=response.risk_level,
        source="Gateway /scan/image/upload",
        action_taken=response.action,
        status="PROCESSED",
        summary=summary_text,
        matched_rules=matched_rules,
        latency_ms=latency_ms,
        sanitized_preview=preview,
        is_output_scan=False
    )

    return response
