"""
Secure Document and Image Redaction Endpoints for Leak-Shield-AI.

Endpoints:
- POST /redact/file: Perform verifiable redaction on document files (.pdf, .docx, .csv, .json, .txt, .md)
- POST /redact/image: Perform pixel-level OCR redaction and EXIF stripping on base64 images
- POST /redact/image/upload: Perform pixel-level OCR redaction and EXIF stripping on multipart uploaded images
- GET /redact/download/{file_id}: Securely retrieve and download verified sanitized artifacts
"""

import time
import base64
import uuid
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List

from fastapi import APIRouter, File, UploadFile, HTTPException, Request, Response
from fastapi.responses import Response

from app.schemas import RedactResponse, RedactImageRequest, Finding
from app.database import load_policies
from app.security.document_redactor import redact_document_bytes
from app.security.image_redactor import redact_image_bytes
from app.services.redaction_store import save_redacted_file, get_redacted_file
from app.services.audit_service import record_audit_event

router = APIRouter(prefix="/redact", tags=["Redaction"])

MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10 MB

MIME_MAP = {
    ".pdf": "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".csv": "text/csv; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
    ".md": "text/markdown; charset=utf-8",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
}


@router.post("/file", response_model=RedactResponse)
async def redact_document_endpoint(file: UploadFile = File(...), request: Request = None):
    """
    POST /redact/file — Redact sensitive data from uploaded document (.pdf, .docx, .csv, .json, .txt, .md).
    Performs format-aware stream redaction, re-scans the output to verify zero residual secrets,
    and returns sanitized download credentials only if verification succeeds.
    """
    start_time = time.time()
    req_id = f"red_doc_{uuid.uuid4().hex[:8]}"
    now_iso = datetime.now(timezone.utc).isoformat()
    raw_filename = file.filename or "uploaded_document.txt"

    # 1. Read and validate upload size
    try:
        file_bytes = await file.read()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read document payload: {str(e)}")

    if not file_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file payload is empty (0 bytes).")

    if len(file_bytes) > MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=413, detail=f"File exceeds maximum allowed upload limit ({MAX_UPLOAD_SIZE // (1024*1024)} MB).")

    # 2. Execute document redaction pipeline
    policy = load_policies()
    result = redact_document_bytes(file_bytes, filename=raw_filename, policy=policy)

    ext = Path(raw_filename).suffix.lower()
    content_type = MIME_MAP.get(ext, "application/octet-stream")

    # 3. Store sanitized artifact if verified and downloadable
    redacted_file_id = None
    download_url = None
    if result["can_download"] and result["sanitized_file_bytes"]:
        try:
            redacted_file_id = save_redacted_file(
                file_bytes=result["sanitized_file_bytes"],
                original_filename=raw_filename,
                content_type=content_type
            )
            download_url = f"/redact/download/{redacted_file_id}"
        except Exception as e:
            result["warnings"].append(f"Failed to cache sanitized artifact for download: {str(e)}")
            result["can_download"] = False

    latency_ms = max(1, int((time.time() - start_time) * 1000))
    client_ip = request.client.host if request and request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "Sentinel-Client") if request else "Sentinel-Client"

    # 4. Audit Persistence in SQLite (Safe metadata only, zero raw secrets)
    record_audit_event(
        request_id=req_id,
        threat_category=result["affected_categories"][0] if result["affected_categories"] else "Document Redaction",
        severity=result["risk_level"],
        source="Gateway /redact/file",
        action_taken=result["action"],
        status="REDACTED" if result["action"] == "REDACT" else ("BLOCKED" if result["action"] == "BLOCK" else "PROCESSED"),
        summary=f"Document Redaction: {result['redaction_count']} secrets sanitized ({result['verification_status']})",
        matched_rules=result["affected_categories"],
        latency_ms=latency_ms,
        client_ip=client_ip,
        user_agent=user_agent,
        sanitized_preview=result.get("sanitized_preview") or f"{raw_filename} ({len(file_bytes)} bytes)",
        is_output_scan=False,
        input_type="file",
        finding_count=result["redaction_count"],
        file_type=ext.lstrip("."),
    )

    findings_objs = [
        Finding(
            type=f.get("type", "SENSITIVE_DATA"),
            category=f.get("category", "Data Privacy"),
            description=f.get("description", "Sensitive information pattern"),
            severity=f.get("severity", "medium"),
            match_preview=f.get("match_preview"),
            start=f.get("start"),
            end=f.get("end"),
            source_location=f.get("source_location") or "Document Text",
            origin="document_text"
        )
        for f in result.get("findings", [])
    ]

    return RedactResponse(
        request_id=req_id,
        action=result["action"],
        risk_level=result["risk_level"],
        filename=raw_filename,
        sanitized_filename=result.get("sanitized_filename") or f"sanitized_{raw_filename}",
        redacted_file_id=redacted_file_id,
        download_url=download_url,
        can_download=result["can_download"],
        redaction_count=result["redaction_count"],
        affected_categories=result["affected_categories"],
        verification_status=result["verification_status"],
        verification_details=result["verification_details"],
        warnings=result["warnings"],
        sanitized_preview=result.get("sanitized_preview"),
        findings=findings_objs,
        processed_at=now_iso
    )


@router.post("/image", response_model=RedactResponse)
async def redact_image_json_endpoint(payload: RedactImageRequest, request: Request = None):
    """
    POST /redact/image — Redact sensitive visual text and EXIF metadata from a base64 encoded image.
    Uses OCR bounding boxes to apply opaque masks and strips all metadata chunks.
    """
    start_time = time.time()
    req_id = f"red_img_{uuid.uuid4().hex[:8]}"
    now_iso = datetime.now(timezone.utc).isoformat()
    raw_filename = payload.filename or "uploaded_image.png"

    raw_b64 = payload.image_base64
    if "," in raw_b64:
        raw_b64 = raw_b64.split(",", 1)[1]

    try:
        image_bytes = base64.b64decode(raw_b64)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid base64 image data: {str(e)}")

    if not image_bytes:
        raise HTTPException(status_code=400, detail="Decoded image payload is empty (0 bytes).")

    if len(image_bytes) > MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=413, detail=f"Image exceeds maximum upload limit ({MAX_UPLOAD_SIZE // (1024*1024)} MB).")

    policy = load_policies()
    result = redact_image_bytes(image_bytes, policy=policy, filename=raw_filename)

    ext = Path(raw_filename).suffix.lower() or ".png"
    content_type = MIME_MAP.get(ext, "image/png")

    redacted_file_id = None
    download_url = None
    if result["can_download"] and result["sanitized_image_bytes"]:
        try:
            redacted_file_id = save_redacted_file(
                file_bytes=result["sanitized_image_bytes"],
                original_filename=raw_filename,
                content_type=content_type
            )
            download_url = f"/redact/download/{redacted_file_id}"
        except Exception as e:
            result["warnings"].append(f"Failed to cache sanitized image for download: {str(e)}")
            result["can_download"] = False

    latency_ms = max(1, int((time.time() - start_time) * 1000))
    client_ip = request.client.host if request and request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "Sentinel-Client") if request else "Sentinel-Client"

    record_audit_event(
        request_id=req_id,
        threat_category=result["affected_categories"][0] if result["affected_categories"] else "Image Privacy Scan",
        severity=result["risk_level"],
        source="Gateway /redact/image",
        action_taken=result["action"],
        status="REDACTED" if result["action"] == "REDACT" else ("BLOCKED" if result["action"] == "BLOCK" else "PROCESSED"),
        summary=f"Image Redaction: {result['redaction_count']} visual text masks ({result['verification_status']})",
        matched_rules=result["affected_categories"],
        latency_ms=latency_ms,
        client_ip=client_ip,
        user_agent=user_agent,
        sanitized_preview=f"{raw_filename} (Opaque masks: {result['redaction_count']})",
        is_output_scan=False,
        input_type="image",
        finding_count=result["redaction_count"],
        file_type=ext.lstrip("."),
    )

    findings_objs = [
        Finding(
            type=f.get("type", "OCR_SENSITIVE_TEXT"),
            category=f.get("category", "Data Privacy"),
            description=f.get("description", "Visible sensitive text detected via OCR"),
            severity=f.get("severity", "medium"),
            match_preview=f.get("match_preview"),
            start=f.get("start"),
            end=f.get("end"),
            source_location=f.get("source_location") or "Visual OCR Text",
            origin="ocr"
        )
        for f in result.get("findings", [])
    ]

    return RedactResponse(
        request_id=req_id,
        action=result["action"],
        risk_level=result["risk_level"],
        filename=raw_filename,
        sanitized_filename=result.get("sanitized_filename") or f"sanitized_{raw_filename}",
        redacted_file_id=redacted_file_id,
        download_url=download_url,
        can_download=result["can_download"],
        redaction_count=result["redaction_count"],
        affected_categories=result["affected_categories"],
        verification_status=result["verification_status"],
        verification_details=result["verification_details"],
        warnings=result["warnings"],
        sanitized_preview=result.get("sanitized_preview"),
        sanitized_image_base64=result.get("sanitized_image_base64"),
        findings=findings_objs,
        processed_at=now_iso
    )


@router.post("/image/upload", response_model=RedactResponse)
async def redact_image_upload_endpoint(file: UploadFile = File(...), request: Request = None):
    """
    POST /redact/image/upload — Redact sensitive visual text and EXIF metadata from multipart image upload.
    """
    start_time = time.time()
    req_id = f"red_img_{uuid.uuid4().hex[:8]}"
    now_iso = datetime.now(timezone.utc).isoformat()
    raw_filename = file.filename or "uploaded_image.png"

    try:
        image_bytes = await file.read()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read image upload: {str(e)}")

    if not image_bytes:
        raise HTTPException(status_code=400, detail="Uploaded image is empty (0 bytes).")

    if len(image_bytes) > MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=413, detail=f"Image exceeds upload limit ({MAX_UPLOAD_SIZE // (1024*1024)} MB).")

    policy = load_policies()
    result = redact_image_bytes(image_bytes, policy=policy, filename=raw_filename)

    ext = Path(raw_filename).suffix.lower() or ".png"
    content_type = MIME_MAP.get(ext, "image/png")

    redacted_file_id = None
    download_url = None
    if result["can_download"] and result["sanitized_image_bytes"]:
        try:
            redacted_file_id = save_redacted_file(
                file_bytes=result["sanitized_image_bytes"],
                original_filename=raw_filename,
                content_type=content_type
            )
            download_url = f"/redact/download/{redacted_file_id}"
        except Exception as e:
            result["warnings"].append(f"Failed to cache sanitized image for download: {str(e)}")
            result["can_download"] = False

    latency_ms = max(1, int((time.time() - start_time) * 1000))
    client_ip = request.client.host if request and request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "Sentinel-Client") if request else "Sentinel-Client"

    record_audit_event(
        request_id=req_id,
        threat_category=result["affected_categories"][0] if result["affected_categories"] else "Image Privacy Scan",
        severity=result["risk_level"],
        source="Gateway /redact/image/upload",
        action_taken=result["action"],
        status="REDACTED" if result["action"] == "REDACT" else ("BLOCKED" if result["action"] == "BLOCK" else "PROCESSED"),
        summary=f"Image Redaction: {result['redaction_count']} visual text masks ({result['verification_status']})",
        matched_rules=result["affected_categories"],
        latency_ms=latency_ms,
        client_ip=client_ip,
        user_agent=user_agent,
        sanitized_preview=f"{raw_filename} (Opaque masks: {result['redaction_count']})",
        is_output_scan=False,
        input_type="image",
        finding_count=result["redaction_count"],
        file_type=ext.lstrip("."),
    )

    findings_objs = [
        Finding(
            type=f.get("type", "OCR_SENSITIVE_TEXT"),
            category=f.get("category", "Data Privacy"),
            description=f.get("description", "Visible sensitive text detected via OCR"),
            severity=f.get("severity", "medium"),
            match_preview=f.get("match_preview"),
            start=f.get("start"),
            end=f.get("end"),
            source_location=f.get("source_location") or "Visual OCR Text",
            origin="ocr"
        )
        for f in result.get("findings", [])
    ]

    return RedactResponse(
        request_id=req_id,
        action=result["action"],
        risk_level=result["risk_level"],
        filename=raw_filename,
        sanitized_filename=result.get("sanitized_filename") or f"sanitized_{raw_filename}",
        redacted_file_id=redacted_file_id,
        download_url=download_url,
        can_download=result["can_download"],
        redaction_count=result["redaction_count"],
        affected_categories=result["affected_categories"],
        verification_status=result["verification_status"],
        verification_details=result["verification_details"],
        warnings=result["warnings"],
        sanitized_preview=result.get("sanitized_preview"),
        sanitized_image_base64=result.get("sanitized_image_base64"),
        findings=findings_objs,
        processed_at=now_iso
    )


@router.get("/download/{file_id}")
def download_redacted_file(file_id: str):
    """
    GET /redact/download/{file_id} — Stream sanitized and verified document or image file.
    Only allows access to valid, non-expired, sanitized artifacts. Enforces strict
    path traversal barriers.
    """
    entry = get_redacted_file(file_id)
    if not entry:
        raise HTTPException(
            status_code=404,
            detail="Sanitized file not found or has expired. Redacted files are held temporarily for 1 hour."
        )

    filename = entry["filename"]
    # Ensure safe ascii or quoted filename for Content-Disposition
    ascii_filename = filename.encode("ascii", "ignore").decode("ascii") or "sanitized_file"

    headers = {
        "Content-Disposition": f'attachment; filename="{ascii_filename}"',
        "Content-Length": str(entry["size_bytes"]),
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    }

    return Response(
        content=entry["file_bytes"],
        media_type=entry["content_type"],
        headers=headers
    )
