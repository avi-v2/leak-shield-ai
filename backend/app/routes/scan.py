"""
Prompt Security Scanner Route for Sentinel AI.

Performs static sensitive-data analysis and prompt-injection detection on raw prompt payloads.
Works locally without external LLM dependencies.
"""

import time
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Request, File, UploadFile, HTTPException
from app.schemas import ScanRequest, ScanResponse, FileScanResponse, Finding
from app.database import load_policies
from app.security.sensitive_data import scan_sensitive_data
from app.security.injection_detector import detect_prompt_injection, extract_injection_indicators
from app.security.policy_engine import evaluate_security_policy
from app.security.file_scanner import scan_uploaded_file
from app.services.audit_service import record_audit_event

router = APIRouter()

@router.post("/scan", response_model=ScanResponse)
def scan_prompt_endpoint(payload: ScanRequest, request: Request):
    """POST /scan — inspect prompt for credentials, PII, and adversarial directives."""
    start_time = time.time()
    req_id = f"scan_{uuid.uuid4().hex[:8]}"
    now_iso = datetime.now(timezone.utc).isoformat()

    # Load active server-side policy
    policy = load_policies()

    # 1. Scan for Sensitive Data & Redact
    sensitive_findings, redacted_text = scan_sensitive_data(payload.prompt, policy)

    # 2. Scan for Prompt Injection & Heuristics
    injection_findings, injection_risk, clf_available, clf_score = detect_prompt_injection(payload.prompt, policy)

    # 3. Apply Central Policy Engine
    policy_decision = evaluate_security_policy(
        sensitive_findings=sensitive_findings,
        injection_findings=injection_findings,
        injection_risk=injection_risk,
        policy=policy
    )

    action = policy_decision["action"]
    risk_level = policy_decision["risk_level"]
    recommendation = policy_decision["recommendation"]
    explanation = policy_decision["explanation"]

    combined_findings = sensitive_findings + injection_findings
    latency_ms = max(1, int((time.time() - start_time) * 1000))
    indicators = extract_injection_indicators(payload.prompt, injection_findings, clf_score)

    client_ip = request.client.host if request and request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "Sentinel-Scanner-UI") if request else "Sentinel-Scanner-UI"

    # 4. Audit Persistence in SQLite for ALL Scans (ensures accurate denominators and rates)
    if action in ("BLOCK", "REDACT"):
        primary_threat = combined_findings[0]["category"] if combined_findings else "Security Violation"
        summary = combined_findings[0]["description"] if combined_findings else explanation

        record_audit_event(
            request_id=req_id,
            threat_category=primary_threat,
            severity=risk_level,
            source="Prompt Scanner",
            action_taken=action,
            status="mitigated",
            summary=summary,
            matched_rules=[f["type"] for f in combined_findings],
            latency_ms=latency_ms,
            client_ip=client_ip,
            user_agent=user_agent,
            sanitized_preview=redacted_text,
            is_output_scan=False,
            input_type="prompt",
            finding_count=len(combined_findings),
            indicators=indicators,
            findings=combined_findings
        )
    else:
        # Record clean scan for accurate total scans and low risk telemetry
        record_audit_event(
            request_id=req_id,
            threat_category="Clean Traffic",
            severity="low",
            source="Prompt Scanner",
            action_taken="ALLOW",
            status="resolved",
            summary="Clean prompt verified — no security threats detected",
            matched_rules=[],
            latency_ms=latency_ms,
            client_ip=client_ip,
            user_agent=user_agent,
            sanitized_preview=redacted_text,
            is_output_scan=False,
            input_type="prompt",
            finding_count=0,
            indicators=[],
            findings=[]
        )

    return ScanResponse(
        action=action,
        risk_level=risk_level,
        prompt_injection_risk=injection_risk,
        findings=[Finding(**f) for f in combined_findings],
        redacted_prompt=redacted_text,
        recommendation=recommendation,
        scanned_at=now_iso,
        request_id=req_id,
        classifier_available=clf_available,
        classifier_score=clf_score,
        explanation=explanation
    )

@router.post("/scan/file", response_model=FileScanResponse)
async def scan_file_endpoint(file: UploadFile = File(...), request: Request = None):
    """
    POST /scan/file — Inspect uploaded document content (.pdf, .docx, .csv, .json, .txt, .md)
    for sensitive credentials, PII leaks, and adversarial prompt injections.
    """
    start_time = time.time()
    req_id = f"file_{uuid.uuid4().hex[:8]}"

    try:
        file_bytes = await file.read()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read uploaded file payload: {str(e)}")

    response = scan_uploaded_file(file_bytes, filename=file.filename or "uploaded_file.txt", request_id=req_id)
    latency_ms = max(1, int((time.time() - start_time) * 1000))

    # Persist audit record to SQLite for all processed files
    client_ip = request.client.host if request and request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "Sentinel-Client") if request else "Sentinel-Client"
    matched_rules = [f.type for f in response.findings]
    primary_threat = response.findings[0].category if response.findings else "Document Content Scan"
    summary_text = response.explanation or f"File scan verdict: {response.action}"
    safe_preview = response.sanitized_preview or f"{file.filename} ({response.detected_file_type}, {len(file_bytes)} bytes)"

    record_audit_event(
        request_id=req_id,
        threat_category=primary_threat,
        severity=response.risk_level,
        source="Gateway /scan/file",
        action_taken=response.action,
        status="mitigated" if response.action in ("BLOCK", "REDACT") else "processed",
        summary=summary_text,
        matched_rules=matched_rules,
        latency_ms=latency_ms,
        client_ip=client_ip,
        user_agent=user_agent,
        sanitized_preview=safe_preview,
        is_output_scan=False,
        input_type="file",
        finding_count=len(response.findings),
        findings=[f.model_dump() for f in response.findings],
        file_type=response.detected_file_type,
        ocr_status=response.ocr_status
    )

    return response
