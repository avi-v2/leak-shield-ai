"""
Prompt Security Scanner Route for Sentinel AI.

Performs static sensitive-data analysis and prompt-injection detection on raw prompt payloads.
Works locally without external LLM dependencies.
"""

import time
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Request
from app.schemas import ScanRequest, ScanResponse, Finding
from app.database import load_policies
from app.security.sensitive_data import scan_sensitive_data
from app.security.injection_detector import detect_prompt_injection
from app.security.policy_engine import evaluate_security_policy
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

    # 4. Audit Persistence in SQLite for Risky Requests
    if action in ("BLOCK", "REDACT"):
        client_ip = request.client.host if request.client else "127.0.0.1"
        user_agent = request.headers.get("user-agent", "Sentinel-Scanner-UI")
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
            is_output_scan=False
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
