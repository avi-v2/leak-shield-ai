"""
Gateway Chat Proxy Route for Sentinel AI.

Executes the end-to-end security firewall workflow:
1. Validates incoming prompt payload.
2. Performs sensitive data and prompt-injection detection on the input.
3. Evaluates security policies.
4. If BLOCKED: Halts execution immediately; NEVER forwards to the upstream LLM.
5. If ALLOWED or REDACTED: Forwards the sanitized prompt payload to Ollama.
6. Scans LLM completion output for accidental data leakage.
7. Enforces output redaction or blocking.
8. Logs sanitized audit metadata to SQLite.
9. Returns real response or honest 503 error if LLM is unavailable.
"""

import time
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Request, HTTPException
from app.schemas import ChatRequest, ChatResponse, Finding
from app.database import load_policies
from app.security.sensitive_data import scan_sensitive_data
from app.security.injection_detector import detect_prompt_injection, extract_injection_indicators
from app.security.policy_engine import evaluate_security_policy
from app.security.output_scanner import scan_model_output
from app.services.llm_service import call_ollama
from app.services.audit_service import record_audit_event

router = APIRouter()

@router.post("/chat", response_model=ChatResponse)
def chat_proxy_endpoint(payload: ChatRequest, request: Request):
    """POST /chat — submit a prompt through the security gateway proxy."""
    start_time = time.time()
    req_id = f"chat_{uuid.uuid4().hex[:8]}"
    now_iso = datetime.now(timezone.utc).isoformat()
    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "Sentinel-Playground")

    # Load active server-side policy
    policy = load_policies()

    # Step 1 & 2: Input Scanning
    sensitive_findings, redacted_text = scan_sensitive_data(payload.prompt, policy)
    injection_findings, injection_risk, _, clf_score = detect_prompt_injection(payload.prompt, policy)
    combined_input_findings = sensitive_findings + injection_findings
    indicators = extract_injection_indicators(payload.prompt, injection_findings, clf_score)

    # Step 3: Policy Evaluation
    policy_decision = evaluate_security_policy(
        sensitive_findings=sensitive_findings,
        injection_findings=injection_findings,
        injection_risk=injection_risk,
        policy=policy
    )

    action = policy_decision["action"]
    risk_level = policy_decision["risk_level"]

    # Step 4: If BLOCKED, NEVER forward to LLM
    if action == "BLOCK":
        latency_ms = max(1, int((time.time() - start_time) * 1000))
        primary_threat = combined_input_findings[0]["category"] if combined_input_findings else "Adversarial Directive"
        summary = combined_input_findings[0]["description"] if combined_input_findings else policy_decision["explanation"]

        record_audit_event(
            request_id=req_id,
            threat_category=primary_threat,
            severity=risk_level,
            source="Gateway Proxy",
            action_taken="BLOCK",
            status="blocked",
            summary=f"Intercepted: {summary}",
            matched_rules=[f["type"] for f in combined_input_findings],
            latency_ms=latency_ms,
            client_ip=client_ip,
            user_agent=user_agent,
            sanitized_preview=redacted_text,
            is_output_scan=False,
            input_type="prompt",
            finding_count=len(combined_input_findings),
            indicators=indicators,
            findings=combined_input_findings
        )

        return ChatResponse(
            decision="BLOCK",
            request_id=req_id,
            latency_ms=latency_ms,
            response=None,
            blocked_reason=f"Leak-Shield-AI Interception: {policy_decision['recommendation']}",
            findings=[Finding(**f) for f in combined_input_findings],
            timestamp=now_iso
        )

    # Step 5: Forward Sanitized Prompt to LLM (Ollama)
    # The prompt passed upstream is strictly the sanitized version
    llm_raw_response = call_ollama(prompt=redacted_text, model_name=payload.model)

    # Step 6 & 7: Output Scanning and Redaction
    final_output, output_findings, output_action = scan_model_output(llm_raw_response, policy)

    final_findings = combined_input_findings + output_findings
    effective_decision = "REDACT" if (action == "REDACT" or output_action == "REDACT") else "ALLOW"
    if output_action == "BLOCK":
        effective_decision = "BLOCK"

    latency_ms = max(1, int((time.time() - start_time) * 1000))

    # Step 8: Record Audit Record
    if effective_decision in ("REDACT", "BLOCK") or combined_input_findings:
        primary_threat = final_findings[0]["category"] if final_findings else "Data Sanitization"
        summary = "Sensitive data masked before egress" if effective_decision == "REDACT" else "Request verified clean"
        record_audit_event(
            request_id=req_id,
            threat_category=primary_threat,
            severity=risk_level,
            source="Gateway Proxy",
            action_taken=effective_decision,
            status="mitigated",
            summary=summary,
            matched_rules=[f["type"] for f in final_findings],
            latency_ms=latency_ms,
            client_ip=client_ip,
            user_agent=user_agent,
            sanitized_preview=redacted_text,
            is_output_scan=bool(output_findings),
            input_type="prompt",
            finding_count=len(final_findings),
            indicators=indicators,
            findings=final_findings
        )
    else:
        # Record clean traffic record for metric consistency
        record_audit_event(
            request_id=req_id,
            threat_category="Clean Traffic",
            severity="low",
            source="Gateway Proxy",
            action_taken="ALLOW",
            status="resolved",
            summary="Prompt and response passed all security guardrails",
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

    # Step 9: Return Real Response
    return ChatResponse(
        decision=effective_decision,
        request_id=req_id,
        latency_ms=latency_ms,
        response=final_output,
        blocked_reason=None if effective_decision != "BLOCK" else "Output blocked due to policy violation",
        findings=[Finding(**f) for f in final_findings],
        timestamp=now_iso
    )
