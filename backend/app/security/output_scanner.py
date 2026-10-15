"""
Model Output Scanner for Sentinel AI.

Inspects text returned from upstream LLMs before delivering it to the client.
Prevents accidental reflection or exfiltration of sensitive internal data, credentials, or PII.
"""

from typing import Tuple, List, Dict, Any, Optional
from app.security.sensitive_data import scan_sensitive_data

def scan_model_output(
    output_text: str,
    policy: Optional[Dict[str, Any]] = None
) -> Tuple[str, List[Dict[str, Any]], str]:
    """
    Scan and sanitize upstream LLM completion text.

    Returns:
        (sanitized_text, findings, action_taken)
        where action_taken is "ALLOW", "REDACT", or "BLOCK"
    """
    if not output_text:
        return "", [], "ALLOW"

    pol = policy or {}
    if not pol.get("inspectModelOutputs", True):
        return output_text, [], "ALLOW"

    findings, redacted_text = scan_sensitive_data(output_text, pol)

    if not findings:
        return output_text, [], "ALLOW"

    # If output contains leaked credentials, always sanitize them
    has_credentials = any(
        f.get("category") == "Credential Exfiltration" or
        "API_KEY" in f.get("type", "") or
        "PASSWORD" in f.get("type", "")
        for f in findings
    )

    if has_credentials:
        # Heavily mask and flag as REDACT
        return redacted_text, findings, "REDACT"

    default_action = pol.get("defaultAction", "REDACT").upper()
    if default_action == "BLOCK":
        return "[RESPONSE BLOCKED: Model output contained sensitive PII filtered by gateway policy]", findings, "BLOCK"

    return redacted_text, findings, "REDACT"
