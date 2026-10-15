"""
Central Security Policy Engine for Sentinel AI.

Combines sensitive data findings, prompt injection vectors, configured policy rules,
and context to enforce ALLOW, REDACT, or BLOCK actions.

CONSERVATIVE ENFORCEMENT RULES:
1. Detected credentials (API keys, passwords, bearer tokens) are ALWAYS blocked regardless
   of frontend configuration.
2. PII categories are redacted by default, or blocked if strict policy is selected.
3. High-risk prompt injections and jailbreaks are blocked according to threshold.
4. Requests are never claimed to be 'safe' solely because an ML model returned benign.
"""

from typing import List, Dict, Any, Tuple

SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4
}

def evaluate_security_policy(
    sensitive_findings: List[Dict[str, Any]],
    injection_findings: List[Dict[str, Any]],
    injection_risk: str,
    policy: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Evaluate combined findings against server-side policy.

    Returns:
        {
            "action": "ALLOW" | "REDACT" | "BLOCK",
            "risk_level": "low" | "medium" | "high" | "critical",
            "recommendation": str,
            "explanation": str
        }
    """
    all_findings = sensitive_findings + injection_findings

    # 1. Check for Credentials (MANDATORY BLOCK)
    has_credentials = any(
        f.get("category") == "Credential Exfiltration" or
        "API_KEY" in f.get("type", "") or
        "PASSWORD" in f.get("type", "")
        for f in sensitive_findings
    )

    if has_credentials:
        return {
            "action": "BLOCK",
            "risk_level": "critical",
            "recommendation": "Reject this request immediately. Prompt contains active credentials or secret keys.",
            "explanation": "Blocked by mandatory credential security rule. Private API keys and passwords may not be forwarded."
        }

    # 2. Check for Prompt Injection Attacks
    threshold = policy.get("highRiskThreshold", "high").lower()
    should_block_injection = False

    if injection_findings:
        if threshold == "medium" and injection_risk in ("medium", "high"):
            should_block_injection = True
        elif threshold == "high" and (injection_risk == "high" or any(f.get("severity") in ("high", "critical") for f in injection_findings)):
            should_block_injection = True
        elif threshold == "critical" and any(f.get("severity") == "critical" for f in injection_findings):
            should_block_injection = True

    if should_block_injection:
        return {
            "action": "BLOCK",
            "risk_level": "critical" if injection_risk == "high" else "high",
            "recommendation": "Reject this request immediately. Prompt contains active injection vectors or jailbreak directives.",
            "explanation": f"Blocked by prompt injection firewall ({len(injection_findings)} adversarial directive(s) identified)."
        }

    # 3. Check for PII / Sensitive Data Findings
    if sensitive_findings:
        default_action = policy.get("defaultAction", "REDACT").upper()
        # Calculate max severity among sensitive findings
        max_sev = "low"
        for f in sensitive_findings:
            sev = f.get("severity", "low")
            if SEVERITY_ORDER.get(sev, 1) > SEVERITY_ORDER.get(max_sev, 1):
                max_sev = sev

        if default_action == "BLOCK":
            return {
                "action": "BLOCK",
                "risk_level": max_sev,
                "recommendation": "Reject this request. Prompt contains sensitive PII under strict BLOCK policy.",
                "explanation": f"Policy defaultAction=BLOCK rejected prompt containing {len(sensitive_findings)} sensitive PII record(s)."
            }
        elif default_action == "REDACT":
            return {
                "action": "REDACT",
                "risk_level": max_sev,
                "recommendation": "Sanitize sensitive tokens before forwarding to upstream AI providers.",
                "explanation": f"Redacted {len(sensitive_findings)} sensitive item(s) to prevent PII egress."
            }
        else: # ALLOW
            return {
                "action": "ALLOW",
                "risk_level": max_sev,
                "recommendation": "Audit only: Sensitive data detected but policy defaultAction is set to ALLOW.",
                "explanation": f"Audited {len(sensitive_findings)} sensitive item(s) without masking per current policy."
            }

    # 4. Clean Traffic
    return {
        "action": "ALLOW",
        "risk_level": "low",
        "recommendation": "Prompt is clear of sensitive data egress patterns and injection directives.",
        "explanation": "No sensitive credentials, PII patterns, or active adversarial directives identified."
    }
