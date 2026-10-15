"""
Tests for security policy engine decision logic.
"""

from app.security.policy_engine import evaluate_security_policy

def test_mandatory_blocking_of_credentials():
    """Verify detected credentials/secrets are ALWAYS blocked."""
    sensitive_findings = [
        {
            "type": "RULE_OPENAI_API_KEY",
            "category": "Credential Exfiltration",
            "description": "API key detected",
            "severity": "critical",
            "match_preview": "Signature pattern [sk-...]"
        }
    ]
    # Even if policy attempts to set defaultAction = ALLOW
    policy = {"defaultAction": "ALLOW", "highRiskThreshold": "critical"}

    decision = evaluate_security_policy(
        sensitive_findings=sensitive_findings,
        injection_findings=[],
        injection_risk="none",
        policy=policy
    )

    assert decision["action"] == "BLOCK"
    assert decision["risk_level"] == "critical"

def test_policy_redaction_for_pii():
    """Verify PII triggers REDACT when defaultAction is REDACT."""
    sensitive_findings = [
        {
            "type": "RULE_EMAIL_ADDRESS",
            "category": "Personal Identifiable Info",
            "description": "Email address detected",
            "severity": "medium",
            "match_preview": "Email pattern"
        }
    ]
    policy = {"defaultAction": "REDACT", "highRiskThreshold": "high"}

    decision = evaluate_security_policy(
        sensitive_findings=sensitive_findings,
        injection_findings=[],
        injection_risk="none",
        policy=policy
    )

    assert decision["action"] == "REDACT"
    assert decision["risk_level"] == "medium"

def test_policy_block_pii_when_configured():
    """Verify strict defaultAction=BLOCK rejects PII."""
    sensitive_findings = [
        {
            "type": "RULE_EMAIL_ADDRESS",
            "category": "Personal Identifiable Info",
            "description": "Email address detected",
            "severity": "medium",
            "match_preview": "Email pattern"
        }
    ]
    policy = {"defaultAction": "BLOCK", "highRiskThreshold": "high"}

    decision = evaluate_security_policy(
        sensitive_findings=sensitive_findings,
        injection_findings=[],
        injection_risk="none",
        policy=policy
    )

    assert decision["action"] == "BLOCK"

def test_clean_request_allowed():
    """Verify clean traffic with zero findings is ALLOWED."""
    policy = {"defaultAction": "REDACT", "highRiskThreshold": "high"}

    decision = evaluate_security_policy(
        sensitive_findings=[],
        injection_findings=[],
        injection_risk="none",
        policy=policy
    )

    assert decision["action"] == "ALLOW"
    assert decision["risk_level"] == "low"
