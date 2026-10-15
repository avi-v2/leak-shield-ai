"""
Tests for sensitive data detection and redaction rules.
Uses synthetic test tokens only.
"""

from app.security.sensitive_data import scan_sensitive_data

def test_email_detection_and_redaction():
    """Verify email detection and deterministic masking."""
    prompt = "Contact our support team at sample.user@example-corp.com for assistance."
    findings, redacted = scan_sensitive_data(prompt)

    assert len(findings) == 1
    assert findings[0]["type"] == "RULE_EMAIL_ADDRESS"
    assert findings[0]["category"] == "Personal Identifiable Info"
    assert "sample.user@example-corp.com" not in redacted
    assert "[REDACTED_EMAIL]" in redacted
    # Ensure character span matches
    start = findings[0]["start"]
    end = findings[0]["end"]
    assert prompt[start:end] == "sample.user@example-corp.com"

def test_api_key_detection_and_redaction():
    """Verify OpenAI and AWS synthetic key patterns are detected."""
    # Synthetic mock key (non-functional placeholder)
    synthetic_key = "sk-proj-abc123456789012345678901234567890"
    prompt = f"Initialize client with key: {synthetic_key}"
    findings, redacted = scan_sensitive_data(prompt)

    assert len(findings) >= 1
    api_key_finding = next(f for f in findings if "API_KEY" in f["type"])
    assert api_key_finding["category"] == "Credential Exfiltration"
    assert api_key_finding["severity"] == "critical"
    # Ensure raw secret is NOT leaked in match_preview
    assert synthetic_key not in api_key_finding["match_preview"]
    assert "[REDACTED_API_KEY]" in redacted
    assert synthetic_key not in redacted

def test_password_assignment_detection():
    """Verify password assignment patterns like password=... are detected."""
    prompt = "Connecting to database: host=localhost; user=admin; password=SyntheticSecretPass123"
    findings, redacted = scan_sensitive_data(prompt)

    assert len(findings) >= 1
    pwd_finding = next(f for f in findings if f["type"] == "RULE_PASSWORD_ASSIGNMENT")
    assert pwd_finding["category"] == "Credential Exfiltration"
    assert "SyntheticSecretPass123" not in redacted
    assert "[REDACTED_PASSWORD]" in redacted

def test_pan_and_aadhaar_detection():
    """Verify Indian PAN and Aadhaar synthetic patterns."""
    # Synthetic PAN format: 5 letters, 4 digits, 1 letter
    prompt = "Customer PAN is ABCDE1234F and Aadhaar is 9876 5432 1098."
    findings, redacted = scan_sensitive_data(prompt)

    pan_finding = next((f for f in findings if f["type"] == "RULE_PAN_NUMBER"), None)
    aadhaar_finding = next((f for f in findings if f["type"] == "RULE_AADHAAR_NUMBER"), None)

    assert pan_finding is not None
    assert aadhaar_finding is not None
    assert "ABCDE1234F" not in redacted
    assert "9876 5432 1098" not in redacted
    assert "[REDACTED_PAN]" in redacted
    assert "[REDACTED_AADHAAR]" in redacted

def test_phone_number_detection():
    """Verify phone number patterns are redacted."""
    prompt = "Reach our emergency hotline at +1-800-555-0199 or 9876543210."
    findings, redacted = scan_sensitive_data(prompt)

    assert len(findings) >= 1
    assert "[REDACTED_PHONE]" in redacted

def test_clean_text_no_false_positives():
    """Verify clean benign text triggers zero findings."""
    clean_prompt = "Write a python function to compute the shortest path using Dijkstra algorithm."
    findings, redacted = scan_sensitive_data(clean_prompt)

    assert len(findings) == 0
    assert redacted == clean_prompt
