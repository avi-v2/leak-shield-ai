"""
Sensitive Data Detection and Redaction Module for Sentinel AI.

Identifies credentials, secrets, financial data, and PII using modular pattern rules,
contextual checks, and deterministic redaction.

NOTE ON REGEX DETECTION LIMITATIONS:
Regex-based pattern matching detects recognizable syntactic signatures. It cannot
detect high-entropy keys with novel formats, obfuscated credentials, or context-only secrets.
Defense-in-depth requires multiple layers of inspection.
"""

import re
from typing import List, Dict, Any, Tuple, Optional

# ==================== Modular Rule Definitions ====================

class SensitiveDataRule:
    """Represents a modular sensitive information detection rule."""

    def __init__(
        self,
        rule_type: str,
        category: str,
        description: str,
        severity: str,
        pattern: re.Pattern,
        replacement: str,
        preview_mask: str,
        validator=None,
        is_credential: bool = False
    ):
        self.rule_type = rule_type
        self.category = category
        self.description = description
        self.severity = severity
        self.pattern = pattern
        self.replacement = replacement
        self.preview_mask = preview_mask
        self.validator = validator
        self.is_credential = is_credential

    def scan(self, text: str) -> List[Dict[str, Any]]:
        findings = []
        for match in self.pattern.finditer(text):
            val = match.group(0)
            # If a capture group exists, find the targeted secret portion
            if match.groups() and match.group(1):
                start, end = match.span(1)
                secret_text = match.group(1)
            else:
                start, end = match.span()
                secret_text = val

            if self.validator and not self.validator(secret_text, text, start, end):
                continue

            findings.append({
                "type": self.rule_type,
                "category": self.category,
                "description": self.description,
                "severity": self.severity,
                "match_preview": self.preview_mask,
                "start": start,
                "end": end,
                "replacement": self.replacement,
                "is_credential": self.is_credential
            })
        return findings

# ==================== Helper Validators ====================

def luhn_checksum_valid(number_str: str) -> bool:
    """Validate credit card number using Luhn algorithm."""
    clean = re.sub(r'[\s-]', '', number_str)
    if not clean.isdigit() or len(clean) < 13 or len(clean) > 19:
        return False
    digits = [int(c) for c in clean]
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0

def card_validator(val: str, full_text: str, start: int, end: int) -> bool:
    """Validate credit card pattern with Luhn or standard major card prefix context."""
    clean = re.sub(r'[\s-]', '', val)
    if len(clean) not in (15, 16):
        return False
    # If standard Luhn check passes
    if luhn_checksum_valid(clean):
        return True
    # If explicitly prefixed with card context (e.g. Card: 4532-...)
    context_window = full_text[max(0, start - 20):start].lower()
    if any(k in context_window for k in ["card", "visa", "mastercard", "amex", "credit", "debit"]):
        return True
    return False

def aadhaar_validator(val: str, full_text: str, start: int, end: int) -> bool:
    """Validate Indian Aadhaar format (12 digits, cannot start with 0 or 1, or contextual)."""
    clean = re.sub(r'[\s-]', '', val)
    if len(clean) != 12 or not clean.isdigit():
        return False
    # Aadhaar numbers never start with 0 or 1
    first_digit = clean[0]
    if first_digit in ('0', '1'):
        return False
    # Contextual check helps eliminate plain 12-digit random numbers
    context_window = full_text[max(0, start - 30):min(len(full_text), end + 30)].lower()
    keywords = ["aadhaar", "uidai", "aadhar", "identity", "id", "card", "citizen"]
    if any(kw in context_window for kw in keywords):
        return True
    # If formatted as 4-4-4 spaces or hyphens, recognize pattern
    if re.match(r'^\d{4}[-\s]\d{4}[-\s]\d{4}$', val):
        return True
    return False

def ssn_validator(val: str, full_text: str, start: int, end: int) -> bool:
    """Validate US Social Security Number rules (area number not 000, 666, or 900+)."""
    clean = re.sub(r'[\s-]', '', val)
    if len(clean) != 9 or not clean.isdigit():
        return False
    area = int(clean[:3])
    group = int(clean[3:5])
    serial = int(clean[5:])
    if area == 0 or area == 666 or area >= 900:
        # Check if context explicitly names it SSN (for synthetic test cases)
        context = full_text[max(0, start - 20):start].lower()
        return "ssn" in context or "social" in context
    if group == 0 or serial == 0:
        return False
    return True

# ==================== Catalog of Detection Rules ====================

SENSITIVE_RULES: List[SensitiveDataRule] = [
    # 1. API Keys & Cloud Credentials
    SensitiveDataRule(
        rule_type="RULE_OPENAI_API_KEY",
        category="Credential Exfiltration",
        description="OpenAI secret key or project token detected in prompt payload.",
        severity="critical",
        pattern=re.compile(r'\b(sk-(?:proj-|svcacct-|[a-zA-Z0-9_\-]{2})[a-zA-Z0-9_\-]{20,})\b'),
        replacement="[REDACTED_API_KEY]",
        preview_mask="Signature pattern [sk-...]",
        is_credential=True
    ),
    SensitiveDataRule(
        rule_type="RULE_AWS_ACCESS_KEY",
        category="Credential Exfiltration",
        description="Amazon Web Services (AWS) Access Key ID pattern detected.",
        severity="critical",
        pattern=re.compile(r'\b(AKIA[0-9A-Z]{16})\b'),
        replacement="[REDACTED_API_KEY]",
        preview_mask="AWS Access Key [AKIA...]",
        is_credential=True
    ),
    SensitiveDataRule(
        rule_type="RULE_AWS_SECRET_KEY",
        category="Credential Exfiltration",
        description="Amazon Web Services (AWS) Secret Access Key assignment detected.",
        severity="critical",
        pattern=re.compile(r'(?:aws_secret_access_key|aws_secret|secret_key)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', re.IGNORECASE),
        replacement="[REDACTED_API_KEY]",
        preview_mask="AWS Secret Key [assignment]",
        is_credential=True
    ),
    SensitiveDataRule(
        rule_type="RULE_GITHUB_TOKEN",
        category="Credential Exfiltration",
        description="GitHub Personal Access Token or fine-grained PAT detected.",
        severity="critical",
        pattern=re.compile(r'\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{22,})\b'),
        replacement="[REDACTED_API_KEY]",
        preview_mask="GitHub Token [ghp_...]",
        is_credential=True
    ),
    SensitiveDataRule(
        rule_type="RULE_GENERIC_BEARER_TOKEN",
        category="Credential Exfiltration",
        description="HTTP Authorization Bearer token detected in prompt payload.",
        severity="critical",
        pattern=re.compile(r'(?:bearer|authorization:\s*bearer)\s+([a-zA-Z0-9_\-\.]{24,})', re.IGNORECASE),
        replacement="[REDACTED_API_KEY]",
        preview_mask="Authorization Bearer [token]",
        is_credential=True
    ),
    SensitiveDataRule(
        rule_type="RULE_GOOGLE_API_KEY",
        category="Credential Exfiltration",
        description="Google Cloud / Firebase API Key pattern detected.",
        severity="critical",
        pattern=re.compile(r'\b(AIza[0-9A-Za-z-_]{35})\b'),
        replacement="[REDACTED_API_KEY]",
        preview_mask="Google API Key [AIza...]",
        is_credential=True
    ),
    SensitiveDataRule(
        rule_type="RULE_SLACK_TOKEN",
        category="Credential Exfiltration",
        description="Slack bot or workspace token pattern detected.",
        severity="critical",
        pattern=re.compile(r'\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b'),
        replacement="[REDACTED_API_KEY]",
        preview_mask="Slack Token [xox...]",
        is_credential=True
    ),

    # 2. Raw Passwords & Secret Assignments
    SensitiveDataRule(
        rule_type="RULE_PASSWORD_ASSIGNMENT",
        category="Credential Exfiltration",
        description="Direct password assignment detected (e.g. password=..., password: ...).",
        severity="critical",
        pattern=re.compile(r'(?:password|passwd|pwd|db_pass|user_password)\s*[:=]\s*["\']?([^\s"\'`;,]{4,})["\']?', re.IGNORECASE),
        replacement="[REDACTED_PASSWORD]",
        preview_mask="Password assignment [password=***]",
        is_credential=True
    ),

    # 3. Payment Card Information (PCI-DSS)
    SensitiveDataRule(
        rule_type="RULE_PCI_DSS_CREDIT_CARD",
        category="PCI-DSS Data Leakage",
        description="Payment card number (Visa, Mastercard, AMEX, Discover) detected.",
        severity="high",
        pattern=re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
        replacement="[REDACTED_CREDIT_CARD]",
        preview_mask="Card pattern ****-****-****-****",
        validator=card_validator
    ),

    # 4. US Social Security Numbers (SSN)
    SensitiveDataRule(
        rule_type="RULE_US_SSN_PATTERN",
        category="Sensitive PII Leakage",
        description="US Social Security Number pattern detected.",
        severity="high",
        pattern=re.compile(r'\b\d{3}[-\s]\d{2}[-\s]\d{4}\b'),
        replacement="[REDACTED_SSN]",
        preview_mask="SSN pattern ***-**-****",
        validator=ssn_validator
    ),

    # 5. Indian Aadhaar Number
    SensitiveDataRule(
        rule_type="RULE_AADHAAR_NUMBER",
        category="Sensitive PII Leakage",
        description="Indian Aadhaar 12-digit national identification number detected.",
        severity="high",
        pattern=re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'),
        replacement="[REDACTED_AADHAAR]",
        preview_mask="Aadhaar format **** **** ****",
        validator=aadhaar_validator
    ),

    # 6. Indian PAN (Permanent Account Number)
    SensitiveDataRule(
        rule_type="RULE_PAN_NUMBER",
        category="Sensitive PII Leakage",
        description="Indian Income Tax Permanent Account Number (PAN) detected.",
        severity="high",
        pattern=re.compile(r'\b([A-Z]{5}[0-9]{4}[A-Z])\b'),
        replacement="[REDACTED_PAN]",
        preview_mask="PAN format [*****0000*]"
    ),

    # 7. Personal Email Addresses
    SensitiveDataRule(
        rule_type="RULE_EMAIL_ADDRESS",
        category="Personal Identifiable Info",
        description="Personal email address detected.",
        severity="medium",
        pattern=re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
        replacement="[REDACTED_EMAIL]",
        preview_mask="Email pattern [***@***]"
    ),

    # 8. Telephone Numbers (International & Regional)
    SensitiveDataRule(
        rule_type="RULE_PHONE_NUMBER",
        category="Personal Identifiable Info",
        description="Telephone or mobile phone number detected.",
        severity="medium",
        pattern=re.compile(r'(?:\+?(\d{1,3})[-.\s]?)?\(?(\d{3})\)?[-.\s]?(\d{3})[-.\s]?(\d{4})\b|\b(?:\+91[-.\s]?)?[6-9]\d{9}\b'),
        replacement="[REDACTED_PHONE]",
        preview_mask="Phone number [***-***-****]"
    ),
]

def scan_sensitive_data(text: str, policy: Optional[Dict[str, Any]] = None) -> Tuple[List[Dict[str, Any]], str]:
    """
    Scan text against sensitive data rules based on active security policy.
    Returns:
        (findings, redacted_text)
    Guarantees deterministic redaction from right-to-left to preserve span offsets.
    """
    if not text:
        return [], ""

    pol = policy or {}
    detect_api_keys = pol.get("detectApiKeys", True) # Mandatory
    detect_passwords = pol.get("detectPasswords", True) # Mandatory
    detect_cards = pol.get("detectCreditCards", True)
    detect_ssn = pol.get("detectSsn", True)
    detect_emails = pol.get("detectEmails", True)
    detect_aadhaar = pol.get("detectAadhaar", True)
    detect_pan = pol.get("detectPan", True)
    detect_phone = pol.get("detectPhone", True)

    raw_findings: List[Dict[str, Any]] = []

    for rule in SENSITIVE_RULES:
        # Check policy switches
        if rule.is_credential:
            # Mandatory credential rules cannot be skipped
            pass
        elif "CREDIT_CARD" in rule.rule_type and not detect_cards:
            continue
        elif "SSN" in rule.rule_type and not detect_ssn:
            continue
        elif "EMAIL" in rule.rule_type and not detect_emails:
            continue
        elif "AADHAAR" in rule.rule_type and not detect_aadhaar:
            continue
        elif "PAN" in rule.rule_type and not detect_pan:
            continue
        elif "PHONE" in rule.rule_type and not detect_phone:
            continue

        findings = rule.scan(text)
        raw_findings.extend(findings)

    if not raw_findings:
        return [], text

    # Deduplicate overlapping spans: prioritize longer spans and higher severity
    # Sort findings by start ascending, length descending
    raw_findings.sort(key=lambda f: (f["start"], -(f["end"] - f["start"])))

    non_overlapping: List[Dict[str, Any]] = []
    current_end = -1

    for f in raw_findings:
        if f["start"] >= current_end:
            non_overlapping.append(f)
            current_end = f["end"]

    # Redact text from right to left (descending order of start)
    redacted = text
    for f in sorted(non_overlapping, key=lambda x: x["start"], reverse=True):
        start = f["start"]
        end = f["end"]
        rep = f["replacement"]
        redacted = redacted[:start] + rep + redacted[end:]

    # Clean findings payload for external exposure (strip internal replacement/credential flags)
    clean_findings = []
    for f in non_overlapping:
        clean_findings.append({
            "type": f["type"],
            "category": f["category"],
            "description": f["description"],
            "severity": f["severity"],
            "match_preview": f["match_preview"],
            "start": f["start"],
            "end": f["end"]
        })

    return clean_findings, redacted
