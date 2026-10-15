"""
Prompt Injection and Adversarial Manipulation Detector for Sentinel AI.

Combines rule-based heuristic patterns (jailbreak tokens, delimiter escaping,
system prompt extraction directives) with the trained TF-IDF + Logistic Regression
machine learning classifier.
"""

import re
from typing import List, Dict, Any, Tuple, Optional
from app.security.classifier import get_classifier

# Known heuristic injection patterns
HEURISTIC_INJECTION_PATTERNS = [
    (
        "RULE_INSTRUCTION_OVERRIDE",
        "Prompt Injection",
        "Directive detected attempting instruction override (ignore/disregard previous directives)",
        "critical",
        re.compile(r'(ignore|disregard|forget|bypass)\s+(all\s+)?(previous|prior|initial)\s+(instructions|guidelines|directives|rules|constraints)', re.IGNORECASE),
        "Instruction Override Directive"
    ),
    (
        "RULE_DAN_PERSONA_JAILBREAK",
        "Jailbreak (DAN)",
        "Adversarial persona adoption detected (Do Anything Now / Unrestricted persona)",
        "critical",
        re.compile(r'\b(you\s+are\s+now\s+(unrestricted|DAN|AIM|STAN|Developer Mode)|act\s+as\s+DAN|do\s+anything\s+now)\b', re.IGNORECASE),
        "DAN / Unrestricted Persona"
    ),
    (
        "RULE_SYSTEM_PROMPT_EXTRACTION",
        "System Prompt Extraction",
        "Directive attempting to exfiltrate hidden system prompt initialization verbatim",
        "high",
        re.compile(r'(system\s+prompt\s+verbatim|output\s+(your\s+)?(initialization|system)\s+(instructions|prompt)|print\s+everything\s+above|repeat\s+from\s+line\s+1)', re.IGNORECASE),
        "System Extraction Directive"
    ),
    (
        "RULE_DELIMITER_HIJACK",
        "Prompt Injection",
        "Adversarial delimiter hijack attempting to break prompt framing",
        "critical",
        re.compile(r'(---\s*\[?STOP SYSTEM|--- END SYSTEM PROMPT ---|<\|im_end\|>|<\|endoftext\|>|\[SYSTEM OVERRIDE\])', re.IGNORECASE),
        "Delimiter Hijack Pattern"
    ),
    (
        "RULE_JAILBREAK_DEVELOPER_MODE",
        "Jailbreak (DAN)",
        "Adversarial attempt to simulate Developer Mode or unrestricted bypass mode",
        "critical",
        re.compile(r'(enable\s+developer\s+mode|simulate\s+unfiltered\s+response|you\s+have\s+no\s+filters)', re.IGNORECASE),
        "Developer Mode Bypass"
    )
]

def detect_prompt_injection(
    text: str,
    policy: Optional[Dict[str, Any]] = None
) -> Tuple[List[Dict[str, Any]], str, bool, Optional[float]]:
    """
    Detect prompt injection through both heuristics and machine learning classifier.

    Returns:
        (findings, prompt_injection_risk, classifier_available, classifier_score)
        where prompt_injection_risk is in ["none", "low", "medium", "high"]
    """
    if not text or not text.strip():
        return [], "none", False, None

    pol = policy or {}
    block_injection = pol.get("blockPromptInjection", True)
    block_jailbreaks = pol.get("blockJailbreaks", True)
    block_extraction = pol.get("blockSystemPromptExtraction", True)

    findings: List[Dict[str, Any]] = []
    heuristic_triggered = False

    # 1. Evaluate Heuristic Patterns
    for rule_type, cat, desc, severity, pattern, preview in HEURISTIC_INJECTION_PATTERNS:
        # Check specific policy controls
        if "JAILBREAK" in rule_type and not block_jailbreaks:
            continue
        if "EXTRACTION" in rule_type and not block_extraction:
            continue
        if ("OVERRIDE" in rule_type or "DELIMITER" in rule_type) and not block_injection:
            continue

        match = pattern.search(text)
        if match:
            start, end = match.span()
            findings.append({
                "type": rule_type,
                "category": cat,
                "description": desc,
                "severity": severity,
                "match_preview": preview,
                "start": start,
                "end": end
            })
            heuristic_triggered = True

    # 2. Evaluate ML Classifier
    clf = get_classifier()
    clf_available = clf.is_available()
    clf_score: Optional[float] = None
    ml_triggered = False

    if clf_available:
        is_injection_pred, score = clf.predict(text, threshold=0.5)
        clf_score = score
        if is_injection_pred and block_injection:
            ml_triggered = True
            # Only add ML finding if not already flagged by heuristics to avoid duplicate noise
            if not heuristic_triggered:
                findings.append({
                    "type": "RULE_ML_INJECTION_CLASSIFIER",
                    "category": "Prompt Injection",
                    "description": f"Statistical anomaly detected by prompt injection classifier (confidence: {score:.1%}).",
                    "severity": "high" if (score and score > 0.8) else "medium",
                    "match_preview": "ML Statistical Injection Classifier",
                    "start": 0,
                    "end": len(text)
                })

    # Determine injection risk level
    if heuristic_triggered or (clf_score is not None and clf_score >= 0.75):
        risk = "high"
    elif ml_triggered or (clf_score is not None and clf_score >= 0.45):
        risk = "medium"
    elif clf_score is not None and clf_score >= 0.2:
        risk = "low"
    else:
        risk = "none"

    return findings, risk, clf_available, clf_score
