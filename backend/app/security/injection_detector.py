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
            matched_raw = match.group(0)
            norm_phrase = re.sub(r'\s+', ' ', matched_raw.strip().lower())
            findings.append({
                "type": rule_type,
                "category": cat,
                "description": desc,
                "severity": severity,
                "match_preview": preview,
                "start": start,
                "end": end,
                "matched_text": norm_phrase
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
                    "end": len(text),
                    "matched_text": "statistical anomaly (ml classifier)"
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

# Canonical candidate phrases for prompt injection intelligence analysis
CANDIDATE_INJECTION_PHRASES: List[Tuple[str, str, str]] = [
    ("ignore all previous instructions", "Prompt Injection", "Instruction Override"),
    ("ignore previous instructions", "Prompt Injection", "Instruction Override"),
    ("disregard previous instructions", "Prompt Injection", "Instruction Override"),
    ("ignore the system message", "Prompt Injection", "Instruction Override"),
    ("override instructions", "Prompt Injection", "Instruction Override"),
    ("reveal your system prompt", "System Prompt Extraction", "System Extraction"),
    ("reveal the system prompt", "System Prompt Extraction", "System Extraction"),
    ("reveal secrets", "System Prompt Extraction", "Secret Exfiltration"),
    ("exfiltrate", "System Prompt Extraction", "Data Exfiltration"),
    ("developer mode", "Jailbreak (DAN)", "Developer Mode Bypass"),
    ("act as an unrestricted ai", "Jailbreak (DAN)", "Unrestricted Persona"),
    ("do anything now", "Jailbreak (DAN)", "DAN Persona Jailbreak"),
    ("dan", "Jailbreak (DAN)", "DAN Persona Jailbreak"),
    ("jailbreak", "Jailbreak (DAN)", "Jailbreak Directive"),
    ("bypass safety", "Prompt Injection", "Safety Filter Bypass"),
    ("bypass restrictions", "Prompt Injection", "Constraint Bypass"),
]

def extract_injection_indicators(
    text: str,
    findings: List[Dict[str, Any]],
    clf_score: Optional[float] = None
) -> List[Dict[str, Any]]:
    """
    Extract structured, non-sensitive detection indicators for dashboard intelligence.
    Normalizes case and whitespace without storing raw malicious prompt text.
    Distinguishes exact regex rule matches from keyword text analysis and ML predictions.
    """
    indicators: List[Dict[str, Any]] = []
    seen_phrases = set()

    # 1. Exact heuristic rule matches from findings
    for f in findings:
        cat = f.get("category", "")
        if "Injection" in cat or "Jailbreak" in cat or "System" in cat or "Override" in cat:
            matched_text = f.get("matched_text")
            if matched_text and matched_text not in seen_phrases:
                seen_phrases.add(matched_text)
                indicators.append({
                    "phrase": matched_text,
                    "detection_method": "regex_heuristic",
                    "category": cat,
                    "rule": f.get("type", "HEURISTIC_RULE"),
                    "is_exact_rule": True
                })

    # 2. Text keyword analysis for candidate phrases in flagged text
    # (Only run if at least one injection/jailbreak finding exists or classifier score is high)
    has_injection_risk = bool(indicators) or (clf_score is not None and clf_score >= 0.5)
    if has_injection_risk and text:
        norm_text = re.sub(r'\s+', ' ', text.strip().lower())
        for phrase, category, rule_desc in CANDIDATE_INJECTION_PHRASES:
            # Check whole phrase presence with word boundaries where feasible
            pattern = r'\b' + re.escape(phrase) + r'\b'
            if re.search(pattern, norm_text) and phrase not in seen_phrases:
                seen_phrases.add(phrase)
                indicators.append({
                    "phrase": phrase,
                    "detection_method": "keyword_analysis",
                    "category": category,
                    "rule": f"KEYWORD_{rule_desc.upper().replace(' ', '_')}",
                    "is_exact_rule": False
                })

    # 3. Statistical ML classifier anomaly
    if clf_score is not None and clf_score >= 0.6:
        ml_phrase = "statistical anomaly (ml classifier)"
        if ml_phrase not in seen_phrases:
            seen_phrases.add(ml_phrase)
            indicators.append({
                "phrase": ml_phrase,
                "detection_method": "ml_classifier",
                "category": "Prompt Injection",
                "rule": "RULE_ML_INJECTION_CLASSIFIER",
                "is_exact_rule": False
            })

    return indicators

