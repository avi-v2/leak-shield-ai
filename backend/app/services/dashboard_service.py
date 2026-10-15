"""
Dashboard Analytics and Aggregation Service for Sentinel AI / Leak-Shield-AI.

Executes parameterized SQL queries against the SQLite database to compute
real-time cybersecurity metrics, time-series telemetry, threat category distributions,
injection keyword intelligence, DLP analytics, policy verdicts, and file/image security.

Strict Privacy Guarantee:
Never returns raw passwords, API keys, full payment cards, or unredacted prompts.
All statistics are computed from real database records with documented denominators.
"""

import json
import re
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple
from app.database import get_db_connection, init_db, load_policies

# Color mapping for cybersecurity visual hierarchy
CATEGORY_COLORS = {
    "Prompt Injection": "#EF4444",          # Red
    "Jailbreak Attempts": "#DC2626",        # Deep Red
    "API Keys & Access Tokens": "#F59E0B",   # Amber
    "Passwords & Credentials": "#D97706",   # Deep Amber
    "Email Addresses": "#3B82F6",           # Blue
    "Payment Cards": "#EC4899",             # Pink
    "Indian Identifiers (PAN/Aadhaar)": "#8B5CF6", # Violet
    "Phone Numbers": "#06B6D4",             # Cyan
    "Image Metadata & GPS": "#10B981",      # Emerald
    "Suspicious Document Content": "#F97316", # Orange
    "Other Sensitive Data": "#64748B",      # Slate
}

def get_cutoff_iso(time_range: str) -> Optional[str]:
    """Calculate ISO 8601 UTC timestamp cutoff for filtering."""
    now = datetime.now(timezone.utc)
    if time_range == "1h":
        cutoff = now - timedelta(hours=1)
    elif time_range == "24h":
        cutoff = now - timedelta(hours=24)
    elif time_range == "7d":
        cutoff = now - timedelta(days=7)
    elif time_range == "30d":
        cutoff = now - timedelta(days=30)
    elif time_range == "all":
        return None
    else:
        # Default fallback to 24h if unrecognized
        cutoff = now - timedelta(hours=24)
    return cutoff.isoformat()

def normalize_category_name(raw_cat: str) -> str:
    """Map raw detection categories into canonical dashboard categories."""
    c = (raw_cat or "").strip().lower()
    if "jailbreak" in c:
        return "Jailbreak Attempts"
    if "injection" in c or "override" in c or "delimiter" in c or "extraction" in c:
        return "Prompt Injection"
    if "api" in c or "token" in c or "aws" in c or "openai" in c or "github" in c:
        return "API Keys & Access Tokens"
    if "password" in c:
        return "Passwords & Credentials"
    if "credit" in c or "card" in c or "pci" in c:
        return "Payment Cards"
    if "pan" in c or "aadhaar" in c:
        return "Indian Identifiers (PAN/Aadhaar)"
    if "email" in c:
        return "Email Addresses"
    if "phone" in c:
        return "Phone Numbers"
    if "gps" in c or "exif" in c or "metadata" in c:
        return "Image Metadata & GPS"
    if "document" in c or "cell" in c or "file" in c:
        return "Suspicious Document Content"
    if "credential" in c or "secret" in c:
        return "Passwords & Credentials"
    if "pii" in c or "ssn" in c:
        return "Other Sensitive Data"
    return "Other Sensitive Data"

def get_dashboard_summary(time_range: str = "all") -> Dict[str, Any]:
    """
    Compute top-level KPI metrics from real SQLite events.
    Handles zero denominators safely.
    Distinguishes total unique scans from individual security findings.
    """
    init_db()
    cutoff = get_cutoff_iso(time_range)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        where_sql = " WHERE timestamp >= ?" if cutoff else ""
        params = [cutoff] if cutoff else []

        # 1. Total Scans (prompts, files, images)
        cursor.execute(f"SELECT COUNT(*) FROM events {where_sql}", params)
        total_scans = cursor.fetchone()[0]

        # 2. Allowed requests
        and_or_where = " AND " if cutoff else " WHERE "
        cursor.execute(f"SELECT COUNT(*) FROM events {where_sql}{and_or_where}action_taken = 'ALLOW'", params)
        allowed_requests = cursor.fetchone()[0]

        # 3. Blocked requests
        cursor.execute(f"SELECT COUNT(*) FROM events {where_sql}{and_or_where}action_taken = 'BLOCK'", params)
        blocked_requests = cursor.fetchone()[0]

        # 4. Redacted requests
        cursor.execute(f"SELECT COUNT(*) FROM events {where_sql}{and_or_where}action_taken = 'REDACT'", params)
        redacted_requests = cursor.fetchone()[0]

        # 5. Threats Detected: scans containing at least one security finding
        cursor.execute(f"""
            SELECT COUNT(*) FROM events
            {where_sql}
            {and_or_where}(action_taken IN ('BLOCK', 'REDACT') OR finding_count > 0 OR threat_category NOT IN ('Clean Traffic', 'Image Privacy Scan', 'Normal', 'None'))
        """, params)
        threats_detected = cursor.fetchone()[0]

        clean_scans = max(0, total_scans - threats_detected)

        # 6. Documented Percentage Metrics with Safe Denominators
        threat_rate_pct = round((threats_detected / total_scans) * 100, 2) if total_scans > 0 else 0.0
        block_rate_pct = round((blocked_requests / total_scans) * 100, 2) if total_scans > 0 else 0.0

        # 7. Scans by input medium
        cursor.execute(f"""
            SELECT
                SUM(CASE WHEN LOWER(input_type) = 'file' OR LOWER(source) LIKE '%file%' THEN 1 ELSE 0 END) as files_count,
                SUM(CASE WHEN LOWER(input_type) = 'image' OR LOWER(source) LIKE '%image%' THEN 1 ELSE 0 END) as images_count,
                SUM(CASE WHEN LOWER(input_type) NOT IN ('file', 'image') AND LOWER(source) NOT LIKE '%file%' AND LOWER(source) NOT LIKE '%image%' THEN 1 ELSE 0 END) as prompts_count
            FROM events
            {where_sql}
        """, params)
        medium_row = cursor.fetchone()
        files_scanned = medium_row["files_count"] or 0
        images_scanned = medium_row["images_count"] or 0
        prompts_scanned = medium_row["prompts_count"] or 0

        # 8. Injection attempts (scans flagged for prompt injection or jailbreak)
        cursor.execute(f"""
            SELECT COUNT(*) FROM events
            {where_sql}
            {and_or_where}(
                LOWER(threat_category) LIKE '%injection%'
                OR LOWER(threat_category) LIKE '%jailbreak%'
                OR LOWER(threat_category) LIKE '%system%'
                OR LOWER(threat_category) LIKE '%override%'
                OR matched_rules LIKE '%INJECTION%'
                OR matched_rules LIKE '%JAILBREAK%'
                OR matched_rules LIKE '%OVERRIDE%'
                OR matched_rules LIKE '%EXTRACTION%'
            )
        """, params)
        injection_attempts = cursor.fetchone()[0]

        # 9. Sensitive data findings count (total detected sensitive-data instances)
        cursor.execute(f"SELECT threat_category, matched_rules, findings_json, finding_count FROM events {where_sql}", params)
        rows = cursor.fetchall()

        sensitive_data_findings = 0
        for r in rows:
            findings_raw = r["findings_json"] if "findings_json" in r.keys() else None
            f_list = []
            if findings_raw:
                try:
                    f_list = json.loads(findings_raw)
                except Exception:
                    f_list = []
            if f_list:
                for f in f_list:
                    cat = f.get("category", "").lower()
                    if any(k in cat for k in ["credential", "key", "password", "pii", "card", "email", "ssn", "aadhaar", "pan", "phone", "metadata", "gps"]):
                        sensitive_data_findings += 1
            else:
                # Fallback to matched_rules and threat_category
                try:
                    rules = json.loads(r["matched_rules"])
                except Exception:
                    rules = []
                cat = r["threat_category"].lower()
                if any(k in cat for k in ["credential", "key", "password", "pii", "card", "email", "ssn", "aadhaar", "pan", "phone", "metadata", "gps"]):
                    non_inj_rules = [rl for rl in rules if not any(x in rl for x in ["INJECTION", "JAILBREAK", "OVERRIDE"])]
                    sensitive_data_findings += max(1, len(non_inj_rules))

        return {
            "total_scans": total_scans,
            "threats_detected": threats_detected,
            "clean_scans": clean_scans,
            "blocked_requests": blocked_requests,
            "redacted_requests": redacted_requests,
            "allowed_requests": allowed_requests,
            "threat_rate_pct": threat_rate_pct,
            "block_rate_pct": block_rate_pct,
            "sensitive_data_findings": sensitive_data_findings,
            "injection_attempts": injection_attempts,
            "prompts_scanned": prompts_scanned,
            "files_scanned": files_scanned,
            "images_scanned": images_scanned,
            "time_window": time_range,
            "generated_at": datetime.now(timezone.utc).isoformat()
        }

def get_activity_timeline(time_range: str = "24h") -> List[Dict[str, Any]]:
    """
    Generate time-series activity data from real timestamps in SQLite.
    Aggregates events into suitable buckets (hours, days, or 5-min intervals).
    """
    init_db()
    cutoff = get_cutoff_iso(time_range)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        where_sql = " WHERE timestamp >= ?" if cutoff else ""
        params = [cutoff] if cutoff else []

        cursor.execute(f"SELECT timestamp, action_taken, threat_category, finding_count FROM events {where_sql} ORDER BY timestamp ASC", params)
        rows = cursor.fetchall()

    if not rows:
        return []

    buckets: Dict[str, Dict[str, Any]] = {}

    for r in rows:
        ts_str = r["timestamp"]
        try:
            # Parse ISO timestamp safely
            clean_ts = ts_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean_ts)
        except Exception:
            continue

        if time_range == "1h":
            # 5-minute buckets (e.g. 14:05, 14:10)
            minute_bucket = (dt.minute // 5) * 5
            bucket_key = dt.strftime(f"%H:{minute_bucket:02d}")
            display_label = bucket_key
        elif time_range == "24h":
            # Hourly buckets (e.g. 14:00)
            bucket_key = dt.strftime("%Y-%m-%d %H:00")
            display_label = dt.strftime("%H:00")
        elif time_range in ("7d", "30d"):
            # Daily buckets (e.g. 2026-10-16 / Oct 16)
            bucket_key = dt.strftime("%Y-%m-%d")
            display_label = dt.strftime("%b %d")
        else: # "all"
            # Daily buckets if span > 2 days, else hourly
            bucket_key = dt.strftime("%Y-%m-%d")
            display_label = dt.strftime("%b %d")

        if bucket_key not in buckets:
            buckets[bucket_key] = {
                "time": display_label,
                "timestamp": bucket_key,
                "inspected": 0,
                "threats": 0,
                "blocked": 0,
                "redacted": 0,
                "allowed": 0
            }

        b = buckets[bucket_key]
        b["inspected"] += 1
        action = r["action_taken"]
        if action == "BLOCK":
            b["blocked"] += 1
            b["threats"] += 1
        elif action == "REDACT":
            b["redacted"] += 1
            b["threats"] += 1
        elif action == "ALLOW":
            b["allowed"] += 1
            if r["finding_count"] > 0 or r["threat_category"] not in ("Clean Traffic", "Image Privacy Scan", "Normal", "None"):
                b["threats"] += 1

    return list(buckets.values())

def get_threat_categories(time_range: str = "all") -> Dict[str, Any]:
    """
    Compute threat category distribution.
    Clearly distinguishes findings count from unique scans count.
    """
    init_db()
    cutoff = get_cutoff_iso(time_range)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        where_sql = " WHERE timestamp >= ?" if cutoff else ""
        params = [cutoff] if cutoff else []

        cursor.execute(f"""
            SELECT id, threat_category, matched_rules, findings_json, action_taken
            FROM events
            {where_sql}
        """, params)
        rows = cursor.fetchall()

    category_findings: Dict[str, int] = {}
    category_scans: Dict[str, set] = {}
    severity_breakdown: Dict[str, Dict[str, int]] = {}
    total_findings = 0
    unique_threatened_scan_ids = set()

    for r in rows:
        evt_id = r["id"]
        findings_raw = r["findings_json"] if "findings_json" in r.keys() else None
        f_list = []
        if findings_raw:
            try:
                f_list = json.loads(findings_raw)
            except Exception:
                f_list = []

        if f_list:
            for f in f_list:
                cat_name = normalize_category_name(f.get("category", ""))
                sev = (f.get("severity") or "medium").lower()

                category_findings[cat_name] = category_findings.get(cat_name, 0) + 1
                total_findings += 1

                if cat_name not in category_scans:
                    category_scans[cat_name] = set()
                category_scans[cat_name].add(evt_id)
                unique_threatened_scan_ids.add(evt_id)

                if cat_name not in severity_breakdown:
                    severity_breakdown[cat_name] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                if sev in severity_breakdown[cat_name]:
                    severity_breakdown[cat_name][sev] += 1
        elif r["action_taken"] in ("BLOCK", "REDACT"):
            # Fallback for events with matched_rules
            cat_name = normalize_category_name(r["threat_category"])
            category_findings[cat_name] = category_findings.get(cat_name, 0) + 1
            total_findings += 1

            if cat_name not in category_scans:
                category_scans[cat_name] = set()
            category_scans[cat_name].add(evt_id)
            unique_threatened_scan_ids.add(evt_id)

            if cat_name not in severity_breakdown:
                severity_breakdown[cat_name] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            severity_breakdown[cat_name]["high"] += 1

    # Format result list sorted by findings count descending
    categories_result = []
    for cat_name, count in sorted(category_findings.items(), key=lambda x: x[1], reverse=True):
        scans_count = len(category_scans.get(cat_name, set()))
        pct = round((count / total_findings) * 100, 1) if total_findings > 0 else 0.0
        categories_result.append({
            "name": cat_name,
            "category": cat_name,
            "count": count,
            "findings_count": count,
            "unique_scans_count": scans_count,
            "percentage": pct,
            "color": CATEGORY_COLORS.get(cat_name, "#64748B"),
            "severity_breakdown": severity_breakdown.get(cat_name, {"critical": 0, "high": 0, "medium": 0, "low": 0})
        })

    return {
        "categories": categories_result,
        "total_findings": total_findings,
        "unique_threatened_scans": len(unique_threatened_scan_ids),
        "explanation": "findings_count represents total detected instances; unique_scans_count represents distinct scans containing this category."
    }

def get_injection_keywords(time_range: str = "all", limit: int = 15) -> Dict[str, Any]:
    """
    Extract and aggregate injection keywords, phrases, and indicators from actual flagged events.
    Normalizes whitespace and case.
    Distinguishes exact regex rule matches from text keyword indicators and ML classifier anomalies.
    """
    init_db()
    cutoff = get_cutoff_iso(time_range)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        where_sql = " WHERE timestamp >= ?" if cutoff else ""
        params = [cutoff] if cutoff else []

        cursor.execute(f"""
            SELECT id, indicators_json, matched_rules, summary, threat_category
            FROM events
            {where_sql}
        """, params)
        rows = cursor.fetchall()

    phrase_data: Dict[str, Dict[str, Any]] = {}
    flagged_scan_ids = set()
    total_indicator_matches = 0

    for r in rows:
        evt_id = r["id"]
        ind_raw = r["indicators_json"] if "indicators_json" in r.keys() else None
        indicators = []
        if ind_raw:
            try:
                indicators = json.loads(ind_raw)
            except Exception:
                indicators = []

        if indicators:
            flagged_scan_ids.add(evt_id)
            for ind in indicators:
                phrase = (ind.get("phrase") or "").strip().lower()
                phrase = re.sub(r'\s+', ' ', phrase)
                if not phrase:
                    continue

                total_indicator_matches += 1
                if phrase not in phrase_data:
                    phrase_data[phrase] = {
                        "phrase": phrase,
                        "count": 0,
                        "events": set(),
                        "detection_methods": set(),
                        "category": ind.get("category", "Prompt Injection"),
                        "is_exact_rule": ind.get("is_exact_rule", False),
                    }
                item = phrase_data[phrase]
                item["count"] += 1
                item["events"].add(evt_id)
                if ind.get("detection_method"):
                    item["detection_methods"].add(ind["detection_method"])
                if ind.get("is_exact_rule"):
                    item["is_exact_rule"] = True
        else:
            # Fallback for historical events without indicators_json
            cat = r["threat_category"].lower()
            if any(k in cat for k in ["injection", "jailbreak", "override", "system"]):
                flagged_scan_ids.add(evt_id)
                try:
                    rules = json.loads(r["matched_rules"])
                except Exception:
                    rules = []

                for rule in rules:
                    rule_clean = rule.replace("RULE_", "").replace("_", " ").lower()
                    if rule_clean not in phrase_data:
                        phrase_data[rule_clean] = {
                            "phrase": rule_clean,
                            "count": 0,
                            "events": set(),
                            "detection_methods": {"regex_heuristic"},
                            "category": r["threat_category"],
                            "is_exact_rule": True,
                        }
                    phrase_data[rule_clean]["count"] += 1
                    phrase_data[rule_clean]["events"].add(evt_id)
                    total_indicator_matches += 1

    total_flagged = len(flagged_scan_ids)
    sorted_phrases = sorted(phrase_data.values(), key=lambda x: x["count"], reverse=True)[:limit]

    formatted_indicators = []
    for item in sorted_phrases:
        unique_evts = len(item["events"])
        pct = round((unique_evts / total_flagged) * 100, 1) if total_flagged > 0 else 0.0
        formatted_indicators.append({
            "phrase": item["phrase"],
            "count": item["count"],
            "unique_events_count": unique_evts,
            "percentage_of_flagged_scans": pct,
            "detection_methods": sorted(list(item["detection_methods"])),
            "associated_category": item["category"],
            "is_exact_rule": item["is_exact_rule"]
        })

    return {
        "total_flagged_scans": total_flagged,
        "total_indicator_matches": total_indicator_matches,
        "indicators": formatted_indicators,
        "disclaimer": "Keyword and phrase frequency is based on rule matches and text indicator analysis of flagged prompts. Keyword presence alone does not constitute semantic AI evaluation."
    }

def get_dlp_analytics(time_range: str = "all") -> Dict[str, Any]:
    """
    Compute sensitive data and DLP statistics.
    Never exposes raw secrets; returns only sanitized previews (e.g. sk-****abcd).
    """
    init_db()
    cutoff = get_cutoff_iso(time_range)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        where_sql = " WHERE timestamp >= ?" if cutoff else ""
        params = [cutoff] if cutoff else []

        cursor.execute(f"SELECT COUNT(*) FROM events {where_sql}", params)
        total_scans = cursor.fetchone()[0]

        cursor.execute(f"""
            SELECT id, threat_category, matched_rules, findings_json, sanitized_preview, action_taken, timestamp
            FROM events
            {where_sql}
            ORDER BY timestamp DESC
        """, params)
        rows = cursor.fetchall()

    category_counts: Dict[str, int] = {}
    scans_with_sensitive_data = set()
    total_sensitive_findings = 0
    values_redacted = 0
    safe_samples = []

    timeline_buckets: Dict[str, int] = {}

    for r in rows:
        evt_id = r["id"]
        findings_raw = r["findings_json"] if "findings_json" in r.keys() else None
        f_list = []
        if findings_raw:
            try:
                f_list = json.loads(findings_raw)
            except Exception:
                f_list = []

        is_sensitive = False
        if f_list:
            for f in f_list:
                cat = f.get("category", "")
                cat_lower = cat.lower()
                if any(k in cat_lower for k in ["credential", "key", "password", "pii", "card", "email", "ssn", "aadhaar", "pan", "phone", "metadata", "gps"]):
                    is_sensitive = True
                    norm_cat = normalize_category_name(cat)
                    category_counts[norm_cat] = category_counts.get(norm_cat, 0) + 1
                    total_sensitive_findings += 1
                    values_redacted += 1

                    # Collect up to 8 safe samples
                    if len(safe_samples) < 8:
                        prev = f.get("match_preview") or "[REDACTED]"
                        safe_samples.append({
                            "category": norm_cat,
                            "rule": f.get("rule", "UNKNOWN"),
                            "preview": prev
                        })
        else:
            # Fallback
            cat_name = r["threat_category"]
            cat_lower = cat_name.lower()
            if any(k in cat_lower for k in ["credential", "key", "password", "pii", "card", "email", "ssn", "aadhaar", "pan", "phone", "metadata", "gps"]):
                is_sensitive = True
                norm_cat = normalize_category_name(cat_name)
                category_counts[norm_cat] = category_counts.get(norm_cat, 0) + 1
                total_sensitive_findings += 1
                if r["action_taken"] == "REDACT":
                    values_redacted += 1

        if is_sensitive:
            scans_with_sensitive_data.add(evt_id)
            # Track redaction timeline
            try:
                dt = datetime.fromisoformat(r["timestamp"].replace("Z", "+00:00"))
                day_key = dt.strftime("%b %d")
                timeline_buckets[day_key] = timeline_buckets.get(day_key, 0) + 1
            except Exception:
                pass

    scans_with_sens_count = len(scans_with_sensitive_data)
    sensitive_pct = round((scans_with_sens_count / total_scans) * 100, 2) if total_scans > 0 else 0.0

    most_frequent = [
        {"name": cat, "count": count, "percentage": round((count / total_sensitive_findings) * 100, 1) if total_sensitive_findings > 0 else 0.0}
        for cat, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True)
    ]

    redaction_timeline = [
        {"time": k, "redactions": v}
        for k, v in timeline_buckets.items()
    ]

    return {
        "total_sensitive_findings": total_sensitive_findings,
        "scans_with_sensitive_data": scans_with_sens_count,
        "sensitive_scan_percentage": sensitive_pct,
        "values_redacted_count": values_redacted,
        "category_counts": category_counts,
        "most_frequent_categories": most_frequent,
        "redaction_timeline": redaction_timeline,
        "safe_samples": safe_samples
    }

def get_policy_decisions(time_range: str = "all") -> Dict[str, Any]:
    """
    Compute policy enforcement distribution and common justification reasons.
    """
    init_db()
    cutoff = get_cutoff_iso(time_range)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        where_sql = " WHERE timestamp >= ?" if cutoff else ""
        params = [cutoff] if cutoff else []

        cursor.execute(f"SELECT action_taken, summary, threat_category FROM events {where_sql}", params)
        rows = cursor.fetchall()

    total = len(rows)
    allow_count = 0
    redact_count = 0
    block_count = 0
    block_reasons: Dict[str, int] = {}
    redact_reasons: Dict[str, int] = {}

    for r in rows:
        action = r["action_taken"]
        summary = r["summary"] or "General Policy Rule"
        clean_reason = summary[:80]

        if action == "ALLOW":
            allow_count += 1
        elif action == "REDACT":
            redact_count += 1
            redact_reasons[clean_reason] = redact_reasons.get(clean_reason, 0) + 1
        elif action == "BLOCK":
            block_count += 1
            block_reasons[clean_reason] = block_reasons.get(clean_reason, 0) + 1

    common_blocks = [
        {"reason": r, "count": c}
        for r, c in sorted(block_reasons.items(), key=lambda x: x[1], reverse=True)[:5]
    ]
    common_redacts = [
        {"reason": r, "count": c}
        for r, c in sorted(redact_reasons.items(), key=lambda x: x[1], reverse=True)[:5]
    ]

    active_policies = load_policies()

    return {
        "total_evaluations": total,
        "distribution": {
            "ALLOW": {"count": allow_count, "percentage": round((allow_count / total) * 100, 1) if total > 0 else 0.0},
            "REDACT": {"count": redact_count, "percentage": round((redact_count / total) * 100, 1) if total > 0 else 0.0},
            "BLOCK": {"count": block_count, "percentage": round((block_count / total) * 100, 1) if total > 0 else 0.0},
        },
        "common_block_reasons": common_blocks,
        "common_redact_reasons": common_redacts,
        "policy_rules_active": active_policies
    }

def get_file_security_analytics(time_range: str = "all") -> Dict[str, Any]:
    """
    Compute telemetry on document and image scanning operations.
    Distinguishes metadata extraction from OCR text inspection.
    """
    init_db()
    cutoff = get_cutoff_iso(time_range)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        where_sql = " WHERE timestamp >= ?" if cutoff else ""
        params = [cutoff] if cutoff else []

        cursor.execute(f"""
            SELECT id, source, input_type, file_type, ocr_status, matched_rules, findings_json, summary
            FROM events
            {where_sql}
        """, params)
        rows = cursor.fetchall()

    files_scanned = 0
    images_scanned = 0
    by_file_type: Dict[str, int] = {}
    ocr_stats = {"executed": 0, "unavailable": 0, "failed": 0, "not_applicable": 0}
    text_extraction_stats = {"success": 0, "partial": 0, "failed": 0, "unsupported": 0}

    metadata_findings_count = 0
    gps_findings_count = 0
    embedded_credential_count = 0
    injection_in_files_count = 0

    for r in rows:
        inp = (r["input_type"] or "").lower()
        src = (r["source"] or "").lower()
        ft = (r["file_type"] or "").lower()
        ocr = (r["ocr_status"] or "").lower()

        is_file = inp == "file" or "file" in src
        is_image = inp == "image" or "image" in src

        if is_file:
            files_scanned += 1
            if ft:
                by_file_type[ft] = by_file_type.get(ft, 0) + 1
            text_extraction_stats["success"] += 1
        elif is_image:
            images_scanned += 1
            if ft:
                by_file_type[ft] = by_file_type.get(ft, 0) + 1

        if ocr in ocr_stats:
            ocr_stats[ocr] += 1

        # Check findings
        findings_raw = r["findings_json"] if "findings_json" in r.keys() else None
        f_list = []
        if findings_raw:
            try:
                f_list = json.loads(findings_raw)
            except Exception:
                f_list = []

        for f in f_list:
            orig = (f.get("origin") or "").lower()
            cat = (f.get("category") or "").lower()
            rule = (f.get("rule") or "").lower()

            if orig == "image_metadata" or "metadata" in cat or "exif" in rule:
                metadata_findings_count += 1
                if "gps" in rule or "gps" in cat:
                    gps_findings_count += 1
            if orig in ("document_text", "ocr", "image_metadata") and any(k in cat for k in ["credential", "key", "password", "secret"]):
                embedded_credential_count += 1
            if orig in ("document_text", "ocr") and any(k in cat for k in ["injection", "jailbreak", "override"]):
                injection_in_files_count += 1

    return {
        "files_scanned": files_scanned,
        "images_scanned": images_scanned,
        "by_file_type": by_file_type,
        "ocr_stats": ocr_stats,
        "text_extraction_stats": text_extraction_stats,
        "metadata_findings_count": metadata_findings_count,
        "gps_findings_count": gps_findings_count,
        "embedded_credential_count": embedded_credential_count,
        "injection_in_files_count": injection_in_files_count
    }

def get_paginated_events(
    limit: int = 25,
    offset: int = 0,
    time_range: str = "all",
    search: Optional[str] = None,
    category: Optional[str] = None,
    action: Optional[str] = None,
    input_type: Optional[str] = None,
    severity: Optional[str] = None
) -> Dict[str, Any]:
    """
    Retrieve filtered, paginated events using parameterized SQL queries.
    Never exposes raw secrets in responses.
    """
    init_db()
    limit = max(1, min(100, limit))
    offset = max(0, offset)

    conditions = []
    params: List[Any] = []

    cutoff = get_cutoff_iso(time_range)
    if cutoff:
        conditions.append("timestamp >= ?")
        params.append(cutoff)

    if action and action.upper() != "ALL":
        conditions.append("action_taken = ?")
        params.append(action.upper())

    if input_type and input_type.upper() != "ALL":
        conditions.append("(LOWER(input_type) = ? OR LOWER(source) LIKE ?)")
        params.append(input_type.lower())
        params.append(f"%{input_type.lower()}%")

    if severity and severity.upper() != "ALL":
        conditions.append("LOWER(severity) = ?")
        params.append(severity.lower())

    if category and category.upper() != "ALL":
        conditions.append("LOWER(threat_category) LIKE ?")
        params.append(f"%{category.lower()}%")

    if search and search.strip():
        term = f"%{search.strip().lower()}%"
        conditions.append("(LOWER(summary) LIKE ? OR LOWER(matched_rules) LIKE ? OR LOWER(request_id) LIKE ? OR LOWER(id) LIKE ?)")
        params.extend([term, term, term, term])

    where_sql = (" WHERE " + " AND ".join(conditions)) if conditions else ""

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Count total matching rows
        cursor.execute(f"SELECT COUNT(*) FROM events {where_sql}", params)
        total = cursor.fetchone()[0]

        # Fetch page rows
        query = f"SELECT * FROM events {where_sql} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        fetch_params = list(params)
        fetch_params.extend([limit, offset])

        cursor.execute(query, fetch_params)
        rows = cursor.fetchall()

    events_list = []
    for r in rows:
        try:
            rules = json.loads(r["matched_rules"])
        except Exception:
            rules = []

        try:
            findings = json.loads(r["findings_json"]) if "findings_json" in r.keys() and r["findings_json"] else []
        except Exception:
            findings = []

        inp_type = r["input_type"] if "input_type" in r.keys() and r["input_type"] else "prompt"
        if inp_type == "prompt":
            s_lower = r["source"].lower()
            if "file" in s_lower:
                inp_type = "file"
            elif "image" in s_lower:
                inp_type = "image"

        f_count = r["finding_count"] if "finding_count" in r.keys() and r["finding_count"] is not None else len(rules)

        # Infer detection methods
        detection_methods = []
        if inp_type == "file":
            detection_methods.append("document_parser")
        elif inp_type == "image":
            detection_methods.append("metadata_inspector")
            if r["ocr_status"] == "executed":
                detection_methods.append("ocr_tesseract")
        for rule in rules:
            if "ML" in rule:
                if "ml_classifier" not in detection_methods:
                    detection_methods.append("ml_classifier")
            elif "RULE_" in rule:
                if "regex_heuristic" not in detection_methods:
                    detection_methods.append("regex_heuristic")
        if not detection_methods:
            detection_methods.append("static_engine")

        events_list.append({
            "id": r["id"],
            "request_id": r["request_id"],
            "timestamp": r["timestamp"],
            "input_type": inp_type,
            "threat_category": r["threat_category"],
            "severity": r["severity"],
            "action_taken": r["action_taken"],
            "status": r["status"],
            "source": r["source"],
            "summary": r["summary"],
            "detection_methods": detection_methods,
            "finding_count": f_count,
            "sanitized_preview": r["sanitized_preview"],
            "file_type": r["file_type"] if "file_type" in r.keys() else None,
            "ocr_status": r["ocr_status"] if "ocr_status" in r.keys() else None,
            "matched_rules": rules,
            "findings": findings,
            "latency_ms": r["latency_ms"],
            "client_ip": r["client_ip"],
            "user_agent": r["user_agent"]
        })

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "events": events_list
    }
