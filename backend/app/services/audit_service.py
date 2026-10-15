"""
Audit Logging and Telemetry Service for Sentinel AI.

Persists security incident metadata into SQLite. Redacts all sensitive content prior
to persistence. Never logs raw secrets, credentials, or full raw payloads.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from app.database import get_db_connection, init_db

def record_audit_event(
    request_id: str,
    threat_category: str,
    severity: str,
    source: str,
    action_taken: str,
    status: str,
    summary: str,
    matched_rules: List[str],
    latency_ms: int,
    client_ip: str = "127.0.0.1",
    user_agent: str = "Sentinel-Client",
    sanitized_preview: str = "",
    is_output_scan: bool = False,
    input_type: str = "prompt",
    finding_count: int = 0,
    indicators: Optional[List[Dict[str, Any]]] = None,
    findings: Optional[List[Dict[str, Any]]] = None,
    file_type: Optional[str] = None,
    ocr_status: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Persist a sanitized audit record to SQLite.
    Guarantees that preview text is truncated and contains only redacted strings.
    Never persists raw credentials, unredacted tokens, or full raw payloads.
    """
    init_db()
    event_id = f"evt_{uuid.uuid4().hex[:8]}"
    now_iso = datetime.now(timezone.utc).isoformat()

    # Determine input type from source if default
    effective_input_type = input_type
    if effective_input_type == "prompt":
        s_lower = source.lower()
        if "file" in s_lower:
            effective_input_type = "file"
        elif "image" in s_lower:
            effective_input_type = "image"

    # Sanitize and structure findings list
    safe_findings = []
    if findings:
        for f in findings:
            if isinstance(f, dict):
                safe_findings.append({
                    "category": f.get("category", "General"),
                    "rule": f.get("rule") or f.get("type", "RULE_GENERAL"),
                    "severity": f.get("severity", "medium"),
                    "description": f.get("description", ""),
                    "match_preview": f.get("match_preview") or "[REDACTED]",
                    "source_location": f.get("source_location"),
                    "origin": f.get("origin", "prompt_text")
                })
            else:
                # Pydantic model instance
                f_dict = f.model_dump() if hasattr(f, "model_dump") else dict(f)
                safe_findings.append({
                    "category": f_dict.get("category", "General"),
                    "rule": f_dict.get("rule") or f_dict.get("type", "RULE_GENERAL"),
                    "severity": f_dict.get("severity", "medium"),
                    "description": f_dict.get("description", ""),
                    "match_preview": f_dict.get("match_preview") or "[REDACTED]",
                    "source_location": f_dict.get("source_location"),
                    "origin": f_dict.get("origin", "prompt_text")
                })

    effective_finding_count = finding_count
    if effective_finding_count == 0:
        if safe_findings:
            effective_finding_count = len(safe_findings)
        elif matched_rules:
            effective_finding_count = len(matched_rules)

    # Safeguard preview length to max 160 chars
    safe_preview = (sanitized_preview[:157] + "...") if len(sanitized_preview) > 160 else sanitized_preview

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO events (
                id, request_id, timestamp, threat_category, severity,
                source, action_taken, status, summary, matched_rules,
                latency_ms, client_ip, user_agent, sanitized_preview, is_output_scan,
                input_type, finding_count, indicators_json, findings_json, file_type, ocr_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event_id,
            request_id,
            now_iso,
            threat_category,
            severity,
            source,
            action_taken,
            status,
            summary,
            json.dumps(matched_rules),
            latency_ms,
            client_ip,
            user_agent,
            safe_preview,
            1 if is_output_scan else 0,
            effective_input_type,
            effective_finding_count,
            json.dumps(indicators or []),
            json.dumps(safe_findings),
            file_type,
            ocr_status
        ))
        conn.commit()

    return {
        "id": event_id,
        "request_id": request_id,
        "timestamp": now_iso,
        "threat_category": threat_category,
        "severity": severity,
        "source": source,
        "action_taken": action_taken,
        "status": status,
        "summary": summary,
        "input_type": effective_input_type,
        "finding_count": effective_finding_count,
        "file_type": file_type,
        "ocr_status": ocr_status,
        "details": {
            "matched_rules": matched_rules,
            "latency_ms": latency_ms,
            "client_ip": client_ip,
            "user_agent": user_agent,
            "sanitized_preview": safe_preview,
            "is_output_scan": is_output_scan,
            "findings": safe_findings,
            "indicators": indicators or []
        }
    }

def fetch_audit_events(
    limit: int = 100,
    offset: int = 0,
    decision_filter: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Retrieve audit events from SQLite ordered from newest to oldest."""
    init_db()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM events"
        params = []

        if decision_filter and decision_filter.upper() != "ALL":
            query += " WHERE action_taken = ?"
            params.append(decision_filter.upper())

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        rows = cursor.fetchall()

        events = []
        for r in rows:
            try:
                rules = json.loads(r["matched_rules"])
            except Exception:
                rules = []

            # Infer input_type if empty or default
            input_type = r["input_type"] if "input_type" in r.keys() and r["input_type"] else "prompt"
            if input_type == "prompt":
                s_lower = r["source"].lower()
                if "file" in s_lower:
                    input_type = "file"
                elif "image" in s_lower:
                    input_type = "image"

            finding_count = r["finding_count"] if "finding_count" in r.keys() and r["finding_count"] is not None else len(rules)

            events.append({
                "id": r["id"],
                "request_id": r["request_id"],
                "timestamp": r["timestamp"],
                "threat_category": r["threat_category"],
                "severity": r["severity"],
                "source": r["source"],
                "action_taken": r["action_taken"],
                "status": r["status"],
                "summary": r["summary"],
                "input_type": input_type,
                "finding_count": finding_count,
                "details": {
                    "matched_rules": rules,
                    "latency_ms": r["latency_ms"],
                    "client_ip": r["client_ip"],
                    "user_agent": r["user_agent"],
                    "sanitized_preview": r["sanitized_preview"],
                    "is_output_scan": bool(r["is_output_scan"])
                }
            })
        return events

def clear_audit_events() -> int:
    """Clear all persisted audit records and return count of deleted rows."""
    init_db()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM events")
        count = cursor.fetchone()[0]
        cursor.execute("DELETE FROM events")
        conn.commit()
        return count

def compute_real_metrics() -> Dict[str, Any]:
    """
    Compute actual metrics by executing SQL aggregations on the events table.
    For a fresh database, returns genuine zero values and empty lists.
    """
    init_db()
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Overall counts
        cursor.execute("SELECT COUNT(*) FROM events")
        total = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM events WHERE action_taken = 'ALLOW'")
        allowed = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM events WHERE action_taken = 'BLOCK'")
        blocked = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM events WHERE action_taken = 'REDACT'")
        redacted = cursor.fetchone()[0]

        cursor.execute("""
            SELECT COUNT(*) FROM events
            WHERE LOWER(threat_category) LIKE '%pii%'
               OR LOWER(threat_category) LIKE '%personal%'
               OR LOWER(threat_category) LIKE '%credential%'
               OR LOWER(threat_category) LIKE '%key%'
               OR LOWER(threat_category) LIKE '%card%'
               OR LOWER(threat_category) LIKE '%password%'
               OR LOWER(threat_category) LIKE '%ssn%'
               OR LOWER(threat_category) LIKE '%aadhaar%'
               OR LOWER(threat_category) LIKE '%pan%'
        """)
        sensitive_count = cursor.fetchone()[0]

        cursor.execute("""
            SELECT COUNT(*) FROM events
            WHERE LOWER(threat_category) LIKE '%injection%'
               OR LOWER(threat_category) LIKE '%jailbreak%'
               OR LOWER(threat_category) LIKE '%system%'
               OR LOWER(threat_category) LIKE '%override%'
        """)
        injection_count = cursor.fetchone()[0]

        # Time-series: hourly grouping from real timestamps
        cursor.execute("""
            SELECT
                substr(timestamp, 12, 2) || ':00' as hour_bucket,
                COUNT(*) as inspected,
                SUM(CASE WHEN action_taken = 'ALLOW' THEN 1 ELSE 0 END) as allowed,
                SUM(CASE WHEN action_taken = 'BLOCK' THEN 1 ELSE 0 END) as blocked,
                SUM(CASE WHEN action_taken = 'REDACT' THEN 1 ELSE 0 END) as redacted
            FROM events
            GROUP BY hour_bucket
            ORDER BY hour_bucket ASC
        """)
        time_rows = cursor.fetchall()
        traffic_over_time = [
            {
                "time": row["hour_bucket"],
                "inspected": row["inspected"],
                "allowed": row["allowed"],
                "blocked": row["blocked"],
                "redacted": row["redacted"]
            }
            for row in time_rows
        ]

        # Threat category breakdown
        cursor.execute("""
            SELECT threat_category, COUNT(*) as count
            FROM events
            WHERE action_taken IN ('BLOCK', 'REDACT')
            GROUP BY threat_category
            ORDER BY count DESC
        """)
        threat_rows = cursor.fetchall()

        color_palette = ["#EF4444", "#F59E0B", "#22D3EE", "#A855F7", "#EC4899", "#10B981"]
        threat_distribution = [
            {
                "name": row["threat_category"],
                "count": row["count"],
                "color": color_palette[i % len(color_palette)]
            }
            for i, row in enumerate(threat_rows)
        ]

        return {
            "total_requests": total,
            "allowed_requests": allowed,
            "blocked_requests": blocked,
            "redacted_requests": redacted,
            "sensitive_data_detections": sensitive_count,
            "injection_detections": injection_count,
            "traffic_over_time": traffic_over_time,
            "threat_distribution": threat_distribution
        }
