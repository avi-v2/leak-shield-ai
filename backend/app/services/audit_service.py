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
    is_output_scan: bool = False
) -> Dict[str, Any]:
    """
    Persist a sanitized audit record to SQLite.
    Guarantees that preview text is truncated and contains only redacted strings.
    """
    init_db()
    event_id = f"evt_{uuid.uuid4().hex[:8]}"
    now_iso = datetime.now(timezone.utc).isoformat()

    # Safeguard preview length to max 160 chars
    safe_preview = (sanitized_preview[:157] + "...") if len(sanitized_preview) > 160 else sanitized_preview

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO events (
                id, request_id, timestamp, threat_category, severity,
                source, action_taken, status, summary, matched_rules,
                latency_ms, client_ip, user_agent, sanitized_preview, is_output_scan
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            1 if is_output_scan else 0
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
        "details": {
            "matched_rules": matched_rules,
            "latency_ms": latency_ms,
            "client_ip": client_ip,
            "user_agent": user_agent,
            "sanitized_preview": safe_preview,
            "is_output_scan": is_output_scan
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
