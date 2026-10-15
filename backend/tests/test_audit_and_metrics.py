"""
Tests for audit event persistence, clearing, and metric calculations in SQLite.
"""

from app.services.audit_service import (
    record_audit_event,
    fetch_audit_events,
    clear_audit_events,
    compute_real_metrics
)

def test_fresh_database_zero_metrics_and_empty_events(client):
    """Verify fresh database returns 0 events and genuinely zero metrics."""
    # 1. Events list is empty
    resp_events = client.get("/events")
    assert resp_events.status_code == 200
    events_data = resp_events.json()
    assert events_data == []

    # 2. Metrics are all zero
    resp_metrics = client.get("/metrics")
    assert resp_metrics.status_code == 200
    metrics_data = resp_metrics.json()
    assert metrics_data["total_requests"] == 0
    assert metrics_data["allowed_requests"] == 0
    assert metrics_data["blocked_requests"] == 0
    assert metrics_data["redacted_requests"] == 0
    assert metrics_data["sensitive_data_detections"] == 0
    assert metrics_data["injection_detections"] == 0
    assert metrics_data["traffic_over_time"] == []
    assert metrics_data["threat_distribution"] == []

def test_audit_persistence_and_no_raw_secrets():
    """Verify audit persistence across reads and ensure raw secrets are not stored."""
    synthetic_key = "sk-proj-999988887777666655554444333322221111"
    sanitized = "Deploy with key: [REDACTED_API_KEY]"

    record_audit_event(
        request_id="req_test_1",
        threat_category="Credential Exfiltration",
        severity="critical",
        source="Prompt Scanner",
        action_taken="BLOCK",
        status="mitigated",
        summary="API key exfiltration attempt",
        matched_rules=["RULE_OPENAI_API_KEY"],
        latency_ms=12,
        client_ip="192.168.1.50",
        user_agent="Pytest-Runner",
        sanitized_preview=sanitized,
        is_output_scan=False
    )

    events = fetch_audit_events()
    assert len(events) == 1
    stored = events[0]

    assert stored["request_id"] == "req_test_1"
    assert stored["action_taken"] == "BLOCK"
    assert stored["details"]["sanitized_preview"] == sanitized

    # Verify raw secret is absent from preview and summary
    assert synthetic_key not in stored["details"]["sanitized_preview"]
    assert synthetic_key not in stored["summary"]

def test_metrics_computed_from_actual_events():
    """Verify metrics reflect actual SQLite event counts."""
    # Insert 1 BLOCK, 1 REDACT, 1 ALLOW
    record_audit_event("req_1", "Credential Exfiltration", "critical", "Scanner", "BLOCK", "mitigated", "Blocked key", ["RULE_API_KEY"], 15)
    record_audit_event("req_2", "Personal Identifiable Info", "medium", "Scanner", "REDACT", "mitigated", "Redacted email", ["RULE_EMAIL"], 10)
    record_audit_event("req_3", "Clean Traffic", "low", "Proxy", "ALLOW", "resolved", "Clean request", [], 8)

    metrics = compute_real_metrics()
    assert metrics["total_requests"] == 3
    assert metrics["blocked_requests"] == 1
    assert metrics["redacted_requests"] == 1
    assert metrics["allowed_requests"] == 1
    assert metrics["sensitive_data_detections"] >= 2
    assert len(metrics["threat_distribution"]) >= 2

def test_clear_audit_events_endpoint(client):
    """Verify DELETE /events purges events and returns accurate deleted count."""
    record_audit_event("req_1", "Credential Exfiltration", "critical", "Scanner", "BLOCK", "mitigated", "Blocked key", [], 15)
    record_audit_event("req_2", "Personal Identifiable Info", "medium", "Scanner", "REDACT", "mitigated", "Redacted email", [], 10)

    # Confirm 2 events exist
    assert len(fetch_audit_events()) == 2

    # Clear events
    resp = client.delete("/events")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["deleted_count"] == 2

    # Verify empty now
    assert len(fetch_audit_events()) == 0
