"""
Telemetry and Metrics Routes for Sentinel AI / Leak-Shield-AI.

Exposes real-time cybersecurity metrics, time-series telemetry, threat category distributions,
prompt injection intelligence, DLP analytics, policy verdicts, and file/image security.
All metrics are computed strictly from real SQLite audit logs.
"""

from typing import Optional, Dict, Any, List
from fastapi import APIRouter, Query
from app.schemas import MetricsResponse
from app.services.audit_service import compute_real_metrics
from app.services.dashboard_service import (
    get_dashboard_summary,
    get_activity_timeline,
    get_threat_categories,
    get_injection_keywords,
    get_dlp_analytics,
    get_policy_decisions,
    get_file_security_analytics,
    get_paginated_events
)

router = APIRouter()

@router.get("/metrics", response_model=MetricsResponse)
def get_metrics_endpoint():
    """GET /metrics — compute real operational metrics from persisted audit events."""
    metrics = compute_real_metrics()
    return MetricsResponse(**metrics)

@router.get("/metrics/summary")
def get_dashboard_summary_endpoint(
    range: str = Query("all", description="Time range: 1h, 24h, 7d, 30d, all"),
    time_range: Optional[str] = Query(None, description="Alias for range parameter")
) -> Dict[str, Any]:
    """GET /metrics/summary — KPI cards data (Total scans, threats, blocked, redacted, rates)."""
    selected_range = time_range if time_range else range
    return get_dashboard_summary(time_range=selected_range)

@router.get("/metrics/timeline")
def get_dashboard_timeline_endpoint(
    range: str = Query("24h", description="Time range: 1h, 24h, 7d, 30d, all"),
    time_range: Optional[str] = Query(None, description="Alias for range parameter")
) -> List[Dict[str, Any]]:
    """GET /metrics/timeline — Time-series telemetry of scans, threats, blocked, and redacted requests."""
    selected_range = time_range if time_range else range
    return get_activity_timeline(time_range=selected_range)

@router.get("/metrics/threat-categories")
def get_threat_categories_endpoint(
    range: str = Query("all", description="Time range: 1h, 24h, 7d, 30d, all"),
    time_range: Optional[str] = Query(None, description="Alias for range parameter")
) -> Dict[str, Any]:
    """GET /metrics/threat-categories — Threat distribution across categories with findings vs unique scans."""
    selected_range = time_range if time_range else range
    return get_threat_categories(time_range=selected_range)

@router.get("/metrics/injection-keywords")
def get_injection_keywords_endpoint(
    range: str = Query("all", description="Time range: 1h, 24h, 7d, 30d, all"),
    time_range: Optional[str] = Query(None, description="Alias for range parameter"),
    limit: int = Query(15, ge=1, le=100, description="Max keywords/phrases to return")
) -> Dict[str, Any]:
    """GET /metrics/injection-keywords — Top injection keywords and phrases extracted from flagged requests."""
    selected_range = time_range if time_range else range
    return get_injection_keywords(time_range=selected_range, limit=limit)

@router.get("/metrics/dlp")
def get_dlp_analytics_endpoint(
    range: str = Query("all", description="Time range: 1h, 24h, 7d, 30d, all"),
    time_range: Optional[str] = Query(None, description="Alias for range parameter")
) -> Dict[str, Any]:
    """GET /metrics/dlp — Sensitive data & DLP stats (findings, safe samples, redaction counts)."""
    selected_range = time_range if time_range else range
    return get_dlp_analytics(time_range=selected_range)

@router.get("/metrics/policies")
def get_policy_decisions_endpoint(
    range: str = Query("all", description="Time range: 1h, 24h, 7d, 30d, all"),
    time_range: Optional[str] = Query(None, description="Alias for range parameter")
) -> Dict[str, Any]:
    """GET /metrics/policies — Policy decision distribution (ALLOW, REDACT, BLOCK) and top reasons."""
    selected_range = time_range if time_range else range
    return get_policy_decisions(time_range=selected_range)

@router.get("/metrics/file-image")
def get_file_image_analytics_endpoint(
    range: str = Query("all", description="Time range: 1h, 24h, 7d, 30d, all"),
    time_range: Optional[str] = Query(None, description="Alias for range parameter")
) -> Dict[str, Any]:
    """GET /metrics/file-image — Document & image scanning telemetry (OCR stats, metadata, GPS, embedded threats)."""
    selected_range = time_range if time_range else range
    return get_file_security_analytics(time_range=selected_range)

@router.get("/metrics/events")
def get_paginated_events_endpoint(
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
    range: str = Query("all", description="Time range: 1h, 24h, 7d, 30d, all"),
    time_range: Optional[str] = Query(None, description="Alias for range parameter"),
    search: Optional[str] = Query(None, description="Search term for summary, rule, or ID"),
    category: Optional[str] = Query(None, description="Filter by threat category"),
    action: Optional[str] = Query(None, description="Filter by action: ALLOW, REDACT, BLOCK"),
    input_type: Optional[str] = Query(None, description="Filter by input medium: prompt, file, image"),
    severity: Optional[str] = Query(None, description="Filter by severity: low, medium, high, critical")
) -> Dict[str, Any]:
    """GET /metrics/events — Multi-faceted filtered and paginated security events."""
    selected_range = time_range if time_range else range
    return get_paginated_events(
        limit=limit,
        offset=offset,
        time_range=selected_range,
        search=search,
        category=category,
        action=action,
        input_type=input_type,
        severity=severity
    )
