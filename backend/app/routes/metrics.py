"""
Telemetry and Metrics Route for Sentinel AI.

Computes live statistics directly from SQLite audit logs.
Returns genuine zero values and empty lists on a fresh database.
"""

from fastapi import APIRouter
from app.schemas import MetricsResponse
from app.services.audit_service import compute_real_metrics

router = APIRouter()

@router.get("/metrics", response_model=MetricsResponse)
def get_metrics_endpoint():
    """GET /metrics — compute real operational metrics from persisted audit events."""
    metrics = compute_real_metrics()
    return MetricsResponse(**metrics)
