"""
Audit Events Management Route for Sentinel AI.

Retrieves and clears persisted security event records from SQLite.
Never returns raw credentials or unredacted secrets.
"""

from typing import List, Optional
from fastapi import APIRouter, Query
from app.schemas import EventResponse
from app.services.audit_service import fetch_audit_events, clear_audit_events

router = APIRouter()

@router.get("/events", response_model=List[EventResponse])
def get_events_endpoint(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    decision: Optional[str] = Query(None, description="Optional filter by action: ALLOW, REDACT, BLOCK")
):
    """GET /events — retrieve persisted audit event logs from SQLite."""
    return fetch_audit_events(limit=limit, offset=offset, decision_filter=decision)

@router.delete("/events")
def clear_events_endpoint():
    """DELETE /events — purge all persisted events after explicit confirmation."""
    deleted_count = clear_audit_events()
    return {
        "status": "success",
        "deleted_count": deleted_count,
        "message": f"Successfully deleted {deleted_count} security event record(s)."
    }
