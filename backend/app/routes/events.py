"""
Audit Events Management Route for Leak-Sheild-AI.

Retrieves, searches (literal and semantic vector similarity), and clears persisted
security event records from SQLite. Never returns raw credentials or unredacted secrets.
"""

from typing import List, Optional
from fastapi import APIRouter, Query
from app.schemas import EventResponse
from app.services.audit_service import fetch_audit_events, clear_audit_events
from app.security.semantic_search import SemanticSearchEngine

router = APIRouter()

@router.get("/events", response_model=List[EventResponse])
def get_events_endpoint(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    decision: Optional[str] = Query(None, description="Optional filter by action: ALLOW, REDACT, BLOCK"),
    semantic_query: Optional[str] = Query(None, description="Optional semantic query to filter and rank by similarity")
):
    """
    GET /events — retrieve persisted audit event logs from SQLite.
    If semantic_query is provided, ranks events using cybersecurity vector-space semantic matching.
    """
    if semantic_query and semantic_query.strip():
        raw_events = fetch_audit_events(limit=500, offset=0, decision_filter=decision)
        ranked = SemanticSearchEngine.rank_events(raw_events, query=semantic_query, min_score=0.05, limit=limit)
        return ranked

    return fetch_audit_events(limit=limit, offset=offset, decision_filter=decision)

@router.get("/events/search", response_model=List[EventResponse])
def search_events_semantic_endpoint(
    query: str = Query(..., min_length=1, description="Natural language semantic search query"),
    min_score: float = Query(0.1, ge=0.0, le=1.0, description="Minimum similarity score threshold (0.0 - 1.0)"),
    limit: int = Query(50, ge=1, le=200, description="Maximum matching events to return")
):
    """
    GET /events/search — vector similarity semantic search across audit events.
    Captures intent, concept synonyms, and threat categories.
    """
    raw_events = fetch_audit_events(limit=500, offset=0)
    return SemanticSearchEngine.rank_events(raw_events, query=query, min_score=min_score, limit=limit)

@router.delete("/events")
def clear_events_endpoint():
    """DELETE /events — purge all persisted events after explicit confirmation."""
    deleted_count = clear_audit_events()
    return {
        "status": "success",
        "deleted_count": deleted_count,
        "message": f"Successfully deleted {deleted_count} security event record(s)."
    }
