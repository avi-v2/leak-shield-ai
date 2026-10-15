"""
Health Check Route for Sentinel AI.

Accurately reports real status of API, SQLite database, ML classifier, and LLM provider.
Never masks offline services as healthy.
"""

from datetime import datetime, timezone
from fastapi import APIRouter
from app.config import settings
from app.database import get_db_connection, init_db
from app.security.classifier import get_classifier
from app.services.llm_service import check_llm_availability
from app.schemas import HealthResponse

router = APIRouter()

@router.get("/health", response_model=HealthResponse)
def get_health_status():
    """GET /health — real system component health inspection."""
    # 1. Database check
    db_ok = False
    try:
        init_db()
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            db_ok = (cursor.fetchone()[0] == 1)
    except Exception:
        db_ok = False

    # 2. ML Classifier check
    clf = get_classifier()
    classifier_ok = clf.is_available()
    classifier_msg = clf.get_status_message()

    # 3. LLM check
    llm_ok, llm_msg = check_llm_availability()

    overall_status = "ok" if (db_ok) else "degraded"

    return HealthResponse(
        status=overall_status,
        gateway="operational" if db_ok else "degraded",
        version=settings.APP_VERSION,
        engine="Sentinel-AI-Engine-v2.0",
        timestamp=datetime.now(timezone.utc).isoformat(),
        database=db_ok,
        classifier=classifier_ok,
        llm=llm_ok,
        llm_provider=settings.LLM_PROVIDER,
        llm_model=settings.OLLAMA_MODEL,
        details={
            "database": "connected" if db_ok else "unreachable",
            "classifier": classifier_msg,
            "llm": llm_msg or "Unavailable"
        }
    )
