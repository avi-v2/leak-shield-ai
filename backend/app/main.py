"""
Sentinel AI — AI Data Leakage Security Gateway & Prompt Injection Firewall
FastAPI Main Application Entrypoint.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.database import init_db
from app.security.classifier import get_classifier
from app.routes import health, scan, chat, events, policies, metrics, image_scan

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown initialization."""
    # 1. Initialize SQLite database schema
    init_db()
    # 2. Warm up injection classifier
    get_classifier()
    yield

app = FastAPI(
    title=settings.APP_TITLE,
    description="Enterprise AI Data Leakage Security Gateway & Prompt Injection Firewall",
    version=settings.APP_VERSION,
    lifespan=lifespan
)

# CORS Middleware with explicit permitted frontend origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.FRONTEND_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Include Application Routers
app.include_router(health.router)
app.include_router(scan.router)
app.include_router(chat.router)
app.include_router(events.router)
app.include_router(policies.router)
app.include_router(metrics.router)
app.include_router(image_scan.router)

# Safe structured error handling
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Prevent unhandled stack traces or sensitive paths from leaking in responses."""
    # Check if it's already an HTTPException handled by FastAPI
    from fastapi import HTTPException
    if isinstance(exc, HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail}
        )
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal gateway error occurred. Check server logs."}
    )
