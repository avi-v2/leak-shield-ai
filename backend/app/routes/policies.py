"""
Security Policy Management Route for Sentinel AI.

Provides GET /policies and PUT /policies for server-side policy synchronization.
Rejects invalid settings and strictly prevents disabling mandatory credential protections.
"""

from fastapi import APIRouter, HTTPException
from app.schemas import PolicySettings
from app.database import load_policies, save_policies

router = APIRouter()

@router.get("/policies", response_model=PolicySettings)
def get_policies_endpoint():
    """GET /policies — retrieve current server-side security policy configuration."""
    policies = load_policies()
    return PolicySettings(**policies)

@router.put("/policies", response_model=PolicySettings)
def update_policies_endpoint(payload: PolicySettings):
    """PUT /policies — validate and update server-side security policies in SQLite."""
    # Ensure mandatory protections cannot be circumvented
    if not payload.detectApiKeys:
        raise HTTPException(status_code=400, detail="Mandatory protection 'detectApiKeys' cannot be disabled.")
    if not payload.detectPasswords:
        raise HTTPException(status_code=400, detail="Mandatory protection 'detectPasswords' cannot be disabled.")

    updated = save_policies(payload.model_dump())
    return PolicySettings(**updated)
