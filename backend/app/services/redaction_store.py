"""
Redaction Storage Service for Leak-Shield-AI.

Provides temporary, secure on-disk persistence for sanitized and verified files
with strict tokenized access, path-traversal prevention, and automatic TTL cleanup.
"""

import os
import re
import time
import json
import uuid
from pathlib import Path
from typing import Optional, Dict, Any

# Dedicated secure directory for sanitized artifacts
REDACTION_CACHE_DIR = Path(__file__).resolve().parent.parent.parent / "redacted_cache"
REDACTION_CACHE_DIR.mkdir(parents=True, exist_ok=True)

# Strict token format: "red_" followed by 16 to 32 hex characters
FILE_ID_PATTERN = re.compile(r"^red_[a-f0-9]{16,32}$")
DEFAULT_TTL_SECONDS = 3600  # 1 hour


def _cleanup_expired(max_age_seconds: int = DEFAULT_TTL_SECONDS) -> int:
    """Removes cached artifacts older than the configured TTL."""
    now = time.time()
    deleted_count = 0
    try:
        for item in REDACTION_CACHE_DIR.glob("red_*"):
            try:
                if item.is_file():
                    mtime = item.stat().st_mtime
                    if now - mtime > max_age_seconds:
                        item.unlink(missing_ok=True)
                        deleted_count += 1
            except Exception:
                continue
    except Exception:
        pass
    return deleted_count


def save_redacted_file(
    file_bytes: bytes,
    original_filename: str,
    content_type: str = "application/octet-stream"
) -> str:
    """
    Stores sanitized file bytes under a randomized secure file_id token.
    Runs background cleanup for expired files on every write.
    """
    # 1. Housekeeping: purge expired artifacts
    _cleanup_expired(DEFAULT_TTL_SECONDS)

    # 2. Generate secure token
    token = f"red_{uuid.uuid4().hex}"
    
    # Sanitize base filename for download header safety
    safe_base = Path(original_filename).name
    # Strip any characters that could break HTTP header formatting
    safe_base = re.sub(r'[^a-zA-Z0-9_.-]', '_', safe_base)
    if not safe_base.startswith("sanitized_"):
        safe_filename = f"sanitized_{safe_base}"
    else:
        safe_filename = safe_base

    data_path = REDACTION_CACHE_DIR / f"{token}.bin"
    meta_path = REDACTION_CACHE_DIR / f"{token}.json"

    meta = {
        "file_id": token,
        "filename": safe_filename,
        "content_type": content_type,
        "size_bytes": len(file_bytes),
        "created_at": time.time(),
    }

    # Write data atomically
    data_path.write_bytes(file_bytes)
    meta_path.write_text(json.dumps(meta), encoding="utf-8")

    return token


def get_redacted_file(file_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieves stored sanitized file bytes and metadata.
    Enforces strict token pattern matching to eliminate path-traversal risks.
    """
    if not file_id or not FILE_ID_PATTERN.match(file_id):
        return None

    data_path = (REDACTION_CACHE_DIR / f"{file_id}.bin").resolve()
    meta_path = (REDACTION_CACHE_DIR / f"{file_id}.json").resolve()

    # Guard against symlink / path traversal escapes
    try:
        if not data_path.is_relative_to(REDACTION_CACHE_DIR.resolve()):
            return None
    except AttributeError:
        # Python <3.9 compatibility (though we run 3.11+)
        if REDACTION_CACHE_DIR.resolve() not in data_path.parents:
            return None

    if not data_path.is_file() or not meta_path.is_file():
        return None

    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        # Check TTL
        if time.time() - meta.get("created_at", 0) > DEFAULT_TTL_SECONDS:
            data_path.unlink(missing_ok=True)
            meta_path.unlink(missing_ok=True)
            return None

        file_bytes = data_path.read_bytes()
        return {
            "file_id": file_id,
            "filename": meta.get("filename", "sanitized_file"),
            "content_type": meta.get("content_type", "application/octet-stream"),
            "size_bytes": len(file_bytes),
            "file_bytes": file_bytes
        }
    except Exception:
        return None


def delete_redacted_file(file_id: str) -> bool:
    """Explicitly deletes a cached redacted file."""
    if not file_id or not FILE_ID_PATTERN.match(file_id):
        return False

    data_path = REDACTION_CACHE_DIR / f"{file_id}.bin"
    meta_path = REDACTION_CACHE_DIR / f"{file_id}.json"

    deleted = False
    if data_path.exists():
        data_path.unlink(missing_ok=True)
        deleted = True
    if meta_path.exists():
        meta_path.unlink(missing_ok=True)
        deleted = True

    return deleted
