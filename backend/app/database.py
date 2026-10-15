"""
SQLite database access and audit event persistence for Sentinel AI.
Uses Python's built-in sqlite3 engine for reliable local storage without external dependencies.
"""

import sqlite3
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional
from app.config import settings

DEFAULT_POLICIES: Dict[str, Any] = {
    "detectApiKeys": True,                 # Mandatory protection
    "detectCreditCards": True,
    "detectSsn": True,
    "detectEmails": True,
    "detectPasswords": True,               # Mandatory protection
    "detectAadhaar": True,
    "detectPan": True,
    "detectPhone": True,
    "blockPromptInjection": True,
    "blockJailbreaks": True,
    "blockSystemPromptExtraction": True,
    "inspectModelOutputs": True,
    "defaultAction": "REDACT",             # ALLOW | REDACT | BLOCK
    "highRiskThreshold": "high",           # medium | high | critical
}

def get_db_path(custom_path: Optional[str] = None) -> str:
    path = custom_path or settings.DATABASE_PATH
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    return path

def get_db_connection(custom_path: Optional[str] = None) -> sqlite3.Connection:
    """Return a database connection with dictionary-like row access."""
    path = get_db_path(custom_path)
    conn = sqlite3.connect(path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(custom_path: Optional[str] = None) -> None:
    """Initialize SQLite tables and seed default policies if not present."""
    path = get_db_path(custom_path)
    with get_db_connection(path) as conn:
        cursor = conn.cursor()

        # Audit events table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                threat_category TEXT NOT NULL,
                severity TEXT NOT NULL,
                source TEXT NOT NULL,
                action_taken TEXT NOT NULL,
                status TEXT NOT NULL,
                summary TEXT NOT NULL,
                matched_rules TEXT NOT NULL,
                latency_ms INTEGER NOT NULL DEFAULT 0,
                client_ip TEXT NOT NULL DEFAULT '127.0.0.1',
                user_agent TEXT NOT NULL DEFAULT 'Unknown',
                sanitized_preview TEXT NOT NULL,
                is_output_scan INTEGER NOT NULL DEFAULT 0,
                input_type TEXT NOT NULL DEFAULT 'prompt',
                finding_count INTEGER NOT NULL DEFAULT 0,
                indicators_json TEXT NOT NULL DEFAULT '[]',
                findings_json TEXT NOT NULL DEFAULT '[]',
                file_type TEXT DEFAULT NULL,
                ocr_status TEXT DEFAULT NULL
            )
        """)

        # Dynamically add any missing columns for existing databases
        cursor.execute("PRAGMA table_info(events)")
        existing_cols = {row[1] for row in cursor.fetchall()}
        columns_to_add = [
            ("input_type", "TEXT NOT NULL DEFAULT 'prompt'"),
            ("finding_count", "INTEGER NOT NULL DEFAULT 0"),
            ("indicators_json", "TEXT NOT NULL DEFAULT '[]'"),
            ("findings_json", "TEXT NOT NULL DEFAULT '[]'"),
            ("file_type", "TEXT DEFAULT NULL"),
            ("ocr_status", "TEXT DEFAULT NULL"),
        ]
        for col_name, col_type in columns_to_add:
            if col_name not in existing_cols:
                cursor.execute(f"ALTER TABLE events ADD COLUMN {col_name} {col_type}")

        # Add indexes for high-performance dashboard aggregation queries
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_action ON events(action_taken)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_threat_category ON events(threat_category)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_input_type ON events(input_type)")

        # Policies table (key-value configuration store)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS policies (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                config_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

        # Insert default policies if table is empty
        cursor.execute("SELECT COUNT(*) FROM policies WHERE id = 1")
        if cursor.fetchone()[0] == 0:
            now_iso = datetime.now(timezone.utc).isoformat()
            cursor.execute(
                "INSERT INTO policies (id, config_json, updated_at) VALUES (1, ?, ?)",
                (json.dumps(DEFAULT_POLICIES), now_iso)
            )

        conn.commit()

def load_policies(custom_path: Optional[str] = None) -> Dict[str, Any]:
    """Retrieve the current server-side security policy from the database."""
    init_db(custom_path)
    with get_db_connection(custom_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT config_json FROM policies WHERE id = 1")
        row = cursor.fetchone()
        if row and row["config_json"]:
            try:
                stored = json.loads(row["config_json"])
                # Merge with default to guarantee all expected keys are present
                merged = {**DEFAULT_POLICIES, **stored}
                # Server-side enforcement: mandatory credential protections cannot be disabled
                merged["detectApiKeys"] = True
                merged["detectPasswords"] = True
                return merged
            except Exception:
                return dict(DEFAULT_POLICIES)
        return dict(DEFAULT_POLICIES)

def save_policies(new_policies: Dict[str, Any], custom_path: Optional[str] = None) -> Dict[str, Any]:
    """Validate, persist, and return updated policies."""
    init_db(custom_path)
    current = load_policies(custom_path)
    merged = {**current, **new_policies}

    # Strict server-side enforcement: mandatory protections cannot be disabled
    merged["detectApiKeys"] = True
    merged["detectPasswords"] = True

    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db_connection(custom_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE policies SET config_json = ?, updated_at = ? WHERE id = 1",
            (json.dumps(merged), now_iso)
        )
        conn.commit()
    return merged
