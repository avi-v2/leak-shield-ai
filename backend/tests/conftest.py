"""
Pytest fixtures and configuration for Sentinel AI backend tests.
Uses an isolated temporary SQLite database for every test session.
"""

import os
import sys
import tempfile
from pathlib import Path
import pytest
from starlette.testclient import TestClient

# Ensure backend root is on sys.path
backend_root = Path(__file__).resolve().parent.parent
if str(backend_root) not in sys.path:
    sys.path.insert(0, str(backend_root))

from app.config import settings
from app.database import init_db
from app.main import app

@pytest.fixture(autouse=True)
def setup_test_db(monkeypatch, tmp_path):
    """Use an isolated SQLite database file for each test."""
    db_file = tmp_path / "test_sentinel.db"
    monkeypatch.setattr(settings, "DATABASE_PATH", str(db_file))
    init_db(str(db_file))
    yield db_file

@pytest.fixture
def client():
    """FastAPI TestClient fixture."""
    with TestClient(app) as test_client:
        yield test_client
