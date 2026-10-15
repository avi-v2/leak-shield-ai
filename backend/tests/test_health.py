"""
Tests for GET /health endpoint.
Verifies real component health reporting on a fresh database.
"""

def test_health_endpoint_fresh_db(client):
    """Verify health endpoint reports database availability and status."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()

    assert data["status"] in ("ok", "degraded")
    assert data["database"] is True
    assert "version" in data
    assert "timestamp" in data
    assert "classifier" in data
    assert "llm" in data
