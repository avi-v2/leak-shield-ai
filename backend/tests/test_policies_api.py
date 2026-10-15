"""
Tests for GET /policies and PUT /policies endpoints.
"""

def test_get_policies_endpoint(client):
    """Verify GET /policies returns default configuration."""
    response = client.get("/policies")
    assert response.status_code == 200
    data = response.json()

    assert data["detectApiKeys"] is True
    assert data["detectPasswords"] is True
    assert data["defaultAction"] in ("ALLOW", "REDACT", "BLOCK")
    assert data["highRiskThreshold"] in ("medium", "high", "critical")

def test_update_valid_policies(client):
    """Verify updating configurable policy switches."""
    payload = {
        "detectApiKeys": True,
        "detectCreditCards": False,
        "detectSsn": True,
        "detectEmails": False,
        "detectPasswords": True,
        "detectAadhaar": True,
        "detectPan": True,
        "detectPhone": False,
        "blockPromptInjection": True,
        "blockJailbreaks": True,
        "blockSystemPromptExtraction": True,
        "inspectModelOutputs": False,
        "defaultAction": "BLOCK",
        "highRiskThreshold": "medium"
    }

    response = client.put("/policies", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["defaultAction"] == "BLOCK"
    assert data["detectEmails"] is False
    assert data["highRiskThreshold"] == "medium"

def test_reject_disabling_mandatory_credentials(client):
    """Verify server rejects attempting to turn off API key or password detection."""
    payload = {
        "detectApiKeys": False, # Prohibited
        "detectCreditCards": True,
        "detectSsn": True,
        "detectEmails": True,
        "detectPasswords": True,
        "detectAadhaar": True,
        "detectPan": True,
        "detectPhone": True,
        "blockPromptInjection": True,
        "blockJailbreaks": True,
        "blockSystemPromptExtraction": True,
        "inspectModelOutputs": True,
        "defaultAction": "REDACT",
        "highRiskThreshold": "high"
    }

    response = client.put("/policies", json=payload)
    # Pydantic validator or router raises validation/bad request
    assert response.status_code in (400, 422)

def test_reject_invalid_action_choice(client):
    """Verify server rejects invalid action values."""
    payload = {
        "detectApiKeys": True,
        "detectCreditCards": True,
        "detectSsn": True,
        "detectEmails": True,
        "detectPasswords": True,
        "detectAadhaar": True,
        "detectPan": True,
        "detectPhone": True,
        "blockPromptInjection": True,
        "blockJailbreaks": True,
        "blockSystemPromptExtraction": True,
        "inspectModelOutputs": True,
        "defaultAction": "INVALID_ACTION_VALUE",
        "highRiskThreshold": "high"
    }

    response = client.put("/policies", json=payload)
    assert response.status_code == 422
