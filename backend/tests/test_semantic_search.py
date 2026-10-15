"""
Automated unit tests for Semantic Search Engine in Leak-Sheild-AI.
Verifies concept expansion, vector similarity, and endpoint matching.
"""

from app.security.semantic_search import SemanticSearchEngine, tokenize, expand_query_terms

def test_tokenize_and_synonym_expansion():
    tokens = tokenize("Need to find credential theft and injection")
    assert "credential" in tokens
    assert "theft" in tokens
    assert "injection" in tokens

    expanded = expand_query_terms(tokens)
    # Synonyms of credential should be present (password, token, api_key, etc.)
    assert "password" in expanded
    assert "api_key" in expanded
    assert "jailbreak" in expanded

def test_semantic_ranking():
    events = [
        {
            "id": "evt_1",
            "threat_category": "Adversarial Prompt Injection",
            "summary": "Detected DAN jailbreak attempt trying to override instructions",
            "action_taken": "BLOCK",
            "source": "Chat Gateway",
            "details": {"matched_rules": ["RULE_INJECTION_OVERRIDE"], "sanitized_preview": "ignore rules"}
        },
        {
            "id": "evt_2",
            "threat_category": "Credential Exposure",
            "summary": "Detected OpenAI API key in prompt",
            "action_taken": "BLOCK",
            "source": "Prompt Scanner",
            "details": {"matched_rules": ["RULE_CREDENTIAL_API_KEY"], "sanitized_preview": "sk-[REDACTED]"}
        },
        {
            "id": "evt_3",
            "threat_category": "Benign Request",
            "summary": "User asked what is the weather today in Seattle",
            "action_taken": "ALLOW",
            "source": "Chat Gateway",
            "details": {"matched_rules": [], "sanitized_preview": "weather in seattle"}
        }
    ]

    # Searching for "jailbreak bypass" should rank evt_1 highest
    ranked_injection = SemanticSearchEngine.rank_events(events, query="jailbreak bypass", min_score=0.1)
    assert len(ranked_injection) > 0
    assert ranked_injection[0]["id"] == "evt_1"
    assert ranked_injection[0]["similarity_score"] > 0.3
    assert ranked_injection[0]["semantic_match_percentage"] > 30

    # Searching for "secret token" should rank evt_2 highest
    ranked_secret = SemanticSearchEngine.rank_events(events, query="secret token", min_score=0.1)
    assert len(ranked_secret) > 0
    assert ranked_secret[0]["id"] == "evt_2"

def test_events_search_api_endpoint(client):
    # Seed a test event
    from app.services.audit_service import record_audit_event
    record_audit_event(
        request_id="req_semantic_test",
        threat_category="Credential Exposure",
        severity="critical",
        source="Gateway Test",
        action_taken="BLOCK",
        status="PROCESSED",
        summary="User attempted to leak AWS AKIA token",
        matched_rules=["RULE_CREDENTIAL_AWS_KEY"],
        latency_ms=12,
        sanitized_preview="AKIA[REDACTED]"
    )

    resp = client.get("/events/search?query=cloud+secret")
    assert resp.status_code == 200
    results = resp.json()
    assert isinstance(results, list)
    assert any(r["threat_category"] == "Credential Exposure" for r in results)
    for r in results:
        assert "similarity_score" in r
        assert "semantic_match_percentage" in r
