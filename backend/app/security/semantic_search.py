"""
Semantic Search Engine for Sentinel / Leak-Sheild-AI.

Performs vector-space semantic matching and concept expansion over audit events,
threat summaries, and security rules. Enables finding relevant security incidents
by intent and meaning, rather than relying exclusively on exact literal substring matches.
"""

import math
import re
from typing import List, Dict, Any, Tuple

# Domain-specific cybersecurity semantic concept mapping
CYBERSECURITY_THESAURUS: Dict[str, List[str]] = {
    "credential": [
        "password", "passwd", "pwd", "secret", "key", "token", "api_key",
        "apikey", "bearer", "auth", "authorization", "exfiltration", "leak", "sk", "akia", "ghp"
    ],
    "password": [
        "credential", "secret", "passwd", "pwd", "hash", "login", "admin", "db_pass"
    ],
    "token": [
        "jwt", "bearer", "oauth", "api_key", "secret", "auth", "session", "github", "slack"
    ],
    "injection": [
        "jailbreak", "override", "bypass", "dan", "persona", "prompt", "adversarial",
        "delimiter", "system", "verbatim", "instruction", "manipulation", "stan", "developer"
    ],
    "jailbreak": [
        "injection", "dan", "unrestricted", "persona", "bypass", "developer_mode", "aim", "stan"
    ],
    "override": [
        "disregard", "ignore", "forget", "bypass", "instruction", "guideline", "directive"
    ],
    "identity": [
        "pii", "personal", "aadhaar", "pan", "ssn", "social", "security", "citizen",
        "email", "phone", "mobile", "user", "individual"
    ],
    "pii": [
        "identity", "personal", "email", "phone", "ssn", "aadhaar", "pan", "card", "name"
    ],
    "financial": [
        "credit", "debit", "card", "pci", "payment", "visa", "mastercard", "amex", "cvv"
    ],
    "card": [
        "credit", "debit", "pci", "payment", "financial", "visa", "mastercard"
    ],
    "email": [
        "mail", "address", "inbox", "contact", "support", "user", "pii"
    ],
    "phone": [
        "telephone", "mobile", "number", "hotline", "contact", "sms"
    ],
    "exfiltration": [
        "leak", "egress", "theft", "unauthorized", "extract", "dump", "disclosure"
    ]
}

def tokenize(text: str) -> List[str]:
    """Tokenize and normalize text into clean alphabetic/numeric words."""
    if not text:
        return []
    return re.findall(r'\b[a-z0-9_]{2,}\b', text.lower())

def expand_query_terms(tokens: List[str]) -> List[str]:
    """Expand query terms with domain synonyms to capture semantic intent."""
    expanded = list(tokens)
    for tok in tokens:
        if tok in CYBERSECURITY_THESAURUS:
            expanded.extend(CYBERSECURITY_THESAURUS[tok])
    return expanded

class SemanticSearchEngine:
    """Vector-space semantic similarity search across audit records and threats."""

    @staticmethod
    def _create_event_document(event: Dict[str, Any]) -> str:
        """Combine all relevant event fields into a rich semantic document."""
        details = event.get("details", {}) or {}
        rules = " ".join(details.get("matched_rules", []))
        preview = details.get("sanitized_preview", "")
        cat = event.get("threat_category", "")
        summary = event.get("summary", "")
        action = event.get("action_taken", "")
        source = event.get("source", "")
        return f"{cat} {summary} {rules} {preview} {action} {source}"

    @classmethod
    def rank_events(
        cls,
        events: List[Dict[str, Any]],
        query: str,
        min_score: float = 0.1,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Rank a collection of events against a semantic query using expanded TF-IDF cosine similarity.

        Returns:
            List of matching events annotated with `similarity_score` (0.0 - 1.0)
            and sorted by relevance.
        """
        if not events or not query or not query.strip():
            return []

        raw_query_tokens = tokenize(query)
        if not raw_query_tokens:
            return []

        expanded_query_tokens = expand_query_terms(raw_query_tokens)

        # 1. Build document corpus
        doc_tokens_list = []
        df: Dict[str, int] = {}
        n_docs = len(events)

        for event in events:
            doc_text = cls._create_event_document(event)
            tokens = tokenize(doc_text)
            doc_tokens_list.append(tokens)
            for unique_tok in set(tokens):
                df[unique_tok] = df.get(unique_tok, 0) + 1

        # 2. Build Query Vector
        query_tf: Dict[str, float] = {}
        for tok in expanded_query_tokens:
            # Give higher weight to literal query terms vs synonyms
            weight = 2.0 if tok in raw_query_tokens else 0.8
            query_tf[tok] = query_tf.get(tok, 0.0) + weight

        query_vec: Dict[str, float] = {}
        query_norm_sq = 0.0
        for tok, tf in query_tf.items():
            doc_freq = df.get(tok, 1)
            idf = math.log((1 + n_docs) / (1 + doc_freq)) + 1.0
            val = tf * idf
            query_vec[tok] = val
            query_norm_sq += val * val

        query_norm = math.sqrt(query_norm_sq) if query_norm_sq > 0 else 1.0

        # 3. Calculate Cosine Similarity with each Document
        scored_events: List[Tuple[float, Dict[str, Any]]] = []

        for idx, (event, doc_tokens) in enumerate(zip(events, doc_tokens_list)):
            if not doc_tokens:
                continue

            doc_tf: Dict[str, float] = {}
            for tok in doc_tokens:
                doc_tf[tok] = doc_tf.get(tok, 0.0) + 1.0

            dot_product = 0.0
            doc_norm_sq = 0.0

            for tok, count in doc_tf.items():
                doc_freq = df.get(tok, 1)
                idf = math.log((1 + n_docs) / (1 + doc_freq)) + 1.0
                val = count * idf
                doc_norm_sq += val * val
                if tok in query_vec:
                    dot_product += val * query_vec[tok]

            doc_norm = math.sqrt(doc_norm_sq) if doc_norm_sq > 0 else 1.0
            cosine_sim = dot_product / (query_norm * doc_norm) if (query_norm * doc_norm) > 0 else 0.0

            # Direct keyword bonus if exact query tokens appear in category or rules
            event_text_lower = cls._create_event_document(event).lower()
            exact_hits = sum(1 for qt in raw_query_tokens if qt in event_text_lower)
            if exact_hits > 0:
                cosine_sim = min(1.0, cosine_sim + (exact_hits / len(raw_query_tokens)) * 0.25)

            if cosine_sim >= min_score:
                event_copy = dict(event)
                event_copy["similarity_score"] = round(cosine_sim, 4)
                event_copy["semantic_match_percentage"] = int(round(cosine_sim * 100))
                scored_events.append((cosine_sim, event_copy))

        # Sort descending by score
        scored_events.sort(key=lambda x: x[0], reverse=True)
        return [evt for _, evt in scored_events[:limit]]
