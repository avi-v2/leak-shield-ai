# Leak-Shield-AI — Complete Technical & Architectural Documentation

## 1. Executive Summary

As organizations integrate Large Language Models (LLMs) into production workflows, applications become vulnerable to novel threat surfaces:
1. **Accidental Credential & Data Exfiltration**: Developers and employees unwittingly paste API keys, credentials, customer PII, or internal tokens into prompt fields.
2. **Adversarial Prompt Injections & Jailbreaks**: Malicious users manipulate prompt contexts to bypass system instructions, leak underlying prompts, or execute unauthorized operations.
3. **Multimodal Metadata Leaks**: Image uploads transmitted to multimodal models often carry sensitive GPS coordinates, device identifiers, or embedded secret comments.
4. **Model Hallucination of Sensitive Output**: Models can inadvertently echo cached secrets, private training data, or indirect prompt injections back to the user.

**Leak-Shield-AI** is a purpose-built security gateway designed to solve these vulnerabilities. Functioning as a high-performance reverse proxy, it analyzes both incoming prompts and outgoing completions, applying automated redaction, heuristic analysis, machine learning classification, and immutable server-side policies before data enters or exits the AI model layer.

---

## 2. System Architecture

Leak-Shield-AI is built on a decoupled, zero-trust architecture comprising three tiers:

```
+-----------------------------------------------------------------------------------+
|                              1. PRESENTATION TIER                                 |
|                                                                                   |
|  React 18 Dashboard (Vite + TailwindCSS + Recharts)                               |
|  - Real-time incident feed & threat visualizer                                    |
|  - Interactive text & multimodal image scanning sandbox                           |
|  - End-to-end LLM proxy playground                                                |
|  - Policy configuration & immutable rule management                               |
|  - Forensic audit logs with semantic search                                       |
+-----------------------------------------------------------------------------------+
                                        |  REST / JSON (CORS Enabled)
                                        v
+-----------------------------------------------------------------------------------+
|                                2. GATEWAY TIER                                    |
|                                                                                   |
|  FastAPI Application Server (Python 3.11+, Uvicorn)                               |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  |                             SECURITY PIPELINE                               |  |
|  |                                                                             |  |
|  |  [A] DLP Regex & Algorithmic Engine (Keys, PII, Luhn-validated Cards)      |  |
|  |  [B] Prompt Injection Detector (Heuristic Rules + TF-IDF Classifier)        |  |
|  |  [C] Multimodal Image Scanner (EXIF GPS & Embedded Chunk Analyzer)          |  |
|  |  [D] Central Policy Engine (Deterministic ALLOW / REDACT / BLOCK)           |  |
|  |  [E] Output Completion Scanner (Post-Generation Response Filter)             |  |
|  |  [F] Semantic Search Engine (Vector Token Ranking for Audit Logs)           |  |
|  +-----------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------+
          |                                                       |
          | Persistent Storage                                    | HTTPX Client (Optional)
          v                                                       v
+-----------------------------+                         +---------------------------+
|      3. PERSISTENCE         |                         |      4. UPSTREAM LLM      |
|                             |                         |                           |
|  SQLite Database (WAL Mode) |                         |  Ollama / Local LLM       |
|  - Audit Events Table       |                         |  (Port 11434)             |
|  - Security Policies Table  |                         |  - Llama 3 / Mistral      |
|  - Zero-Secret Preview Log  |                         |                           |
+-----------------------------+                         +---------------------------+
```

---

## 3. End-to-End Request Lifecycle

### Pipeline A: Text Prompt Scanning (`POST /scan`)
1. **Input Validation**: Request prompt is validated via Pydantic schemas (length boundary check, non-empty validation).
2. **DLP Inspection**: The prompt is processed through the regular expression and algorithmic verification engine:
   - Identifies high-risk credentials (OpenAI, AWS, GitHub, Slack tokens, generic passwords).
   - Identifies personal data (SSN, credit cards with Luhn checksum validation, Indian PAN, Aadhaar, email, phone numbers).
3. **Deterministic Redaction**: Replacements are calculated and applied right-to-left (`[REDACTED_API_KEY]`, `[REDACTED_CARD]`, etc.) to prevent offset distortion.
4. **Prompt Injection Evaluation**:
   - Evaluated against heuristic jailbreak signatures (DAN, instruction overrides, system delimiters).
   - Vectorized using TF-IDF and scored via the Logistic Regression model.
5. **Policy Decision**: The Central Policy Engine synthesizes findings and issues an enforcement decision (`ALLOW`, `REDACT`, or `BLOCK`).
6. **Audit Event Generation**: A structured incident report is persisted to SQLite with a sanitized preview (maximum 160 characters).
7. **Response**: A JSON report is returned to the client detailing action, risk level, findings, and sanitized text.

### Pipeline B: Full Chat Proxying (`POST /chat`)
1. **Pre-Flight Input Scan**: Executes Pipeline A.
2. **Early Termination on Block**: If the policy evaluates to `BLOCK`, the request is halted immediately. No network request is initiated to the upstream LLM.
3. **Upstream Forwarding**: If evaluated to `ALLOW` or `REDACT`, the sanitized prompt is forwarded to Ollama via an asynchronous HTTPX client with strict timeout controls.
4. **Post-Flight Output Scan**: The LLM's generated response text is inspected for any inadvertent sensitive data leakage before leaving the gateway.
5. **Final Audit & Delivery**: Audit records capture prompt findings, output findings, total end-to-end latency, and upstream model metadata.

### Pipeline C: Image Privacy & Exfiltration Scan (`POST /scan/image`)
1. **Base64 Ingestion**: Base64 data or Data URIs are decoded into raw binary buffers.
2. **Format & Integrity Check**: Verified using Pillow (`PIL.Image`).
3. **EXIF & GPS Parsing**:
   - Decodes standard EXIF tags (Make, Model, Software, Serial Number).
   - Extracts GPS IFD tags (Latitude, Longitude, Altitude, Timestamp) and converts degrees/minutes/seconds rational tuples to standard decimal coordinates.
4. **Steganography & Comment Extraction**:
   - Extracts PNG chunks (`tEXt`, `zTXt`, `iTXt`).
   - Scans chunk values and JPEG user comments using DLP credential patterns.
5. **Sanitization**: Strips all metadata markers, re-encoding a pristine image buffer.
6. **Policy Enforcement & Storage**: Audit event is generated with image dimensions and format; returned with sanitized base64 output.

---

## 4. Deep Dive: Security Engines & Detection Logic

### 4.1 Sensitive Data DLP Engine (`app/security/sensitive_data.py`)

The DLP engine utilizes a combination of pattern matching, structural verification, and algorithmic integrity checks:

| Rule Identifier | Detection Strategy | Validation Mechanism | Replacement Token |
|---|---|---|---|
| `RULE_OPENAI_API_KEY` | Regex: `\b(sk-[a-zA-Z0-9]{20,T3BlbkFJ[a-zA-Z0-9]{20,}\|sk-proj-[a-zA-Z0-9_-]{40,})\b` | Prefix & Length | `[REDACTED_API_KEY]` |
| `RULE_AWS_ACCESS_KEY` | Regex: `\b((?:AKIA\|ABIA\|ACCA\|ASIA)[0-9A-Z]{16})\b` | Standard AWS IAM prefix | `[REDACTED_AWS_KEY]` |
| `RULE_GITHUB_TOKEN` | Regex: `\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b` | GitHub token prefix format | `[REDACTED_GITHUB_TOKEN]` |
| `RULE_SLACK_TOKEN` | Regex: `\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32})\b` | Slack workspace token format | `[REDACTED_SLACK_TOKEN]` |
| `RULE_CREDIT_CARD` | Regex: `\b(?:4[0-9]{12}(?:[0-9]{3})?\|5[1-5][0-9]{14}\|3[47][0-9]{13})\b` | **Luhn Checksum Algorithm** | `[REDACTED_CARD]` |
| `RULE_US_SSN` | Regex: `\b(?!000\|666\|9\d{2})(\d{3})[- ]?(?!00)(\d{2})[- ]?(?!0000)(\d{4})\b` | Area/Group code validation | `[REDACTED_SSN]` |
| `RULE_INDIAN_PAN` | Regex: `\b([A-Z]{5}[0-9]{4}[A-Z])\b` | Format verification | `[REDACTED_PAN]` |
| `RULE_INDIAN_AADHAAR`| Regex: `\b([2-9]{1}[0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4})\b` | Non-zero starting digit format | `[REDACTED_AADHAAR]` |
| `RULE_PASSWORD` | Contextual: `(?:password\|passwd\|pwd)\s*(?:=|:|is)\s*['"]?([^\s'"]{6,})` | Assignment pattern matching | `[REDACTED_PASSWORD]` |
| `RULE_EMAIL_ADDRESS`| RFC 5322 Standard Email Regex | Standard host syntax | `[REDACTED_EMAIL]` |
| `RULE_PHONE_NUMBER` | E.164 & International Format Regex | Digit grouping verification | `[REDACTED_PHONE]` |

#### Deterministic Right-to-Left Replacement
When multiple sensitive patterns exist in a single document, naive sequential replacement causes string offset drift (a string modification at index 10 invalidates all matches recorded at index 50+). Leak-Shield-AI solves this by sorting all identified findings by their starting index in descending order:
```python
findings.sort(key=lambda f: f.start, reverse=True)
for finding in findings:
    redacted = redacted[:finding.start] + finding.replacement + redacted[finding.end:]
```
This guarantees mathematical immutability for remaining match boundaries.

---

### 4.2 Prompt Injection & Jailbreak Defense (`app/security/injection_detector.py` & `classifier.py`)

Adversarial prompts employ semantic camouflage, instruction overrides, or roleplay personas (DAN). Leak-Shield-AI uses a two-stage hybrid detector:

#### Stage 1: Rule-Based Heuristic Signatures
Immediate high-confidence triggers catch known jailbreak framing:
- **Instruction Overrides**: Patterns like `ignore (?:all )?(?:previous|prior) (?:instructions|rules|prompts)`, `disregard all earlier directives`.
- **System Delimiters**: Artificial framing such as `--- BEGIN SYSTEM OVERRIDE ---`, `[SYSTEM PROMPT]`, `<<SYS>>`.
- **Persona Jailbreaks**: "Do Anything Now" (DAN), "Developer Mode enabled", "unfiltered AI assistant with no moral guidelines".
- **Privileged Leak Commands**: `print your initial system prompt`, `reveal instructions above`.

#### Stage 2: Machine Learning TF-IDF Classifier
- **Feature Extraction**: Sub-word and word-level n-grams (1 to 2 n-grams) capturing structural syntax of adversarial attacks.
- **Model Architecture**: Logistic Regression with L2 regularization tuned for high recall.
- **Serialization Safety**: Serialized as standard JSON containing dictionary weights, vocabulary maps, and intercept values. This completely eliminates the arbitrary remote code execution (RCE) vulnerabilities inherent in Python's standard `pickle` serialization.

---

### 4.3 Multimodal Image Security Engine (`app/security/image_scanner.py`)

Modern multimodal LLMs accept images directly into the prompt context. Leak-Shield-AI prevents two primary image-based attack vectors:
1. **EXIF Geolocation Leakage**: Mobile devices embed precise GPS coordinates into photograph headers. The engine parses the `GPSInfo` tag block:
   $$\text{Decimal Degrees} = \text{Degrees} + \frac{\text{Minutes}}{60} + \frac{\text{Seconds}}{3600}$$
   If GPS metadata is detected, a high-severity finding is generated and the user is provided with latitude, longitude, and an automated sanitized image.
2. **Steganographic Chunk Exfiltration**: Malicious payloads or leaked API keys can be stored inside non-visual image chunks (such as PNG `tEXt` or JPEG `COM` chunks). The engine extracts all raw string values from these metadata blocks and pipes them through the DLP engine.

---

### 4.4 Central Policy Engine (`app/security/policy_engine.py`)

The policy engine operates as a deterministic decision matrix mapping detected threat categories and risk scores to enforcement actions:

- **`BLOCK`**: The request is completely intercepted and rejected with an explanation.
- **`REDACT`**: The prompt is allowed to proceed to the upstream LLM, but all sensitive values are replaced with deterministic placeholder tokens.
- **`ALLOW`**: The prompt contains zero policy violations and passes unaltered.

#### Immutable Invariants
To prevent misconfiguration or client-side tampering, the policy engine enforces immutable core constraints:
- `detectApiKeys`: Mandatory (`True`). Cannot be disabled via API or UI.
- `detectPasswords`: Mandatory (`True`). Cannot be disabled via API or UI.
- Any API request attempting to disable mandatory rules returns an immediate HTTP `400 Bad Request`.

---

### 4.5 Semantic Audit Search Engine (`app/security/semantic_search.py`)

To allow security analysts to search through thousands of historical security logs without requiring heavy external vector databases, Leak-Shield-AI implements an in-memory lexical-semantic search system:
1. **Tokenization & Normalization**: Strips punctuation, transforms text to lowercase, and filters common stop words.
2. **Security Synonym Expansion**: Queries are expanded using a cybersecurity domain thesaurus (e.g., query "api key" expands to include "credential", "secret", "token", "sk-proj").
3. **TF-IDF Vector Space Scoring**: Computes cosine similarity between the expanded query vector and pre-indexed event summaries.
4. **Ranked Output**: Returns top-matching audit events sorted by relevance score.

---

## 5. Database Schema & Persistence

All security events and system policies are persisted in a local SQLite database (`backend/sentinel.db`) with Write-Ahead Logging (WAL) enabled for concurrency.

### Table: `events`
Stores audit records for every inspected transaction:
```sql
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT NOT NULL UNIQUE,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    threat_category TEXT NOT NULL,
    severity TEXT NOT NULL,
    source TEXT NOT NULL,
    action_taken TEXT NOT NULL,
    status TEXT NOT NULL,
    summary TEXT NOT NULL,
    matched_rules TEXT,
    latency_ms INTEGER DEFAULT 0,
    sanitized_preview TEXT,
    is_output_scan BOOLEAN DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_action ON events(action_taken);
CREATE INDEX IF NOT EXISTS idx_events_category ON events(threat_category);
```

### Table: `policies`
Stores configuration parameters for detection rules:
```sql
CREATE TABLE IF NOT EXISTS policies (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    description TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Zero-Secret Privacy Guarantee
The database column `sanitized_preview` stores at most 160 characters of the prompt **after** all redaction tokens have been applied. Raw API keys, cleartext passwords, and original unredacted text are discarded from memory immediately after inspection and are never written to disk.

---

## 6. Frontend Dashboard Architecture

The frontend is an enterprise Cyber Operations dashboard built using React 18, Tailwind CSS, Lucide icons, and Recharts.

### Key Pages:
- **Security Overview (`Overview.jsx`)**: Real-time KPI cards (Inspected, Allowed, Blocked, PII leaks, Injections), hourly traffic area chart, threat category pie chart, and recent violations table.
- **Live Threat Monitor (`ThreatMonitor.jsx`)**: Real-time event stream with interactive filtering by severity, enforcement action, and category.
- **Prompt Security Scanner (`PromptScanner.jsx`)**: Interactive dual-tab sandbox for testing text prompts and multimodal image files with immediate visual feedback on matched rules and redacted previews.
- **Request Playground (`Playground.jsx`)**: Live interactive chat interface proxying sanitized requests directly to an active Ollama instance with round-trip latency tracking.
- **Security Policies (`Policies.jsx`)**: Interactive management of DLP sensitivity levels, prompt injection thresholds, and enforcement actions.
- **Audit Logs (`AuditLogs.jsx`)**: Full forensic log viewer featuring semantic search, CSV export, and selective log purging.
- **System Settings (`Settings.jsx`)**: Diagnostic endpoint testing, backend connection ping, and theme controls.

---

## 7. Automated Test Suite (37 Scenarios)

The test suite validates every critical security behavior under pytest:

| Category | File | Count | Verified Scenarios |
|---|---|---|---|
| **Sensitive Data** | `test_sensitive_data.py` | 6 | API keys, passwords, PAN/Aadhaar, credit cards, emails, benign clean text |
| **Prompt Injection**| `test_injection.py` | 4 | Instruction overrides, DAN jailbreaks, benign questions, model offline fallback |
| **Policy Engine** | `test_policy_engine.py` | 4 | Mandatory credential blocking, PII redaction, PII blocking, clean request flow |
| **Policies API** | `test_policies_api.py` | 4 | Policy retrieval, valid update, rejection of mandatory rule modification, invalid choices |
| **Chat Gateway** | `test_chat_gateway.py` | 5 | Blocked prompt isolation, upstream 503 handling, output redaction, standalone scan, input validation |
| **Image Scanner** | `test_image_scanner.py` | 6 | Clean images, embedded secret detection, GPS leak extraction & sanitization, corrupt files, API upload |
| **Audit & Metrics** | `test_audit_and_metrics.py` | 4 | Fresh database metrics, zero raw secret persistence, SQL aggregation accuracy, audit clearing |
| **Semantic Search** | `test_semantic_search.py` | 3 | Tokenization & synonym expansion, cosine vector ranking, `/events/search` endpoint |
| **Health Check** | `test_health.py` | 1 | Live system readiness reporting |
| **Total** | | **37** | **All 37 passing** |

---

## 8. Deployment & Operational Best Practices

1. **Reverse Proxy Configuration**: Deploy behind an enterprise reverse proxy (e.g., Nginx or Cloudflare) configured for SSL/TLS termination and DDoS mitigation.
2. **Environment Isolation**: Run the Python backend inside an isolated container with read-only access to root filesystems and write access restricted strictly to the SQLite database path.
3. **Database Maintenance**: SQLite with WAL mode handles high concurrency effectively. For large-scale distributed deployments, the SQLite persistence layer can be replaced with PostgreSQL with zero changes to schema definitions.
4. **Upstream Model Scaling**: In enterprise environments, point `OLLAMA_BASE_URL` to an internal vLLM, TensorRT-LLM, or private cloud LLM gateway cluster.
