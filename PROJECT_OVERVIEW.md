# Leak-Shield-AI — Complete Technical & Architectural Documentation

## 1. Executive Summary

As organizations integrate Large Language Models (LLMs) into production workflows, applications become vulnerable to novel threat surfaces:
1. **Accidental Credential & Data Exfiltration**: Developers and employees unwittingly paste API keys, credentials, customer PII, or internal tokens into prompt fields.
2. **Adversarial Prompt Injections & Jailbreaks**: Malicious users manipulate prompt contexts to bypass system instructions, leak underlying prompts, or execute unauthorized operations.
3. **Multimodal Metadata Leaks**: Image uploads transmitted to multimodal models often carry sensitive GPS coordinates, device identifiers, or embedded secret comments.
4. **Document Data Leakage & Hidden Injections**: Uploaded PDF, Word, or spreadsheet attachments frequently contain embedded credentials, hidden metadata, or injected adversarial instructions.
5. **Model Hallucination of Sensitive Output**: Models can inadvertently echo cached secrets, private training data, or indirect prompt injections back to the user.

**Leak-Shield-AI** is a purpose-built security gateway and Security Operations Center (SOC) designed to solve these vulnerabilities. Functioning as a high-performance reverse proxy, it analyzes incoming prompts, uploaded files, and images, as well as outgoing model completions. It applies automated redaction, heuristic analysis, machine learning classification, structural file sanitization, and immutable server-side policies before data enters or exits the AI model layer.

---

## 2. System Architecture

Leak-Shield-AI is built on a decoupled, zero-trust architecture comprising three tiers:

```
+-----------------------------------------------------------------------------------+
|                              1. PRESENTATION TIER                                 |
|                                                                                   |
|  React 18 Dashboard (Vite + TailwindCSS + Recharts)                               |
|  - AI Security Operations Center (SOC) with 8 Real-time KPI Cards                 |
|  - Time-series security activity telemetry (1h, 24h, 7d, 30d, All Time)           |
|  - Threat category breakdown (Findings count vs. Unique threatened scans)         |
|  - Prompt injection intelligence (Normalized phrase frequency & detection methods)|
|  - DLP analytics & verified sanitized preview samples (Zero raw secrets)          |
|  - Policy verdict distribution (ALLOW / REDACT / BLOCK) & top justifications       |
|  - File & image security telemetry (MIME breakdown, OCR stats, metadata leaks)    |
|  - Filterable security event audit log with forensic modal inspection             |
|  - Interactive text, document, and image scanner with live redaction              |
|  - End-to-end LLM proxy playground & policy configuration                         |
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
|  |  [C] Document Content Scanner & Redactor (PyMuPDF, python-docx, CSV, JSON)  |  |
|  |  [D] Multimodal Image Scanner & Redactor (OCR Box Masking & EXIF Scrubber)  |  |
|  |  [E] Central Policy Engine (Deterministic ALLOW / REDACT / BLOCK)           |  |
|  |  [F] Output Completion Scanner (Post-Generation Response Filter)             |  |
|  |  [G] Real-Time SOC Analytics & Aggregation Engine (dashboard_service.py)   |  |
|  |  [H] Semantic Search Engine (Vector Token Ranking for Audit Logs)           |  |
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

## 3. End-to-End Request Lifecycles

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
7. **Response**: A JSON report is returned detailing action, risk level, findings, and sanitized text.

### Pipeline B: Full Chat Proxying (`POST /chat`)
1. **Pre-Flight Input Scan**: Executes Pipeline A.
2. **Early Termination on Block**: If evaluated to `BLOCK`, the request is halted immediately. No network request is initiated to the upstream LLM.
3. **Upstream Forwarding**: If evaluated to `ALLOW` or `REDACT`, the sanitized prompt is forwarded to Ollama via an asynchronous HTTPX client with strict timeout controls.
4. **Post-Flight Output Scan**: The LLM's generated response text is inspected for any inadvertent sensitive data leakage before leaving the gateway.
5. **Final Audit & Delivery**: Audit records capture prompt findings, output findings, total end-to-end latency, and upstream model metadata.

### Pipeline C: Document Content Redaction (`POST /redact/file`)
1. **Format Validation**: Validates file magic bytes and extensions (`.pdf`, `.docx`, `.csv`, `.json`, `.txt`, `.md`).
2. **Adversarial Injection Check**: Evaluates full extracted document text for prompt injections. **Prompt injections trigger a mandatory BLOCK** because redacting an API key does not neutralize malicious instructions.
3. **Structural Content Redaction**:
   - **PDF**: Uses PyMuPDF (`add_redact_annot` and `apply_redactions`) to genuinely purge sensitive text characters from underlying PDF content streams. No superficial black rectangles.
   - **DOCX**: Traverses paragraphs, table cells, headers, and footers, replacing sensitive tokens in place.
   - **CSV**: Performs cell-by-cell redaction while preserving row/column CSV delimiters.
   - **JSON**: Recursively traverses nested keys and arrays, masking sensitive string values while maintaining valid JSON structure.
   - **TXT / MD**: Applies deterministic right-to-left UTF-8 text masking.
4. **Multi-Stage Verification**:
   - Reopens the sanitized file to verify structural integrity.
   - Re-scans the reopened document to ensure zero residual sensitive data patterns remain.
5. **Verified Download Token**: Issues a cryptographic single-use file ID for secure client download via `GET /redact/download/{file_id}`.

### Pipeline D: Image Privacy & OCR Redaction (`POST /redact/image`)
1. **Base64 Ingestion**: Base64 or multipart image data is decoded into memory.
2. **EXIF & Metadata Stripping**: Strips EXIF metadata, GPS latitude/longitude coordinates, and embedded comments.
3. **OCR Text Recognition**: Reuses the OCR pipeline to detect text and capture exact bounding boxes $(x, y, w, h)$.
4. **Sensitive Span Mapping**: Identifies sensitive tokens (credentials, phone numbers, PII) in the OCR text and maps them to coordinate bounding boxes.
5. **Opaque Visual Masking**: Draws opaque rectangular masks over the exact bounding boxes of detected sensitive values.
6. **Verification & Delivery**: Re-opens and verifies the sanitized image, returning sanitized Base64 output.

### Pipeline E: SOC Telemetry & Real-Time Analytics (`GET /metrics/*`)
1. **Database-Driven Computation**: Queries SQLite directly; never returns fabricated metrics or demo placeholders.
2. **Time-Range Filtering**: Supports `1h`, `24h`, `7d`, `30d`, and `all`, translating into ISO 8601 UTC cutoff queries.
3. **Documented Denominators**: Calculates:
   $$\text{Threat Rate (\%)} = \frac{\text{Threatened Scans}}{\text{Total Scans}} \times 100$$
   $$\text{Block Rate (\%)} = \frac{\text{Blocked Requests}}{\text{Total Scans}} \times 100$$
   Handles zero denominators safely without division-by-zero exceptions.
4. **Category Normalization**: Unifies detection rules into 11 canonical cybersecurity categories, tracking both raw findings and unique affected scans.
5. **Privacy Guarantee**: All returned previews and audit snippets are strictly sanitized. Raw secrets and credentials never enter telemetry responses.

---

## 4. Deep Dive: Security Engines & Detection Logic

### 4.1 Sensitive Data DLP Engine (`app/security/sensitive_data.py`)

The DLP engine utilizes a combination of pattern matching, structural verification, and algorithmic integrity checks:

| Rule Identifier | Category | Validation Mechanism | Replacement Token |
|---|---|---|---|
| `RULE_OPENAI_API_KEY` | Credential Exfiltration | Prefix & Length validation | `[REDACTED_API_KEY]` |
| `RULE_AWS_ACCESS_KEY` | Credential Exfiltration | AWS IAM prefix (`AKIA`, `ASIA`, etc.) | `[REDACTED_AWS_KEY]` |
| `RULE_AWS_SECRET_KEY` | Credential Exfiltration | High-entropy 40-character base64 secret | `[REDACTED_AWS_SECRET]` |
| `RULE_GITHUB_TOKEN` | Credential Exfiltration | Prefix validation (`ghp_`, `gho_`, etc.) | `[REDACTED_GITHUB_TOKEN]` |
| `RULE_SLACK_TOKEN` | Credential Exfiltration | Workspace token structure | `[REDACTED_SLACK_TOKEN]` |
| `RULE_CREDIT_CARD` | Financial Data | **Luhn Checksum Algorithm** | `[REDACTED_CARD]` |
| `RULE_US_SSN` | Personal Identifiable Info | Area/Group code syntax validation | `[REDACTED_SSN]` |
| `RULE_INDIAN_PAN` | Indian Identifiers | Structural pattern (`[A-Z]{5}[0-9]{4}[A-Z]`) | `[REDACTED_PAN]` |
| `RULE_INDIAN_AADHAAR`| Indian Identifiers | 12-digit non-zero leading pattern | `[REDACTED_AADHAAR]` |
| `RULE_PASSWORD` | Credential Exfiltration | Assignment pattern (`password = ...`) | `[REDACTED_PASSWORD]` |
| `RULE_EMAIL_ADDRESS`| Personal Identifiable Info | RFC 5322 Standard Email Regex | `[REDACTED_EMAIL]` |
| `RULE_PHONE_NUMBER` | Personal Identifiable Info | E.164 & International Format Regex | `[REDACTED_PHONE]` |

---

## 5. Automated Test Suite (71 Tests Passing)

The backend features 71 automated tests in Pytest validating real security enforcement:

```powershell
.\backend\.venv\Scripts\pytest.exe -v
```

### Test Distribution:
- **`test_dashboard_analytics.py` (3 tests)**: Empty database zero-denominator handling, full metrics accuracy on populated database, time range filtering, prompt injection keyword extraction, DLP safe previews, and parameterized event filters.
- **`test_redaction.py` (13 tests)**: Plaintext redaction, CSV cell redaction, JSON object redaction, DOCX paragraph and table tree scrubbing, PyMuPDF PDF stream purging, OCR bounding box image redaction, EXIF metadata stripping, prompt injection mandatory BLOCK enforcement, and download token verification.
- **`test_file_and_image_content_scanner.py` (18 tests)**: Document parsing across PDF, DOCX, CSV, JSON, TXT, MD; image OCR extraction; and file signature checks.
- **`test_sensitive_data.py` (6 tests)**: Regex accuracy, Luhn algorithm card verification, right-to-left redaction, and Indian identifiers (PAN/Aadhaar).
- **`test_injection.py` (4 tests)**: Adversarial prompts, DAN personas, system delimiter overrides, and TF-IDF classifier inference.
- **`test_policy_engine.py` (4 tests)**: Central policy matrix evaluation, threshold overrides, and remediation actions.
- **`test_policies_api.py` (4 tests)**: Policy configuration API and mandatory credential rule enforcement.
- **`test_chat_gateway.py` (5 tests)**: Proxy request handling, early termination on block, and output completion scanning.
- **`test_audit_and_metrics.py` (4 tests)**: SQLite WAL audit logging, zero-secret persistence, and operational metrics.
- **`test_semantic_search.py` (3 tests)**: Vector similarity scoring, keyword expansion, and token cosine similarity.
- **`test_image_scanner.py` (6 tests)**: EXIF GPS coordinates, camera serial numbers, and metadata sanitization.
- **`test_health.py` (1 test)**: Diagnostics and component readiness.

---

## 6. Production Security Guarantees

1. **Zero Secret Persistence**: Raw secrets, plaintext passwords, and full payment cards are never stored in the database or returned in telemetry responses. Previews are truncated to 160 characters and masked.
2. **Immutable Protection**: Mandated security controls (API key and password detection) cannot be disabled via API or UI policies.
3. **True Redaction**: Redaction physically purges sensitive byte streams and covers OCR bounding boxes, guaranteeing that data cannot be recovered by inspecting underlying file objects.
4. **Prompt Injection Independence**: Adversarial prompt injections in files or images trigger an immediate BLOCK, ensuring compromised files are never routed to an LLM under the guise of being "sanitized."
