# Leak-Sheild-AI — AI Data Leakage Security Gateway & Prompt Firewall

**Leak-Sheild-AI** is an enterprise AI Data Leakage Prevention (DLP) and Prompt Injection Security Gateway built with Python, FastAPI, Scikit-learn, SQLite, and React.

It acts as a secure reverse proxy between client applications and Large Language Models (LLMs), inspecting, redacting, or blocking requests that contain sensitive credentials, personal identifiable information (PII), payment card data, or adversarial prompt injection attacks.

---

## Architecture Overview

```
                      +---------------------------------------+
                      |       React Frontend Dashboard        |
                      |   (Vite, TailwindCSS, Recharts)       |
                      +---------------------------------------+
                                          |
                      REST API (CORS, JSON, AbortController)
                                          |
                                          v
                      +---------------------------------------+
                      |     FastAPI Security Gateway          |
                      |          (Port 8000)                  |
                      +---------------------------------------+
                                          |
         +--------------------------------+--------------------------------+
         |                                |                                |
         v                                v                                v
+------------------+            +-------------------+            +-------------------+
|  Sensitive Data  |            | Prompt Injection  |            |  Central Policy   |
|   DLP Engine     |            |  TF-IDF + ML      |            |      Engine       |
|  (Regex & Luhn)  |            |  Classification   |            | (ALLOW/REDACT/BLK)|
+------------------+            +-------------------+            +-------------------+
         |                                |                                |
         +--------------------------------+--------------------------------+
                                          |
                                  +-------+-------+
                                  |               |
                         (If BLOCKED)    (If ALLOW / REDACT)
                                  |               |
                                  v               v
                      [Immediate 200 Rejection]  [Sanitized Prompt to Ollama]
                                                  |
                                                  v
                                         [Output DLP Scanner]
                                                  |
                                                  v
                                        +-------------------+
                                        | SQLite Database   |
                                        | (Audit & Metrics) |
                                        +-------------------+
```

### Backend Structure (`backend/`)
- **`app/main.py`**: FastAPI application entrypoint, CORS middleware, global exception handler.
- **`app/config.py`**: Environment variable loading and configurable defaults.
- **`app/schemas.py`**: Pydantic models for validation and request/response typing.
- **`app/database.py`**: SQLite database connection, table initialization, and policy persistence.
- **`app/routes/`**:
  - `health.py`: Live component health checking (API, SQLite, ML model, Ollama).
  - `scan.py`: Standalone DLP and prompt injection scanning (runs without LLM).
  - `chat.py`: End-to-end proxy pipeline (input scan -> policy -> LLM -> output scan -> audit).
  - `events.py`: Audit log retrieval and deletion with pagination.
  - `policies.py`: Server-side policy management with mandatory protection enforcement.
  - `metrics.py`: Real-time telemetry computed directly from SQLite events.
- **`app/security/`**:
  - `sensitive_data.py`: Modular regex rules and contextual validators (API keys, SSN, PAN, Aadhaar, Cards, Passwords, Emails, Phone numbers).
  - `injection_detector.py`: Heuristic override/jailbreak detection combined with ML scoring.
  - `classifier.py`: Production inference interface loading TF-IDF + Logistic Regression model safely.
  - `policy_engine.py`: Central policy enforcement with conservative defaults.
  - `output_scanner.py`: Post-generation inspection to sanitize LLM completion data.
- **`app/services/`**:
  - `audit_service.py`: Zero-secret audit persistence and real SQL metric aggregations.
  - `llm_service.py`: HTTPX client communicating with local Ollama instances.
- **`training/`**:
  - `training_data.csv`: Labeled benign and prompt injection dataset.
  - `train_classifier.py`: Standalone TF-IDF vectorization and Logistic Regression training pipeline.
- **`tests/`**: Comprehensive Pytest suite covering all 14 required security scenarios.

---

## Quick Start on Windows

### 1. Prerequisites
- **Python 3.11+** installed
- **Node.js 18+** installed

### 2. Automated One-Click Launch
Double-click `start.bat` in the project root, or execute from PowerShell:
```powershell
.\start.bat
```
This script automatically:
1. Detects Python.
2. Starts the FastAPI server on `http://127.0.0.1:8000`.
3. Starts the Vite React dashboard on `http://localhost:5173`.
4. Opens your browser to `http://localhost:5173`.

---

## Manual Step-by-Step Setup

### Step 1: Backend Setup
Open a terminal in the project directory:
```powershell
cd backend

# Install dependencies
pip install -r requirements.txt

# Train baseline ML classifier
python training/train_classifier.py

# Start the FastAPI server
python main.py
```
Backend will be live at:
- Gateway Base URL: `http://127.0.0.1:8000`
- Interactive Swagger API Docs: `http://127.0.0.1:8000/docs`

### Step 2: Frontend Setup
Open a second terminal in the project root:
```powershell
# Install frontend dependencies
npm install

# Start Vite development server
npm run dev
```
Frontend will be live at: `http://localhost:5173`.

---

## Machine Learning Classifier Training

The prompt injection classifier uses a lightweight TF-IDF Vectorizer and Logistic Regression baseline.

To train or re-train the model:
```powershell
cd backend
python training/train_classifier.py
```

### Held-Out Evaluation Results:
```
--- Held-Out Test Set Performance ---
Accuracy:  1.0000
Precision: 1.0000
Recall:    1.0000
F1 Score:  1.0000
Confusion Matrix: TP=8, FP=0, FN=0, TN=8

Artifact Exported: backend/models/injection_classifier.json
```

---

## Automated Testing Suite

Leak-Sheild-AI includes a full test suite verifying DLP detection, heuristic jailbreak analysis, prompt injection scoring, policy enforcement, blocked prompt isolation, output redaction, and metric computation.

Run tests with Pytest:
```powershell
pytest backend/tests -v
```

All 28 tests execute against an isolated temporary SQLite database:
```
tests/test_audit_and_metrics.py ....
tests/test_chat_gateway.py .....
tests/test_health.py .
tests/test_injection.py ....
tests/test_policies_api.py ....
tests/test_policy_engine.py ....
tests/test_sensitive_data.py ......
======================== 28 passed ========================
```

---

## Local LLM Integration (Ollama)

Leak-Sheild-AI works out of the box **without** an LLM for prompt scanning (`POST /scan`).

To enable end-to-end chat proxying with a local model:
1. Download and install [Ollama](https://ollama.com/).
2. Pull a local model (e.g. Llama 3):
   ```bash
   ollama run llama3
   ```
3. Set environment variables (or rely on the defaults in `.env.example`):
   - `LLM_PROVIDER=ollama`
   - `OLLAMA_BASE_URL=http://127.0.0.1:11434`
   - `OLLAMA_MODEL=llama3`

If Ollama is stopped or unreachable, `POST /chat` returns an honest `503 Service Unavailable` error detailing that the upstream provider cannot be reached. It **never** fabricates a simulated AI response.

---

## API Reference & Schemas

### 1. `GET /health`
Returns actual availability status of database, classifier, and LLM:
```json
{
  "status": "ok",
  "gateway": "operational",
  "version": "1.0.0",
  "engine": "Leak-Sheild-AI-Engine-v2.0",
  "timestamp": "2026-10-15T09:00:00Z",
  "database": true,
  "classifier": true,
  "llm": false,
  "llm_provider": "ollama",
  "llm_model": "llama3",
  "details": {
    "database": "connected",
    "classifier": "Active (TF-IDF + Logistic Regression Baseline)",
    "llm": "Cannot connect to Ollama at http://127.0.0.1:11434. Service is not running."
  }
}
```

### 2. `POST /scan`
Inspects prompt for sensitive data, secrets, and adversarial directives without calling an LLM:
**Request:**
```json
{
  "prompt": "Here is my key: sk-proj-123456789012345678901234567890"
}
```
**Response:**
```json
{
  "action": "BLOCK",
  "risk_level": "critical",
  "prompt_injection_risk": "none",
  "findings": [
    {
      "type": "RULE_OPENAI_API_KEY",
      "category": "Credential Exfiltration",
      "description": "OpenAI secret key or project token detected in prompt payload.",
      "severity": "critical",
      "match_preview": "Signature pattern [sk-...]",
      "start": 16,
      "end": 58
    }
  ],
  "redacted_prompt": "Here is my key: [REDACTED_API_KEY]",
  "recommendation": "Reject this request immediately. Prompt contains active credentials or secret keys.",
  "explanation": "Blocked by mandatory credential security rule. Private API keys and passwords may not be forwarded.",
  "scanned_at": "2026-10-15T09:00:00Z",
  "request_id": "scan_8f4a12bc",
  "classifier_available": true,
  "classifier_score": 0.05
}
```

### 3. `POST /chat`
Secure proxy routing permitted, sanitized prompts to the LLM:
**Request:**
```json
{
  "prompt": "Please summarize customer email john.doe@example.com",
  "model": "llama3"
}
```
**Response (Allowed / Redacted):**
```json
{
  "decision": "REDACT",
  "request_id": "chat_90c128ba",
  "latency_ms": 320,
  "response": "Here is the summary of the customer email...",
  "blocked_reason": null,
  "findings": [
    {
      "type": "RULE_EMAIL_ADDRESS",
      "category": "Personal Identifiable Info",
      "severity": "medium",
      "match_preview": "Email pattern [***@***]"
    }
  ],
  "timestamp": "2026-10-15T09:00:00Z"
}
```
*Note: If a prompt is `BLOCK`ed, it is intercepted immediately and never sent to the LLM.*

### 4. `GET /events`
Retrieves paginated audit events:
- Parameters: `limit` (default: 100), `offset` (default: 0), `decision` (optional: `ALLOW`, `REDACT`, `BLOCK`)
- Returns array of event objects without raw secrets.

### 5. `DELETE /events`
Purges audit log records upon explicit user confirmation.

### 6. `GET /policies` & `PUT /policies`
Inspects and modifies server-side security policies. Attempts to disable mandatory protections (`detectApiKeys`, `detectPasswords`) are rejected with `400 Bad Request`.

### 7. `GET /metrics`
Returns real aggregation queries from the SQLite database:
- `total_requests`, `allowed_requests`, `blocked_requests`, `redacted_requests`
- `sensitive_data_detections`, `injection_detections`
- `traffic_over_time`: Hourly bucketed time-series
- `threat_distribution`: Real breakdown of detected violations

---

## Security Guarantees and Limitations

1. **Deterministic Redaction**: Replacements use standard tokens (`[REDACTED_EMAIL]`, `[REDACTED_API_KEY]`, `[REDACTED_PASSWORD]`, etc.) replaced from right-to-left to ensure character positions do not corrupt simultaneous findings.
2. **Mandatory Credential Protection**: Server logic overrides any frontend attempt to disable detection of API keys or passwords.
3. **Audit Trail Privacy**: Audit events record only sanitized previews up to 160 characters. Raw secrets and passwords never touch logs or databases.
4. **Prototype Boundaries**:
   - The regex rules match known pattern signatures. Obfuscated, encrypted, or novel formats cannot be guaranteed caught by regex alone.
   - The TF-IDF + Logistic Regression model is a lightweight statistical baseline. It is not an absolute barrier against sophisticated multilingual, multi-step, or token-manipulation adversarial jailbreaks. Production deployments should incorporate continuous threat intelligence feeds and multi-tiered defense-in-depth.
