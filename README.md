# Leak-Shield-AI — AI Data Leakage Security Gateway & Prompt Firewall

Leak-Shield-AI is an enterprise-grade security gateway and reverse proxy positioned between client applications and Large Language Models (LLMs). It intercepts, evaluates, redacts, or blocks prompts and completions that contain sensitive credentials, personal identifiable information (PII), payment card data, adversarial prompt injection attacks, or image-based metadata/exfiltration leaks.

Built with **Python (FastAPI)**, **Scikit-learn**, **SQLite**, and **React (Vite + TailwindCSS)**, Leak-Shield-AI enforces zero-trust security boundaries entirely server-side, ensuring unbypassable policy enforcement with zero raw credential retention.

---

## Key Features

- **Sensitive Data Loss Prevention (DLP)**: High-precision regex engine with algorithmic contextual validators (such as Luhn algorithm verification for credit cards) detecting API keys (OpenAI, AWS, GitHub, Slack, HuggingFace, Generic), passwords, credit cards, SSNs, Indian PAN cards, Aadhaar numbers, phone numbers, and email addresses.
- **Bi-Directional Redaction**: Deterministic, right-to-left character replacement ensuring multi-token overlaps do not shift character offsets or corrupt prompt semantics.
- **Prompt Injection & Jailbreak Defense**: Multi-layered detection pairing rule-based heuristic pattern matching (DAN, system override delimiters, developer mode commands) with a trained TF-IDF + Logistic Regression machine learning model.
- **Document Content Security Scanner (`POST /scan/file`)**: Deep parsing and inspection of uploaded `.pdf`, `.docx`, `.csv`, `.json`, `.txt`, and `.md` files. Validates magic signatures, chunks large text with source location tracking (page, row, paragraph), and scans the actual contents for sensitive data and injection attacks.
- **Multimodal Image & Visible OCR Scanner (`POST /scan/image`)**: Inspects uploaded images using Tesseract OCR for visible injection directives and leaked credentials, extracts EXIF GPS location data and camera/device fingerprints, inspects PNG/JPEG embedded metadata comments, and generates sanitized clean images.
- **Semantic Audit Log Search**: Search past security incidents using intelligent keyword expansion and cosine similarity token scoring across threat events.
- **Enforced Server-Side Policies**: Configurable protection profiles with immutable enforcement of mandatory rules (credential detection cannot be bypassed or disabled).
- **Zero-Secret Audit Logging**: Only sanitized previews and cryptographically masked audit logs touch persistent storage. Raw secrets, tokens, and plaintext passwords are never recorded in logs or databases.
- **Offline & Standalone Operation**: Standalone prompt and image inspection runs entirely locally without requiring an upstream LLM connection.

---

## Architecture & Data Flow

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
     +-------------------+----------------+-------------------+-------------------+
     |                   |                |                   |                   |
     v                   v                v                   v                   v
+----------+       +-----------+    +-----------+       +-----------+       +-----------+
| Sensitive|       | Prompt    |    | Multimodal|       | Central   |       | Semantic  |
| Data DLP |       | Injection |    | Image     |       | Policy    |       | Search &  |
| Engine   |       | Classifier|    | Scanner   |       | Engine    |       | Analytics |
+----------+       +-----------+    +-----------+       +-----------+       +-----------+
     |                   |                |                   |                   |
     +-------------------+----------------+-------------------+-------------------+
                                          |
                                  +-------+-------+
                                  |               |
                         (If BLOCKED)    (If ALLOW / REDACT)
                                  |               |
                                  v               v
                      [Immediate 200 Rejection]  [Forward to Upstream LLM]
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

---

## Directory Structure

```
leak-shield-ai/
├── backend/
│   ├── app/
│   │   ├── main.py                  # FastAPI entry point & CORS configuration
│   │   ├── config.py                # Environment configuration & settings
│   │   ├── database.py              # SQLite connection, schemas & seeds
│   │   ├── schemas.py               # Pydantic v2 validation models
│   │   ├── routes/
│   │   │   ├── health.py            # Diagnostic health check endpoint
│   │   │   ├── scan.py              # Text prompt DLP & injection scanner
│   │   │   ├── image_scan.py        # Image EXIF & steganography scanner
│   │   │   ├── chat.py              # End-to-end LLM reverse proxy
│   │   │   ├── events.py            # Audit log retrieval, search & purge
│   │   │   ├── policies.py          # Security policy management API
│   │   │   └── metrics.py           # Real-time incident telemetry
│   │   ├── security/
│   │   │   ├── sensitive_data.py    # DLP regex patterns & Luhn checksum
│   │   │   ├── injection_detector.py# Heuristic injection rules & scoring
│   │   │   ├── classifier.py        # TF-IDF + Logistic Regression inference
│   │   │   ├── image_scanner.py     # EXIF metadata parser & sanitization
│   │   │   ├── semantic_search.py   # Token matching & vector ranking
│   │   │   ├── policy_engine.py     # Central policy evaluation matrix
│   │   │   └── output_scanner.py    # Post-generation LLM output filter
│   │   └── services/
│   │       ├── audit_service.py     # Zero-secret database logging
│   │       └── llm_service.py       # Asynchronous HTTPX Ollama client
│   ├── models/
│   │   └── injection_classifier.json# Pretrained classifier artifact
│   ├── training/
│   │   ├── training_data.csv        # Balanced prompt injection dataset
│   │   └── train_classifier.py      # Retraining pipeline script
│   ├── tests/                       # 37-scenario Pytest test suite
│   └── requirements.txt             # Python backend dependencies
├── src/
│   ├── components/
│   │   ├── common/                  # UI cards, badges, modals, toasts
│   │   ├── layout/                  # Navigation bar, sidebar, layout
│   │   └── threats/                 # Threat detail modal components
│   ├── context/
│   │   └── GatewayContext.jsx       # Global state & telemetry synchronization
│   ├── pages/
│   │   ├── Overview.jsx             # Security posture analytics & graphs
│   │   ├── ThreatMonitor.jsx        # Live security incident feed
│   │   ├── PromptScanner.jsx        # Interactive text & image sandbox
│   │   ├── Playground.jsx           # Live LLM proxy chat testbed
│   │   ├── Policies.jsx             # Policy configuration panel
│   │   ├── AuditLogs.jsx            # Forensic search & compliance table
│   │   └── Settings.jsx             # Connection status & gateway preferences
│   ├── services/
│   │   └── api.js                   # Typed backend client with error handling
│   ├── App.jsx                      # Client router & page routes
│   └── main.jsx                     # Vite entry point
├── package.json                     # Frontend dependencies & scripts
├── start.bat                        # Automated Windows one-click runner
├── vite.config.js                   # Vite bundler configuration
├── tailwind.config.js               # Tailwind CSS theme settings
└── PROJECT_OVERVIEW.md              # Detailed technical documentation
```

---

## Quick Start (Windows)

### Automated Launch
Double-click `start.bat` in the project root, or execute via PowerShell:
```powershell
.\start.bat
```
This script automatically:
1. Detects `backend\.venv` Python virtual environment.
2. Starts the FastAPI server on `http://127.0.0.1:8000`.
3. Starts the Vite React dashboard on `http://localhost:5173`.
4. Opens your default web browser to the dashboard.

---

## Manual Installation & Setup

### Prerequisites
- **Python 3.11+**
- **Node.js 18+**

### 1. Backend Setup
```powershell
cd backend

# Create virtual environment
python -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Install required packages
pip install -r requirements.txt

# Start backend server
python main.py
```
Backend will be active at:
- Gateway API: `http://127.0.0.1:8000`
- Interactive OpenAPI Docs: `http://127.0.0.1:8000/docs`

### 2. Frontend Setup
In a new terminal window at the project root:
```powershell
# Install dependencies
npm install

# Start Vite development server
npm run dev
```
Frontend will be accessible at `http://localhost:5173`.

---

## API Reference

### 1. Health Status
`GET /health`
Returns live readiness status of the database, classifier model, and upstream LLM:
```json
{
  "status": "ok",
  "gateway": "operational",
  "version": "1.0.0",
  "database": true,
  "classifier": true,
  "llm": false,
  "llm_provider": "ollama",
  "details": {
    "database": "connected",
    "classifier": "Active (TF-IDF + Logistic Regression Baseline)",
    "llm": "Ollama service offline or not configured"
  }
}
```

### 2. Prompt Text Scan
`POST /scan`
Evaluates a prompt without invoking an external LLM.

**Request:**
```json
{
  "prompt": "Export user details where token = 'sk-proj-9874591238914891238912839128'"
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
      "severity": "critical",
      "description": "OpenAI secret key or project token detected in prompt payload.",
      "match_preview": "Signature pattern [sk-...]",
      "start": 33,
      "end": 74,
      "replacement": "[REDACTED_API_KEY]"
    }
  ],
  "redacted_prompt": "Export user details where token = '[REDACTED_API_KEY]'",
  "recommendation": "Reject this request immediately. Prompt contains active credentials or secret keys.",
  "classifier_score": 0.05
}
```

### 3. Document Content Security Scan
`POST /scan/file`
Accepts multipart file upload (`.pdf`, `.docx`, `.csv`, `.json`, `.txt`, `.md`). Extracts text without executing embedded code, chunks large documents with location markers, and detects sensitive credentials and prompt injection attacks.

**Request:**
`multipart/form-data` with `file=@financial_report.pdf`

**Response:**
```json
{
  "request_id": "file_829fa110",
  "action": "BLOCK",
  "risk_level": "critical",
  "filename": "financial_report.pdf",
  "detected_file_type": ".pdf",
  "file_size_bytes": 104230,
  "extraction_status": "SUCCESS",
  "ocr_status": "unavailable",
  "total_pages_or_rows": 4,
  "findings": [
    {
      "type": "RULE_OPENAI_API_KEY",
      "category": "Credential Exfiltration",
      "severity": "critical",
      "description": "OpenAI secret key or project token detected in prompt payload.",
      "match_preview": "Signature pattern [sk-...]",
      "source_location": "PDF Page 2 (Chunk 1, char 120-170)",
      "origin": "document_text"
    }
  ],
  "finding_count": 1,
  "scanned_components": [
    "PDF Page 1",
    "PDF Page 2 (Chunk 1, char 120-170)",
    "PDF Page 3",
    "PDF Page 4"
  ],
  "sanitized_preview": "Internal Report: Key = [REDACTED_API_KEY]...",
  "recommendation": "Reject this request immediately. Prompt contains active credentials or secret keys.",
  "scanned_at": "2026-10-15T22:30:00Z"
}
```

### 4. Image Privacy, EXIF & Visible OCR Scan
`POST /scan/image`
Inspects image files for visible OCR text, EXIF GPS coordinates, camera serial numbers, and embedded binary comments.

**Request:**
```json
{
  "image_base64": "data:image/png;base64,iVBORw0KGgo...",
  "filename": "document_scan.png"
}
```
**Response:**
```json
{
  "action": "BLOCK",
  "risk_level": "critical",
  "findings": [
    {
      "type": "IMAGE_EMBEDDED_SECRET",
      "category": "Credential Exfiltration",
      "severity": "critical",
      "description": "Found embedded credential in image metadata: api_key=sk-proj-...",
      "metadata_key": "tEXt:credential"
    }
  ],
  "metadata": {
    "format": "PNG",
    "width": 1024,
    "height": 768,
    "has_exif": true,
    "has_gps": false
  },
  "sanitized_image_base64": "data:image/png;base64,..."
}
```

### 4. End-to-End Chat Proxy
`POST /chat`
Proxies sanitized prompts to an upstream LLM (such as local Ollama). Blocked prompts are stopped immediately before touching the network.

**Request:**
```json
{
  "prompt": "Hello, please summarize this email: contact@domain.com",
  "model": "llama3"
}
```
**Response:**
```json
{
  "decision": "REDACT",
  "request_id": "chat_4a8f9c1b",
  "latency_ms": 280,
  "response": "Here is the summary of the contact request...",
  "findings": [
    {
      "type": "RULE_EMAIL_ADDRESS",
      "category": "Personal Identifiable Info",
      "severity": "medium",
      "match_preview": "Email pattern [***@***]"
    }
  ],
  "timestamp": "2026-10-15T22:00:00Z"
}
```

### 5. Semantic Audit Search
`GET /events/search?q=api+key+leak`
Performs token-level semantic expansion and ranking across recorded audit logs.

### 6. Security Policies
- `GET /policies`: Inspect active rules and threshold settings.
- `PUT /policies`: Update enforcement actions (`ALLOW`, `REDACT`, `BLOCK`). Attempts to disable mandatory credential protection return HTTP 400.

### 7. Telemetry & Metrics
`GET /metrics`
Computes real-time analytics directly from SQLite:
- Aggregate request counters (Inspected, Allowed, Redacted, Blocked)
- Classification breakdown (Sensitive Data vs Prompt Injections)
- Hourly traffic time-series
- Severity and category distribution

---

## Machine Learning Classifier

The prompt injection classifier uses a high-performance **TF-IDF Vectorizer + Logistic Regression** architecture:
- Sub-millisecond evaluation latency suitable for inline proxying.
- Pre-trained on a curated dataset of jailbreaks, roleplay bypasses, delimiter attacks, and standard software engineering queries.
- Serialized to lightweight JSON (`backend/models/injection_classifier.json`) for safe loading without fragile pickle binaries.

To retrain the model on updated data:
```powershell
cd backend
.\.venv\Scripts\python.exe training/train_classifier.py
```

---

## Test Suite

The project includes an automated test suite verifying all 55 critical security behaviors across prompts, documents, images, and proxy workflows:

```powershell
cd backend
.\.venv\Scripts\pytest.exe -v
```

### Test Coverage Highlights (55 Passed):
- **DLP Accuracy**: Email, Phone, SSN, Credit Card (Luhn check), Indian PAN, Aadhaar, AWS, GitHub, OpenAI keys.
- **Document Content Extraction**: Clean text, synthetic API keys in documents, password assignments, prompt overrides in Markdown, extractable text in PDFs, DOCX table and paragraph inspection, CSV PII row inspection, JSON credential walking, oversized file boundaries, corrupted payloads.
- **Image & OCR Recognition**: Visible injection text via OCR, visible credentials via OCR, EXIF GPS coordinate parsing, PNG text chunk secret detection, metadata stripping, graceful fallback when OCR is unavailable.
- **Injection Defense**: Instruction overrides, DAN jailbreaks, base64 obfuscation, benign query isolation.
- **Proxy Integrity**: Blocked prompt isolation, output inspection redaction, Ollama connection resilience.
- **Policy Engine**: Immutable mandatory credential enforcement, schema validation.
- **Audit Compliance**: Zero raw credential persistence, semantic search accuracy.

---

## Production Security Considerations

1. **Mandatory Rules**: The gateway hard-blocks attempts to disable detection for API keys and passwords.
2. **Deterministic Sanitization**: Redaction operates right-to-left using standardized placeholders (`[REDACTED_API_KEY]`, `[REDACTED_EMAIL]`, etc.) to prevent overlapping pattern corruption.
3. **Audit Privacy**: Audit trails store preview strings masked to 160 characters. Secrets never persist in database tables.
4. **Defense in Depth**: While regex and TF-IDF catch common and known threat structures, production environments should augment the gateway with dynamic model safety guards and network egress limits.

---

## License

This project is licensed under the MIT License.
