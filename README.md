# Leak-Shield-AI — AI Data Leakage Security Gateway & Prompt Firewall

Leak-Shield-AI is an enterprise-grade AI security gateway, reverse proxy, and Security Operations Center (SOC) positioned between client applications and Large Language Models (LLMs). It intercepts, evaluates, redacts, or blocks prompts, uploaded documents, images, and model completions that contain sensitive credentials, personal identifiable information (PII), payment card data, adversarial prompt injection attacks, or image-based metadata/exfiltration leaks.

Built with **Python 3.11+ (FastAPI)**, **Scikit-learn**, **PyMuPDF**, **python-docx**, **Pillow**, **SQLite**, and **React (Vite + TailwindCSS + Recharts)**, Leak-Shield-AI enforces zero-trust security boundaries entirely server-side, ensuring unbypassable policy enforcement with zero raw credential retention.

---

## Key Features

- **AI Security Operations Center (SOC) Dashboard**: Live operational monitoring with 8 real-time KPI cards, Recharts time-series activity telemetry (`1h`, `24h`, `7d`, `30d`, `All Time`), threat category breakdown (findings count vs. unique scans), prompt injection intelligence with normalized phrase frequency ranking, DLP analytics, policy verdict distributions, and paginated security audit logs with forensic detail inspection.
- **Sensitive Data Loss Prevention (DLP)**: High-precision regex engine with algorithmic contextual validators (such as Luhn algorithm checksum verification for payment cards) detecting API keys (OpenAI, AWS, GitHub, Slack, HuggingFace, Generic), passwords, credit cards, US SSNs, Indian PAN cards, Aadhaar numbers, phone numbers, and RFC 5322 email addresses.
- **Bi-Directional Redaction**: Deterministic, right-to-left character replacement ensuring multi-token overlaps do not shift character offsets or corrupt prompt semantics.
- **Genuine Document Redaction (`POST /redact/file`)**: True structural content redaction for `.pdf`, `.docx`, `.csv`, `.json`, `.txt`, and `.md`. For PDFs, performs genuine content stream purging via PyMuPDF (not superficial black rectangle overlays). For DOCX, scrubs paragraphs, tables, headers, and footers.
- **Image Redaction & Metadata Stripping (`POST /redact/image`)**: Associates OCR bounding boxes with sensitive findings, paints opaque redaction masks over sensitive text, completely strips EXIF GPS coordinates and camera fingerprints, and produces verified sanitized images.
- **Prompt Injection & Jailbreak Defense**: Multi-layered detection pairing rule-based heuristic pattern matching (DAN, system override delimiters, developer mode commands) with a trained TF-IDF + Logistic Regression machine learning model.
- **Document Content Security Scanner (`POST /scan/file`)**: Deep parsing and inspection of uploaded files. Validates magic signatures, chunks large text with source location tracking (page, row, paragraph), and scans the actual contents for sensitive data and injection attacks.
- **Multimodal Image & Visible OCR Scanner (`POST /scan/image`)**: Inspects uploaded images using Tesseract OCR for visible injection directives and leaked credentials, extracts EXIF GPS location data and camera/device fingerprints, inspects PNG/JPEG embedded metadata comments, and generates sanitized clean images.
- **Semantic Audit Log Search**: Search past security incidents using intelligent keyword expansion and cosine similarity token scoring across threat events.
- **Enforced Server-Side Policies**: Configurable protection profiles with immutable enforcement of mandatory rules (credential detection cannot be bypassed or disabled).
- **Zero-Secret Audit Logging**: Only sanitized previews and cryptographically masked audit logs touch persistent storage. Raw secrets, tokens, and plaintext passwords are never recorded in logs or databases.
- **Offline & Standalone Operation**: Standalone prompt, file, and image inspection runs entirely locally without requiring an upstream LLM connection.

---

## Architecture & Data Flow

```
                      +---------------------------------------+
                      |     React Frontend SOC Dashboard      |
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
| Sensitive|       | Prompt    |    | Document  |       | Central   |       | Dashboard |
| Data DLP |       | Injection |    | & Image   |       | Policy    |       | Analytics |
| Engine   |       | Classifier|    | Redactor  |       | Engine    |       | Engine    |
+----------+       +-----------+    +-----------+       +-----------+       +-----------+
     |                   |                |                   |                   |
     +-------------------+----------------+-------------------+-------------------+
                                          |
                                  +-------+-------+
                                  |               |
                         (If BLOCKED)    (If ALLOW / REDACT)
                                  |               |
                                  v               v
                      [Immediate Rejection]      [Forward to Upstream LLM]
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
│   │   │   ├── redact.py            # Document & image content sanitization
│   │   │   ├── chat.py              # End-to-end LLM reverse proxy
│   │   │   ├── events.py            # Audit log retrieval, search & purge
│   │   │   ├── policies.py          # Security policy management API
│   │   │   └── metrics.py           # Real-time incident telemetry & SOC analytics
│   │   ├── security/
│   │   │   ├── sensitive_data.py    # DLP regex patterns & Luhn checksum
│   │   │   ├── injection_detector.py# Heuristic injection rules & scoring
│   │   │   ├── classifier.py        # TF-IDF + Logistic Regression inference
│   │   │   ├── file_scanner.py      # Magic signature & document content parser
│   │   │   ├── image_scanner.py     # EXIF metadata parser & sanitization
│   │   │   ├── document_redactor.py # PyMuPDF stream purging & DOCX/CSV redactor
│   │   │   ├── image_redactor.py    # OCR bounding-box masking & EXIF scrubber
│   │   │   ├── semantic_search.py   # Token matching & vector ranking
│   │   │   ├── policy_engine.py     # Central policy evaluation matrix
│   │   │   └── output_scanner.py    # Post-generation LLM output filter
│   │   └── services/
│   │       ├── audit_service.py     # Zero-secret database logging
│   │       ├── dashboard_service.py # Real-time SQL aggregations & metrics
│   │       └── llm_service.py       # Asynchronous HTTPX Ollama client
│   ├── models/
│   │   └── injection_classifier.json# Pretrained classifier artifact
│   ├── training/
│   │   ├── training_data.csv        # Balanced prompt injection dataset
│   │   └── train_classifier.py      # Retraining pipeline script
│   ├── tests/                       # 71-scenario automated test suite
│   └── requirements.txt             # Python backend dependencies
├── src/
│   ├── components/
│   │   ├── common/                  # StatCards, Badges, Modals, Cards, Skeletons
│   │   ├── layout/                  # Navbar, Sidebar, AppLayout
│   │   └── threats/                 # Threat detail forensic inspection modal
│   ├── context/
│   │   └── GatewayContext.jsx       # Global state & telemetry synchronization
│   ├── pages/
│   │   ├── Dashboard.jsx            # Full AI Security Operations Center (SOC)
│   │   ├── Overview.jsx             # Security Overview route integration
│   │   ├── ThreatMonitor.jsx        # Live security incident feed & semantic search
│   │   ├── PromptScanner.jsx        # Interactive text, document & image sandbox
│   │   ├── Playground.jsx           # Live LLM proxy chat testbed
│   │   ├── Policies.jsx             # Policy configuration panel
│   │   ├── AuditLogs.jsx            # Forensic compliance & audit table
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
1. Detects the `backend\.venv` Python virtual environment.
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

# Start backend server with Uvicorn (app-dir backend)
.\.venv\Scripts\uvicorn.exe app.main:app --app-dir . --host 127.0.0.1 --port 8000 --reload
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
Evaluates a text prompt for sensitive credentials and adversarial injection attacks without invoking an external LLM.

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

### 3. Document Content Security Scan & Redaction
- `POST /scan/file`: Deep inspection of `.pdf`, `.docx`, `.csv`, `.json`, `.txt`, `.md`.
- `POST /redact/file`: Generates structural, verified redacted documents.
- `GET /redact/download/{file_id}`: Secure verified download for sanitized files.

### 4. Image Privacy, EXIF & Visible OCR Scan & Redaction
- `POST /scan/image`: Inspects Base64 image data for visible text, GPS coordinates, and camera metadata.
- `POST /scan/image/upload`: Multipart image file scanning.
- `POST /redact/image`: Bounding-box text masking and EXIF metadata scrubbing.

### 5. AI Operations Center & Telemetry Routes
- `GET /metrics/summary?range={1h|24h|7d|30d|all}`: 8 KPI metrics (Total scans, threats, blocked, redacted, threat rate, block rate, sensitive findings, injection attempts).
- `GET /metrics/timeline?range=...`: Time-series activity telemetry.
- `GET /metrics/threat-categories?range=...`: Distribution of findings vs unique scans.
- `GET /metrics/injection-keywords?range=...`: Ranked injection phrases and detection methods.
- `GET /metrics/dlp?range=...`: Sensitive data findings and safe masked previews.
- `GET /metrics/policies?range=...`: Policy verdict distributions and top block reasons.
- `GET /metrics/file-image?range=...`: Media and OCR telemetry.
- `GET /metrics/events?limit=...&offset=...&range=...`: Paginated, multi-attribute filterable security audit logs.

### 6. End-to-End Chat Proxy
`POST /chat`
Proxies sanitized prompts to an upstream LLM (such as local Ollama). Blocked prompts are stopped immediately before touching the network.

### 7. Security Policies
- `GET /policies`: Inspect active rules and threshold settings.
- `PUT /policies`: Update enforcement actions (`ALLOW`, `REDACT`, `BLOCK`). Attempts to disable mandatory credential protection return HTTP 400.

---

## Machine Learning Classifier

The prompt injection classifier uses a high-performance **TF-IDF Vectorizer + Logistic Regression** architecture:
- Sub-millisecond evaluation latency suitable for inline proxying.
- Pre-trained on a curated dataset of jailbreaks, roleplay bypasses, delimiter attacks, and standard queries.
- Serialized to lightweight JSON (`backend/models/injection_classifier.json`) for safe loading without pickle vulnerabilities.

To retrain the model on updated data:
```powershell
cd backend
.\.venv\Scripts\python.exe training/train_classifier.py
```

---

## Test Suite

The project includes an automated test suite verifying all 71 critical security behaviors across prompts, documents, images, redaction, and SOC telemetry:

```powershell
.\backend\.venv\Scripts\pytest.exe -v
```

### Test Coverage Highlights (71 Passed):
- **DLP Accuracy**: Email, Phone, SSN, Credit Card (Luhn check), Indian PAN, Aadhaar, AWS, GitHub, OpenAI keys.
- **Genuine Document Redaction**: PyMuPDF content stream purging, DOCX paragraph & table tree scrubbing, CSV structured cell redaction, JSON node traversal, and verification.
- **Image Redaction & OCR**: Visible injection text detection, OCR bounding-box coordinate mapping, EXIF GPS coordinate parsing, PNG text chunk secret detection, metadata stripping.
- **Injection Defense**: Instruction overrides, DAN jailbreaks, base64 obfuscation, benign query isolation.
- **SOC Dashboard & Analytics**: Safe zero denominators, time-series bucketing across ranges (`1h`, `24h`, `7d`, `30d`, `all`), unique scans vs findings differentiation, injection keyword extraction, and zero-secret leak verification.
- **Proxy Integrity**: Blocked prompt isolation, output inspection redaction, Ollama connection resilience.
- **Policy Engine**: Immutable mandatory credential enforcement, schema validation.
- **Audit Compliance**: Zero raw credential persistence, semantic search accuracy.

---

## License

This project is licensed under the MIT License.
