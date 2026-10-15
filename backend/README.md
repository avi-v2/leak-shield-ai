# Leak-Shield-AI — FastAPI Security Gateway Backend

This is the Python FastAPI backend for the **Leak-Shield-AI** Data Leakage Security Gateway & Prompt Injection Firewall.

## Requirements
- Python 3.11+
- `pip install -r requirements.txt`

## Core Security Endpoints

### Diagnostics & Proxying
- `GET /health` — Real-time component health status (API, SQLite, ML Classifier, Ollama)
- `POST /chat` — AI security proxy with automated input & output DLP scanning

### Static & Multimodal Scanning
- `POST /scan` — Static prompt inspection, sensitive data detection, and injection risk analysis
- `POST /scan/file` — Document content scanner (`.pdf`, `.docx`, `.csv`, `.json`, `.txt`, `.md`)
- `POST /scan/image` — Multimodal image privacy scanner (EXIF GPS location leak, camera fingerprinting, embedded secrets)
- `POST /scan/image/upload` — Multipart image file upload scanner

### Genuine Document & Image Redaction
- `POST /redact/file` — Structural document redaction with PyMuPDF content stream purging and DOCX/CSV/JSON scrubbing
- `POST /redact/image` — OCR bounding-box sensitive text masking and EXIF metadata stripping
- `POST /redact/image/upload` — Multipart image upload redaction
- `GET /redact/download/{file_id}` — Verified token-based download endpoint for sanitized documents

### AI Security Operations Center (SOC) Telemetry
- `GET /metrics` — Legacy aggregate metrics endpoint
- `GET /metrics/summary` — 8 KPI metrics (Total Scans, Threats Detected, Blocked, Redacted, Threat Rate %, Block Rate %, PII Findings, Injections)
- `GET /metrics/timeline` — Time-series activity telemetry across selectable windows (`1h`, `24h`, `7d`, `30d`, `all`)
- `GET /metrics/threat-categories` — Distribution of detected findings vs unique affected scans
- `GET /metrics/injection-keywords` — Frequency-ranked injection phrases, rules, and detection methods
- `GET /metrics/dlp` — Data loss prevention stats and safe masked previews (zero raw secrets)
- `GET /metrics/policies` — Policy verdict distributions and top block/redact justifications
- `GET /metrics/file-image` — Document and image scanning telemetry with OCR stats
- `GET /metrics/events` — Paginated and multi-attribute filterable security audit logs

### Policies & Audit Logs
- `GET /policies` — Retrieve server-side security policies
- `PUT /policies` — Update server-side policies with mandatory credential protection
- `GET /events` — Forensic security incident audit store from SQLite
- `GET /events/search` — Vector similarity semantic search across security audit logs
- `DELETE /events` — Purge audit logs upon explicit user confirmation

## Running the Backend

From the project root:
```powershell
.\backend\.venv\Scripts\uvicorn.exe app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload
```

Or from inside the `backend` directory:
```powershell
cd backend
.\.venv\Scripts\uvicorn.exe app.main:app --app-dir . --host 127.0.0.1 --port 8000 --reload
```

Interactive OpenAPI Swagger documentation will be available at:
`http://127.0.0.1:8000/docs`

## Automated Test Suite

Run all 71 automated tests across DLP, injection classification, OCR scanning, file redaction, and SOC telemetry:
```powershell
.\backend\.venv\Scripts\pytest.exe -v
```
