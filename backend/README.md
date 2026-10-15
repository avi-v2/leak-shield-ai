# Sentinel AI — FastAPI Security Gateway Backend

This is the Python FastAPI backend for the Sentinel AI Data Leakage Security Gateway.

## Requirements
- Python 3.10+
- `pip install -r requirements.txt`

## Endpoints
- `GET /health` — Health check & gateway version
- `POST /scan` — Real-time prompt inspection & DLP analysis
- `POST /chat` — AI security proxy with automated interception
- `GET /events` — Forensic security incident audit store
- `DELETE /events` — Clear audit logs

## Quick Start
```bash
cd backend
pip install -r requirements.txt
python main.py
```
Or with uvicorn directly:
```bash
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```
The backend will run on `http://127.0.0.1:8000`.
The React frontend connects to this URL via `VITE_API_BASE_URL`.
