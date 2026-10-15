# Leak-Sheild-AI — FastAPI Security Gateway Backend

This is the Python FastAPI backend for the **Leak-Sheild-AI** Data Leakage Security Gateway.

## Requirements
- Python 3.11+
- `pip install -r requirements.txt`

## Endpoints
- `GET /health` — Real-time component health status (API, SQLite, ML Classifier, Ollama)
- `POST /scan` — Static prompt inspection, sensitive data detection, and injection risk analysis
- `POST /chat` — AI security proxy with automated input & output DLP scanning
- `GET /events` — Forensic security incident audit store from SQLite
- `DELETE /events` — Clear audit logs upon user confirmation
- `GET /policies` — Retrieve server-side security policies
- `PUT /policies` — Update server-side policies with mandatory credential protection
- `GET /metrics` — Compute operational metrics directly from SQLite database

## Quick Start (Windows)
```powershell
cd backend
pip install -r requirements.txt
python training/train_classifier.py
python main.py
```
Or with uvicorn directly:
```powershell
uvicorn app.main:app --host 127.0.0.1 --port 8000
```
The backend will run on `http://127.0.0.1:8000` (Interactive Swagger docs at `http://127.0.0.1:8000/docs`).
