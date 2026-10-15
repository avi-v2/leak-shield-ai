"""
Sentinel AI — AI Data Leakage Security Gateway Launcher.
Runs the real FastAPI server with Uvicorn.
"""

import sys
from pathlib import Path

# Ensure backend directory is in sys.path
backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

import uvicorn
from app.main import app

if __name__ == "__main__":
    print("================================================================")
    print(" Starting Sentinel AI — Enterprise AI Security Gateway Backend  ")
    print(" Powered by Python, FastAPI, Scikit-learn, and SQLite           ")
    print(" Listening on http://127.0.0.1:8000 (Docs: /docs)               ")
    print("================================================================")
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=False)
