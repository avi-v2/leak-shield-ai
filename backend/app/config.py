"""
Configuration settings for Sentinel AI Security Gateway.
Reads environment variables with secure defaults.
"""

import os
from pathlib import Path
from typing import List

# Base directories
BACKEND_DIR = Path(__file__).resolve().parent.parent
BASE_DIR = BACKEND_DIR.parent

class Settings:
    """Application settings loaded from environment variables."""

    APP_ENV: str = os.getenv("APP_ENV", "development")
    APP_TITLE: str = "Leak-Shield-AI Security Gateway"
    APP_VERSION: str = "1.0.0"

    # SQLite Database path
    DATABASE_PATH: str = os.getenv(
        "DATABASE_PATH",
        str(BACKEND_DIR / "sentinel.db")
    )

    # Allowed CORS Origins (comma-separated or list)
    _raw_origins = os.getenv(
        "FRONTEND_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:3000"
    )
    FRONTEND_ORIGINS: List[str] = [origin.strip() for origin in _raw_origins.split(",") if origin.strip()]

    # LLM Settings (Ollama local integration)
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "ollama")
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip("/")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama3")
    OLLAMA_TIMEOUT_SECONDS: float = float(os.getenv("OLLAMA_TIMEOUT_SECONDS", "15.0"))

    # Machine Learning Model Artifact
    MODEL_ARTIFACT_PATH: str = os.getenv(
        "MODEL_ARTIFACT_PATH",
        str(BACKEND_DIR / "models" / "injection_classifier.json")
    )

    # Prompt bounds
    MAX_PROMPT_LENGTH: int = int(os.getenv("MAX_PROMPT_LENGTH", "20000"))

    # File and Document Scan Configuration
    MAX_FILE_SIZE_BYTES: int = int(os.getenv("MAX_FILE_SIZE_BYTES", str(15 * 1024 * 1024)))  # 15 MB
    ALLOWED_DOCUMENT_EXTENSIONS: List[str] = [".txt", ".md", ".csv", ".json", ".pdf", ".docx"]
    ALLOWED_IMAGE_EXTENSIONS: List[str] = [".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tiff"]

    # OCR Configuration
    TESSERACT_CMD: str = os.getenv("TESSERACT_CMD", "")

settings = Settings()
