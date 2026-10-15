"""
OCR (Optical Character Recognition) Integration Utility for Leak-Shield-AI.

Provides robust visible text extraction from image buffers using pytesseract.
Handles missing binaries, platform differences (Windows/Linux/macOS), and timeouts gracefully.
Never crashes the gateway if Tesseract is uninstalled; accurately reports OCR availability.
"""

import os
import shutil
import logging
from typing import Optional, Tuple
from PIL import Image

try:
    import pytesseract
except ImportError:
    pytesseract = None

from app.config import settings

logger = logging.getLogger("leak_shield.ocr")

# Optional test mock hook
_MOCK_OCR_HANDLER = None

def set_mock_ocr_handler(handler):
    """Set a custom test handler for OCR text extraction (for unit testing)."""
    global _MOCK_OCR_HANDLER
    _MOCK_OCR_HANDLER = handler

def get_tesseract_cmd() -> Optional[str]:
    """
    Locates the tesseract executable path across environment variables,
    configuration settings, and standard platform directories.
    """
    # 1. Configured via environment / settings
    if settings.TESSERACT_CMD and os.path.isfile(settings.TESSERACT_CMD):
        return settings.TESSERACT_CMD

    # 2. Check if available on system PATH
    which_cmd = shutil.which("tesseract")
    if which_cmd:
        return which_cmd

    # 3. Standard Windows locations
    standard_windows_paths = [
        r"C:\Program Files\Tesseract-OCR\tesseract.exe",
        r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\Tesseract-OCR\tesseract.exe")
    ]
    for p in standard_windows_paths:
        if os.path.isfile(p):
            return p

    return None

def is_ocr_available() -> bool:
    """Check if pytesseract library and tesseract binary are available."""
    if _MOCK_OCR_HANDLER is not None:
        return True
    if pytesseract is None:
        return False
    return get_tesseract_cmd() is not None

def extract_text_from_image(img: Image.Image, timeout_seconds: int = 10) -> Tuple[Optional[str], str]:
    """
    Run OCR on a Pillow Image object.

    Returns:
        (extracted_text, ocr_status)
        Where ocr_status can be:
        - "executed": OCR completed successfully.
        - "unavailable": Tesseract binary not installed on system.
        - "failed": OCR crashed, timed out, or encountered an error.
    """
    global _MOCK_OCR_HANDLER
    if _MOCK_OCR_HANDLER is not None:
        try:
            mock_text = _MOCK_OCR_HANDLER(img)
            return (mock_text, "executed")
        except Exception as e:
            return (None, f"failed: {str(e)}")

    if pytesseract is None:
        return (None, "unavailable")

    tess_cmd = get_tesseract_cmd()
    if not tess_cmd:
        return (None, "unavailable")

    try:
        pytesseract.pytesseract.tesseract_cmd = tess_cmd
        # Convert image to RGB if needed for OCR
        rgb_img = img.convert("RGB") if img.mode not in ("RGB", "L") else img
        text = pytesseract.image_to_string(rgb_img, timeout=timeout_seconds)
        cleaned = text.strip() if text else ""
        return (cleaned, "executed")
    except Exception as e:
        logger.warning(f"OCR execution error: {e}")
        return (None, f"failed: {str(e)}")
