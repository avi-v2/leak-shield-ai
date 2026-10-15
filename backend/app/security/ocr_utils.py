"""
OCR (Optical Character Recognition) Integration Utility for Leak-Shield-AI.

Provides robust visible text extraction from image buffers using pytesseract.
Handles missing binaries, platform differences (Windows/Linux/macOS), and timeouts gracefully.
Never crashes the gateway if Tesseract is uninstalled; accurately reports OCR availability.
"""

import os
import shutil
import logging
from typing import Optional, Tuple, List, Dict, Any
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

def clear_mock_ocr_handler():
    """Reset the mock OCR handler to None."""
    global _MOCK_OCR_HANDLER
    _MOCK_OCR_HANDLER = None

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

def extract_text_and_boxes_from_image(
    img: Image.Image,
    timeout_seconds: int = 10
) -> Tuple[Optional[str], List[dict], str]:
    """
    Run OCR on a Pillow Image object returning recognized text and word-level bounding boxes.

    Returns:
        (extracted_text, word_boxes, ocr_status)
        Each item in word_boxes has:
            {
                "text": str,
                "left": int,
                "top": int,
                "width": int,
                "height": int,
                "conf": float,
                "start_char": int,
                "end_char": int
            }
    """
    global _MOCK_OCR_HANDLER
    if _MOCK_OCR_HANDLER is not None:
        try:
            mock_output = _MOCK_OCR_HANDLER(img)
            if isinstance(mock_output, dict):
                text = mock_output.get("text", "")
                boxes = mock_output.get("boxes", [])
                return (text, boxes, "executed")
            elif isinstance(mock_output, tuple) and len(mock_output) == 2:
                return (mock_output[0], mock_output[1], "executed")
            else:
                text = str(mock_output) if mock_output is not None else ""
                # Synthesize realistic non-overlapping bounding boxes for words across the image
                words = text.split()
                boxes = []
                cur_pos = 0
                img_w, img_h = img.size if hasattr(img, "size") else (800, 600)
                line_height = 24
                x = 20
                y = 30
                for w in words:
                    start_idx = text.find(w, cur_pos)
                    if start_idx == -1:
                        start_idx = cur_pos
                    end_idx = start_idx + len(w)
                    cur_pos = end_idx

                    word_w = max(20, len(w) * 10)
                    if x + word_w > img_w - 20:
                        x = 20
                        y += line_height + 8

                    boxes.append({
                        "text": w,
                        "left": x,
                        "top": y,
                        "width": word_w,
                        "height": line_height,
                        "conf": 95.0,
                        "start_char": start_idx,
                        "end_char": end_idx
                    })
                    x += word_w + 12

                return (text, boxes, "executed")
        except Exception as e:
            return (None, [], f"failed: {str(e)}")

    if pytesseract is None:
        return (None, [], "unavailable")

    tess_cmd = get_tesseract_cmd()
    if not tess_cmd:
        return (None, [], "unavailable")

    try:
        pytesseract.pytesseract.tesseract_cmd = tess_cmd
        rgb_img = img.convert("RGB") if img.mode not in ("RGB", "L") else img

        # Use image_to_data to obtain words and coordinate boxes
        data = pytesseract.image_to_data(rgb_img, timeout=timeout_seconds, output_type=pytesseract.Output.DICT)

        n_boxes = len(data.get("text", []))
        word_boxes = []
        full_text_parts = []
        current_char_offset = 0

        for i in range(n_boxes):
            word_str = data["text"][i]
            if not word_str or not word_str.strip():
                continue

            w_text = word_str.strip()
            left = int(data["left"][i])
            top = int(data["top"][i])
            width = int(data["width"][i])
            height = int(data["height"][i])
            try:
                conf = float(data["conf"][i])
            except (ValueError, TypeError):
                conf = 0.0

            if full_text_parts:
                current_char_offset += 1  # For the space
            start_char = current_char_offset
            end_char = start_char + len(w_text)
            current_char_offset = end_char

            full_text_parts.append(w_text)
            word_boxes.append({
                "text": w_text,
                "left": left,
                "top": top,
                "width": width,
                "height": height,
                "conf": conf,
                "start_char": start_char,
                "end_char": end_char
            })

        full_text = " ".join(full_text_parts) if full_text_parts else ""
        return (full_text, word_boxes, "executed")
    except Exception as e:
        logger.warning(f"OCR execution error: {e}")
        return (None, [], f"failed: {str(e)}")

def extract_text_from_image(img: Image.Image, timeout_seconds: int = 10) -> Tuple[Optional[str], str]:
    """
    Run OCR on a Pillow Image object.
    Returns:
        (extracted_text, ocr_status)
    """
    text, _, status = extract_text_and_boxes_from_image(img, timeout_seconds=timeout_seconds)
    return (text, status)

