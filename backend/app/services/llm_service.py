"""
LLM Provider Integration Service for Sentinel AI.

Integrates with local Ollama instance over HTTPX.
Checks availability honestly; raises clear 503 HTTP exceptions if the model or provider
is unreachable. Never fabricates responses.
"""

from typing import Tuple, Optional
import httpx
from fastapi import HTTPException
from app.config import settings

def check_llm_availability() -> Tuple[bool, Optional[str]]:
    """
    Check if the configured LLM provider is reachable.
    Returns:
        (is_available: bool, status_message: Optional[str])
    """
    if settings.LLM_PROVIDER.lower() != "ollama":
        return False, f"Unsupported or disabled provider: {settings.LLM_PROVIDER}"

    url = f"{settings.OLLAMA_BASE_URL}/api/tags"
    try:
        with httpx.Client(timeout=httpx.Timeout(connect=1.0, read=2.0, write=2.0, pool=1.0)) as client:
            resp = client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                models = [m.get("name") for m in data.get("models", [])]
                return True, f"Ollama operational. Models available: {', '.join(models) if models else 'None installed'}"
            return False, f"Ollama returned HTTP {resp.status_code}"
    except httpx.ConnectError:
        return False, f"Cannot connect to Ollama at {settings.OLLAMA_BASE_URL}. Service is not running."
    except httpx.TimeoutException:
        return False, f"Timeout connecting to Ollama at {settings.OLLAMA_BASE_URL}."
    except Exception as e:
        return False, f"Ollama check failed: {str(e)}"

def call_ollama(prompt: str, model_name: Optional[str] = None) -> str:
    """
    Send a sanitized prompt to the local Ollama instance.
    Raises HTTPException(503) if the service is unreachable.
    """
    model = model_name or settings.OLLAMA_MODEL
    url = f"{settings.OLLAMA_BASE_URL}/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False
    }

    try:
        with httpx.Client(timeout=settings.OLLAMA_TIMEOUT_SECONDS) as client:
            resp = client.post(url, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                response_text = data.get("response", "")
                return response_text
            else:
                error_detail = resp.text[:200]
                raise HTTPException(
                    status_code=503,
                    detail=f"Ollama returned HTTP {resp.status_code}: {error_detail}"
                )
    except httpx.ConnectError:
        raise HTTPException(
            status_code=503,
            detail=f"Ollama is unreachable at {settings.OLLAMA_BASE_URL}. Ensure Ollama is running and model '{model}' is pulled."
        )
    except httpx.TimeoutException:
        raise HTTPException(
            status_code=504,
            detail=f"LLM request timed out after {settings.OLLAMA_TIMEOUT_SECONDS}s at {settings.OLLAMA_BASE_URL}."
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"Failed to communicate with LLM provider: {str(e)}"
        )
