"""
Prompt Injection Machine Learning Classifier for Sentinel AI.

Loads the trained TF-IDF + Logistic Regression model artifact safely from local storage.
If the artifact is missing, reports that the classifier is unavailable. Never fabricates predictions.

IMPORTANT SECURITY LIMITATION:
A small TF-IDF + Logistic Regression baseline provides a basic heuristic barrier against known
injection phrasings. It is NOT sufficient on its own to defend against sophisticated, multilingual,
encoded, or zero-day adversarial jailbreaks. Defense-in-depth is essential.
"""

import os
import re
import math
import json
from pathlib import Path
from typing import Tuple, Optional
from app.config import settings

class InjectionClassifier:
    """Production inference interface for the prompt injection classifier."""

    _instance: Optional["InjectionClassifier"] = None

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or settings.MODEL_ARTIFACT_PATH
        self._loaded: bool = False
        self._load_error: Optional[str] = None
        self._vocab: dict = {}
        self._idf: dict = {}
        self._weights: dict = {}
        self._bias: float = 0.0
        self._load_model()

    def _load_model(self) -> None:
        """Safely load model artifact from disk."""
        target_path = Path(self.model_path)

        # Also check for .json sibling if specified path is .joblib
        json_path = target_path.with_suffix(".json")
        candidate_path = None
        if target_path.exists():
            candidate_path = target_path
        elif json_path.exists():
            candidate_path = json_path

        if not candidate_path:
            self._loaded = False
            self._load_error = f"Model artifact not found at {self.model_path}. Train model using training/train_classifier.py."
            return

        try:
            if candidate_path.suffix == ".json":
                with open(candidate_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._vocab = data["vocabulary"]
                self._idf = data["idf"]
                # JSON keys for dict weights might be string indices, convert to int
                self._weights = {int(k): float(v) for k, v in data["weights"].items()}
                self._bias = float(data["bias"])
                self._loaded = True
                self._load_error = None
            else:
                # If joblib pipeline exists and sklearn is available
                import joblib
                self._joblib_pipeline = joblib.load(candidate_path)
                self._loaded = True
                self._load_error = None
        except Exception as e:
            self._loaded = False
            self._load_error = f"Failed to load classifier artifact: {str(e)}"

    def is_available(self) -> bool:
        """Check if the classifier is loaded and ready for inference."""
        return self._loaded

    def get_status_message(self) -> str:
        if self.is_available():
            return "Active (TF-IDF + Logistic Regression Baseline)"
        return self._load_error or "Model artifact unavailable"

    def _tokenize(self, text: str):
        words = re.findall(r'\b[a-z0-9_]+\b', text.lower())
        tokens = list(words)
        for i in range(len(words) - 1):
            tokens.append(f"{words[i]}_{words[i+1]}")
        return tokens

    def predict(self, text: str, threshold: float = 0.5) -> Tuple[bool, Optional[float]]:
        """
        Predict whether a prompt contains adversarial prompt injection.

        Returns:
            (is_injection: bool, confidence_score: Optional[float])
            If model is unavailable, returns (False, None).
        """
        if not self.is_available():
            return False, None

        if not text or not text.strip():
            return False, 0.0

        try:
            # If using JSON artifact: compute TF-IDF and sigmoid
            if self._vocab:
                tokens = self._tokenize(text)
                tf = {}
                for tok in tokens:
                    if tok in self._vocab:
                        tf[tok] = tf.get(tok, 0) + 1

                vec = {}
                norm_sq = 0.0
                for tok, count in tf.items():
                    val = count * self._idf.get(tok, 1.0)
                    idx = self._vocab[tok]
                    vec[idx] = val
                    norm_sq += val * val

                norm = math.sqrt(norm_sq) if norm_sq > 0 else 1.0

                dot = sum((val / norm) * self._weights.get(idx, 0.0) for idx, val in vec.items()) + self._bias
                dot = max(-25.0, min(25.0, dot))
                injection_prob = 1.0 / (1.0 + math.exp(-dot))

                is_injection = injection_prob >= threshold
                return is_injection, round(injection_prob, 4)

            # If using joblib pipeline
            elif hasattr(self, "_joblib_pipeline") and self._joblib_pipeline is not None:
                probs = self._joblib_pipeline.predict_proba([text])[0]
                injection_prob = float(probs[1])
                return injection_prob >= threshold, round(injection_prob, 4)

            return False, None
        except Exception:
            return False, None

# Singleton accessor
_classifier_singleton: Optional[InjectionClassifier] = None

def get_classifier(model_path: Optional[str] = None) -> InjectionClassifier:
    global _classifier_singleton
    if _classifier_singleton is None or model_path is not None:
        _classifier_singleton = InjectionClassifier(model_path)
    return _classifier_singleton

def reload_classifier(model_path: Optional[str] = None) -> InjectionClassifier:
    global _classifier_singleton
    _classifier_singleton = InjectionClassifier(model_path)
    return _classifier_singleton
