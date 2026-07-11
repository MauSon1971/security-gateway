"""PromptGuard 2-86M wrapper.

Uses HuggingFace transformers, CPU inference.
The model returns 2 labels: BENIGN (0) and MALICIOUS (1). We take the softmax
probability of MALICIOUS as risk_score in [0,1].
"""
from __future__ import annotations

import logging
import threading
from typing import Optional

log = logging.getLogger(__name__)

# Threshold above which we mark injection=fail. Tunable via env if needed.
DEFAULT_THRESHOLD = 0.5


class PromptInjectionGuard:
    def __init__(
        self,
        model_name: str,
        cache_dir: str,
        threshold: float = DEFAULT_THRESHOLD,
        hf_token: Optional[str] = None,
    ) -> None:
        self.model_name = model_name
        self.cache_dir = cache_dir
        self.threshold = threshold
        self._hf_token = hf_token
        self._lock = threading.Lock()
        self._tokenizer = None
        self._model = None
        self._torch = None
        self._loaded = False
        self._load_error: str | None = None

    def load(self) -> None:
        with self._lock:
            if self._loaded:
                return
            try:
                import torch
                from transformers import (
                    AutoModelForSequenceClassification,
                    AutoTokenizer,
                )

                kwargs = {"cache_dir": self.cache_dir}
                if self._hf_token:
                    kwargs["token"] = self._hf_token

                self._tokenizer = AutoTokenizer.from_pretrained(
                    self.model_name, **kwargs
                )
                self._model = AutoModelForSequenceClassification.from_pretrained(
                    self.model_name, **kwargs
                )
                self._model.eval()
                self._torch = torch
                self._loaded = True
                log.info(
                    "prompt_guard.loaded",
                    extra={"event": "model_loaded", "model": self.model_name},
                )
            except Exception as e:
                self._load_error = str(e)
                log.error(
                    "prompt_guard.load_failed",
                    extra={"event": "model_load_failed", "error": str(e)},
                )
                raise

    @property
    def loaded(self) -> bool:
        return self._loaded

    @property
    def load_error(self) -> str | None:
        return self._load_error

    def score(self, text: str) -> tuple[float, str]:
        """Return (risk_score, verdict) where verdict is 'pass' or 'fail'."""
        if not self._loaded:
            raise RuntimeError("model not loaded")

        torch = self._torch
        inputs = self._tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=512,
        )
        with torch.no_grad():
            logits = self._model(**inputs).logits
            probs = torch.softmax(logits, dim=-1).squeeze(0).tolist()

        # PromptGuard 2 label ordering: id2label from model.config.
        id2label = self._model.config.id2label
        # Find the MALICIOUS-ish label
        malicious_prob = 0.0
        for idx, name in id2label.items():
            if name.upper() in {"MALICIOUS", "INJECTION", "LABEL_1"}:
                malicious_prob = float(probs[int(idx)])
                break
        else:
            # fallback: assume last index is malicious
            malicious_prob = float(probs[-1])

        verdict = "fail" if malicious_prob >= self.threshold else "pass"
        return malicious_prob, verdict
