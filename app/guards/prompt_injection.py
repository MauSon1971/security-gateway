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
        # Una inferencia a la vez: con la RAM corta del VPS, N peticiones en
        # paralelo multiplican la memoria de activaciones y no van más rápido.
        self._infer_lock = threading.Lock()
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

    # ------------------------------------------------------------------
    # 861 · el texto ENTERO, no sólo los primeros 512 tokens
    # ------------------------------------------------------------------
    def _malicious_index(self) -> int:
        id2label = self._model.config.id2label
        for idx, name in id2label.items():
            if str(name).upper() in {"MALICIOUS", "INJECTION", "LABEL_1"}:
                return int(idx)
        return len(id2label) - 1

    def score_full(
        self,
        text: str,
        window_tokens: int = 512,
        stride_tokens: int = 64,
        max_windows: int = 0,
        batch_size: int = 8,
    ) -> dict:
        """Puntúa TODO el texto en ventanas solapadas y devuelve la peor.

        `score()` trunca a 512 tokens: una inyección al final de un correo largo no
        se veía nunca. Aquí el texto se trocea en ventanas de `window_tokens` con
        `stride_tokens` de solape y manda la ventana con más riesgo.

        `max_windows=0` = sin tope. Con tope se miran las primeras y las últimas
        ventanas, y `truncated=True` + `coverage` dicen cuánto quedó sin mirar.
        Coste medido (15-nov-2026, VPS con CPU cargada): ~0,2–0,3 s una ventana,
        ~1,8 s por ventana de 512 tokens en lote; 60 000 caracteres = 40 ventanas
        = 80 s. Por eso el portero pone un tope (SG_PG_MAX_WINDOWS).
        """
        if not self._loaded:
            raise RuntimeError("model not loaded")
        tok = self._tokenizer
        ids = tok(text, add_special_tokens=False, truncation=False)["input_ids"]
        body = max(8, window_tokens - 2)            # CLS + SEP
        step = max(1, body - stride_tokens)
        starts = list(range(0, max(1, len(ids) - stride_tokens), step)) or [0]
        total_windows = len(starts)
        truncated = False
        if max_windows and len(starts) > max_windows:
            # Cabeza y cola: es donde va una inyección que quiere que la lean.
            head_n = max(1, max_windows // 2)
            starts = starts[:head_n] + starts[-(max_windows - head_n):]
            truncated = True
        head = tok.cls_token_id if tok.cls_token_id is not None else tok.bos_token_id
        tail = tok.sep_token_id if tok.sep_token_id is not None else tok.eos_token_id
        pre = [head] if head is not None else []
        post = [tail] if tail is not None else []
        windows = [pre + ids[s:s + body] + post for s in starts]

        mal = self._malicious_index()
        with self._infer_lock:
            worst, worst_at = self._run_windows(windows, mal, batch_size)
        verdict = "fail" if worst >= self.threshold else "pass"
        return {
            "risk_score": worst,
            "verdict": verdict,
            "windows": len(windows),
            "windows_total": total_windows,
            "worst_window": worst_at,
            "tokens": len(ids),
            "truncated": truncated,
            "coverage": round(len(windows) / total_windows, 3) if total_windows else 1.0,
        }

    def _run_windows(self, windows: list[list[int]], mal: int, batch_size: int) -> tuple[float, int]:
        torch = self._torch
        tok = self._tokenizer
        worst, worst_at = 0.0, 0
        pad_id = tok.pad_token_id or 0
        for b in range(0, len(windows), batch_size):
            chunk = windows[b:b + batch_size]
            width = max(len(w) for w in chunk)
            input_ids = torch.tensor([w + [pad_id] * (width - len(w)) for w in chunk])
            mask = torch.tensor([[1] * len(w) + [0] * (width - len(w)) for w in chunk])
            with torch.no_grad():
                logits = self._model(input_ids=input_ids, attention_mask=mask).logits
                probs = torch.softmax(logits, dim=-1)[:, mal].tolist()
            for i, p in enumerate(probs):
                if p > worst:
                    worst, worst_at = float(p), b + i
        return worst, worst_at
