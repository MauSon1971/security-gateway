"""Capa 3.5 · LlamaGuard 3 wrapper.

Local Ollama classifier for content safety (harm categories S1-S13).
Complementary to Capa 3 (protectai) which focuses on prompt injection.

LlamaGuard 3 categories:
    S1 Violent Crimes    S2 Non-Violent Crimes   S3 Sex Crimes
    S4 Child Exploit.    S5 Defamation           S6 Specialized Advice
    S7 Privacy           S8 IP                   S9 Indiscriminate Weapons
    S10 Hate             S11 Suicide/Self-harm    S12 Sexual Content
    S13 Elections
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass

import requests

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
MODEL = os.environ.get("SG_LLAMAGUARD_MODEL", "llama-guard3:1b")
TIMEOUT = int(os.environ.get("SG_LLAMAGUARD_TIMEOUT", "10"))

log = logging.getLogger("llama_guard")


@dataclass
class GuardVerdict:
    safe: bool
    categories: list[str]   # e.g. ["S7", "S10"]
    raw: str
    error: str | None = None


def is_available() -> bool:
    try:
        r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=3)
        if r.status_code != 200:
            return False
        return any(m.get("name", "").startswith(MODEL.split(":")[0]) for m in r.json().get("models", []))
    except Exception:
        return False


def classify(text: str) -> GuardVerdict:
    """Classify text via LlamaGuard 3. Fail-open on error (safe=True, error set)."""
    if not text or not text.strip():
        return GuardVerdict(safe=True, categories=[], raw="")

    payload = {
        "model": MODEL,
        "prompt": f"User: {text}",
        "stream": False,
        "options": {"temperature": 0.0, "num_predict": 20},
    }
    try:
        r = requests.post(f"{OLLAMA_URL}/api/generate", json=payload, timeout=TIMEOUT)
        r.raise_for_status()
        raw = (r.json().get("response") or "").strip()
    except Exception as e:
        log.warning("llamaguard_unavailable: %s", e)
        return GuardVerdict(safe=True, categories=[], raw="", error=str(e))

    # Expected output: "safe" OR "unsafe\nS7,S10"
    lower = raw.lower()
    if lower.startswith("safe"):
        return GuardVerdict(safe=True, categories=[], raw=raw)

    # Extract categories
    cats: list[str] = []
    import re
    for m in re.findall(r"S\d+", raw.upper()):
        if m not in cats:
            cats.append(m)

    return GuardVerdict(safe=False, categories=cats, raw=raw)
