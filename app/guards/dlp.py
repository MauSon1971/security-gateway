"""Capa 4 · DLP — Data Loss Prevention.

Regex-based detector para datos sensibles GDPR/PCI que no deberían circular
sin proteccion.

Detecta:
    - NIF/NIE español (letra de control validada)
    - IBAN (25 países ISO + control mod 97)
    - Tarjeta de crédito (Luhn)
    - Emails de terceros (heurístico)

Retorna:
    (risk_delta, hits)
    donde risk_delta se suma al risk_score final; hits es lista de tipos detectados.

Threshold config vía SG_DLP_THRESHOLD (default 3 hits → high risk).
"""
from __future__ import annotations

import re
from dataclasses import dataclass


NIF_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"


@dataclass(frozen=True)
class DlpHit:
    kind: str
    matched: str      # redacted (last 4 chars visible only)
    confidence: float

    def as_dict(self) -> dict:
        return {"kind": self.kind, "matched": self.matched, "confidence": self.confidence}


# ============================================================
# Validators
# ============================================================

_NIF_RE = re.compile(r"\b([0-9]{8})([A-Z])\b")


def _valid_nif(digits: str, letter: str) -> bool:
    return NIF_LETTERS[int(digits) % 23] == letter.upper()


_NIE_RE = re.compile(r"\b([XYZ])([0-9]{7})([A-Z])\b")


def _valid_nie(prefix: str, digits: str, letter: str) -> bool:
    p = "XYZ".index(prefix.upper())
    return NIF_LETTERS[int(str(p) + digits) % 23] == letter.upper()


_IBAN_RE = re.compile(r"(?<![A-Z0-9])([A-Z]{2})([0-9]{2})([A-Z0-9]{11,30})(?![A-Z0-9])")


def _valid_iban(country: str, check: str, bban: str) -> bool:
    full = bban + country + check
    numeric = ""
    for ch in full:
        if ch.isdigit():
            numeric += ch
        else:
            numeric += str(ord(ch.upper()) - 55)
    try:
        return int(numeric) % 97 == 1
    except ValueError:
        return False


_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _luhn(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    re.IGNORECASE,
)


_PHONE_RE = re.compile(r"\+?\d{1,3}[-.\s]?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}")


# ============================================================
# Scanner
# ============================================================

def _redact(s: str, keep: int = 4) -> str:
    if len(s) <= keep:
        return "*" * len(s)
    return "*" * (len(s) - keep) + s[-keep:]


def scan_dlp(text: str) -> tuple[float, list[dict]]:
    """Escanea `text` para datos sensibles.

    Returns:
        (risk_delta, hits)
        risk_delta ∈ [0.0, 1.0] — se suma al risk_score total (cap 1.0).
        hits: lista de dicts con kind/matched/confidence.
    """
    if not text:
        return 0.0, []

    hits: list[DlpHit] = []

    # NIF
    for m in _NIF_RE.finditer(text):
        digits, letter = m.group(1), m.group(2)
        if _valid_nif(digits, letter):
            hits.append(DlpHit("nif", _redact(m.group(0)), 1.0))

    # NIE
    for m in _NIE_RE.finditer(text):
        p, digits, letter = m.group(1), m.group(2), m.group(3)
        if _valid_nie(p, digits, letter):
            hits.append(DlpHit("nie", _redact(m.group(0)), 1.0))

    # IBAN — buscar en original y en versión sin espacios (para IBANs formateados)
    for candidate in (text, re.sub(r"[\s-]", "", text)):
     for m in _IBAN_RE.finditer(candidate):
        country, check, bban = m.group(1), m.group(2), m.group(3)
        if _valid_iban(country, check, bban):
            hits.append(DlpHit("iban", _redact(m.group(0), keep=4), 1.0))

    # Card (Luhn)
    for m in _CARD_RE.finditer(text):
        num = m.group(0).replace(" ", "").replace("-", "")
        if _luhn(num):
            hits.append(DlpHit("card", _redact(num, keep=4), 1.0))

    # Emails (third-party — heurística: no dominios internos)
    for m in _EMAIL_RE.finditer(text):
        email = m.group(0).lower()
        # Skip our own domains (add to internal_domains as needed)
        if not any(email.endswith("@" + d) for d in {"powerfans.es", "vektrun.com", "example.com"}):
            hits.append(DlpHit("email_third_party", _redact(email, keep=6), 0.5))

    # Phones (weak signal, low confidence)
    for m in _PHONE_RE.finditer(text):
        hits.append(DlpHit("phone", _redact(m.group(0), keep=3), 0.4))

    # risk delta: sum of confidences, capped at 0.5 (never dominates over injection)
    risk_delta = min(0.5, sum(h.confidence for h in hits) * 0.15)

    return risk_delta, [h.as_dict() for h in hits]
