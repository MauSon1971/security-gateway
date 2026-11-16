"""Unit tests for DLP Capa 4."""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # el repo, no lo desplegado
from app.guards.dlp import scan_dlp


def test_no_pii_in_benign_text():
    text = "Hola Mauri, confirmo asistencia a la reunion de manana."
    risk, hits = scan_dlp(text)
    assert risk == 0.0
    assert hits == []


def test_detects_valid_nif():
    # Real-format NIF: 12345678Z (Z is valid for 12345678 % 23 = 22 → Z)
    text = "Cliente Juan Perez con NIF 12345678Z"
    risk, hits = scan_dlp(text)
    kinds = [h["kind"] for h in hits]
    assert "nif" in kinds
    assert risk > 0


def test_invalid_nif_ignored():
    # 12345678A is invalid (correct letter is Z)
    text = "NIF supuesto 12345678A"
    risk, hits = scan_dlp(text)
    kinds = [h["kind"] for h in hits]
    assert "nif" not in kinds


def test_detects_valid_iban_es():
    # ES91 2100 0418 4502 0005 1332 (test IBAN público de ejemplo Banco Santander)
    text = "Transferir a IBAN ES9121000418450200051332"
    risk, hits = scan_dlp(text)
    kinds = [h["kind"] for h in hits]
    assert "iban" in kinds


def test_detects_luhn_valid_card():
    # 4242 4242 4242 4242 (Stripe test card, Luhn valid)
    text = "Card 4242424242424242 for demo"
    risk, hits = scan_dlp(text)
    kinds = [h["kind"] for h in hits]
    assert "card" in kinds


def test_detects_third_party_email_ignores_internal():
    text = "Contacto externo cliente@extern.com y interno admin@powerfans.es"
    risk, hits = scan_dlp(text)
    emails = [h for h in hits if h["kind"] == "email_third_party"]
    assert len(emails) == 1
    assert emails[0]["matched"].endswith("n.com")


def test_multiple_hits_accumulate_risk():
    text = "NIF 12345678Z, IBAN ES9121000418450200051332, tarjeta 4242424242424242"
    risk, hits = scan_dlp(text)
    assert len(hits) >= 3
    assert 0 < risk <= 0.5   # cap at 0.5


def test_risk_capped():
    # Many hits shouldn't blow up the risk beyond 0.5
    text = " ".join(["12345678Z"] * 20)
    risk, hits = scan_dlp(text)
    assert risk <= 0.5


def test_hits_are_redacted():
    text = "IBAN ES9121000418450200051332"
    _, hits = scan_dlp(text)
    for h in hits:
        # Never leak more than 4-6 chars in matched
        assert "*" in h["matched"]
