"""Tests for the client-side seal verification."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone

import pytest

from sg_client import InvalidSeal, has_check, verify_seal


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _make_seal(claims: dict, key: bytes) -> str:
    payload = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8")
    mac = hmac.new(key, payload, hashlib.sha256).digest()
    return f"{_b64url(payload)}.{_b64url(mac)}"


KEY = bytes.fromhex("11" * 32)


def _now_iso(delta_hours: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=delta_hours)).isoformat().replace("+00:00", "Z")


def test_valid_seal_roundtrip():
    claims = {
        "source_id": "email:12345",
        "checks_passed": ["injection", "malware"],
        "risk_score": 0.01,
        "sealed_at": _now_iso(0),
        "ttl_hours": 24,
    }
    seal = _make_seal(claims, KEY)
    got = verify_seal(seal, expected_source_id="email:12345", key_bytes=KEY)
    assert got["source_id"] == "email:12345"
    assert has_check(got, "injection")
    assert has_check(got, "malware")
    assert not has_check(got, "unknown")


def test_wrong_key_fails():
    claims = {
        "source_id": "x",
        "checks_passed": [],
        "risk_score": 0.0,
        "sealed_at": _now_iso(0),
        "ttl_hours": 24,
    }
    seal = _make_seal(claims, KEY)
    with pytest.raises(InvalidSeal, match="signature_mismatch"):
        verify_seal(seal, key_bytes=bytes.fromhex("22" * 32))


def test_expired_seal_fails():
    claims = {
        "source_id": "x",
        "checks_passed": [],
        "risk_score": 0.0,
        "sealed_at": _now_iso(-25),  # 25h ago
        "ttl_hours": 24,
    }
    seal = _make_seal(claims, KEY)
    with pytest.raises(InvalidSeal, match="seal_expired"):
        verify_seal(seal, key_bytes=KEY)


def test_source_id_mismatch_fails():
    claims = {
        "source_id": "email:A",
        "checks_passed": [],
        "risk_score": 0.0,
        "sealed_at": _now_iso(0),
        "ttl_hours": 24,
    }
    seal = _make_seal(claims, KEY)
    with pytest.raises(InvalidSeal, match="source_id_mismatch"):
        verify_seal(seal, expected_source_id="email:B", key_bytes=KEY)


def test_malformed_seal_fails():
    with pytest.raises(InvalidSeal, match="malformed_seal"):
        verify_seal("not-a-real-seal", key_bytes=KEY)


def test_tampered_payload_fails():
    claims = {
        "source_id": "x",
        "checks_passed": [],
        "risk_score": 0.0,
        "sealed_at": _now_iso(0),
        "ttl_hours": 24,
    }
    seal = _make_seal(claims, KEY)
    # Tamper: flip last char of payload
    parts = seal.split(".")
    tampered_payload = parts[0][:-1] + ("A" if parts[0][-1] != "A" else "B")
    tampered = f"{tampered_payload}.{parts[1]}"
    with pytest.raises(InvalidSeal):
        verify_seal(tampered, key_bytes=KEY)
