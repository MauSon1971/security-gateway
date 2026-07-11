"""HMAC sign/verify tests."""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

from app.security import sign_seal, verify_seal


def test_roundtrip_ok():
    key = secrets.token_bytes(32)
    seal, claims = sign_seal(
        key, source_id="src-1", checks_passed=["injection"], risk_score=0.05
    )
    ok, reason, verified = verify_seal(key, seal)
    assert ok is True
    assert reason == "ok"
    assert verified is not None
    assert verified.source_id == "src-1"
    assert verified.checks_passed == ["injection"]


def test_expired_seal():
    key = secrets.token_bytes(32)
    past = datetime.now(timezone.utc) - timedelta(hours=48)
    seal, _ = sign_seal(
        key,
        source_id="src-1",
        checks_passed=["injection"],
        risk_score=0.05,
        ttl_hours=24,
        now=past,
    )
    ok, reason, _ = verify_seal(key, seal)
    assert ok is False
    assert reason == "expired"


def test_bad_signature():
    key1 = secrets.token_bytes(32)
    key2 = secrets.token_bytes(32)
    seal, _ = sign_seal(
        key1, source_id="src-1", checks_passed=["injection"], risk_score=0.05
    )
    ok, reason, _ = verify_seal(key2, seal)
    assert ok is False
    assert reason == "bad_signature"


def test_malformed():
    key = secrets.token_bytes(32)
    ok, reason, _ = verify_seal(key, "not-a-valid-seal")
    assert ok is False
    assert reason == "malformed"


def test_tamper_payload_detected():
    key = secrets.token_bytes(32)
    seal, _ = sign_seal(
        key, source_id="src-1", checks_passed=["injection"], risk_score=0.05
    )
    payload_b64, mac_b64 = seal.split(".", 1)
    # Flip last char of payload
    tampered = payload_b64[:-1] + ("A" if payload_b64[-1] != "A" else "B") + "." + mac_b64
    ok, reason, _ = verify_seal(key, tampered)
    assert ok is False
    # either malformed (invalid b64/json) or bad_signature
    assert reason in {"bad_signature", "malformed", "bad_claims"}
