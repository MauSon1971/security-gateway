"""HMAC seal utilities.

Seal format:
    base64url(claims_json).base64url(hmac_sha256(claims_json, key))

Claims:
    source_id, checks_passed[], risk_score, sealed_at (ISO8601 UTC), ttl_hours
"""
from __future__ import annotations

import base64
import hmac
import hashlib
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from typing import Iterable


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


@dataclass(frozen=True)
class SealClaims:
    source_id: str
    checks_passed: list[str]
    risk_score: float
    sealed_at: str  # ISO8601
    ttl_hours: int
    issued_to: str | None = None   # 861: consumidor que pidió el sello (None = 0.3.x)

    def to_json(self) -> bytes:
        # sort_keys so the digest is deterministic
        d = asdict(self)
        if d.get("issued_to") is None:
            d.pop("issued_to", None)   # sellos sin consumidor: bytes idénticos a 0.3.x
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )


def sign_seal(
    key: bytes,
    source_id: str,
    checks_passed: Iterable[str],
    risk_score: float,
    ttl_hours: int = 24,
    now: datetime | None = None,
    issued_to: str | None = None,
) -> tuple[str, SealClaims]:
    now = now or datetime.now(timezone.utc)
    claims = SealClaims(
        source_id=source_id,
        checks_passed=list(checks_passed),
        risk_score=float(risk_score),
        sealed_at=now.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        ttl_hours=int(ttl_hours),
        issued_to=issued_to,
    )
    payload = claims.to_json()
    mac = hmac.new(key, payload, hashlib.sha256).digest()
    seal = f"{_b64url_encode(payload)}.{_b64url_encode(mac)}"
    return seal, claims


def verify_seal(
    key: bytes, seal: str, now: datetime | None = None
) -> tuple[bool, str, SealClaims | None]:
    """Return (ok, reason, claims_if_valid).

    reason is 'ok' | 'malformed' | 'bad_signature' | 'expired' | 'bad_claims'.
    """
    try:
        payload_b64, mac_b64 = seal.split(".", 1)
        payload = _b64url_decode(payload_b64)
        mac = _b64url_decode(mac_b64)
    except Exception:
        return False, "malformed", None

    expected = hmac.new(key, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        return False, "bad_signature", None

    try:
        data = json.loads(payload)
        claims = SealClaims(
            source_id=data["source_id"],
            checks_passed=list(data["checks_passed"]),
            risk_score=float(data["risk_score"]),
            sealed_at=data["sealed_at"],
            ttl_hours=int(data["ttl_hours"]),
            issued_to=data.get("issued_to"),
        )
    except Exception:
        return False, "bad_claims", None

    try:
        sealed_at = datetime.fromisoformat(claims.sealed_at.replace("Z", "+00:00"))
    except Exception:
        return False, "bad_claims", None

    now = now or datetime.now(timezone.utc)
    if now > sealed_at + timedelta(hours=claims.ttl_hours):
        return False, "expired", None

    return True, "ok", claims
