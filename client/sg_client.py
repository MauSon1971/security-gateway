"""Security Gateway · Client library for consumers.

Any agent (WALLY, NEURUS, NEXUS, etc.) that reads security-sensitive input
must verify the HMAC seal before trusting the data.

Usage:

    from sg_client import verify_seal, InvalidSeal

    try:
        claims = verify_seal(seal_hmac, expected_source_id="email:12345",
                             key_path="/etc/security-gateway/hmac.key")
    except InvalidSeal as e:
        # Reject the message — do NOT process it
        log.warning("seal_invalid", extra={"reason": str(e), "seal": seal_hmac[:20]})
        return

    # claims contains: source_id, checks_passed, risk_score, sealed_at, ttl_hours
    assert "injection" in claims["checks_passed"] or \
           "injection_prescan" in claims["checks_passed"]
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import pathlib
from datetime import datetime, timezone
from typing import Any


class InvalidSeal(Exception):
    """Raised when the HMAC seal cannot be verified or has expired."""


def _b64url_decode(s: str) -> bytes:
    # Pad
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def _load_key(key_path: str) -> bytes:
    """Load HMAC key from file (hex-encoded, 32 bytes → 64 hex chars)."""
    p = pathlib.Path(key_path)
    if not p.is_file():
        raise InvalidSeal(f"key_file_missing: {key_path}")
    raw = p.read_text().strip()
    try:
        return bytes.fromhex(raw)
    except ValueError as e:
        raise InvalidSeal(f"key_file_not_hex: {e}") from e


def verify_seal(
    seal_hmac: str,
    expected_source_id: str | None = None,
    key_path: str = "/etc/security-gateway/hmac.key",
    key_bytes: bytes | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify seal HMAC + TTL + optional source_id match.

    Args:
        seal_hmac: The seal string as returned by the gateway.
        expected_source_id: If provided, the claim's source_id must match.
        key_path: Path to hex-encoded HMAC secret (default gateway path).
        key_bytes: Alternative — provide the raw key bytes directly.
        now: Injectable clock for testing.

    Returns:
        The verified claims dict.

    Raises:
        InvalidSeal: If the seal is malformed, signature invalid, TTL expired,
                     or source_id does not match.
    """
    if not seal_hmac or "." not in seal_hmac:
        raise InvalidSeal("malformed_seal")

    payload_b64, mac_b64 = seal_hmac.split(".", 1)

    try:
        payload_bytes = _b64url_decode(payload_b64)
        expected_mac = _b64url_decode(mac_b64)
    except Exception as e:
        raise InvalidSeal(f"base64_decode_error: {e}") from e

    key = key_bytes if key_bytes is not None else _load_key(key_path)
    computed_mac = hmac.new(key, payload_bytes, hashlib.sha256).digest()

    if not hmac.compare_digest(expected_mac, computed_mac):
        raise InvalidSeal("signature_mismatch")

    try:
        claims: dict[str, Any] = json.loads(payload_bytes.decode("utf-8"))
    except Exception as e:
        raise InvalidSeal(f"payload_not_json: {e}") from e

    # TTL check
    sealed_at_str = claims.get("sealed_at")
    ttl_hours = claims.get("ttl_hours")
    if not sealed_at_str or ttl_hours is None:
        raise InvalidSeal("missing_ttl_fields")

    sealed_at = datetime.fromisoformat(sealed_at_str.replace("Z", "+00:00"))
    now = now or datetime.now(timezone.utc)
    ttl_seconds = int(ttl_hours) * 3600
    if (now - sealed_at).total_seconds() > ttl_seconds:
        raise InvalidSeal(
            f"seal_expired: sealed_at={sealed_at_str} ttl_h={ttl_hours} now={now.isoformat()}"
        )

    # source_id check
    if expected_source_id is not None:
        if claims.get("source_id") != expected_source_id:
            raise InvalidSeal(
                f"source_id_mismatch: expected={expected_source_id} got={claims.get('source_id')}"
            )

    return claims


def has_check(claims: dict[str, Any], name: str) -> bool:
    """Convenience: does the seal include a passed check with this name?"""
    return name in (claims.get("checks_passed") or [])


# ============================================================
# SQL helper for consumers using Postgres
# ============================================================

ADMITTED_MESSAGES_SQL = """
    SELECT *
    FROM security_gateway.admitted_messages
    WHERE ($1::text IS NULL OR entity_code = $1)
      AND ($2::text IS NULL OR related_wrk_id = $2)
      AND received_at >= COALESCE($3::timestamptz, NOW() - INTERVAL '30 days')
    ORDER BY received_at DESC
    LIMIT COALESCE($4::integer, 100)
"""
