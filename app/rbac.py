"""VKF · RBAC via OIDC (Keycloak) with local dev fallback.

Two auth paths:
  1. Bearer JWT signed by Keycloak realm vkf (verified via JWKS).
  2. X-Local-Admin-Token header matched against $VKF_LOCAL_ADMIN_TOKEN
     (dev/self-hosted operator escape hatch, rotated by rotate.sh).

Usage:
    from fastapi import Depends
    from app.rbac import require_role

    @app.post("/admin/action", dependencies=[Depends(require_role("vkf-admin"))])
    async def action(): ...
"""
from __future__ import annotations

import os
import time
from typing import Any

import httpx
from fastapi import Header, HTTPException, status
from jose import jwt


OIDC_ISSUER = os.environ.get("VKF_OIDC_ISSUER", "http://127.0.0.1:8180/realms/vkf")
OIDC_AUDIENCE = os.environ.get("VKF_OIDC_AUDIENCE", "vkf-gateway")
LOCAL_ADMIN_TOKEN = os.environ.get("VKF_LOCAL_ADMIN_TOKEN", "")
AUTH_DISABLED = os.environ.get("VKF_AUTH_DISABLED", "0") == "1"

# JWKS cache (5 min TTL)
_jwks_cache: dict[str, Any] = {"ts": 0, "keys": None}
_JWKS_TTL = 300


def _get_jwks() -> dict:
    now = time.time()
    if _jwks_cache["keys"] is not None and now - _jwks_cache["ts"] < _JWKS_TTL:
        return _jwks_cache["keys"]
    with httpx.Client(timeout=5) as client:
        r = client.get(f"{OIDC_ISSUER}/protocol/openid-connect/certs")
        r.raise_for_status()
        _jwks_cache["keys"] = r.json()
        _jwks_cache["ts"] = now
    return _jwks_cache["keys"]


def _decode_jwt(token: str) -> dict:
    try:
        unverified_header = jwt.get_unverified_header(token)
    except Exception as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"invalid token header: {e}")

    kid = unverified_header.get("kid")
    jwks = _get_jwks()
    key = next((k for k in jwks["keys"] if k["kid"] == kid), None)
    if key is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "kid not in JWKS")

    try:
        payload = jwt.decode(
            token,
            key,
            algorithms=[key.get("alg", "RS256")],
            audience=OIDC_AUDIENCE,
            issuer=OIDC_ISSUER,
            options={"verify_at_hash": False},
        )
    except jwt.JWTError as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"invalid token: {e}")

    return payload


def _extract_roles(payload: dict) -> list[str]:
    roles = set()
    # Keycloak realm roles
    roles.update(payload.get("realm_access", {}).get("roles", []) or [])
    # Client roles for vkf-gateway
    client_roles = payload.get("resource_access", {}).get(OIDC_AUDIENCE, {}).get("roles", []) or []
    roles.update(client_roles)
    return sorted(roles)


def require_role(*allowed_roles: str):
    """FastAPI dependency: 401 if no auth, 403 if role missing."""

    async def _check(
        authorization: str | None = Header(default=None),
        x_local_admin_token: str | None = Header(default=None, alias="X-Local-Admin-Token"),
    ):
        if AUTH_DISABLED:
            return {"sub": "auth-disabled", "roles": list(allowed_roles)}

        # Path 1: local admin token
        if x_local_admin_token and LOCAL_ADMIN_TOKEN and x_local_admin_token == LOCAL_ADMIN_TOKEN:
            return {"sub": "local-admin", "roles": ["vkf-admin"]}

        # Path 2: bearer JWT
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "bearer token required")

        token = authorization.split(" ", 1)[1].strip()
        payload = _decode_jwt(token)
        roles = _extract_roles(payload)

        if not any(r in roles for r in allowed_roles):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"missing role (need one of: {list(allowed_roles)}, have: {roles})",
            )
        return {"sub": payload.get("sub"), "roles": roles}

    return _check


# ────────────────────────────────────────────────────────────
# G5-D9.5 · HMAC per-role verifier (Vektrun agents internos)
# ────────────────────────────────────────────────────────────
import hmac as _hmac
import hashlib as _hashlib
from fastapi import Request as _Request


_ROLES_ALLOWED = {"NEURUS", "NEXUS", "WALLY", "FISCUS", "LEGALITUS", "SECURITUS", "FIERRITUS"}


def _hmac_secret_for(role: str) -> bytes | None:
    val = os.environ.get(f"HMAC_{role.upper()}")
    return val.encode() if val else None


def require_hmac_role(*allowed_roles: str):
    """Dependency que valida X-Agent-Role + X-Signature HMAC-SHA256 del body.

    Uso:
        @app.post("/internal/action", dependencies=[Depends(require_hmac_role("NEURUS", "SECURITUS"))])
        async def action(...): ...
    """
    allowed = set(r.upper() for r in allowed_roles) or _ROLES_ALLOWED

    async def _verify(request: _Request, x_agent_role: str = Header(...), x_signature: str = Header(...)) -> str:
        role = x_agent_role.strip().upper()
        if role not in allowed:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"role {role} not in allowed set")
        secret = _hmac_secret_for(role)
        if secret is None:
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, f"HMAC secret for {role} not configured")

        body = await request.body()
        sig_header = x_signature.strip()
        if not sig_header.startswith("sha256="):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "signature must start with sha256=")
        provided = sig_header.split("=", 1)[1]
        expected = _hmac.new(secret, body, _hashlib.sha256).hexdigest()
        if not _hmac.compare_digest(expected, provided):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "HMAC signature mismatch")
        # Attach verified role to state for downstream handlers
        request.state.verified_role = role
        return role

    return _verify
