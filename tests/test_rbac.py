"""VKF · RBAC unit tests (local admin path)."""
from __future__ import annotations

import os
import sys

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

os.environ["VKF_LOCAL_ADMIN_TOKEN"] = "test-admin-token-xyz"

import app.rbac as _rbac  # el código del REPO, no el árbol desplegado
from app.rbac import require_role  # type: ignore

# LOCAL_ADMIN_TOKEN se lee al importar app.rbac; si otro test lo importó antes
# (p. ej. vía app.main), la variable de entorno de arriba llega tarde.
_rbac.LOCAL_ADMIN_TOKEN = "test-admin-token-xyz"
from fastapi import Depends


app = FastAPI()


@app.get("/protected-admin", dependencies=[Depends(require_role("vkf-admin"))])
async def protected_admin():
    return {"ok": True}


@app.get("/protected-viewer", dependencies=[Depends(require_role("vkf-viewer", "vkf-admin"))])
async def protected_viewer():
    return {"ok": True}


client = TestClient(app)


def test_no_auth_returns_401():
    r = client.get("/protected-admin")
    assert r.status_code == 401


def test_local_admin_token_ok():
    r = client.get("/protected-admin", headers={"X-Local-Admin-Token": "test-admin-token-xyz"})
    assert r.status_code == 200
    assert r.json() == {"ok": True}


def test_local_admin_token_wrong():
    r = client.get("/protected-admin", headers={"X-Local-Admin-Token": "wrong"})
    assert r.status_code == 401


def test_local_admin_can_access_viewer_endpoint():
    r = client.get("/protected-viewer", headers={"X-Local-Admin-Token": "test-admin-token-xyz"})
    assert r.status_code == 200


def test_invalid_bearer_returns_401():
    r = client.get("/protected-admin", headers={"Authorization": "Bearer notavalidjwt"})
    assert r.status_code == 401
