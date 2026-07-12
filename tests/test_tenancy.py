"""VKF · Multi-tenancy RLS isolation tests."""
from __future__ import annotations

import os
import sys
import uuid

import psycopg2
import pytest

sys.path.insert(0, "/var/www/security-gateway")
from app import db  # type: ignore


def _make_tenant_fixture(prefix: str):
    tid = f"{prefix}_{uuid.uuid4().hex[:8]}"
    conn = psycopg2.connect(db.get_dsn())
    with conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO security_gateway.tenants (tenant_id, display_name) "
            "VALUES (%s, %s) ON CONFLICT DO NOTHING",
            (tid, f"{prefix} {tid}"),
        )
    conn.close()
    return tid


def _cleanup_tenant(tid: str):
    # Scope session to tenant so RLS lets us see and delete its rows
    conn = psycopg2.connect(db.get_dsn())
    try:
        with conn, conn.cursor() as cur:
            cur.execute("SELECT set_config('vkf.tenant', %s, false)", (tid,))
            cur.execute("DELETE FROM security_gateway.raw_messages WHERE tenant_id = %s", (tid,))
        with conn, conn.cursor() as cur:
            # tenants table has no RLS
            cur.execute("DELETE FROM security_gateway.tenants WHERE tenant_id = %s", (tid,))
    finally:
        conn.close()


@pytest.fixture
def tenant_a():
    tid = _make_tenant_fixture("testA")
    yield tid
    _cleanup_tenant(tid)


@pytest.fixture
def tenant_b():
    tid = _make_tenant_fixture("testB")
    yield tid
    _cleanup_tenant(tid)


def test_current_tenant_default():
    with db.connect() as conn:
        assert db.current_tenant(conn) == "msn"


def test_current_tenant_scoped(tenant_a):
    with db.connect(tenant_id=tenant_a) as conn:
        assert db.current_tenant(conn) == tenant_a


def test_rls_isolation(tenant_a, tenant_b):
    # Insert one row per tenant
    ext_a = f"iso-a-{uuid.uuid4().hex[:8]}"
    ext_b = f"iso-b-{uuid.uuid4().hex[:8]}"

    with db.connect(tenant_id=tenant_a) as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO security_gateway.raw_messages "
            "(external_id, source_type, source_channel, received_at, tenant_id) "
            "VALUES (%s, 'test', 'test', NOW(), %s)",
            (ext_a, tenant_a),
        )
        conn.commit()

    with db.connect(tenant_id=tenant_b) as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO security_gateway.raw_messages "
            "(external_id, source_type, source_channel, received_at, tenant_id) "
            "VALUES (%s, 'test', 'test', NOW(), %s)",
            (ext_b, tenant_b),
        )
        conn.commit()

    # Tenant A must see only its row
    with db.connect(tenant_id=tenant_a) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT external_id FROM security_gateway.raw_messages "
            "WHERE external_id IN (%s, %s)",
            (ext_a, ext_b),
        )
        rows = [r[0] for r in cur.fetchall()]
        assert ext_a in rows
        assert ext_b not in rows

    # Tenant B must see only its row
    with db.connect(tenant_id=tenant_b) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT external_id FROM security_gateway.raw_messages "
            "WHERE external_id IN (%s, %s)",
            (ext_a, ext_b),
        )
        rows = [r[0] for r in cur.fetchall()]
        assert ext_b in rows
        assert ext_a not in rows


def test_rls_cross_tenant_insert_blocked(tenant_a, tenant_b):
    """WITH CHECK: session as tenant_a cannot insert row with tenant_id=B."""
    ext = f"cross-{uuid.uuid4().hex[:8]}"
    with db.connect(tenant_id=tenant_a) as conn:
        with conn.cursor() as cur, pytest.raises(psycopg2.errors.InsufficientPrivilege):
            cur.execute(
                "INSERT INTO security_gateway.raw_messages "
                "(external_id, source_type, source_channel, received_at, tenant_id) "
                "VALUES (%s, 'test', 'test', NOW(), %s)",
                (ext, tenant_b),
            )
