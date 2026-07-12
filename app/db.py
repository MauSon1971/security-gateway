"""VKF · DB helpers with automatic multi-tenancy scope.

Usage:
    with db.connect(tenant_id="msn") as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM security_gateway.raw_messages")
            # RLS restricts rows to tenant_id='msn'
"""
from __future__ import annotations

import os
from contextlib import contextmanager

import psycopg2


DEFAULT_TENANT = "msn"


def get_dsn() -> str:
    return os.environ.get(
        "SG_DB_DSN",
        "host=/var/run/postgresql dbname=vektrun user=vektrun_user",
    )


@contextmanager
def connect(tenant_id: str = DEFAULT_TENANT):
    """Open a Postgres connection with RLS scoped to `tenant_id`.

    The session-level `vkf.tenant` GUC is set before the caller sees the
    connection, so any SELECT/INSERT/UPDATE goes through the per_tenant policy.
    """
    conn = psycopg2.connect(get_dsn())
    try:
        with conn.cursor() as cur:
            # `set_config` is safe against SQL injection (parameter binding)
            cur.execute("SELECT set_config('vkf.tenant', %s, false)", (tenant_id,))
        yield conn
    finally:
        conn.close()


def current_tenant(conn) -> str:
    with conn.cursor() as cur:
        cur.execute("SELECT security_gateway.current_tenant()")
        return cur.fetchone()[0]
