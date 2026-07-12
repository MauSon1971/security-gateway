"""VKF · DLQ retry worker tests."""
from __future__ import annotations

import sys
import uuid
from datetime import datetime, timedelta, timezone

import psycopg2
import pytest

sys.path.insert(0, "/var/www/security-gateway")
from hooks import dlq_retry_worker as drw  # type: ignore


@pytest.fixture
def conn():
    c = psycopg2.connect(drw.DB_DSN)
    yield c
    c.close()


@pytest.fixture
def task_row(conn):
    task_id = f"TSK-DLQ-{uuid.uuid4().hex[:8]}"
    with conn, conn.cursor() as cur:
        cur.execute("SELECT set_config('vkf.tenant', 'msn', false)")
        cur.execute(
            "INSERT INTO vkf_ledger.agent_tasks "
            "(task_id, title, handoff_json, from_agent, to_agent, state, tenant_id) "
            "VALUES (%s, 'test', '{}'::jsonb, 'A', 'B', 'failed', 'msn')",
            (task_id,),
        )
    yield task_id
    with conn, conn.cursor() as cur:
        cur.execute("SELECT set_config('vkf.tenant', 'msn', false)")
        cur.execute("DELETE FROM vkf_ledger.agent_tasks WHERE task_id = %s", (task_id,))


def _insert_dlq(conn, task_id, retry_count=0, next_retry_ago_seconds=60):
    with conn, conn.cursor() as cur:
        cur.execute("SELECT set_config('vkf.tenant', 'msn', false)")
        cur.execute(
            "INSERT INTO vkf_ledger.agent_dlq "
            "(task_id, agent, error, retry_count, next_retry_at, tenant_id) "
            "VALUES (%s, 'B', 'boom', %s, NOW() - INTERVAL '%s seconds', 'msn') "
            "RETURNING id",
            (task_id, retry_count, next_retry_ago_seconds),
        )
        return cur.fetchone()[0]


def _cleanup_dlq(conn, dlq_id):
    with conn, conn.cursor() as cur:
        cur.execute("SELECT set_config('vkf.tenant', 'msn', false)")
        cur.execute("DELETE FROM vkf_ledger.agent_dlq WHERE id = %s", (dlq_id,))


def test_compute_backoff():
    now = datetime.now(timezone.utc)
    # retry_count=1 → 5min
    delta = drw.compute_next_retry(0) - now
    assert timedelta(minutes=4) < delta < timedelta(minutes=6)
    # retry_count=4+ → 12h (720min)
    delta = drw.compute_next_retry(5) - now
    assert timedelta(hours=11) < delta < timedelta(hours=13)


def test_reenqueue_failed_task(conn, task_row):
    dlq_id = _insert_dlq(conn, task_row)
    try:
        resolved, retried = drw.process_dlq(conn)
        assert resolved >= 1
        # Task should be back to pending
        with conn.cursor() as cur:
            cur.execute("SELECT set_config('vkf.tenant', 'msn', false)")
            cur.execute("SELECT state FROM vkf_ledger.agent_tasks WHERE task_id = %s", (task_row,))
            assert cur.fetchone()[0] == "pending"
        # DLQ row must be resolved
        with conn.cursor() as cur:
            cur.execute("SELECT resolved_at FROM vkf_ledger.agent_dlq WHERE id = %s", (dlq_id,))
            assert cur.fetchone()[0] is not None
    finally:
        _cleanup_dlq(conn, dlq_id)


def test_dlq_null_task_marks_resolved(conn):
    """DLQ row with NULL task_id should be marked resolved to drain."""
    with conn, conn.cursor() as cur:
        cur.execute("SELECT set_config('vkf.tenant', 'msn', false)")
        cur.execute(
            "INSERT INTO vkf_ledger.agent_dlq "
            "(task_id, agent, error, retry_count, next_retry_at, tenant_id) "
            "VALUES (NULL, 'B', 'boom', 0, NOW() - INTERVAL '1 minute', 'msn') "
            "RETURNING id"
        )
        dlq_id = cur.fetchone()[0]
    try:
        resolved, _ = drw.process_dlq(conn)
        assert resolved >= 1
        with conn.cursor() as cur:
            cur.execute("SELECT resolved_at FROM vkf_ledger.agent_dlq WHERE id = %s", (dlq_id,))
            assert cur.fetchone()[0] is not None
    finally:
        _cleanup_dlq(conn, dlq_id)
