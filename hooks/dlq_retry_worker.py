#!/usr/bin/env python3
"""VKF · Dead Letter Queue retry worker.

Reads `vkf_ledger.agent_dlq` rows where:
  - resolved_at IS NULL
  - retry_count < max_retries
  - next_retry_at <= NOW()

For each row, attempts to re-enqueue the task (INSERT into agent_tasks with
state='pending' if not already terminal). On success, marks resolved_at=NOW().
On failure, increments retry_count and pushes next_retry_at by exponential
backoff: 5min → 30min → 2h → 12h.

Runs from a systemd timer every 5 minutes.
"""
from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone

import psycopg2
import psycopg2.extras

LOG = logging.getLogger("vkf.dlq_retry")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

DB_DSN = os.environ.get("SG_DB_DSN", "host=/var/run/postgresql dbname=vektrun user=vektrun_user")

# Exponential backoff in minutes for each retry attempt
BACKOFF_MINUTES = [5, 30, 120, 720]  # 5min, 30min, 2h, 12h


def compute_next_retry(retry_count: int) -> datetime:
    """Given the incremented retry_count, return next_retry_at absolute."""
    idx = min(retry_count, len(BACKOFF_MINUTES) - 1)
    return datetime.now(timezone.utc) + timedelta(minutes=BACKOFF_MINUTES[idx])


def try_reenqueue(conn, dlq_row: dict) -> bool:
    """Attempt to move the DLQ item back into agent_tasks as pending.

    Returns True on success (worker will mark resolved), False on failure
    (worker will increment retry_count).
    """
    task_id = dlq_row["task_id"]
    if not task_id:
        # DLQ entry without task_id → cannot re-enqueue; mark resolved to drain
        LOG.warning("DLQ row %s has no task_id, marking resolved", dlq_row["id"])
        return True

    with conn.cursor() as cur:
        cur.execute(
            "SELECT state FROM vkf_ledger.agent_tasks WHERE task_id = %s",
            (task_id,),
        )
        row = cur.fetchone()
        if row is None:
            LOG.warning("task_id %s not found; DLQ entry stale, marking resolved", task_id)
            return True

        state = row[0]
        if state in ("completed", "cancelled"):
            LOG.info("task_id %s already terminal (%s), marking DLQ resolved", task_id, state)
            return True

        if state == "failed":
            # Transition failed → pending is allowed by state machine
            cur.execute(
                "UPDATE vkf_ledger.agent_tasks "
                "SET state = 'pending', updated_at = NOW(), error = NULL "
                "WHERE task_id = %s AND state = 'failed'",
                (task_id,),
            )
            cur.execute(
                "INSERT INTO vkf_ledger.agent_task_transitions "
                "(task_id, from_state, to_state, actor, detail) "
                "VALUES (%s, 'failed', 'pending', 'dlq_retry_worker', %s)",
                (task_id, json.dumps({"dlq_id": dlq_row["id"]})),
            )
            LOG.info("Re-enqueued task_id=%s from failed → pending", task_id)
            return True

        # For any other state (pending, claimed, in_progress, blocked, expired),
        # do not force-reset. Retry later.
        LOG.info("task_id %s in state=%s, deferring re-enqueue", task_id, state)
        return False


def process_dlq(conn) -> tuple[int, int]:
    """Return (resolved_count, retried_count)."""
    resolved = 0
    retried = 0
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT id, task_id, agent, retry_count, max_retries "
            "FROM vkf_ledger.agent_dlq "
            "WHERE resolved_at IS NULL "
            "  AND retry_count < max_retries "
            "  AND next_retry_at <= NOW() "
            "ORDER BY next_retry_at ASC "
            "LIMIT 100 "
            "FOR UPDATE SKIP LOCKED",
        )
        rows = cur.fetchall()

    for row in rows:
        try:
            with conn:
                ok = try_reenqueue(conn, row)
                if ok:
                    with conn.cursor() as cur:
                        cur.execute(
                            "UPDATE vkf_ledger.agent_dlq "
                            "SET resolved_at = NOW() WHERE id = %s",
                            (row["id"],),
                        )
                    resolved += 1
                else:
                    new_count = row["retry_count"] + 1
                    next_at = compute_next_retry(new_count)
                    with conn.cursor() as cur:
                        cur.execute(
                            "UPDATE vkf_ledger.agent_dlq "
                            "SET retry_count = %s, next_retry_at = %s "
                            "WHERE id = %s",
                            (new_count, next_at, row["id"]),
                        )
                    retried += 1
        except Exception:
            LOG.exception("DLQ row %s failed to process", row["id"])
            # Increment retry_count so we don't loop forever
            new_count = row["retry_count"] + 1
            next_at = compute_next_retry(new_count)
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE vkf_ledger.agent_dlq "
                        "SET retry_count = %s, next_retry_at = %s "
                        "WHERE id = %s",
                        (new_count, next_at, row["id"]),
                    )
            retried += 1

    return resolved, retried


def main() -> int:
    try:
        conn = psycopg2.connect(DB_DSN)
    except Exception:
        LOG.exception("Cannot connect to Postgres")
        return 2

    try:
        resolved, retried = process_dlq(conn)
        LOG.info("DLQ pass complete · resolved=%d retried=%d", resolved, retried)
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
