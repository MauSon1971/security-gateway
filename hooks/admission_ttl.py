"""Brain Admission Control · TTL job.

Executes daily (systemd timer). Applies aging to quarantined messages:

    Day 0-14  · quarantined              (Mauri can decide via batch report)
    Day 14    · quarantined → review_later  (moves to _TO_REVIEW window)
    Day 30    · review_later → expired      (drops from workflow)

Never deletes rows (audit trail preserved). Generates a report each time it
moves anything, appended to _report_Mau.
"""
from __future__ import annotations

import json
import logging
import os
import sys
from datetime import date, datetime, timezone
from pathlib import Path

import psycopg2
import psycopg2.extras

DB_DSN = os.environ.get(
    "SG_DB_DSN",
    "host=/var/run/postgresql dbname=vektrun user=vektrun_user",
)
REPORT_DIR = Path(os.environ.get(
    "SG_REPORT_DIR",
    "/var/www/vaults/V0_MSN/_MD/_REPORTS/_report_Mau",
))

log = logging.getLogger("admission_ttl")


_MOVE_TO_REVIEW_LATER = """
    WITH moved AS (
        UPDATE security_gateway.raw_messages
        SET admission_status = 'review_later',
            admission_decided_at = NOW(),
            admission_decided_by = 'auto:ttl_14d'
        WHERE admission_status = 'quarantined'
          AND ingested_at < NOW() - INTERVAL '14 days'
        RETURNING id, external_id, subject, from_addr, ingested_at
    )
    SELECT * FROM moved
"""

_MOVE_TO_EXPIRED = """
    WITH moved AS (
        UPDATE security_gateway.raw_messages
        SET admission_status = 'expired',
            admission_decided_at = NOW(),
            admission_decided_by = 'auto:ttl_44d'
        WHERE admission_status = 'review_later'
          AND admission_decided_at < NOW() - INTERVAL '30 days'
        RETURNING id, external_id, subject, from_addr
    )
    SELECT * FROM moved
"""

_AUDIT = """
    INSERT INTO security_gateway.audit_log (message_id, event, actor, detail)
    VALUES (%s, %s, %s, %s::jsonb)
"""


def run(conn=None) -> dict:
    close = False
    if conn is None:
        conn = psycopg2.connect(DB_DSN)
        close = True

    to_review = []
    to_expired = []

    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(_MOVE_TO_REVIEW_LATER)
        to_review = [dict(r) for r in cur.fetchall()]

        cur.execute(_MOVE_TO_EXPIRED)
        to_expired = [dict(r) for r in cur.fetchall()]

    with conn.cursor() as cur:
        for r in to_review:
            cur.execute(_AUDIT, (
                r["id"], "ttl_moved_to_review", "admission_ttl",
                json.dumps({"external_id": r["external_id"]}),
            ))
        for r in to_expired:
            cur.execute(_AUDIT, (
                r["id"], "ttl_moved_to_expired", "admission_ttl",
                json.dumps({"external_id": r["external_id"]}),
            ))
    conn.commit()

    result = {"moved_to_review": len(to_review), "moved_to_expired": len(to_expired)}
    log.info(f"ttl_done: {json.dumps(result)}")

    # Report to Mauri only if something happened
    if to_review or to_expired:
        _write_report(to_review, to_expired)

    if close:
        conn.close()
    return result


def _write_report(review: list[dict], expired: list[dict]) -> None:
    today = date.today()
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    fpath = REPORT_DIR / f"{today:%y%m%d}_ttl_ejecutado.md"
    lines = [
        "---",
        f"doc: TTL_REPORT",
        f"fecha: {today.isoformat()}",
        f"generado: {datetime.now(timezone.utc).isoformat()}",
        f"generador: admission_ttl.py",
        f"moved_to_review_later: {len(review)}",
        f"moved_to_expired: {len(expired)}",
        "---",
        "",
        f"# TTL Ejecutado · {today:%Y-%m-%d}",
        "",
    ]
    if review:
        lines.append("## Cuarentena → _TO_REVIEW (14 días sin decisión)")
        lines.append("")
        for r in review:
            when = r["ingested_at"].strftime("%Y-%m-%d") if r["ingested_at"] else "?"
            lines.append(
                f"- **#{r['id']}** {r.get('subject', '(sin asunto)')[:60]} · "
                f"from `{r.get('from_addr') or '-'}` · ingested {when}"
            )
        lines.append("")
    if expired:
        lines.append("## _TO_REVIEW → expired (44 días totales)")
        lines.append("")
        for r in expired:
            lines.append(
                f"- **#{r['id']}** {r.get('subject', '(sin asunto)')[:60]} · from `{r.get('from_addr') or '-'}`"
            )
        lines.append("")
    lines.append("_Rows NO borrados (audit trail preservado). Consultar via `/admission/quarantined?status=expired` cuando esté disponible._")

    fpath.write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    r = run()
    print(json.dumps(r))
    sys.exit(0)
