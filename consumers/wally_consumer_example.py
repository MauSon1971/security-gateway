"""Ejemplo de consumer WALLY que lee del Security Gateway pipeline.

Patron P0: agentes leen SOLO desde security_gateway.admitted_messages (view).
Verifica el sello HMAC en cada mensaje antes de procesar (defensa en profundidad).
"""
from __future__ import annotations

import logging
import os
import sys
from typing import Iterator

import psycopg2
import psycopg2.extras

sys.path.insert(0, "/var/www/security-gateway/client")
from sg_client import InvalidSeal, verify_seal  # type: ignore

DB_DSN = os.environ.get(
    "SG_DB_DSN",
    "host=/var/run/postgresql dbname=vektrun user=vektrun_user",
)
HMAC_KEY_PATH = os.environ.get(
    "SG_HMAC_KEY_PATH",
    "/etc/security-gateway/hmac.key",
)

log = logging.getLogger("wally_consumer")


def iter_pending_for_wally(entity_code: str | None = None, limit: int = 50) -> Iterator[dict]:
    """Yield admitted messages, verifying the HMAC seal on each."""
    if entity_code:
        sql = """
            SELECT id, external_id, source_type, source_channel,
                   entity_code, related_wrk_id, related_asset_id,
                   subject, body, from_addr, to_addrs, attachments, metadata,
                   received_at, seal_hmac, checks, risk_score,
                   admission_rules_matched
            FROM security_gateway.admitted_messages
            WHERE entity_code = %s
              AND received_at >= NOW() - INTERVAL '30 days'
            ORDER BY received_at DESC
            LIMIT %s
        """
        params = (entity_code, limit)
    else:
        sql = """
            SELECT id, external_id, source_type, source_channel,
                   entity_code, related_wrk_id, related_asset_id,
                   subject, body, from_addr, to_addrs, attachments, metadata,
                   received_at, seal_hmac, checks, risk_score,
                   admission_rules_matched
            FROM security_gateway.admitted_messages
            WHERE received_at >= NOW() - INTERVAL '30 days'
            ORDER BY received_at DESC
            LIMIT %s
        """
        params = (limit,)

    with psycopg2.connect(DB_DSN) as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, params)
            for row in cur.fetchall():
                msg = dict(row)
                seal = msg.get("seal_hmac")
                if not seal:
                    log.warning("no_seal_on_admitted_row id=%s", msg["id"])
                    continue
                try:
                    source_id = (
                        f"{msg['source_type']}:{msg['source_channel']}:{msg['external_id']}"
                    )
                    verify_seal(seal, expected_source_id=source_id, key_path=HMAC_KEY_PATH)
                except InvalidSeal as e:
                    log.error("seal_verify_failed id=%s reason=%s", msg["id"], e)
                    continue
                yield msg


def mark_processed(message_id: int, actor: str = "wally", note: str = "") -> None:
    import json
    with psycopg2.connect(DB_DSN) as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO security_gateway.audit_log (message_id, event, actor, detail) VALUES (%s, %s, %s, %s::jsonb)",
            (message_id, "processed", actor, json.dumps({"note": note})),
        )
        conn.commit()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    entity = sys.argv[1] if len(sys.argv) > 1 else None
    count = 0
    for msg in iter_pending_for_wally(entity_code=entity, limit=20):
        print(
            f"[{msg['id']}] {msg['received_at']:%Y-%m-%d %H:%M} "
            f"{msg['source_type']}/{msg['source_channel']} "
            f"from={msg['from_addr'] or '-'} "
            f"subject={(msg['subject'] or '-')[:60]} "
            f"rules={msg['admission_rules_matched']}"
        )
        mark_processed(msg["id"], actor="demo", note="wally_consumer_example")
        count += 1
    print(f"Processed {count} admitted messages.")
