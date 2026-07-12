"""SG → WALLY bridge adapter.

Puentea `security_gateway.admitted_messages` → filesystem WALLY (`data/emails/`)
sin modificar la lógica interna de WALLY.

WALLY sigue leyendo desde `data/emails/*.md` como siempre. Pero ahora ese
directorio se llena SOLO con mensajes que ya:
    1. Pasaron el Security Gateway (Capa 0 + Capa 3 + malware)
    2. Fueron admitidos por Brain Admission Control
    3. Tienen seal HMAC verificable

Idempotente. Se ejecuta 1×/15 min vía systemd timer.
"""
from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

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
WALLY_INBOX = Path(os.environ.get(
    "WALLY_INBOX",
    "/var/www/browser-agent/data/emails/gateway",
))

log = logging.getLogger("sg_wally_adapter")


_SELECT_NEW = """
    SELECT id, external_id, source_type, source_channel,
           entity_code, related_wrk_id, related_asset_id,
           subject, body, from_addr, to_addrs, attachments, metadata,
           received_at, seal_hmac, checks, risk_score,
           admission_rules_matched
    FROM security_gateway.admitted_messages
    WHERE received_at >= NOW() - INTERVAL '7 days'
      AND id NOT IN (
          SELECT COALESCE((detail->>'sg_message_id')::bigint, -1)
          FROM security_gateway.audit_log
          WHERE actor = 'sg_wally_adapter'
            AND event = 'delivered_to_wally'
      )
    ORDER BY received_at ASC
    LIMIT 200
"""


def _slug(external_id: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in external_id)[:80]


def _emit(msg: dict) -> Path:
    WALLY_INBOX.mkdir(parents=True, exist_ok=True)
    received = msg["received_at"] or datetime.now(timezone.utc)
    fname = f"{received.strftime('%y%m%d_%H%M%S')}_{_slug(msg['external_id'])}.md"
    path = WALLY_INBOX / fname

    fm = {
        "external_id": msg["external_id"],
        "source_type": msg["source_type"],
        "source_channel": msg["source_channel"],
        "entity_code": msg.get("entity_code"),
        "related_wrk_id": msg.get("related_wrk_id"),
        "related_asset_id": msg.get("related_asset_id"),
        "from_addr": msg.get("from_addr"),
        "to_addrs": msg.get("to_addrs") or [],
        "received_at": received.isoformat(),
        "checks": msg.get("checks") or {},
        "risk_score": float(msg["risk_score"]) if msg.get("risk_score") is not None else None,
        "admission_rules_matched": msg.get("admission_rules_matched") or [],
        "seal_hmac": msg["seal_hmac"],
        "gateway_verified": True,
        "sg_message_id": msg["id"],
    }

    fm_yaml = "\n".join(f"{k}: {json.dumps(v, ensure_ascii=False)}" for k, v in fm.items())
    body = msg.get("body") or ""
    subject = msg.get("subject") or ""
    content = (
        "---\n"
        f"{fm_yaml}\n"
        "---\n\n"
        f"# {subject}\n\n"
        f"{body}\n"
    )
    path.write_text(content, encoding="utf-8")
    return path


def run() -> dict:
    delivered = 0
    seal_failed = 0
    total_seen = 0

    with psycopg2.connect(DB_DSN) as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(_SELECT_NEW)
            rows = cur.fetchall()

        for row in rows:
            total_seen += 1
            msg = dict(row)
            seal = msg.get("seal_hmac")
            if not seal:
                log.warning("no_seal id=%s", msg["id"])
                continue
            try:
                source_id = f"{msg['source_type']}:{msg['source_channel']}:{msg['external_id']}"
                verify_seal(seal, expected_source_id=source_id, key_path=HMAC_KEY_PATH)
            except InvalidSeal as e:
                seal_failed += 1
                log.error("seal_invalid id=%s reason=%s", msg["id"], e)
                continue

            try:
                out_path = _emit(msg)
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO security_gateway.audit_log (message_id, event, actor, detail) "
                        "VALUES (%s, %s, %s, %s::jsonb)",
                        (
                            msg["id"], "delivered_to_wally", "sg_wally_adapter",
                            json.dumps({"sg_message_id": msg["id"], "path": str(out_path)}),
                        ),
                    )
                conn.commit()
                delivered += 1
            except Exception as e:
                log.exception("emit_failed id=%s reason=%s", msg["id"], e)

    result = {"seen": total_seen, "delivered": delivered, "seal_failed": seal_failed}
    log.info("adapter_done: %s", json.dumps(result))
    return result


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    r = run()
    print(json.dumps(r))
    sys.exit(0)
