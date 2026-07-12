"""Brain Admission Control worker · v2 con schemas reales.

Ver [[feedback-brain-admission-control]]. 6 reglas P0.
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import psycopg2
import psycopg2.extras

DB_DSN = os.environ.get(
    "SG_DB_DSN",
    "host=/var/run/postgresql dbname=vektrun user=vektrun_user",
)
BATCH_LIMIT = int(os.environ.get("SG_ADMISSION_BATCH", "200"))

log = logging.getLogger("admission_worker")


@dataclass
class ReferenceData:
    active_wrk_ids: set[str]
    known_asset_names: list[str]
    known_entity_codes: set[str]
    contact_senders: dict[str, str]
    contract_deadlines: list[tuple[str, datetime, str]]

    def summary(self) -> str:
        return (
            f"wrk={len(self.active_wrk_ids)} assets={len(self.known_asset_names)} "
            f"entities={len(self.known_entity_codes)} contacts={len(self.contact_senders)} "
            f"deadlines={len(self.contract_deadlines)}"
        )


def _load_reference(conn) -> ReferenceData:
    with conn.cursor() as cur:
        cur.execute("""
            SELECT DISTINCT 'WRK_' || LPAD(task_id::text, 4, '0')
            FROM gestiones
            WHERE COALESCE(estado, 'activa') NOT IN ('cerrada', 'archivada', 'cancelada')
        """)
        active_wrk_ids = {r[0] for r in cur.fetchall() if r[0]}

        cur.execute("""
            SELECT DISTINCT a.name
            FROM assets a
            WHERE COALESCE(a.is_active, true) = true
              AND length(a.name) >= 3
        """)
        known_asset_names = [r[0] for r in cur.fetchall() if r[0]]

        cur.execute("SELECT DISTINCT code FROM entities WHERE code IS NOT NULL")
        db_entities = {r[0].upper() for r in cur.fetchall() if r[0]}
        known_entity_codes = db_entities | {"MAN", "TPL", "PWF", "MSN", "KUG", "TSC"}

        cur.execute("""
            SELECT LOWER(c.email), COALESCE(e.code, '')
            FROM contacts c
            LEFT JOIN entities e ON c.entity_id = e.id
            WHERE c.email IS NOT NULL AND c.email <> ''
              AND COALESCE(c.is_active, true) = true
        """)
        contact_senders = {r[0]: r[1] for r in cur.fetchall()}

        # Contract deadlines within ±30 days (using fecha_fin as deadline)
        cur.execute("""
            SELECT
                COALESCE(c.numero_contrato, c.titulo),
                c.fecha_fin,
                COALESCE(e.code, '')
            FROM contracts c
            LEFT JOIN entities e ON c.entity_id = e.id
            WHERE c.fecha_fin IS NOT NULL
              AND c.fecha_fin >= (CURRENT_DATE - INTERVAL '7 days')
              AND c.fecha_fin <= (CURRENT_DATE + INTERVAL '30 days')
              AND COALESCE(c.estado, 'activo') NOT IN ('cerrado', 'cancelado', 'archivado')
        """)
        contract_deadlines = [
            (r[0] or "", r[1], (r[2] or "").upper()) for r in cur.fetchall() if r[1]
        ]

    return ReferenceData(
        active_wrk_ids=active_wrk_ids,
        known_asset_names=known_asset_names,
        known_entity_codes=known_entity_codes,
        contact_senders=contact_senders,
        contract_deadlines=contract_deadlines,
    )


_WRK_RE = re.compile(r"WRK[_\-\s]?(\d{3,5})", re.IGNORECASE)
_WIKILINK_RE = re.compile(r"\[\[([^\]|]+)(?:\|[^\]]+)?\]\]")


def _text_pool(msg: dict) -> str:
    parts = [msg.get("subject") or "", msg.get("body") or ""]
    return " \n ".join(p for p in parts if p)


def rule_wrk(text: str, ref: ReferenceData) -> str | None:
    for m in _WRK_RE.finditer(text):
        wrk = f"WRK_{m.group(1).zfill(4)}"
        if wrk in ref.active_wrk_ids:
            return wrk
    return None


def rule_asset(text: str, ref: ReferenceData) -> str | None:
    t = text.lower()
    for name in ref.known_asset_names:
        n = name.lower()
        if len(n) < 4:
            continue
        if n in t:
            return f"asset:{name[:40]}"
    return None


def rule_thread(msg: dict, conn) -> str | None:
    meta = msg.get("metadata") or {}
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except Exception:
            meta = {}
    ref_id = meta.get("in_reply_to") or meta.get("thread_id") or meta.get("references")
    if not ref_id:
        return None
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT external_id FROM security_gateway.raw_messages
            WHERE (external_id = %s OR metadata->>'message_id' = %s)
              AND admission_status = 'admitted' LIMIT 1
            """,
            (str(ref_id), str(ref_id)),
        )
        return f"thread:{ref_id}" if cur.fetchone() else None


def rule_sender(msg: dict, ref: ReferenceData) -> str | None:
    from_addr = (msg.get("from_addr") or "").strip().lower()
    if not from_addr:
        return None
    if from_addr in ref.contact_senders:
        return f"sender:{from_addr}"
    if "@" in from_addr:
        domain = from_addr.split("@", 1)[-1]
        if domain and any(k.endswith("@" + domain) for k in ref.contact_senders):
            return f"sender_domain:{domain}"
    return None


def rule_deadline(text: str, ref: ReferenceData) -> str | None:
    t_upper = text.upper()
    for contract_id, deadline, entity in ref.contract_deadlines:
        if entity and re.search(rf"\b{re.escape(entity)}\b", t_upper):
            return f"deadline:{contract_id[:30]}:{deadline.isoformat() if hasattr(deadline, 'isoformat') else deadline}"
    return None


def rule_wikilink(text: str, ref: ReferenceData) -> str | None:
    m = _WIKILINK_RE.search(text or "")
    if not m:
        return None
    ref_txt = m.group(1).strip()
    return f"wikilink:{ref_txt[:40]}"


def evaluate(msg: dict, ref: ReferenceData, conn) -> list[str]:
    text = _text_pool(msg)
    matched: list[str] = []
    if h := rule_wrk(text, ref):
        matched.append(f"R1_wrk:{h}")
    if h := rule_asset(text, ref):
        matched.append(f"R2_asset:{h}")
    if h := rule_thread(msg, conn):
        matched.append(f"R3_thread:{h}")
    if h := rule_sender(msg, ref):
        matched.append(f"R4_sender:{h}")
    if h := rule_deadline(text, ref):
        matched.append(f"R5_deadline:{h}")
    if h := rule_wikilink(text, ref):
        matched.append(f"R6_wikilink:{h}")
    return matched


_SELECT_PENDING = """
    SELECT id, external_id, source_type, source_channel,
           subject, body, from_addr, metadata, received_at
    FROM security_gateway.raw_messages
    WHERE sealed = TRUE AND admission_status = 'pending' AND seal_ttl > NOW()
    ORDER BY received_at ASC LIMIT %s
"""

_UPDATE = """
    UPDATE security_gateway.raw_messages
    SET admission_status=%s, admission_rules_matched=%s,
        admission_decided_by=%s, admission_decided_at=NOW()
    WHERE id=%s
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

    ref = _load_reference(conn)
    log.info(f"reference_loaded: {ref.summary()}")

    admitted = 0
    quarantined = 0
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(_SELECT_PENDING, (BATCH_LIMIT,))
        pending = cur.fetchall()

    for msg in pending:
        rules = evaluate(dict(msg), ref, conn)
        if rules:
            status = "admitted"
            actor = "auto:" + ",".join(sorted({r.split(":", 1)[0] for r in rules}))
            admitted += 1
        else:
            status = "quarantined"
            actor = "auto:no_rule_match"
            quarantined += 1

        with conn.cursor() as cur:
            cur.execute(_UPDATE, (status, rules, actor, msg["id"]))
            cur.execute(_AUDIT, (
                msg["id"], f"admission_{status}", "admission_worker",
                json.dumps({"rules": rules, "source_id": msg["external_id"]}),
            ))
        conn.commit()

    result = {"processed": len(pending), "admitted": admitted, "quarantined": quarantined}
    log.info(f"worker_done: {json.dumps(result)}")
    if close:
        conn.close()
    return result


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    r = run()
    print(json.dumps(r))
    sys.exit(0)
