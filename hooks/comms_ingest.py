"""COMMS_Hub → Security Gateway ingest hook.

Cualquier código que capture mensajes externos (email IMAP puller, chat webhook,
social API, vault external watcher) DEBE llamar a `ingest_message()` antes de
persistir localmente.

Flujo (patrón P0 Security Gateway):
    1. Insert raw a security_gateway.raw_messages con sealed=0.
    2. Fast-path malware inline en adjuntos (ClamAV --stream).
    3. Async gateway sealing (scan-text + attachments) → HMAC.
    4. Agentes leen SOLO security_gateway.admitted_messages (view con sealed=1).

No consume mail_events (legacy). Permite coexistencia gradual.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psycopg2
import psycopg2.extras
import requests

GATEWAY_URL = os.environ.get("SG_GATEWAY_URL", "http://127.0.0.1:8850")
DB_DSN = os.environ.get(
    "SG_DB_DSN",
    "host=/var/run/postgresql dbname=vektrun user=vektrun_user",
)
INGEST_TIMEOUT = int(os.environ.get("SG_INGEST_TIMEOUT", "20"))


@dataclass
class Attachment:
    filename: str
    content_bytes: bytes
    mime_type: str | None = None

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content_bytes).hexdigest()

    @property
    def size(self) -> int:
        return len(self.content_bytes)


@dataclass
class IncomingMessage:
    """Normalized incoming message from any source (email, chat, webhook)."""

    external_id: str
    source_type: str            # 'email' | 'chat' | 'webhook' | 'vault_external' | 'api'
    source_channel: str         # 'gmail:admin@powerfans.es' | 'telegram:wally_bot'
    received_at: datetime

    subject: str | None = None
    body: str = ""
    from_addr: str | None = None
    to_addrs: list[str] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class IngestResult:
    message_id: int
    sealed: bool
    seal_hmac: str | None
    risk_score: float | None
    checks: dict[str, str]
    attachments_scanned: list[dict[str, Any]]
    error: str | None = None


# ============================================================
# Gateway API calls
# ============================================================

def _auth_headers() -> dict[str, str]:
    """861 · token de servicio de este consumidor ($SG_CONSUMER_TOKEN_FILE)."""
    path = os.environ.get("SG_CONSUMER_TOKEN_FILE")
    if not path:
        return {}
    try:
        tok = open(path, encoding="utf-8").read().strip()
    except OSError:
        return {}
    return {"X-SG-Token": tok} if tok else {}


def _scan_text_via_gateway(text: str, source_id: str) -> dict[str, Any]:
    if not text or not text.strip():
        # No text to scan — trivially pass
        return {
            "risk_score": 0.0,
            "checks": {"injection": "pass"},
            "seal_hmac": None,
            "reason": "empty_text",
        }
    r = requests.post(
        f"{GATEWAY_URL}/gateway/scan-text",
        json={"text": text[:100_000], "source_id": source_id},  # cap 100k chars
        headers=_auth_headers(),
        timeout=INGEST_TIMEOUT,
    )
    r.raise_for_status()
    return r.json()


def _scan_attachment_via_gateway(att: Attachment, source_id: str) -> dict[str, Any]:
    files = {"file": (att.filename, att.content_bytes, att.mime_type or "application/octet-stream")}
    r = requests.post(
        f"{GATEWAY_URL}/gateway/scan-attachment",
        files=files,
        data={"source_id": source_id},
        headers=_auth_headers(),
        timeout=INGEST_TIMEOUT,
    )
    r.raise_for_status()
    return r.json()


# ============================================================
# DB persistence
# ============================================================

_UPSERT_SQL = """
    INSERT INTO security_gateway.raw_messages (
        external_id, source_type, source_channel,
        subject, body, from_addr, to_addrs,
        attachments, metadata, received_at, ingested_at,
        sealed, seal_hmac, seal_ttl, checks,
        risk_score, malware_scan_pass, seal_error
    ) VALUES (
        %(external_id)s, %(source_type)s, %(source_channel)s,
        %(subject)s, %(body)s, %(from_addr)s, %(to_addrs)s,
        %(attachments)s::jsonb, %(metadata)s::jsonb, %(received_at)s, NOW(),
        %(sealed)s, %(seal_hmac)s, %(seal_ttl)s, %(checks)s::jsonb,
        %(risk_score)s, %(malware_scan_pass)s, %(seal_error)s
    )
    ON CONFLICT (external_id, source_channel) DO UPDATE SET
        sealed = EXCLUDED.sealed,
        seal_hmac = EXCLUDED.seal_hmac,
        seal_ttl = EXCLUDED.seal_ttl,
        checks = EXCLUDED.checks,
        risk_score = EXCLUDED.risk_score,
        malware_scan_pass = EXCLUDED.malware_scan_pass,
        seal_error = EXCLUDED.seal_error
    RETURNING id
"""


def _persist(conn, msg: IncomingMessage, gateway_text: dict, att_results: list[dict]) -> int:
    all_pass = (
        gateway_text.get("checks", {}).get("injection") == "pass"
        and all(a.get("malware_scan") == "pass" for a in att_results)
    )

    checks: dict[str, str] = {}
    if "injection" in gateway_text.get("checks", {}):
        checks["injection"] = gateway_text["checks"]["injection"]
    if att_results:
        checks["malware"] = "pass" if all(a.get("malware_scan") == "pass" for a in att_results) else "fail"

    risk_score = gateway_text.get("risk_score")
    seal_hmac = gateway_text.get("seal_hmac") if all_pass else None
    seal_ttl_hours = gateway_text.get("seal_ttl_hours") or 24
    seal_ttl = None
    if seal_hmac:
        seal_ttl = datetime.now(timezone.utc) + _hours(seal_ttl_hours)

    reason_pieces: list[str] = []
    if gateway_text.get("reason"):
        reason_pieces.append(f"text:{gateway_text['reason']}")
    for a in att_results:
        if a.get("reason"):
            reason_pieces.append(f"att:{a['reason']}")

    attachments_meta = [
        {
            "filename": a.filename,
            "size": a.size,
            "sha256": a.sha256,
            "mime": a.mime_type,
            "scan": r.get("malware_scan"),
            "reason": r.get("reason"),
        }
        for a, r in zip(msg.attachments, att_results)
    ]

    with conn.cursor() as cur:
        cur.execute(_UPSERT_SQL, {
            "external_id": msg.external_id,
            "source_type": msg.source_type,
            "source_channel": msg.source_channel,
            "subject": msg.subject,
            "body": msg.body,
            "from_addr": msg.from_addr,
            "to_addrs": msg.to_addrs,
            "attachments": json.dumps(attachments_meta, ensure_ascii=False),
            "metadata": json.dumps(msg.metadata, ensure_ascii=False),
            "received_at": msg.received_at,
            "sealed": all_pass,
            "seal_hmac": seal_hmac,
            "seal_ttl": seal_ttl,
            "checks": json.dumps(checks),
            "risk_score": risk_score,
            "malware_scan_pass": all(a.get("malware_scan") == "pass" for a in att_results) if att_results else None,
            "seal_error": " | ".join(reason_pieces) if reason_pieces else None,
        })
        row = cur.fetchone()
        message_id = row[0]

    # Audit
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO security_gateway.audit_log (message_id, event, actor, detail) VALUES (%s, %s, %s, %s::jsonb)",
            (
                message_id,
                "sealed" if all_pass else "quarantine_pending",
                "gateway",
                json.dumps({"risk_score": risk_score, "checks": checks}),
            ),
        )
    conn.commit()
    return message_id


def _hours(h: int):
    from datetime import timedelta
    return timedelta(hours=int(h))


# ============================================================
# Public API
# ============================================================

def ingest_message(msg: IncomingMessage, conn=None) -> IngestResult:
    """Ingest an external message through the Security Gateway pipeline.

    - Text is scanned via /gateway/scan-text (Capa 0 + Capa 3).
    - Each attachment is scanned via /gateway/scan-attachment (ClamAV --stream).
    - Row is inserted in security_gateway.raw_messages with sealed=1 iff ALL checks pass.
    - Agents must consume via security_gateway.admitted_messages (view).
    """
    source_id = f"{msg.source_type}:{msg.source_channel}:{msg.external_id}"

    text_full = "\n".join(x for x in [msg.subject, msg.body] if x)
    gateway_text = _scan_text_via_gateway(text_full, source_id)

    att_results: list[dict] = []
    for att in msg.attachments:
        try:
            r = _scan_attachment_via_gateway(att, f"{source_id}:att:{att.filename}")
        except Exception as e:
            r = {"malware_scan": "fail", "engine": "error", "reason": f"scan_exception:{e}"}
        att_results.append(r)

    close_conn = False
    if conn is None:
        conn = psycopg2.connect(DB_DSN)
        close_conn = True

    try:
        message_id = _persist(conn, msg, gateway_text, att_results)
    finally:
        if close_conn:
            conn.close()

    all_pass = (
        gateway_text.get("checks", {}).get("injection") == "pass"
        and all(a.get("malware_scan") == "pass" for a in att_results)
    )

    return IngestResult(
        message_id=message_id,
        sealed=all_pass,
        seal_hmac=gateway_text.get("seal_hmac") if all_pass else None,
        risk_score=gateway_text.get("risk_score"),
        checks=gateway_text.get("checks", {}) | ({"malware": "pass" if all(a.get("malware_scan") == "pass" for a in att_results) else "fail"} if att_results else {}),
        attachments_scanned=att_results,
    )
