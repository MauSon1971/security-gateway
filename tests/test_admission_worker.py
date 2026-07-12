"""Integration tests for Brain Admission Control worker (v2 con schemas reales)."""
from __future__ import annotations

import os
from datetime import datetime, timezone

import psycopg2
import pytest

from hooks.admission_worker import run
from hooks.comms_ingest import IncomingMessage, ingest_message

DB_DSN = os.environ.get(
    "SG_DB_DSN",
    "host=/var/run/postgresql dbname=vektrun user=vektrun_user",
)


def _cleanup():
    with psycopg2.connect(DB_DSN) as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM security_gateway.raw_messages WHERE external_id LIKE 'test-adm-%%'")
        conn.commit()


def _fresh(external_id, subject, body, from_addr=None):
    return IncomingMessage(
        external_id=external_id,
        source_type="email",
        source_channel="test:adm",
        received_at=datetime.now(timezone.utc),
        subject=subject,
        body=body,
        from_addr=from_addr,
    )


def _status(external_id):
    with psycopg2.connect(DB_DSN) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT admission_status, admission_rules_matched FROM security_gateway.raw_messages WHERE external_id=%s",
            (external_id,),
        )
        return cur.fetchone()


@pytest.fixture(autouse=True)
def cleanup_around():
    _cleanup()
    yield
    _cleanup()


def test_worker_quarantines_message_with_no_signal():
    r = ingest_message(_fresh(
        "test-adm-nosignal",
        "Newsletter mensual",
        "Suscribete a nuestro nuevo boletin semanal con novedades del sector.",
        "newsletter@example.com",
    ))
    assert r.sealed is True
    run()
    status, rules = _status("test-adm-nosignal")
    assert status == "quarantined"
    assert not rules


def test_worker_admits_message_with_explicit_wikilink():
    r = ingest_message(_fresh(
        "test-adm-wikilink",
        "Recordatorio",
        "Referencia a [[MSN]] gestion activa vigente.",
        "anyone@example.com",
    ))
    assert r.sealed is True
    run()
    status, rules = _status("test-adm-wikilink")
    assert status == "admitted"
    assert any(rr.startswith("R6_wikilink") for rr in (rules or []))


def test_worker_admits_message_with_real_wrk_reference():
    with psycopg2.connect(DB_DSN) as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT task_id FROM gestiones
            WHERE COALESCE(estado, 'activa') NOT IN ('cerrada', 'archivada', 'cancelada')
            LIMIT 1
        """)
        row = cur.fetchone()
    if not row:
        pytest.skip("no active WRK in DB")
    wrk_num = str(row[0]).zfill(4)
    wrk_id = f"WRK_{wrk_num}"

    r = ingest_message(_fresh(
        "test-adm-wrk",
        f"Actualizacion {wrk_id}",
        f"Adjuntamos documentacion adicional del expediente {wrk_id}.",
        "abogado@example.com",
    ))
    assert r.sealed is True
    run()
    status, rules = _status("test-adm-wrk")
    assert status == "admitted", f"expected admitted got {status} rules={rules}"
    assert any(rr.startswith("R1_wrk") for rr in (rules or []))


def test_worker_admits_message_with_known_contact_sender():
    # Pick a real contact from DB
    with psycopg2.connect(DB_DSN) as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT LOWER(email) FROM contacts
            WHERE email IS NOT NULL AND email <> ''
              AND COALESCE(is_active, true) = true
            LIMIT 1
        """)
        row = cur.fetchone()
    if not row or not row[0]:
        pytest.skip("no active contacts with email")
    contact_email = row[0]

    r = ingest_message(_fresh(
        "test-adm-sender",
        "Consulta rutinaria",
        "Hola, adjunto los datos actualizados. Un saludo.",
        contact_email,
    ))
    assert r.sealed is True
    run()
    status, rules = _status("test-adm-sender")
    assert status == "admitted", f"expected admitted got {status} rules={rules}"
    assert any(rr.startswith("R4_sender") for rr in (rules or []))
