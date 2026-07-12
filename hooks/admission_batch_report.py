"""Brain Admission · Batch report Mauri.

Se ejecuta 1×/día 08:00 Europe/Madrid (systemd timer).
Genera `_report_Mau/YYMMDD_admision_brain.md` en el brain vault con:
    - Lista de mensajes quarantined en las últimas 24h
    - Un check-box por mensaje para decisión Mauri
    - Enlaces al endpoint de reprocess

Mauri edita el .md marcando checkboxes y otro script (futuro) aplica.
"""
from __future__ import annotations

import json
import os
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import psycopg2
import psycopg2.extras

DB_DSN = os.environ.get(
    "SG_DB_DSN",
    "host=/var/run/postgresql dbname=vektrun user=vektrun_user",
)

REPORT_DIR = Path(os.environ.get(
    "SG_REPORT_DIR",
    "/var/www/vaults/V0_MSN/_REPORTS/_report_Mau",
))

WINDOW_HOURS = int(os.environ.get("SG_REPORT_WINDOW_HOURS", "24"))


_SELECT_QUARANTINED = """
    SELECT id, external_id, source_type, source_channel,
           subject, from_addr, received_at, ingested_at,
           risk_score, checks, seal_error, admission_rules_matched
    FROM security_gateway.raw_messages
    WHERE admission_status = 'quarantined'
      AND ingested_at >= NOW() - INTERVAL '%s hours'
    ORDER BY received_at DESC
""" % (WINDOW_HOURS,)


def generate_report() -> Path:
    today = date.today()
    fname = f"{today:%y%m%d}_admision_brain.md"
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = REPORT_DIR / fname

    with psycopg2.connect(DB_DSN) as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(_SELECT_QUARANTINED)
            rows = cur.fetchall()

    lines: list[str] = []
    lines.append(f"---")
    lines.append(f"doc: ADMISION_BRAIN_REPORT")
    lines.append(f"fecha: {today.isoformat()}")
    lines.append(f"generado: {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"generador: admission_batch_report.py")
    lines.append(f"window_hours: {WINDOW_HOURS}")
    lines.append(f"total_quarantined: {len(rows)}")
    lines.append(f"---")
    lines.append("")
    lines.append(f"# 🧭 Admisión Brain — decisión SuperAdmin · {today:%Y-%m-%d}")
    lines.append("")

    if not rows:
        lines.append("✅ Sin mensajes en cuarentena en las últimas "
                     f"{WINDOW_HOURS}h. Ecosistema limpio.")
        out_path.write_text("\n".join(lines) + "\n")
        return out_path

    lines.append(f"Hay **{len(rows)} mensajes** en cuarentena esperando tu decisión.")
    lines.append("")
    lines.append("Para cada uno:")
    lines.append("- `[ ]` **admitir** — deja que agentes lo procesen (vinculará a WRK detectada)")
    lines.append("- `[ ]` **descartar** — marca como no relevante")
    lines.append("- `[ ]` **_TO_REVIEW** — revisar más tarde (te reaparece en 14 días)")
    lines.append("")

    for r in rows:
        subject = (r["subject"] or "(sin asunto)")[:100]
        from_addr = r["from_addr"] or "(sin remitente)"
        received = r["received_at"].strftime("%Y-%m-%d %H:%M") if r["received_at"] else "?"
        risk = r["risk_score"] if r["risk_score"] is not None else "-"
        checks = json.dumps(r["checks"] or {}, ensure_ascii=False)
        rules = r["admission_rules_matched"] or []
        rules_str = ", ".join(rules) if rules else "ninguna"

        lines.append(f"---")
        lines.append("")
        lines.append(f"## msg#{r['id']} · {r['source_type']} · {from_addr}")
        lines.append(f"**Asunto:** {subject}")
        lines.append(f"**Recibido:** {received} · **Canal:** `{r['source_channel']}`")
        lines.append(f"**External ID:** `{r['external_id']}`")
        lines.append(f"**Risk score:** {risk} · **Checks:** `{checks}`")
        lines.append(f"**Reglas match:** {rules_str}")
        if r["seal_error"]:
            lines.append(f"**Seal error:** `{r['seal_error']}`")
        lines.append("")
        lines.append(f"- [ ] admitir → `curl -X POST http://127.0.0.1:8850/admission/reprocess?id={r['id']}&decision=admit&by=mauri`")
        lines.append(f"- [ ] descartar → `curl -X POST http://127.0.0.1:8850/admission/reprocess?id={r['id']}&decision=reject&by=mauri`")
        lines.append(f"- [ ] _TO_REVIEW → `curl -X POST http://127.0.0.1:8850/admission/reprocess?id={r['id']}&decision=review&by=mauri`")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(f"_TTL cuarentena_: si no decides en 14 días → auto-move a `_TO_REVIEW/`. "
                 f"Tras 30 días desde ahí → `_TRASH/` con report (nunca `rm`).")

    out_path.write_text("\n".join(lines) + "\n")
    return out_path


if __name__ == "__main__":
    p = generate_report()
    print(f"Report generated: {p}")
    sys.exit(0)
