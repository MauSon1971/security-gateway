"""VKF Bypass detection · alert if >N blocked attempts / hour per source.

Runs on systemd timer every 15 min. If threshold exceeded, appends to
SECURITY_LOG.md and to _report_Mau (batch).
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import psycopg2

DB_DSN = os.environ.get(
    "SG_DB_DSN",
    "host=/var/run/postgresql dbname=vektrun user=vektrun_user",
)
SECURITY_LOG = Path("/var/www/vaults/V0_MSN/_MD/SECURITY_LOG.md")
THRESHOLD = int(os.environ.get("SG_BYPASS_THRESHOLD", "5"))


_SELECT_HOT = """
    SELECT
        COALESCE(source_id, 'unknown') AS src,
        reason,
        count(*) AS attempts
    FROM security_gateway.blocked_attempts
    WHERE ts >= NOW() - INTERVAL '1 hour'
    GROUP BY 1, 2
    HAVING count(*) >= %s
    ORDER BY attempts DESC
"""


def run():
    with psycopg2.connect(DB_DSN) as conn, conn.cursor() as cur:
        cur.execute(_SELECT_HOT, (THRESHOLD,))
        hot = cur.fetchall()

    if not hot:
        return {"alerts": 0}

    ts = datetime.now(timezone.utc).isoformat()
    lines = [f"\n## 🔴 [{ts}] VKF Beacon · Bypass attempts detected"]
    for src, reason, attempts in hot:
        lines.append(f"- source=`{src}` reason=`{reason}` attempts={attempts} (last 1h)")

    lines.append("Recommended: review `security_gateway.blocked_attempts` for source pattern; consider block via consumer whitelist rules.")

    try:
        with SECURITY_LOG.open("a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except Exception as e:
        print(f"WARN: SECURITY_LOG write failed: {e}", file=sys.stderr)

    return {"alerts": len(hot), "hot_sources": [(s, r, a) for s, r, a in hot]}


if __name__ == "__main__":
    import json
    print(json.dumps(run()))
