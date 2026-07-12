"""Brain Admission · Batch report parser.

Reads `_report_Mau/YYMMDD_admision_brain.md` files, parses checkboxes marked
by Mauri, applies the decisions via POST /admission/reprocess, and leaves a
processed-file audit trail.

Runs on a systemd timer (every 15 min). Idempotent: files that have already
been fully processed get renamed with `.processed` suffix.
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
from datetime import date
from pathlib import Path

import requests

REPORT_DIR = Path(os.environ.get(
    "SG_REPORT_DIR",
    "/var/www/vaults/V0_MSN/_REPORTS/_report_Mau",
))
GATEWAY_URL = os.environ.get("SG_GATEWAY_URL", "http://127.0.0.1:8850")
ACTOR = os.environ.get("SG_ADMISSION_ACTOR", "mauri")
TIMEOUT = 10

log = logging.getLogger("admission_report_parser")


# Match: `- [x] admitir → curl ... id=NNN...`
# We tolerate spaces, unicode arrows, and multiple decisions per message block.
_CHECKED_RE = re.compile(
    r"^\s*-\s*\[[xX]\]\s+(admitir|descartar|_TO_REVIEW|review)\s*(?:→|->|=>|:)+"
    r".*?[?&]id=(\d+).*?[?&]decision=(admit|reject|review)",
    re.MULTILINE,
)

# Fallback: match checkbox + id + decision keyword (in case URL format changes)
_FALLBACK_CHECKED_RE = re.compile(
    r"^\s*-\s*\[[xX]\]\s+(admitir|descartar|_TO_REVIEW|review)\b.*?id=(\d+)",
    re.MULTILINE,
)


_LABEL_TO_DECISION = {
    "admitir": "admit",
    "descartar": "reject",
    "_TO_REVIEW": "review",
    "review": "review",
}


def _decisions_in_file(md_path: Path) -> list[tuple[int, str]]:
    """Return list of (message_id, decision) checked by the user."""
    text = md_path.read_text(encoding="utf-8")
    out: list[tuple[int, str]] = []
    seen: set[tuple[int, str]] = set()

    for m in _CHECKED_RE.finditer(text):
        label, msg_id, decision = m.group(1), int(m.group(2)), m.group(3)
        key = (msg_id, decision)
        if key not in seen:
            seen.add(key)
            out.append(key)

    if not out:
        # Try fallback (label-based)
        for m in _FALLBACK_CHECKED_RE.finditer(text):
            label, msg_id = m.group(1), int(m.group(2))
            decision = _LABEL_TO_DECISION.get(label)
            if not decision:
                continue
            key = (msg_id, decision)
            if key not in seen:
                seen.add(key)
                out.append(key)

    return out


def _apply(msg_id: int, decision: str) -> dict:
    r = requests.post(
        f"{GATEWAY_URL}/admission/reprocess",
        params={"id": msg_id, "decision": decision, "by": ACTOR},
        timeout=TIMEOUT,
    )
    if r.status_code == 404:
        return {"id": msg_id, "decision": decision, "result": "not_found"}
    r.raise_for_status()
    return r.json() | {"result": "applied"}


def run() -> dict:
    processed_files = 0
    total_applied = 0
    total_errors = 0
    total_checkboxes = 0

    if not REPORT_DIR.is_dir():
        log.warning("report_dir_missing: %s", REPORT_DIR)
        return {"processed_files": 0, "applied": 0, "errors": 0}

    for md in sorted(REPORT_DIR.glob("*_admision_brain.md")):
        if md.name.endswith(".processed.md") or md.stat().st_size < 100:
            continue

        decisions = _decisions_in_file(md)
        if not decisions:
            log.info("no_checkboxes_in %s", md.name)
            continue

        total_checkboxes += len(decisions)
        applied_in_file = []
        for msg_id, decision in decisions:
            try:
                res = _apply(msg_id, decision)
                applied_in_file.append(res)
                total_applied += 1
                log.info("applied id=%s decision=%s result=%s", msg_id, decision, res.get("result"))
            except Exception as e:
                total_errors += 1
                log.exception("apply_failed id=%s decision=%s: %s", msg_id, decision, e)

        # Append audit trail block at end of the .md
        audit_block = [
            "",
            "---",
            f"## Aplicado por parser · {len(applied_in_file)} decisiones",
            "",
        ]
        for r in applied_in_file:
            audit_block.append(f"- id={r.get('id')} decision={r.get('decision', '-')} result={r.get('result', '-')}")

        with md.open("a", encoding="utf-8") as f:
            f.write("\n".join(audit_block) + "\n")

        # Rename file to prevent re-processing (unless someone edits again)
        # We use `.processed.md` so the report is still readable in Obsidian.
        new_name = md.with_suffix(".processed.md")
        md.rename(new_name)
        processed_files += 1

    return {
        "processed_files": processed_files,
        "checkboxes_seen": total_checkboxes,
        "applied": total_applied,
        "errors": total_errors,
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    r = run()
    print(json.dumps(r))
    sys.exit(0 if r["errors"] == 0 else 1)
