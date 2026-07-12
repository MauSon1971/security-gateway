"""FastAPI app for Security Gateway (F0 skeleton).

Bind: 127.0.0.1:8850 (never public).
Endpoints:
    GET  /health
    POST /gateway/scan-text
    POST /gateway/scan-attachment
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse

import psycopg2
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from .settings import Settings
from .security import sign_seal
from .schemas import (
    HealthResponse,
    ScanAttachmentResponse,
    ScanChecks,
    ScanTextRequest,
    ScanTextResponse,
)
from .guards.prompt_injection import PromptInjectionGuard
from .guards.heuristic_prescan import HeuristicPrescan
from .guards.malware import MalwareGuard


# ------- Logging (JSON stdout + rotating file) -------
class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:  # type: ignore[override]
        obj: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "event": getattr(record, "event", record.getMessage()),
        }
        for attr in ("source_id", "action", "risk_score", "check", "reason"):
            if hasattr(record, attr):
                obj[attr] = getattr(record, attr)
        if record.exc_info:
            obj["exc"] = self.formatException(record.exc_info)
        return json.dumps(obj, ensure_ascii=False)


def _setup_logging(log_path: str) -> None:
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    fmt = JsonFormatter()

    stream = logging.StreamHandler()
    stream.setFormatter(fmt)
    root.addHandler(stream)

    try:
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        fileh = logging.FileHandler(log_path)
        fileh.setFormatter(fmt)
        root.addHandler(fileh)
    except PermissionError:
        # Running as unprivileged user without file perms — stdout only
        root.warning(
            "log_file_unavailable", extra={"event": "log_file_permission_denied"}
        )


log = logging.getLogger("security_gateway")


# ------- App lifecycle -------
_state: dict[str, Any] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = Settings.load()
    _setup_logging(settings.log_path)
    log.info("startup", extra={"event": "startup", "action": "loading_model"})

    guard = PromptInjectionGuard(
        model_name=settings.prompt_guard_model,
        cache_dir=settings.model_cache_dir,
        hf_token=settings.hf_token_env,
    )
    try:
        guard.load()
    except Exception as e:
        log.error(
            "model_load_failed",
            extra={"event": "model_load_failed", "reason": str(e)},
        )

    malware = MalwareGuard(clamdscan_bin=settings.clamdscan_bin)

    _state["settings"] = settings
    _state["prescan"] = HeuristicPrescan()
    _state["prompt_guard"] = guard
    _state["malware"] = malware
    log.info(
        "ready",
        extra={
            "event": "ready",
            "action": "gateway_ready",
            "reason": f"model_loaded={guard.loaded} clamav={malware.clamav_available}",
        },
    )
    yield
    log.info("shutdown", extra={"event": "shutdown"})


limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="Security Gateway",
    version="0.1.0",
    lifespan=lifespan,
    docs_url=None,  # keep internal — no public docs
    redoc_url=None,
)


app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.middleware("http")
async def add_version_header(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Gateway-Version"] = _state.get(
        "settings", Settings.load()
    ).version if _state.get("settings") else "0.1.0"
    return response


# ------- Endpoints -------
@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    guard: PromptInjectionGuard = _state.get("prompt_guard")
    malware: MalwareGuard = _state.get("malware")
    settings: Settings = _state.get("settings")
    return HealthResponse(
        status="ok" if guard and guard.loaded else "degraded",
        model_loaded=bool(guard and guard.loaded),
        clamav=bool(malware and malware.clamav_available),
        version=settings.version if settings else "0.1.0",
    )


@app.post("/gateway/scan-text", response_model=ScanTextResponse)
@limiter.limit("60/minute")
async def scan_text(request: Request, req: ScanTextRequest) -> ScanTextResponse:
    guard: PromptInjectionGuard = _state.get("prompt_guard")
    prescan: HeuristicPrescan = _state.get("prescan")
    settings: Settings = _state["settings"]

    if guard is None or not guard.loaded:
        raise HTTPException(status_code=503, detail="model_not_loaded")

    # ---- Capa 0: heuristic prescan (regex EN+ES) ----
    has_signal, matched = prescan.has_injection_signal(req.text) if prescan else (True, [])
    if not has_signal:
        seal, _claims = sign_seal(
            key=settings.hmac_key,
            source_id=req.source_id,
            checks_passed=["injection_prescan"],
            risk_score=0.0,
            ttl_hours=settings.seal_ttl_hours,
        )
        log.info(
            "scan_text_prescan_pass",
            extra={
                "event": "scan_text_prescan_pass",
                "source_id": req.source_id,
                "action": "pass",
                "risk_score": 0.0,
                "check": "injection_prescan",
            },
        )
        return ScanTextResponse(
            risk_score=0.0,
            checks=ScanChecks(injection="pass"),
            seal_hmac=seal,
            seal_ttl_hours=settings.seal_ttl_hours,
            reason=None,
        )

    # ---- Capa 3: ML classifier (only when Capa 0 matched) ----
    try:
        risk_score, verdict = guard.score(req.text)
    except Exception as e:
        log.exception("scan_text_error", extra={"event": "scan_text_error"})
        raise HTTPException(status_code=500, detail=f"scan_error:{e}") from e

    checks = ScanChecks(injection=verdict)
    seal = None
    ttl = None
    reason = None
    if verdict == "pass":
        seal, _claims = sign_seal(
            key=settings.hmac_key,
            source_id=req.source_id,
            checks_passed=["injection_prescan", "injection"],
            risk_score=risk_score,
            ttl_hours=settings.seal_ttl_hours,
        )
        ttl = settings.seal_ttl_hours
    else:
        reason = "prompt_injection_detected"

    log.info(
        "scan_text",
        extra={
            "event": "scan_text",
            "source_id": req.source_id,
            "action": verdict,
            "risk_score": round(risk_score, 4),
            "check": "injection",
            "prescan_matched": ",".join(matched),
        },
    )
    return ScanTextResponse(
        risk_score=round(risk_score, 6),
        checks=checks,
        seal_hmac=seal,
        seal_ttl_hours=ttl,
        reason=reason,
    )


@app.post("/gateway/scan-attachment", response_model=ScanAttachmentResponse)
@limiter.limit("30/minute")
async def scan_attachment(
    request: Request,
    file: UploadFile = File(...),
    source_id: str = Form(...),
) -> ScanAttachmentResponse:
    malware: MalwareGuard = _state["malware"]
    settings: Settings = _state["settings"]

    # Save to a temp file (PrivateTmp=true keeps this per-service)
    suffix = Path(file.filename or "upload").suffix
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        data = await file.read()
        tmp.write(data)
        tmp_path = tmp.name

    try:
        verdict, reason = malware.scan_file(tmp_path)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    seal = None
    ttl = None
    if verdict == "pass":
        seal, _claims = sign_seal(
            key=settings.hmac_key,
            source_id=source_id,
            checks_passed=["malware"],
            risk_score=0.0,
            ttl_hours=settings.seal_ttl_hours,
        )
        ttl = settings.seal_ttl_hours

    log.info(
        "scan_attachment",
        extra={
            "event": "scan_attachment",
            "source_id": source_id,
            "action": verdict,
            "check": "malware",
            "reason": reason,
        },
    )
    return ScanAttachmentResponse(
        malware_scan=verdict,
        engine=malware.engine,
        seal_hmac=seal,
        seal_ttl_hours=ttl,
        reason=reason if verdict == "fail" else None,
    )


# ============================================================
# Admission Control endpoints
# ============================================================

def _get_db_dsn() -> str:
    return os.environ.get(
        "SG_DB_DSN",
        "host=/var/run/postgresql dbname=vektrun user=vektrun_user",
    )


@app.get("/admission/quarantined")
async def list_quarantined(hours: int = 24, limit: int = 100) -> dict:
    """List messages currently in quarantine (pending Mauri decision)."""
    with psycopg2.connect(_get_db_dsn()) as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, external_id, source_type, source_channel,
                   subject, from_addr, received_at,
                   risk_score, checks, admission_rules_matched
            FROM security_gateway.raw_messages
            WHERE admission_status = 'quarantined'
              AND ingested_at >= NOW() - (%s || ' hours')::interval
            ORDER BY received_at DESC
            LIMIT %s
            """,
            (hours, limit),
        )
        rows = cur.fetchall()
    items = [
        {
            "id": r[0], "external_id": r[1], "source_type": r[2], "source_channel": r[3],
            "subject": r[4], "from_addr": r[5], "received_at": r[6].isoformat() if r[6] else None,
            "risk_score": float(r[7]) if r[7] is not None else None,
            "checks": r[8], "admission_rules_matched": r[9],
        }
        for r in rows
    ]
    return {"count": len(items), "hours": hours, "items": items}


@app.post("/admission/reprocess")
async def reprocess(id: int, decision: str, by: str = "mauri") -> dict:
    """Apply a manual decision to a quarantined message.

    decision: 'admit' | 'reject' | 'review'
        admit  → admission_status='admitted' (agents will see it)
        reject → admission_status='rejected' (drop from workflow)
        review → admission_status='review_later' (bump to _TO_REVIEW after TTL)
    """
    dmap = {"admit": "admitted", "reject": "rejected", "review": "review_later"}
    if decision not in dmap:
        raise HTTPException(status_code=400, detail=f"decision must be one of {list(dmap)}")

    new_status = dmap[decision]
    with psycopg2.connect(_get_db_dsn()) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE security_gateway.raw_messages
                SET admission_status = %s,
                    admission_decided_by = %s,
                    admission_decided_at = NOW()
                WHERE id = %s
                RETURNING id, external_id, admission_status
                """,
                (new_status, f"human:{by}", id),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail=f"message_id={id} not found")

            cur.execute(
                "INSERT INTO security_gateway.audit_log (message_id, event, actor, detail) "
                "VALUES (%s, %s, %s, %s::jsonb)",
                (id, f"admission_{decision}", f"human:{by}",
                 '{"decision": "' + decision + '"}'),
            )
            conn.commit()

    log.info(
        "admission_reprocess",
        extra={
            "event": "admission_reprocess",
            "source_id": row[1],
            "action": decision,
        },
    )
    return {"id": row[0], "external_id": row[1], "new_status": row[2], "decision": decision, "by": by}

