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
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

import psycopg2
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from . import __version__
from .settings import Settings
from .security import sign_seal
from .schemas import (
    HealthResponse,
    ScanAttachmentResponse,
    ScanTextRequest,
    ScanTextResponse,
)
from .auth import ConsumerRegistry, Consumer, parse_until, token_from_request
from .guards.clamd import ClamdProbe
from .guards.filetype import extraer_texto, inspeccionar
from .guards.llama_guard import LlamaGuardClient
from .guards.prompt_injection import PromptInjectionGuard
from .guards.heuristic_prescan import HeuristicPrescan
from .guards.dlp import scan_dlp
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from .guards.malware import MalwareGuard, categoria_firma
from .rbac import require_role


# ------- Logging (JSON stdout + rotating file) -------
class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:  # type: ignore[override]
        obj: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "event": getattr(record, "event", record.getMessage()),
        }
        for attr in ("source_id", "action", "risk_score", "check", "reason",
                     "consumer", "auth", "prescan_matched", "windows", "latency_ms"):
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




# ============================================================
# Prometheus metrics (VKF Beacon observability)
# ============================================================
_METRIC_SCAN_TEXT = Counter(
    "vkf_gateway_scan_text_total",
    "Total scan-text requests",
    ["verdict", "capa"],
)
_METRIC_SCAN_ATTACHMENT = Counter(
    "vkf_gateway_scan_attachment_total",
    "Total scan-attachment requests",
    ["verdict"],
)
_METRIC_DLP_HITS = Counter(
    "vkf_gateway_dlp_hits_total",
    "DLP hits by kind",
    ["kind"],
)
_METRIC_SCAN_DURATION = Histogram(
    "vkf_gateway_scan_duration_seconds",
    "Scan duration histogram",
    ["endpoint"],
    buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)
_METRIC_CONSUMER = Counter(
    "vkf_gateway_consumer_requests_total",
    "Scan requests by consumer and auth path (861)",
    ["consumer", "auth", "endpoint"],
)
_METRIC_LLAMAGUARD = Counter(
    "vkf_gateway_llamaguard_total",
    "LlamaGuard verdicts by mode (861)",
    ["mode", "result"],
)
_METRIC_ATTACHMENT_FINDING = Counter(
    "vkf_gateway_attachment_findings_total",
    "Attachment findings by category (861)",
    ["categoria"],
)
_METRIC_ADMISSION = Counter(
    "vkf_admission_decisions_total",
    "Admission decisions",
    ["status"],
)

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

    if settings.torch_threads:
        try:
            import torch
            torch.set_num_threads(settings.torch_threads)
        except Exception:  # pragma: no cover
            pass

    _state.update(build_components(settings))
    _state["prompt_guard"] = guard
    clamd = _state["clamd"].status(fresh=True)
    log.info(
        "ready",
        extra={
            "event": "ready",
            "action": "gateway_ready",
            "reason": (f"model_loaded={guard.loaded} clamd={clamd.estado} "
                       f"llamaguard={_state['llamaguard'].mode} auth={_state['consumers'].effective_mode()}"),
        },
    )
    yield
    _BG.shutdown(wait=False, cancel_futures=True)
    log.info("shutdown", extra={"event": "shutdown"})


def build_components(settings: Settings) -> dict[str, Any]:
    """Todo menos el modelo (que tarda): separado para que los tests lo usen."""
    return {
        "settings": settings,
        "prescan": HeuristicPrescan(),
        "malware": MalwareGuard(clamdscan_bin=settings.clamdscan_bin,
                                require_clamav=settings.require_clamav),
        "clamd": ClamdProbe(settings.clamd_socket,
                            max_db_age_hours=settings.clamd_max_db_age_hours),
        "llamaguard": LlamaGuardClient(
            url=settings.llamaguard_url,
            model=settings.llamaguard_model,
            timeout_s=settings.llamaguard_timeout_s,
            mode=settings.llamaguard_mode,
            keep_alive=settings.llamaguard_keep_alive,
            max_chunks=settings.llamaguard_max_chunks,
            no_bloquea=frozenset(c.strip().upper() for c in settings.llamaguard_no_bloquea.split(",") if c.strip()),
        ),
        "consumers": ConsumerRegistry(
            settings.consumers_file,
            mode=settings.auth_mode,
            transition_until=parse_until(settings.auth_transition_until),
        ),
    }


# LlamaGuard en sombra: un hilo, cola acotada. Si se llena se descarta y se cuenta
# (en sombra no decide nada; no se le deja acumular RAM ni CPU).
_BG = ThreadPoolExecutor(max_workers=1, thread_name_prefix="llamaguard-sombra")
_BG_PENDING = threading.BoundedSemaphore(int(os.environ.get("SG_LLAMAGUARD_SOMBRA_COLA", "16")))


def _rate_key(request: Request) -> str:
    """Límite por CONSUMIDOR (861), no por IP: todo llega de 127.0.0.1 y un
    consumidor con atasco dejaba sin cupo a los demás (17-oct, 429 en COMMS)."""
    reg: ConsumerRegistry | None = _state.get("consumers")
    tok = token_from_request(request)
    if reg is not None and tok:
        name = reg.lookup(tok)
        if name:
            return f"consumer:{name}"
    return get_remote_address(request)


limiter = Limiter(key_func=_rate_key)

app = FastAPI(
    title="VKF Guard · Security Gateway",
    description=(
        "Vektrun Forge · Multi-layer gateway for prompt injection, "
        "malware, DLP and admission control. Internal API — RBAC protected."
    ),
    version=__version__,
    lifespan=lifespan,
    docs_url=None,       # served explicitly under /admin/docs with RBAC
    redoc_url=None,
    openapi_url="/openapi.json",  # kept open for contract tests + Prometheus scrape context
)
app.openapi_version = "3.0.3"  # schemathesis 3.x compat


app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# OpenTelemetry tracing → Jaeger (127.0.0.1:4317)
try:
    from .otel import init_tracing
    init_tracing(app)
except Exception:  # pragma: no cover
    logging.getLogger(__name__).exception("OTel init failed; continuing without tracing")


@app.middleware("http")
async def add_version_header(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Gateway-Version"] = __version__
    return response


# ------- Endpoints -------
@app.get(
    "/admin/docs",
    include_in_schema=False,
    dependencies=[Depends(require_role("vkf-viewer", "vkf-auditor", "vkf-admin"))],
)
async def swagger_ui():
    from fastapi.openapi.docs import get_swagger_ui_html
    return get_swagger_ui_html(openapi_url="/openapi.json", title="VKF Guard · API docs")


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Estado REAL de cada componente (861). Nada de «el binario existe»."""
    guard: PromptInjectionGuard | None = _state.get("prompt_guard")
    clamd: ClamdProbe | None = _state.get("clamd")
    lg: LlamaGuardClient | None = _state.get("llamaguard")
    reg: ConsumerRegistry | None = _state.get("consumers")
    settings: Settings | None = _state.get("settings")

    cst = await run_in_threadpool(clamd.status) if clamd else None
    lst = await run_in_threadpool(lg.status) if lg else {"estado": "no_configurado"}
    pg_ok = bool(guard and guard.loaded)
    componentes: dict[str, Any] = {
        "promptguard": {
            "estado": "ok" if pg_ok else "no_cargado",
            "modelo": getattr(guard, "model_name", None),
            "error": None if pg_ok else (getattr(guard, "load_error", None) or "sin_modelo"),
            "siempre": True,
            "max_ventanas": settings.pg_max_windows if settings else None,
        },
        "clamav": cst.as_dict() if cst else {"estado": "no_configurado", "vivo": False},
        "llamaguard": lst,
        "auth": reg.status() if reg else {"modo": "no_configurado"},
    }
    clam_ok = bool(cst and cst.vivo)
    return HealthResponse(
        status="ok" if (pg_ok and clam_ok) else "degraded",
        model_loaded=pg_ok,
        clamav=clam_ok,
        version=__version__,
        componentes=componentes,
    )


async def scan_consumer(request: Request, response: Response) -> Consumer:
    """Dependencia de las rutas de escaneo: quién pide el sello (861)."""
    reg: ConsumerRegistry | None = _state.get("consumers")
    if reg is None:
        raise HTTPException(status_code=503, detail="auth_not_ready")
    consumer = reg.identify(token_from_request(request))
    if not consumer.authenticated:
        response.headers["X-SG-Auth"] = "transicion"
    _METRIC_CONSUMER.labels(consumer=consumer.name, auth=consumer.auth,
                            endpoint=request.url.path).inc()
    return consumer


def _classify(guard: PromptInjectionGuard, text: str, max_windows: int, batch: int) -> dict:
    return guard.score_full(text, max_windows=max_windows, batch_size=batch)


def _llamaguard_layer(lg: LlamaGuardClient | None, text: str, source_id: str,
                      consumer: str) -> tuple[dict, str | None]:
    """→ (capa para la respuesta, veredicto 'pass'|'fail'|None si no decide)."""
    if lg is None:
        return {"estado": "no_configurado"}, None
    if lg.mode == "off":
        return {"estado": "apagado", "modo": "off"}, None
    if lg.mode == "sombra":
        if not _BG_PENDING.acquire(blocking=False):
            _METRIC_LLAMAGUARD.labels(mode="sombra", result="descartado_cola_llena").inc()
            return {"estado": "descartado_cola_llena", "modo": "sombra"}, None

        def _run() -> None:
            try:
                v = lg.classify(text)
                res = "error" if v.error and v.error != "parcial" else ("safe" if v.safe else "unsafe")
                _METRIC_LLAMAGUARD.labels(mode="sombra", result=res).inc()
                log.info("llamaguard_sombra", extra={
                    "event": "llamaguard_sombra", "source_id": source_id, "consumer": consumer,
                    "action": res, "reason": ",".join(v.categories) or v.error or "",
                    "latency_ms": v.latency_ms})
            finally:
                _BG_PENDING.release()

        _BG.submit(_run)
        return {"estado": "en_sombra", "modo": "sombra",
                "nota": "no decide; resultado en el log (llamaguard_sombra)"}, None
    # bloquear
    if not lg.available:
        _METRIC_LLAMAGUARD.labels(mode="bloquear", result="no_disponible").inc()
        return {"estado": "no_disponible", "modo": "bloquear", **{k: v for k, v in lg.status().items()
                                                                  if k == "error"}}, None
    v = lg.classify(text)
    if v.error and v.error != "parcial":
        _METRIC_LLAMAGUARD.labels(mode="bloquear", result="no_disponible").inc()
        return {"estado": "no_disponible", "modo": "bloquear", "error": v.error}, None
    blocking = lg.blocking_categories(v)
    _METRIC_LLAMAGUARD.labels(mode="bloquear", result="unsafe" if blocking else "safe").inc()
    capa = {"estado": "evaluado", "modo": "bloquear", "categorias": v.categories,
            "bloquean": blocking, "trozos": v.chunks, "latencia_ms": v.latency_ms,
            "parcial": v.error == "parcial"}
    return capa, ("fail" if blocking else "pass")


@app.post("/gateway/scan-text", response_model=ScanTextResponse)
@limiter.limit("60/minute")
async def scan_text(
    request: Request,
    req: ScanTextRequest,
    consumer: Consumer = Depends(scan_consumer),
) -> ScanTextResponse:
    guard: PromptInjectionGuard = _state.get("prompt_guard")
    prescan: HeuristicPrescan = _state.get("prescan")
    settings: Settings = _state["settings"]

    if guard is None or not guard.loaded:
        raise HTTPException(status_code=503, detail="model_not_loaded")

    # ---- Capa 0: regex EN+ES. Desde 0.4.0 (#851 A) ya NO decide si se llama al
    # clasificador: sólo se registra. El clasificador corre SIEMPRE.
    has_signal, matched = prescan.has_injection_signal(req.text) if prescan else (False, [])

    # ---- Capa 3: clasificador sobre todo el texto (ventanas) ----
    try:
        cls = await run_in_threadpool(_classify, guard, req.text,
                                      settings.pg_max_windows, settings.pg_batch_size)
    except Exception as e:
        log.exception("scan_text_error", extra={"event": "scan_text_error"})
        raise HTTPException(status_code=500, detail=f"scan_error:{type(e).__name__}") from e
    risk_score, verdict = float(cls["risk_score"]), cls["verdict"]

    # ---- Capa 3.5: LlamaGuard ----
    lg_capa, lg_verdict = await run_in_threadpool(
        _llamaguard_layer, _state.get("llamaguard"), req.text, req.source_id, consumer.name)

    # ---- Capa 4: DLP ----
    dlp_risk, dlp_hits = scan_dlp(req.text)
    for _h in dlp_hits:
        _METRIC_DLP_HITS.labels(kind=_h.get("kind", "unknown")).inc()

    checks: dict[str, str] = {"injection": verdict}
    if lg_verdict is not None:
        checks["content_safety"] = lg_verdict
    overall = "pass" if all(v == "pass" for v in checks.values()) else "fail"
    _METRIC_SCAN_TEXT.labels(verdict=overall, capa="ml").inc()

    seal = ttl = reason = None
    if overall == "pass":
        passed = ["injection_prescan", "injection", "dlp"]
        if lg_verdict == "pass":
            passed.append("content_safety")
        seal, _claims = sign_seal(
            key=settings.hmac_key,
            source_id=req.source_id,
            checks_passed=passed,
            risk_score=min(1.0, risk_score + dlp_risk),
            ttl_hours=settings.seal_ttl_hours,
            issued_to=consumer.name,
        )
        ttl = settings.seal_ttl_hours
    elif verdict == "fail":
        reason = "prompt_injection_detected"
    else:
        reason = "content_safety_unsafe"

    log.info(
        "scan_text",
        extra={
            "event": "scan_text",
            "source_id": req.source_id,
            "consumer": consumer.name,
            "auth": consumer.auth,
            "action": overall,
            "risk_score": round(risk_score, 4),
            "check": "injection",
            "prescan_matched": ",".join(matched),
            "windows": f"{cls['windows']}/{cls.get('windows_total', cls['windows'])}",
        },
    )
    return ScanTextResponse(
        risk_score=round(risk_score, 6),
        checks=checks,
        seal_hmac=seal,
        seal_ttl_hours=ttl,
        reason=reason,
        consumer=consumer.name,
        capas={
            "prescan": {"senal": bool(has_signal), "patrones": matched},
            "clasificador": {
                "ventanas": cls["windows"],
                "ventanas_total": cls.get("windows_total", cls["windows"]),
                "cobertura": cls.get("coverage", 1.0),
                "parcial": bool(cls.get("truncated")),
            },
            "llamaguard": lg_capa,
            "dlp": {"riesgo": dlp_risk, "hallazgos": len(dlp_hits)},
        },
    )


def _scan_attachment_sync(data: bytes, filename: str, source_id: str,
                          consumer: Consumer) -> ScanAttachmentResponse:
    malware: MalwareGuard = _state["malware"]
    settings: Settings = _state["settings"]
    guard: PromptInjectionGuard | None = _state.get("prompt_guard")
    findings: list[dict[str, str]] = []
    checks: dict[str, str] = {}
    capas: dict[str, Any] = {"tamano": len(data), "nombre": filename}

    # 0 · tamaño: por encima de MaxFileSize, clamd NO mira y contesta «OK».
    if len(data) > settings.max_attachment_bytes:
        findings.append({"categoria": "no_inspeccionable",
                         "detalle": f"demasiado_grande:{len(data)}>{settings.max_attachment_bytes}"})
        checks["malware"] = "fail"
    else:
        # 1 · ClamAV (con OLE2BlockMacros yes, la macro llega aquí como firma)
        mv, mreason = malware.scan_bytes(data, Path(filename).suffix)
        checks["malware"] = mv
        capas["clamav"] = mreason
        if mv == "fail":
            cat = categoria_firma(mreason.split(":", 1)[1]) if mreason.startswith("clamav:") else (
                "motor" if mreason.startswith(("clamav_error", "clamdscan_", "clamav_no_")) else "malware")
            findings.append({"categoria": cat, "detalle": mreason})

    # 2 · detección propia por tipo
    tipo = inspeccionar(data, filename)
    checks["tipo"] = "fail" if tipo else "pass"
    findings.extend(h.as_dict() for h in tipo)

    # 3 · el texto del adjunto también pasa por el clasificador (#851 A)
    text, metodo = (None, "omitido_por_hallazgos")
    if not findings:
        text, metodo = extraer_texto(data, filename, settings.pdftotext_bin,
                                     max_chars=settings.attachment_text_max_chars)
    capa_txt: dict[str, Any] = {"extraccion": metodo}
    if text and text.strip():
        if guard is None or not guard.loaded:
            findings.append({"categoria": "motor", "detalle": "clasificador_no_cargado"})
            checks["injection"] = "fail"
        else:
            cls = _classify(guard, text, settings.pg_max_windows, settings.pg_batch_size)
            checks["injection"] = cls["verdict"]
            capa_txt.update({"caracteres": len(text), "riesgo": round(float(cls["risk_score"]), 6),
                             "ventanas": cls["windows"], "ventanas_total": cls.get("windows_total"),
                             "parcial": bool(cls.get("truncated"))})
            if cls["verdict"] == "fail":
                findings.append({"categoria": "inyeccion",
                                 "detalle": f"clasificador:{round(float(cls['risk_score']), 3)}"})
        lg_capa, lg_verdict = _llamaguard_layer(_state.get("llamaguard"), text, source_id, consumer.name)
        capas["llamaguard"] = lg_capa
        if lg_verdict is not None:
            checks["content_safety"] = lg_verdict
            if lg_verdict == "fail":
                findings.append({"categoria": "contenido",
                                 "detalle": "llamaguard:" + ",".join(lg_capa.get("bloquean", []))})
    capas["texto"] = capa_txt

    for f in findings:
        _METRIC_ATTACHMENT_FINDING.labels(categoria=f["categoria"]).inc()
    verdict = "fail" if findings else "pass"
    seal = ttl = None
    if verdict == "pass":
        passed = ["malware", "file_type"] + (["injection"] if "injection" in checks else []) + (
            ["content_safety"] if checks.get("content_safety") == "pass" else [])
        seal, _claims = sign_seal(
            key=settings.hmac_key,
            source_id=source_id,
            checks_passed=passed,
            risk_score=float(capa_txt.get("riesgo", 0.0)),
            ttl_hours=settings.seal_ttl_hours,
            issued_to=consumer.name,
        )
        ttl = settings.seal_ttl_hours
    reason = None
    if findings:
        reason = f"{findings[0]['categoria']}:{findings[0]['detalle']}"
    return ScanAttachmentResponse(
        malware_scan=verdict,
        engine=malware.engine,
        seal_hmac=seal,
        seal_ttl_hours=ttl,
        reason=reason,
        verdict=verdict,
        quarantine=verdict == "fail",
        checks=checks,
        findings=findings,
        consumer=consumer.name,
        capas=capas,
    )


@app.post("/gateway/scan-attachment", response_model=ScanAttachmentResponse)
@limiter.limit("30/minute")
async def scan_attachment(
    request: Request,
    file: UploadFile = File(...),
    source_id: str = Form(...),
    consumer: Consumer = Depends(scan_consumer),
) -> ScanAttachmentResponse:
    """Malware + tipo + texto. Cualquier hallazgo → `fail` + `quarantine: true`.

    Se lee en memoria (tope `SG_MAX_ATTACHMENT_BYTES` + 1): ya no hay fichero
    temporal en disco que limpiar.
    """
    settings: Settings = _state["settings"]
    data = await file.read(settings.max_attachment_bytes + 1)
    filename = file.filename or "upload"
    res = await run_in_threadpool(_scan_attachment_sync, data, filename, source_id, consumer)
    _METRIC_SCAN_ATTACHMENT.labels(verdict=res.verdict).inc()
    log.info(
        "scan_attachment",
        extra={
            "event": "scan_attachment",
            "source_id": source_id,
            "consumer": consumer.name,
            "auth": consumer.auth,
            "action": res.verdict,
            "check": ",".join(f"{k}={v}" for k, v in res.checks.items()),
            "reason": res.reason,
        },
    )
    return res


# ============================================================
# Admission Control endpoints
# ============================================================

def _get_db_dsn() -> str:
    return os.environ.get(
        "SG_DB_DSN",
        "host=/var/run/postgresql dbname=vektrun user=vektrun_user",
    )


@app.get(
    "/admission/quarantined",
    dependencies=[Depends(require_role("vkf-viewer", "vkf-auditor", "vkf-admin"))],
)
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


@app.post(
    "/admission/reprocess",
    dependencies=[Depends(require_role("vkf-admin"))],
)
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


@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint (VKF Beacon)."""
    from fastapi.responses import Response
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

