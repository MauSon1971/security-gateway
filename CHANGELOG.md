# Security Gateway · CHANGELOG

## [0.4.1] · 2026-11-16 · 861 · clasificador en sombra (#876 A)

La instalación de 0.4.0 volvió atrás sola: con el modelo real (Meta PG2-86M) y el
clasificador decidiendo siempre, 3 de 5 textos limpios en español dieron `injection: fail`
(0,99999 · 0,9898 · 0,9956) — el canario, un cierre fiscal y una adenda de arras.

### Changed
- `SG_CLASIFICADOR_MODO = sombra | regex | siempre` (por defecto y en el drop-in: `sombra`).
  - `sombra`: el clasificador corre SIEMPRE sobre todo lo que entra (texto y adjuntos) y su
    puntuación se devuelve en `capas.clasificador` (`riesgo`, `veredicto_propio`,
    `revisar`) y se registra en el log (`clasificador_riesgo`, `clasificador_revisar`) y en
    `vkf_gateway_clasificador_revisar_total`. El veredicto sólo es `fail` si el regex ve
    señal y el clasificador la confirma (lo que decidía 0.1.0-0.3.x).
  - `regex`: 0.1.0 tal cual (sin señal no se llama al modelo).
  - `siempre`: 0.4.0 (decide el clasificador).
  - Valor desconocido → `sombra`.
- 🔴 `revisar` va en `capas.clasificador`, NO en `checks`: `checks` sigue siendo sólo
  `pass`/`fail` porque cortex-comms (`servicios/gateway.py`) levanta `GatewayCaido` con
  cualquier otro valor y pararía toda la ingesta.
- `/health` → `componentes.promptguard.modo`.

## [0.4.0] · 2026-11-15 · 861 · portero honesto (#871 A · #851 A)

Huecos medidos por FIERRITUS (`261115_fierritus_flux_espacio.md`) y cerrados aquí.

### Fixed
- **`/health` con dato real.** `clamav` ya no es «el binario existe»: PING al socket de
  `clamd` (`app/guards/clamd.py`); BD de firmas por `VERSION` o, con
  `EnableVersionCommand false` (como está el VPS), por la cabecera de `daily.cld`. BD de más
  de 72 h = `bd_antigua` = no vivo. Nuevo bloque `componentes` con el estado de
  `promptguard`, `clamav`, `llamaguard` y `auth`. `version` es la del código (antes un
  `SG_VERSION` viejo decía 0.1.0).
- **Rutas de escaneo con credencial** (`app/auth.py`). Token de servicio por consumidor en
  `X-SG-Token` (o `Authorization: Bearer`); el portero guarda sólo su sha256 en
  `SG_CONSUMERS_FILE`, relee al cambiar. `SG_AUTH_MODE=transicion|exigir` +
  `SG_AUTH_TRANSITION_UNTIL`. En transición, sin token se atiende, se registra
  `consumer=anonimo`, cabecera `X-SG-Auth: transicion`. Token presente e inválido = 401
  siempre. El sello lleva `issued_to` (sellos sin consumidor, byte a byte como 0.3.x).
  Límite de peticiones por consumidor, no por IP.
- **Clasificador SIEMPRE** (#851 A). El regex ya no decide si se llama al modelo; sólo se
  registra en `capas.prescan`. Y mira el texto ENTERO en ventanas de 512 tokens
  (`score_full`), no sólo los primeros 512: tope `SG_PG_MAX_WINDOWS` (8, cabeza+cola) con
  `capas.clasificador.cobertura`. Inferencia en hilo aparte (antes bloqueaba el bucle de
  eventos: con el modelo lento, `/health` también se colgaba) y una a la vez.
- **LlamaGuard cableado** (#851 A). `SG_LLAMAGUARD_MODE=off|sombra|bloquear`; `/api/chat`
  en vez de `/api/generate` con «User:». Sin Ollama o sin modelo: `no_disponible` en
  `/health` y en `capas.llamaguard`, sin romper. `SG_LLAMAGUARD_NO_BLOQUEA` (S6 por defecto).
- **Adjuntos: macros y tipo** (`app/guards/filetype.py`). Cualquier hallazgo → `verdict:
  fail`, `quarantine: true`, `findings[{categoria, detalle}]`. `Heuristics.OLE2.ContainsMacros`
  (ClamAV con `OLE2BlockMacros yes`) → `macro`. Detección propia: docm/xlsm/pptm…,
  `vbaProject.bin` en OOXML aunque se llame .docx, `_VBA_PROJECT` en OLE2, ejecutables por
  extensión y por firma (PE/ELF/Mach-O/#!) también dentro de zip, zip con contraseña,
  OOXML protegido (`EncryptedPackage`), PDF con `/Encrypt`, rar/7z/zip corrupto = duda.
  Mayor que `SG_MAX_ATTACHMENT_BYTES` (25 MiB) = no inspeccionable (clamd no lo miraría y
  diría OK). El texto del adjunto (txt/OOXML/PDF vía pdftotext) pasa por el clasificador.
  `malware_scan` (compat 0.3.x) es ahora el veredicto global. Sin ClamAV y
  `SG_REQUIRE_CLAMAV=1` → `fail`, nunca el mock por extensión.
- `checks` sólo lleva `"pass"/"fail"` (cortex-comms levanta con cualquier otro valor).
- Tests apuntaban al árbol DESPLEGADO (`sys.path` a `/var/www/security-gateway`): ahora al repo.

### Added
- `tests/test_portero_861.py` (53 tests, sin modelo ni red ni BD). Corpus vivo: docx real,
  docx corrupto, docm, vbaProject disfrazado, ejecutable, `componentes` en `/health`.
- `client/sg_client.auth_headers()`, token en `hooks/comms_ingest.py` y `canary_test.sh`
  (por descriptor, nunca en la línea de órdenes).
- `systemd/security-gateway.service.d/861-portero.conf` (parámetros no secretos).
- Métricas `vkf_gateway_consumer_requests_total`, `vkf_gateway_llamaguard_total`,
  `vkf_gateway_attachment_findings_total`.

### Coste medido (VPS, 15-nov-2026, CPU con PSI 20-50 %, modelo de prueba protectai deberta-v3-base)
- Clasificador siempre: texto corto 0,2-0,3 s · 5 000 car. 6 s · 60 000 car. 16 s (8/37
  ventanas). RSS del proceso 525 → ~930 MB, pico 1,18 GB (prod hoy 588 MB con Meta PG2-86M).
- LlamaGuard 3 1B: +1,8 GB en Ollama, 4-27 s por llamada en caliente, 30 s+ en frío; en
  sombra el clasificador pasa de 0,3 a 2-4 s y de 6 a 35 s. 3/3 correos de negocio ES →
  `unsafe` S1/S2. Se despliega `off`.
- 🔴 protectai da falsos positivos en español (cierre fiscal, arras, «confirmo asistencia»).
  El modelo de producción (Meta PG2-86M, con gate de HF) no se pudo medir desde `neurus`: el
  guion de instalación lo comprueba con el corpus benigno y vuelve atrás si falla.

## [0.3.0] · 2026-07-12 · Sprint D2 · Multi-tenancy + observability + RBAC

### Added
- **Multi-tenancy** (D2.1): `security_gateway.tenants` registry + `tenant_id` FK on `raw_messages`, `vkf_ledger.agent_tasks`, `agent_dlq`, `agent_task_transitions`. Postgres RLS with policy `per_tenant` using `current_setting('vkf.tenant')`. Function `security_gateway.current_tenant()`. Helper `app/db.py` with `connect(tenant_id)` scoping. Default tenant 'msn' backfilled. Migration `db/004_multi_tenancy.sql`.
- **DLQ retry worker** (D2.2): `hooks/dlq_retry_worker.py` + `vkf-dlq-retry.service/timer` (every 5min). Exponential backoff 5min → 30min → 2h → 12h. State machine enforced (failed → pending). NULL task_id drains cleanly.
- **Grafana + Prometheus + Jaeger stack** (D2.3, D2.4): `/var/www/vkf-observability/` compose. Prometheus (host network mode) scraping gateway `/metrics`. 3 dashboards preprovisioned (VKF Overview / Injection Defense / Admission Control). Grafana port 127.0.0.1:3050. Jaeger 127.0.0.1:16686 receiving OTLP gRPC.
- **OpenTelemetry tracing** (D2.4): `app/otel.py` bootstrap. FastAPI + psycopg2 instrumented. Exports to Jaeger. Excluded URLs: /metrics, /health.
- **Keycloak OIDC realm** (D2.5): `/var/www/vkf-keycloak/` compose (Postgres backend). Realm `vkf` with roles vkf-viewer/auditor/admin. Client `vkf-gateway`. Port 127.0.0.1:8180.
- **RBAC granular** (D2.6): `app/rbac.py` with dual auth path — Bearer JWT (Keycloak, JWKS-verified, cached 5min) OR X-Local-Admin-Token header. Applied to `/admission/reprocess` (admin), `/admission/quarantined` (viewer+), `/admin/docs` (viewer+).
- **Contract tests via Schemathesis** (D2.7): `tests/test_contract.py`. Fuzzes every endpoint from /openapi.json, asserts no 5xx. FastAPI forced to OpenAPI 3.0.3 for compat.
- **Load testing baseline** (D2.8): `perf/locustfile.py`. Documented in `docs/PERFORMANCE.md` — p95=11ms scan-text on VPS.
- **Swagger UI RBAC-protected** (D2.9): `/admin/docs` (viewer role or admin token required).
- **Operational runbook** (D2.10): `docs/RUNBOOK.md` with incident playbooks (gateway down, HMAC breach, DB restore, ClamAV down, LlamaGuard down, DLQ explosion, credential rotation, CI failing, bypass alert).

### Changed
- App title/version: 0.1.0 → 0.3.0. Description mentions VKF Guard branding.
- `requirements.txt`: added opentelemetry-* + python-jose[cryptography].
- `requirements-dev.txt` new: pytest, hypothesis, schemathesis, locust.

### Metrics
- Tests: **80 total** (68 pre-D2 + 12 D2: 4 tenancy + 3 dlq + 5 rbac), 2 skipped by design.
- Timers systemd active: **11** (10 pre-D2 + vkf-dlq-retry).
- Containers docker: **10 pre-D2 + 3 obs + 2 keycloak = 15**.
- Score self-eval: 8.0 → **8.5 mid-tier alto** (multi-tenancy schema, observability full, enterprise SSO ready).

# Security Gateway · CHANGELOG

## [0.1.2] · 2026-07-12 · Sprint A · Pipeline end-to-end COMMS_Hub → WALLY

### Added
- `hooks/comms_ingest.py` — API pública `ingest_message(IncomingMessage) -> IngestResult` para que cualquier código externo (email puller, chat webhook, social API) ingeste vía gateway.
- Postgres peer auth mapping `sg_map` para user securitus → vektrun_user vía socket (sin passwords).
- `hooks/admission_worker.py` — 6 reglas auto-admisión (WRK activa, asset, thread, sender whitelist, deadline, wikilink). Cargó reference real: 67 WRK + 6 entidades + 989 contactos.
- `admission_worker.service + .timer` — cada 15min. Aplica reglas + audit log.
- `hooks/admission_batch_report.py` + `admission_report.timer` — 08:00 Europe/Madrid diario. Genera `_report_Mau/YYMMDD_admision_brain.md` con checkboxes decisión Mauri por mensaje quarantined.
- `consumers/wally_consumer_example.py` — patrón consumer: SELECT admitted_messages + verify_seal HMAC en hot path.
- Tests: 6 comms_ingest + 4 admission_worker + 24 corpus + 6 client + 5 hmac + 4 malware = **49 pass, 2 skipped**.
- ACLs vault _report_Mau para escritura desde user securitus.

### Fixed
- `test_comms_ingest` obsoleto \"admission_status == pending\" (worker corre en background timer).
- `admission_worker` v1 usaba columnas inexistentes (`wrk_id`, `deadline`) → v2 usa schema real de `gestiones/assets/entities/contacts/contracts`.

### Pending F1 remaining
- Endpoint `POST /admission/reprocess` — permite parsear checkboxes del report .md y decidir manualmente.
- Migrar WALLY email pipeline actual a consumir desde `admitted_messages` view.

## [0.1.1] · 2026-07-12 · F0+F1 partial · Estable con corpus real

### Added
- Capa 0 heuristic prescan (`app/guards/heuristic_prescan.py`) — 20 regex patterns EN + ES + structural. Auto-pass sin gastar compute ML si no hay señal.
- ClamAV daemon real (F1) integrated via `--stream` (stdin bytes) — universal under PrivateTmp.
- Postgres schema `security_gateway` (v001_init) with tables: `raw_messages`, `audit_log`, `schema_migrations`; views: `admitted_messages`, `quarantined_messages`.
- Client library `client/sg_client.py` — `verify_seal()` for consumers (WALLY, NEURUS, etc.). 6/6 unit tests + integration sign→verify.
- Corpus test suite `tests/test_corpus_real.py` — **24/24 passing**: 7 benignos EN/ES (notario, fiscal, inmobiliaria, factura, arras, meeting, bank), 12 injections (5 EN + 5 ES + 3 estructural: xml/token/template), 3 attachments (EICAR bloqueado + PDF/docx pass), health.

### Changed
- `SG_PROMPT_GUARD_MODEL` default: `meta-llama/Llama-Prompt-Guard-2-86M` → `protectai/deberta-v3-base-prompt-injection-v2` (Apache 2.0, no gate). Meta model queda como fallback opcional via env var.
- HF cache: `HF_HOME=/var/lib/security-gateway/hf_home` (respeta usuario system `securitus` sin home writable).
- Malware scan: `clamdscan --fdpass path` → `clamdscan --stream` (fdpass falla bajo PrivateTmp — stream siempre funciona).

### Fixed
- False positive español business context: emails legítimos de notario/fiscal/inmobiliaria antes puntuaban `risk_score:0.98` → ahora `0.0` via prescan.
- ClamAV `rc=2` (file not visible bajo systemd PrivateTmp) → resuelto con stdin streaming.

### Security
- Bind sigue 127.0.0.1:8850 (nunca público).
- HMAC-SHA256 key rotativa en `/etc/security-gateway/hmac.key` (chmod 600, owner securitus).
- systemd unit hardened: `ProtectSystem=strict`, `NoNewPrivileges`, `PrivateTmp`, `User=securitus`.

### Pending F1 remaining
- Integración COMMS_Hub: hook pre-write que consulta `POST /gateway/scan-text` antes de persistir en `raw_messages`.
- Brain Admission Control worker: aplica las 6 reglas + cuarentena + batch 08:00.
- WALLY email pipeline: cambiar `SELECT raw_messages` → `SELECT admitted_messages`.

## [0.1.0] · 2026-07-11 · F0 skeleton
- FastAPI on 127.0.0.1:8850 + systemd hardened + user securitus.
- HMAC seal (base64url payload + MAC, 24h TTL).
- Endpoints: `/health`, `/gateway/scan-text`, `/gateway/scan-attachment`.
- Guards: `prompt_injection.py` (Llama Prompt-Guard, gated on Meta), `malware.py` (extension-mock fallback).
- Unit tests HMAC + malware mock: 9/9 pass.
