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
