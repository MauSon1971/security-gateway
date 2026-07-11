# Security Gateway · CHANGELOG

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
