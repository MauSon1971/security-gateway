# Vektrun Forge · Security Gateway (VKF Guard)

Part of the **Vektrun Forge** AI Operations Fabric for SMB — the plug-and-play platform where business agents are forged and run safely day-to-day.

Vektrun Forge modules:
- **VKF Guard** (this repo) — Security Gateway: prompt-injection + malware + DLP + HMAC seal
- **VKF Admit** — Brain Admission Control (governance de relevancia)
- **VKF Anvil** — NEXUS sandbox (safe subprocess execution)
- **VKF Bridge** — Consumer adapter (WALLY inbox)
- **VKF Beacon** — Canary + audit + observability
- **VKF Ledger** — HMAC rotation + audit log

---



Filtro de seguridad central del ecosistema Vektrun. Ningún agente accede a input externo sin haber pasado por aquí.

Deploy: VPS `/var/www/security-gateway/` · systemd `security-gateway.service` · bind `127.0.0.1:8850` (nunca público).

## Arquitectura (F0+F1 parcial)

```
              scan-text                              scan-attachment
                   │                                        │
   ┌───────────────▼──────────────────┐    ┌────────────────▼───────────────┐
   │ Capa 0 · Heuristic prescan       │    │ Fast-path: ClamAV --stream     │
   │   regex EN+ES+estructural        │    │   universal bajo PrivateTmp    │
   │   has_signal=False → auto-pass   │    │   EICAR bloqueado, benignos ok │
   └──────────────┬───────────────────┘    └────────────────┬───────────────┘
                  │ signal=True                             │ pass
   ┌──────────────▼───────────────────┐    ┌────────────────▼───────────────┐
   │ Capa 3 · protectai deberta-v3    │    │ HMAC seal (24h TTL)            │
   │   base prompt-injection-v2       │    │   claims: source_id, checks,   │
   │   Apache 2.0, sin gate           │    │   risk_score, sealed_at        │
   └──────────────┬───────────────────┘    └────────────────┬───────────────┘
                  │ verdict                                 │
                  └──────────┬────────────────────────────  ┘
                             ▼
              HMAC-SHA256 seal (base64url.base64url)
```

## Endpoints

- `GET /health` → `{status, model_loaded, clamav, version}`
- `POST /gateway/scan-text` — body `{text, source_id}` → verdict + optional HMAC seal
- `POST /gateway/scan-attachment` — multipart `file` + `source_id` → verdict + optional HMAC seal

## Estado tests

```
tests/test_hmac.py            5/5 pass
tests/test_malware.py         4/4 pass
tests/test_corpus_real.py    24/24 pass · corpus MSN real (EN+ES benignos+injections+attachments)
client/test_sg_client.py      6/6 pass · verify_seal roundtrip
```

## Consumer integration

Los agentes que leen `raw_messages` **DEBEN** verificar el sello antes de procesar:

```python
from sg_client import verify_seal, InvalidSeal, has_check

try:
    claims = verify_seal(
        seal_hmac=msg["seal_hmac"],
        expected_source_id=msg["source_id"],
        key_path="/etc/security-gateway/hmac.key",
    )
except InvalidSeal as e:
    log.warning("seal_invalid", extra={"reason": str(e)})
    return  # Don't process
```

O más simple: consultar la vista `security_gateway.admitted_messages` que ya filtra `sealed=1 AND seal_ttl > NOW() AND risk_score < 0.5 AND admission_status='admitted'`.

## Config

`/etc/security-gateway/.env`:
- `HF_TOKEN` — para descargar modelo desde HuggingFace (rotate.sh)
- `HF_HOME=/var/lib/security-gateway/hf_home`
- `SG_PROMPT_GUARD_MODEL=protectai/deberta-v3-base-prompt-injection-v2` (default; swap a Llama-Prompt-Guard-2-86M cuando Meta apruebe)

`/etc/security-gateway/hmac.key` — HMAC secret hex (chmod 600).

## Ver también

- Arquitectura completa: `[[project-security-gateway-architecture]]` (memoria NEURUS)
- Brain Admission Control: `[[feedback-brain-admission-control]]`
- Master roadmap: `_SADMIN/PROPUESTA_ECOSISTEMA_260711.md`
