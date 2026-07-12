# NIST AI RMF (AI 100-1) · Vektrun Forge Profile

Perfil de alineamiento con [NIST AI Risk Management Framework 1.0](https://www.nist.gov/itl/ai-risk-management-framework) + [Generative AI Profile (AI 600-1)](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence).

Sistema evaluado: **Vektrun Forge (VKF) v0.1.5** — AI operations fabric para SMB.

## Contexto sistema

- **Uso previsto:** filtrar y gobernar comunicaciones + operaciones agénticas de negocio (email, chat, webhooks) en PyMEs.
- **Usuarios:** SuperAdmin humano + agentes autónomos (WALLY, NEURUS, NEXUS, SECURITUS, FISCUS, LEGALITUS).
- **Datos:** emails/documentos con PII/PCI/GDPR-scope.
- **Infra:** self-hosted VPS o on-prem con opción NAS local.

## GOVERN · Cultura + política

| Práctica | Estado | Evidencia |
|---|---|---|
| GV-1.1 · Legal/regulatory obligations documented | 🟡 Parcial | GDPR/PCI mapping in DLP (Capa 4) · Falta DPA por proveedor formal |
| GV-1.2 · AI Risk Management strategy | ✅ | `_SADMIN/PROPUESTA_ECOSISTEMA_260711.md` + threat model |
| GV-2.1 · Roles & responsibilities | ✅ | SECURITUS coordina Gateway · NEXUS ejecuta · NEURUS diseña · Mauri decide P0 |
| GV-3.2 · Accountability structure | ✅ | Triple confirmación destructivo · `_report_Mau/` batch |
| GV-4.1 · Diverse perspectives in team | 🔴 N/A | Solo-founder MSN — mitigación: multi-agente review + AlexandrIa research corpus |
| GV-5.1 · Post-deployment monitoring | ✅ | Canary hourly · admission_worker · audit_log · SECURITY_LOG.md |

## MAP · Contexto + riesgos identificados

| Práctica | Estado | Evidencia |
|---|---|---|
| MP-1.1 · Intended use context defined | ✅ | Sub-productos VKF Guard/Admit/Anvil/Bridge/Beacon/Ledger + `[[project-vektrun-forge-naming]]` |
| MP-2.1 · System capabilities mapped | ✅ | Master doc `PROPUESTA_ECOSISTEMA_260711.md` sección 8 |
| MP-3.1 · AI actors identified | ✅ | 7 agentes definidos + memoria por rol |
| MP-4.1 · Risks catalogued | ✅ | Threat model STRIDE · `THREAT_MODEL.md` |
| MP-5.1 · Impact assessment | 🟡 Parcial | Impact per asset en threat model; falta cuantificar prob |

## MEASURE · Metrics + evaluation

| Práctica | Estado | Evidencia |
|---|---|---|
| MS-1.1 · Metrics defined | 🟡 Parcial | 62 tests + canary hourly · Falta Prometheus /metrics (Fase 9) |
| MS-2.1 · Third-party validation | 🔴 Falta | Sin auditoría externa · plan post-MANNY validated |
| MS-3.1 · Trustworthiness properties assessed | ✅ | Test corpus real MSN 7 benignos ES · falsos positivos 0% |
| MS-4.1 · Adverse effects tracked | ✅ | `_report_Mau/YYMMDD_admision_brain.md` batch |

## MANAGE · Priorización + mitigación

| Práctica | Estado | Evidencia |
|---|---|---|
| MG-1.1 · Risks prioritized | ✅ | Sprint A/B/C matrix P0/P1/P2 |
| MG-2.1 · Response strategies | ✅ | HMAC rotation grace 24h · TTL cuarentena · NEXUS sandbox unshare |
| MG-3.1 · Response mechanisms deployed | ✅ | Canary alert SECURITY_LOG.md · admission_worker · admission_ttl |
| MG-4.1 · Continuous improvement | ✅ | Waves research en AlexandrIa · roadmap 8 semanas |

## AI 600-1 · Generative AI specific

### GAI-002 · Data privacy

- **Control:** Capa 4 DLP redacta hits antes de audit_log
- **Control:** AGE encrypt at-rest para `_CONFIDENTIAL/`
- **Control:** Peer auth Postgres (sin passwords en .env)
- **Gap:** row-level encryption post-Sprint E

### GAI-004 · Data poisoning

- **Control:** protectai/LlamaGuard entrenados por vendors trusted (Apache 2.0 / Llama license)
- **Control:** No fine-tune propio con corpus MSN sin sanitization
- **Gap:** Threat intelligence feed integration futuro

### GAI-005 · Confabulation (hallucinations)

- **Control:** Guardrails AI validators (F1 pending Sprint E)
- **Control:** Human-in-loop para acciones irreversibles (triple confirmación P0)
- **Control:** Verify_seal en cada mensaje admitido (no confía blind)

### GAI-007 · Environmental / cost

- **Control:** Rate limit gateway (60/min text)
- **Control:** LlamaGuard 3-1B CPU (no GPU intensive)
- **Gap:** agent_costs meter Postgres post-Sprint E

## Overall RMF alignment score (self-assessed)

- **GOVERN:** 4/5 (falta solo diverse perspectives — inherente solo-founder)
- **MAP:** 5/5
- **MEASURE:** 3/5 (Prometheus + auditoría externa pending)
- **MANAGE:** 5/5

**Total: 17/20 (85%) · aceptable para SMB con roadmap hacia enterprise.**

## Roadmap para 100%

- **Prometheus /metrics + Grafana dashboards** (Fase 9)
- **Auditoría externa post-cliente #3** (Q4-2026)
- **DPA formal por proveedor** (Anthropic, HF, Meta) — antes de MANNY firma
- **Cost meter agent_costs** (post-MS-A2)
- **Row-level encryption** (Sprint E)
- **Threat intelligence feed** (Sprint F)
