# OWASP LLM Top 10 (2025) · Vektrun Forge Compliance Matrix

Este documento mapea los 10 vectores más críticos identificados por [OWASP Foundation](https://genai.owasp.org) a los controles concretos implementados en Vektrun Forge (VKF).

Última revisión: 2026-07-12 · v0.1.5

| # | Vector OWASP | Riesgo | Control VKF | Estado |
|---|---|---|---|---|
| **LLM01** | Prompt Injection | Manipulación instrucciones vía input externo | Capa 0 heuristic prescan (regex EN+ES) + Capa 3 protectai/deberta ML + LlamaGuard 3-1B | ✅ Producción |
| **LLM02** | Sensitive Information Disclosure | Fuga PII/PCI/secretos | Capa 4 DLP (NIF/NIE/IBAN/Luhn/email/phone) + AGE/SOPS at-rest encryption | ✅ Producción |
| **LLM03** | Supply Chain | Modelos/deps comprometidas | protectai Apache 2.0 (no gate) · SBOM automático (Trivy + Dependabot) | 🟡 Parcial (SBOM Fase 11) |
| **LLM04** | Data & Model Poisoning | Corpus training corrupto | protectai + LlamaGuard entrenados por vendors trusted · sin fine-tune propio | ✅ Diseño |
| **LLM05** | Improper Output Handling | Output LLM ejecuta sin validar | Guardrails AI (Fase futura) · verify_seal HMAC obligatorio en consumers | 🟡 F1 pending |
| **LLM06** | Excessive Agency | Agente actúa fuera scope | NEXUS sandbox (`safe_run` + allowlist paths+exec + verb denylist + `unshare -n`) | ✅ Producción |
| **LLM07** | System Prompt Leakage | Extracción del system prompt | Instruction hierarchy Anthropic + XML tags convención + rate limiting | ✅ Producción |
| **LLM08** | Vector & Embedding Weaknesses | Retrieval poisoning | Brain Admission Control · 6 reglas + cuarentena batch + TTL | ✅ Producción |
| **LLM09** | Misinformation | Alucinaciones agente | Guardrails AI validators por entidad (F2 pending) · human-in-the-loop obligatorio destructivo | 🟡 Parcial |
| **LLM10** | Unbounded Consumption | DoS / cost explosion | Rate limit slowapi (60/min text · 30/min attachment) + Windmill agent_costs meter | 🟡 Cost meter F2 |

## Referencias
- [OWASP GenAI LLM Top 10 (2025)](https://genai.owasp.org/llm-top-10/)
- [OWASP AI Testing Guide](https://genai.owasp.org/ai-testing/)

## Estado summary
- ✅ **Producción · 6/10** — LLM01, LLM02, LLM04, LLM06, LLM07, LLM08
- 🟡 **Parcial · 4/10** — LLM03 (SBOM en Fase 11), LLM05 (Guardrails AI F1), LLM09 (validators F2), LLM10 (cost meter F2)

**Coverage global: 70% completo · 30% en roadmap Q3-2026.**

## Roadmap para 100%
- LLM03 · SBOM automation en `.github/workflows/security.yml` (Fase 11)
- LLM05 · Guardrails AI + `canUseTool` Claude Agent SDK (Sprint E)
- LLM09 · Validators per entity NIF/IBAN/importes (Sprint E)
- LLM10 · agent_costs meter Postgres + budget alerts (post-MS-A2)
