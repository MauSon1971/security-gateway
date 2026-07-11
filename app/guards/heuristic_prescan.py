"""Heuristic pre-scanner for injection patterns (Capa 0).

Regex-based fast pass that runs BEFORE the ML classifier.
Reduces false positives on business text (esp. non-English) by only
invoking the ML model when at least one known injection pattern
matches.

Patterns cover EN + ES. Add languages as the corpus grows.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Pattern:
    name: str
    regex: re.Pattern[str]


_PATTERNS: list[Pattern] = [
    # ---- English: instruction override
    Pattern("ignore_previous_en", re.compile(
        r"\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|the\s+above|earlier)\s+(instructions|directions|rules|prompts?)\b",
        re.IGNORECASE)),
    Pattern("reveal_system_en", re.compile(
        r"\b(reveal|show|print|display|output|leak|expose|dump)\s+(the\s+|your\s+)?(system\s+)?(prompt|instructions|rules|role|password|api[\s_-]*key|secret|token)\b",
        re.IGNORECASE)),
    Pattern("override_rules_en", re.compile(
        r"\b(override|bypass|circumvent|break)\s+(your\s+|the\s+)?(instructions|rules|restrictions|guidelines|safety|guardrails)\b",
        re.IGNORECASE)),
    Pattern("act_as_admin_en", re.compile(
        r"\b(act|behave|respond|answer|reply)\s+as\s+(a\s+|an\s+)?(different|new|another|unrestricted|admin|superuser|root|god|dev(eloper)?\s+mode|malicious|hacker|jailbroken)\b",
        re.IGNORECASE)),
    Pattern("pretend_role_en", re.compile(
        r"\b(pretend|imagine|assume|role[\s_-]?play)\s+(you\s+are|to\s+be|that\s+you\s+are)\b",
        re.IGNORECASE)),
    Pattern("jailbreak_words_en", re.compile(
        r"\b(jailbreak|dan\s+mode|do\s+anything\s+now|god\s+mode|developer\s+mode|unrestricted\s+mode)\b",
        re.IGNORECASE)),
    Pattern("no_restrictions_en", re.compile(
        r"\bwithout\s+(any\s+)?(restrictions|filters|limits|guardrails|censorship|rules)\b",
        re.IGNORECASE)),
    Pattern("role_prefix_en", re.compile(
        r"^\s*(system|assistant|human|user|ai)\s*:\s*(?=\S)",
        re.IGNORECASE | re.MULTILINE)),

    # ---- Spanish: instruction override
    Pattern("olvida_instrucciones_es", re.compile(
        r"\b(olvida|olvide|olvidad|ignora|ignore|descarta|descarte|desecha|omite|omita)\s+(todas\s+)?(las\s+)?(instrucciones|reglas|indicaciones|órdenes|directrices|normas)\s+(anteriores|previas|arriba)\b",
        re.IGNORECASE)),
    Pattern("revela_secreto_es", re.compile(
        r"\b(revela|revele|muestra|muestre|imprime|imprima|dime|dice|filtra|expon|exponme|enseña)\s+(el\s+|tu\s+|la\s+)?(prompt|instrucciones|rol|contraseña|clave|token|secreto|api[\s_-]*key)\b",
        re.IGNORECASE)),
    Pattern("actua_como_es", re.compile(
        r"\b(actúa|actua|comportate|compórtate|responde|contesta)\s+como\s+(un|una)?\s*(otro|otra|diferente|nuevo|nueva|admin|superusuario|dios|desarrollador|hacker|sin\s+restricciones|jailbroken)\b",
        re.IGNORECASE)),
    Pattern("finge_ser_es", re.compile(
        r"\b(finge|imagina|simula|supón|haz\s+de\s+cuenta)\s+(que\s+)?(eres|ser|estar)\b",
        re.IGNORECASE)),
    Pattern("sin_restricciones_es", re.compile(
        r"\bsin\s+(ninguna\s+|ningún\s+)?(restricci[oó]n(es)?|filtros?|l[íi]mites?|censura|reglas|guardarra[íi]les)\b",
        re.IGNORECASE)),
    Pattern("saltea_reglas_es", re.compile(
        r"\b(salta|salt[ae]arse|salt[ae]a|omite|omitir|evita|evadir|evade|burla)\s+(las\s+)?(restricciones|reglas|filtros|instrucciones|censura)\b",
        re.IGNORECASE)),
    Pattern("modo_dan_es", re.compile(
        r"\b(modo\s+dan|modo\s+desarrollador|modo\s+dios|modo\s+sin\s+restricciones|haz\s+cualquier\s+cosa\s+ahora)\b",
        re.IGNORECASE)),
    Pattern("role_prefix_es", re.compile(
        r"^\s*(sistema|asistente|humano|usuario|ia)\s*:\s*(?=\S)",
        re.IGNORECASE | re.MULTILINE)),

    # ---- Structural / special-token injection (language-independent)
    Pattern("special_tokens", re.compile(r"<\|[a-z_]+\|>", re.IGNORECASE)),
    Pattern("xml_instruction", re.compile(
        r"</?\s*(instruction|system|prompt|role|assistant|user|human)\s*>",
        re.IGNORECASE)),
    Pattern("template_injection", re.compile(r"\{\{[^}]+\}\}")),
    Pattern("markdown_hidden_instruction", re.compile(
        r"<!--\s*(system|instruction|prompt)[^>]*-->",
        re.IGNORECASE)),
]


class HeuristicPrescan:
    """Fast regex-based pre-classifier (Capa 0).

    Returns (has_signal, matched_pattern_names).
    If has_signal is False → caller can auto-pass without invoking ML.
    """

    def has_injection_signal(self, text: str) -> tuple[bool, list[str]]:
        if not text or not text.strip():
            return False, []
        matched: list[str] = []
        for p in _PATTERNS:
            if p.regex.search(text):
                matched.append(p.name)
        return (bool(matched), matched)
