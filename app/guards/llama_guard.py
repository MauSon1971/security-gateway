"""Capa 3.5 · LlamaGuard 3 (Ollama local) — cableado en 861 (#851 A).

Hasta 0.3.x este fichero existía y NADIE lo importaba. Ahora el portero lo llama
en `scan-text` y sobre el texto de cada adjunto, en uno de tres modos
(`SG_LLAMAGUARD_MODE`):

    off       no se llama. /health y el veredicto lo dicen («apagado»).
    sombra    (por defecto) se llama en segundo plano, DESPUÉS de responder: no
              añade latencia ni cambia el veredicto; el resultado queda en el log
              y en métricas para medir su tasa de falsos positivos antes de
              dejarle bloquear. La respuesta dice `en_sombra`.
    bloquear  se llama dentro de la petición; `unsafe` en una categoría que no
              esté en `SG_LLAMAGUARD_NO_BLOQUEA` → `checks.content_safety=fail`.

🔴 Por qué `sombra` y no `bloquear` de entrada — medido el 15-nov-2026 en el VPS
(llama-guard3:1b Q8_0, CPU, Ollama 0.30.6): 4–27 s por llamada en caliente y
**3 de 3 correos de negocio en español marcados `unsafe` (S1/S2)**. Bloqueando,
habría mandado a cuarentena el correo del notario. Ver CHANGELOG 0.4.0.

Si Ollama no contesta o el modelo no está: estado `no_disponible`, el veredicto
lo dice y NO rompe (es una capa añadida; la que decide sigue siendo PromptGuard).

Categorías: S1 Violent Crimes · S2 Non-Violent Crimes · S3 Sex Crimes · S4 Child
Exploitation · S5 Defamation · S6 Specialized Advice · S7 Privacy · S8 IP ·
S9 Indiscriminate Weapons · S10 Hate · S11 Self-harm · S12 Sexual · S13 Elections ·
S14 Code Interpreter Abuse
"""
from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import dataclass, field

import requests

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
MODEL = os.environ.get("SG_LLAMAGUARD_MODEL", "llama-guard3:1b")
TIMEOUT = int(os.environ.get("SG_LLAMAGUARD_TIMEOUT", "30"))

log = logging.getLogger("llama_guard")

MODES = ("off", "sombra", "bloquear")


@dataclass
class GuardVerdict:
    safe: bool
    categories: list[str]   # e.g. ["S7", "S10"]
    raw: str
    error: str | None = None
    chunks: int = 0
    latency_ms: float = 0.0


@dataclass
class LlamaGuardClient:
    url: str = OLLAMA_URL
    model: str = MODEL
    timeout_s: int = TIMEOUT
    mode: str = "sombra"
    keep_alive: str = "5m"
    chunk_chars: int = 6_000
    max_chunks: int = 4
    no_bloquea: frozenset[str] = frozenset({"S6"})
    cache_s: float = 30.0
    _cache: tuple[float, dict] | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.mode not in MODES:
            log.warning("llamaguard_mode_desconocido:%s → sombra", self.mode)
            self.mode = "sombra"

    # ---------------- estado ----------------
    def status(self, fresh: bool = False) -> dict:
        now = time.monotonic()
        if not fresh and self._cache and now - self._cache[0] < self.cache_s:
            return self._cache[1]
        st: dict = {"modo": self.mode, "modelo": self.model, "url": self.url}
        if self.mode == "off":
            st["estado"] = "apagado"
        else:
            try:
                r = requests.get(f"{self.url}/api/tags", timeout=3)
                r.raise_for_status()
                names = [m.get("name", "") for m in r.json().get("models", [])]
                if self.model in names or any(n.split(":")[0] == self.model for n in names):
                    st["estado"] = "disponible"
                    try:
                        ps = requests.get(f"{self.url}/api/ps", timeout=3).json().get("models", [])
                        cargado = next((m for m in ps if m.get("name") == self.model), None)
                        st["cargado_en_ram"] = bool(cargado)
                        if cargado:
                            st["ram_mb"] = round(int(cargado.get("size", 0)) / 1_048_576)
                    except Exception:  # noqa: BLE001
                        pass
                else:
                    st["estado"] = "no_disponible"
                    st["error"] = "modelo_no_descargado"
            except Exception as e:  # noqa: BLE001
                st["estado"] = "no_disponible"
                st["error"] = f"ollama:{type(e).__name__}"
        self._cache = (now, st)
        return st

    @property
    def available(self) -> bool:
        return self.status().get("estado") == "disponible"

    # ---------------- clasificar ----------------
    def _chunks(self, text: str) -> tuple[list[str], bool]:
        n = max(500, self.chunk_chars)
        parts = [text[i:i + n] for i in range(0, len(text), n)] or [""]
        if self.max_chunks and len(parts) > self.max_chunks:
            half = max(1, self.max_chunks // 2)
            return parts[:half] + parts[-(self.max_chunks - half):], True
        return parts, False

    def classify(self, text: str) -> GuardVerdict:
        """Fail-open en error (safe=True, error puesto): quien llama lo marca `no_disponible`."""
        if not text or not text.strip():
            return GuardVerdict(safe=True, categories=[], raw="")
        parts, partial = self._chunks(text)
        cats: list[str] = []
        raws: list[str] = []
        t0 = time.perf_counter()
        for part in parts:
            payload = {
                "model": self.model,
                "messages": [{"role": "user", "content": part}],
                "stream": False,
                "keep_alive": self.keep_alive,
                "options": {"temperature": 0.0, "num_predict": 20, "num_ctx": 4096},
            }
            try:
                r = requests.post(f"{self.url}/api/chat", json=payload, timeout=self.timeout_s)
                r.raise_for_status()
                raw = ((r.json().get("message") or {}).get("content") or "").strip()
            except Exception as e:  # noqa: BLE001
                log.warning("llamaguard_unavailable: %s", type(e).__name__)
                return GuardVerdict(safe=True, categories=[], raw="", error=f"{type(e).__name__}",
                                    chunks=len(raws), latency_ms=round((time.perf_counter() - t0) * 1000, 1))
            raws.append(raw)
            if not raw.lower().startswith("safe"):
                for m in re.findall(r"S\d+", raw.upper()):
                    if m not in cats:
                        cats.append(m)
                if not cats:
                    cats.append("S?")
        v = GuardVerdict(safe=not cats, categories=cats, raw=" | ".join(raws)[:200],
                         chunks=len(parts), latency_ms=round((time.perf_counter() - t0) * 1000, 1))
        if partial:
            v.error = "parcial"
        return v

    def blocking_categories(self, v: GuardVerdict) -> list[str]:
        return [c for c in v.categories if c not in self.no_bloquea]


# ---- compat 0.3.x (funciones de módulo) ----
_default = LlamaGuardClient(mode="bloquear")


def is_available() -> bool:
    return _default.status(fresh=True).get("estado") == "disponible"


def classify(text: str) -> GuardVerdict:
    return _default.classify(text)
