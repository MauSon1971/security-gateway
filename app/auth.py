"""Credencial de consumidor para las rutas de escaneo (861).

Hasta 0.3.x `scan-text` y `scan-attachment` no pedían nada: cualquier proceso del
VPS obtenía un sello HMAC válido 24 h (FIERRITUS lo comprobó el 15-nov-2026).

## Cómo
- Cada consumidor tiene un **token de servicio** propio. El portero NO guarda el
  token: guarda su **sha256** en `SG_CONSUMERS_FILE`
  (`/etc/security-gateway/consumers.tokens`, root:securitus 0640), una línea por
  consumidor:   `<nombre> <sha256hex>`   (`#` comenta).
  El fichero se relee solo cuando cambia (mtime): alta/baja sin reiniciar.
- El consumidor manda el token en `X-SG-Token: <token>` (o
  `Authorization: Bearer <token>`). Lo lee de SU fichero de secretos (0400, su
  usuario), nunca de la línea de órdenes.
- Comparación en tiempo constante. El token nunca se registra; el log lleva el
  NOMBRE del consumidor (`consumer=`) — eso es «quién escanea».

## Transición (`SG_AUTH_MODE`)
- `transicion` (por defecto): sin token se atiende igual, pero queda registrado
  como `consumer=anonimo`, se cuenta en `/health` y en métricas, y la respuesta
  lleva `X-SG-Auth: transicion`. Con `SG_AUTH_TRANSITION_UNTIL=AAAA-MM-DD`,
  pasada esa fecha (UTC) se comporta como `exigir` sin tocar nada.
- `exigir`: sin token válido → 401.
- Un token PRESENTE pero desconocido es 401 siempre, también en transición: quien
  manda una credencial mala no es un consumidor sin migrar.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import threading
from dataclasses import dataclass, field
from datetime import date, datetime, timezone

from fastapi import HTTPException, Request, status

log = logging.getLogger("security_gateway.auth")

MODES = ("transicion", "exigir")
ANON = "anonimo"


@dataclass(frozen=True)
class Consumer:
    name: str
    authenticated: bool
    auth: str        # "token" | "transicion"


def hash_token(token: str) -> str:
    return hashlib.sha256(token.strip().encode("utf-8")).hexdigest()


@dataclass
class ConsumerRegistry:
    path: str
    mode: str = "transicion"
    transition_until: date | None = None
    _hashes: dict[str, str] = field(default_factory=dict, repr=False)   # sha256 → nombre
    _mtime: float | None = field(default=None, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    seen: dict[str, str] = field(default_factory=dict)                 # nombre → último ISO
    counts: dict[str, int] = field(default_factory=dict)
    load_error: str | None = None

    def __post_init__(self) -> None:
        if self.mode not in MODES:
            log.warning("auth_mode_desconocido:%s → exigir", self.mode)
            self.mode = "exigir"          # ante la duda, cerrado
        self._reload(force=True)

    # ---------------- fichero ----------------
    def _reload(self, force: bool = False) -> None:
        try:
            mt = os.stat(self.path).st_mtime
        except FileNotFoundError:
            if force or self._hashes:
                self._hashes, self._mtime = {}, None
                self.load_error = "fichero_no_existe"
            return
        except OSError as e:
            self.load_error = f"no_se_lee:{type(e).__name__}"
            return
        if not force and mt == self._mtime:
            return
        hashes: dict[str, str] = {}
        try:
            with open(self.path, encoding="utf-8") as fh:
                for n, line in enumerate(fh, 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) != 2 or len(parts[1]) != 64:
                        log.warning("consumers_linea_invalida", extra={"event": "consumers_linea_invalida",
                                                                       "reason": f"linea {n}"})
                        continue
                    hashes[parts[1].lower()] = parts[0]
        except OSError as e:
            self.load_error = f"no_se_lee:{type(e).__name__}"
            return
        with self._lock:
            self._hashes, self._mtime, self.load_error = hashes, mt, None

    # ---------------- política ----------------
    def effective_mode(self, today: date | None = None) -> str:
        if self.mode == "transicion" and self.transition_until:
            today = today or datetime.now(timezone.utc).date()
            if today > self.transition_until:
                return "exigir"
        return self.mode

    def lookup(self, token: str | None) -> str | None:
        if not token:
            return None
        self._reload()
        h = hash_token(token)
        with self._lock:
            for known, name in self._hashes.items():
                if hmac.compare_digest(known, h):
                    return name
        return None

    def identify(self, token: str | None) -> Consumer:
        if token:
            name = self.lookup(token)
            if name is None:
                self._note("token_invalido")
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "consumer_token_invalido")
            self._note(name)
            return Consumer(name, True, "token")
        if self.effective_mode() == "exigir":
            self._note("sin_token_rechazado")
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "consumer_token_requerido")
        self._note(ANON)
        return Consumer(ANON, False, "transicion")

    def _note(self, name: str) -> None:
        self.seen[name] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.counts[name] = self.counts.get(name, 0) + 1

    def status(self) -> dict:
        self._reload()
        return {
            "modo": self.mode,
            "modo_efectivo": self.effective_mode(),
            "transicion_hasta": self.transition_until.isoformat() if self.transition_until else None,
            "consumidores_registrados": len(self._hashes),
            "fichero": self.path,
            "error": self.load_error,
            "vistos": dict(self.seen),
            "peticiones": dict(self.counts),
        }


def token_from_request(request: Request) -> str | None:
    tok = request.headers.get("x-sg-token")
    if tok:
        return tok.strip() or None
    authz = request.headers.get("authorization") or ""
    if authz.lower().startswith("bearer "):
        return authz.split(" ", 1)[1].strip() or None
    return None


def parse_until(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value.strip())
    except ValueError:
        log.warning("auth_until_invalido:%s", value)
        return None
