"""Sonda REAL del demonio ClamAV (861).

Hasta 0.3.x `/health` decía `clamav: true` porque `shutil.which("clamdscan")`
encontraba el binario. Con `clamd` caído seguía en verde: un verde sin dato.

Aquí se habla con el socket de `clamd` con su propio protocolo:
    zPING\\0     → "PONG"
    zVERSION\\0  → "ClamAV 1.5.4/28184/Sat Nov 15 06:27:00 2026"
y sólo un PONG cuenta como vivo. La versión trae el número y la fecha de la BD
de firmas: una BD de hace una semana es una avería aunque el demonio conteste.
"""
from __future__ import annotations

import os
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

DEFAULT_SOCKET = "/var/run/clamav/clamd.ctl"
DEFAULT_DB_DIR = "/var/lib/clamav"


def _db_from_disk(db_dir: str) -> tuple[int | None, str | None, float | None]:
    """Cabecera de `daily.cld|cvd`: «ClamAV-VDB:15 Nov 2026 06-27 +0000:28184:…».

    Plan B cuando clamd tiene `EnableVersionCommand false` (así está el VPS el
    15-nov-2026): la BD EN DISCO, que es la que clamd carga en cada recarga.
    """
    for name in ("daily.cld", "daily.cvd"):
        try:
            with open(os.path.join(db_dir, name), "rb") as fh:
                head = fh.read(512).decode("latin-1")
        except OSError:
            continue
        parts = head.split(":")
        if len(parts) < 3 or parts[0] != "ClamAV-VDB":
            continue
        bd = int(parts[2]) if parts[2].isdigit() else None
        fecha = parts[1].strip()
        edad = None
        try:
            dt = datetime.strptime(fecha, "%d %b %Y %H-%M %z")
            edad = round((datetime.now(timezone.utc) - dt).total_seconds() / 3600, 1)
        except ValueError:
            pass
        return bd, fecha, edad
    return None, None, None


@dataclass
class ClamdStatus:
    estado: str                      # "ok" | "caido" | "bd_antigua"
    socket: str
    version: str | None = None       # "1.5.4"
    bd_version: int | None = None    # 28184
    bd_fecha: str | None = None      # texto tal cual lo da clamd
    bd_edad_horas: float | None = None
    bd_origen: str | None = None     # "clamd" | "disco"
    latencia_ms: float | None = None
    error: str | None = None
    comprobado: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    @property
    def vivo(self) -> bool:
        return self.estado == "ok"

    def as_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if v is not None}
        d["vivo"] = self.vivo
        return d


def _cmd(path: str, cmd: bytes, timeout: float) -> str:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(path)
        s.sendall(b"z" + cmd + b"\0")
        chunks: list[bytes] = []
        while True:
            b = s.recv(4096)
            if not b:
                break
            chunks.append(b)
            if b.endswith(b"\0"):
                break
        return b"".join(chunks).rstrip(b"\0").decode("utf-8", errors="replace").strip()
    finally:
        s.close()


def _parse_version(txt: str) -> tuple[str | None, int | None, str | None, float | None]:
    # "ClamAV 1.5.4/28184/Sat Nov 15 06:27:00 2026"
    if not txt.startswith("ClamAV"):
        return None, None, None, None
    parts = txt.split("/", 2)
    ver = parts[0].replace("ClamAV", "").strip() or None
    bd = int(parts[1]) if len(parts) > 1 and parts[1].strip().isdigit() else None
    fecha = parts[2].strip() if len(parts) > 2 else None
    edad = None
    if fecha:
        try:
            dt = datetime.strptime(fecha, "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
            edad = round((datetime.now(timezone.utc) - dt).total_seconds() / 3600, 1)
        except ValueError:
            pass
    return ver, bd, fecha, edad


class ClamdProbe:
    def __init__(self, socket_path: str = DEFAULT_SOCKET, timeout_s: float = 3.0,
                 max_db_age_hours: float = 72.0, cache_s: float = 5.0,
                 db_dir: str = DEFAULT_DB_DIR) -> None:
        self.socket_path = socket_path
        self.db_dir = db_dir
        self.timeout_s = timeout_s
        self.max_db_age_hours = max_db_age_hours
        self.cache_s = cache_s
        self._cache: tuple[float, ClamdStatus] | None = None

    def status(self, fresh: bool = False) -> ClamdStatus:
        now = time.monotonic()
        if not fresh and self._cache and now - self._cache[0] < self.cache_s:
            return self._cache[1]
        st = self._probe()
        self._cache = (now, st)
        return st

    def _probe(self) -> ClamdStatus:
        path = self.socket_path
        if not os.path.exists(path):
            return ClamdStatus("caido", path, error="socket_no_existe")
        t0 = time.perf_counter()
        try:
            pong = _cmd(path, b"PING", self.timeout_s)
        except Exception as e:  # noqa: BLE001 — cualquier fallo de socket es «caído»
            return ClamdStatus("caido", path, error=f"ping:{type(e).__name__}:{e}"[:200])
        lat = round((time.perf_counter() - t0) * 1000, 1)
        if pong != "PONG":
            return ClamdStatus("caido", path, latencia_ms=lat, error=f"ping_respuesta:{pong[:60]!r}")
        try:
            ver_txt = _cmd(path, b"VERSION", self.timeout_s)
        except Exception:  # noqa: BLE001
            ver_txt = ""
        ver, bd, fecha, edad = _parse_version(ver_txt)
        origen = "clamd"
        if bd is None:
            bd, fecha, edad = _db_from_disk(self.db_dir)
            origen = "disco" if bd is not None else None
        estado = "ok"
        err = None
        if edad is not None and edad > self.max_db_age_hours:
            estado, err = "bd_antigua", f"bd_de_hace_{edad}h(max {self.max_db_age_hours}h)"
        return ClamdStatus(estado, path, version=ver, bd_version=bd, bd_fecha=fecha,
                           bd_edad_horas=edad, bd_origen=origen, latencia_ms=lat, error=err)
