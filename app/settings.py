"""Configuration for Security Gateway.

Loads from env with sane defaults. NEVER logs secrets.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from . import __version__


def _flag(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None or not v.strip():
        return default
    return v.strip().lower() in ("1", "true", "yes", "si", "sí", "on")


def _read_key_file(path: str) -> bytes:
    p = Path(path)
    if not p.exists():
        raise RuntimeError(f"HMAC key file missing: {path}")
    data = p.read_text().strip()
    if len(data) < 32:
        raise RuntimeError("HMAC key too short (need >=32 hex chars)")
    return data.encode("utf-8")


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    version: str
    hmac_key_path: str
    hmac_key: bytes
    model_cache_dir: str
    prompt_guard_model: str
    seal_ttl_hours: int
    log_path: str
    clamdscan_bin: str
    hf_token_env: str | None
    # ---- 861 ----
    clamd_socket: str = "/var/run/clamav/clamd.ctl"
    clamd_max_db_age_hours: float = 72.0
    require_clamav: bool = True
    max_attachment_bytes: int = 25 * 1024 * 1024
    pdftotext_bin: str = "pdftotext"
    attachment_text_max_chars: int = 200_000
    pg_max_windows: int = 8
    pg_batch_size: int = 2
    torch_threads: int = 0
    consumers_file: str = "/etc/security-gateway/consumers.tokens"
    auth_mode: str = "transicion"
    auth_transition_until: str | None = None
    llamaguard_mode: str = "sombra"
    llamaguard_url: str = "http://127.0.0.1:11434"
    llamaguard_model: str = "llama-guard3:1b"
    llamaguard_timeout_s: int = 30
    llamaguard_keep_alive: str = "5m"
    llamaguard_max_chunks: int = 4
    llamaguard_no_bloquea: str = "S6"

    @classmethod
    def load(cls) -> "Settings":
        hmac_key_path = os.getenv("SG_HMAC_KEY_PATH", "/etc/security-gateway/hmac.key")
        return cls(
            host=os.getenv("SG_HOST", "127.0.0.1"),
            port=int(os.getenv("SG_PORT", "8850")),
            # La versión es la del CÓDIGO: un SG_VERSION viejo en .env mentía (/health
            # decía 0.1.0 con 0.3.0 desplegado).
            version=__version__,
            hmac_key_path=hmac_key_path,
            hmac_key=_read_key_file(hmac_key_path),
            model_cache_dir=os.getenv(
                "SG_MODEL_CACHE_DIR", "/var/lib/security-gateway/models"
            ),
            prompt_guard_model=os.getenv(
                "SG_PROMPT_GUARD_MODEL", "meta-llama/Llama-Prompt-Guard-2-86M"
            ),
            seal_ttl_hours=int(os.getenv("SG_SEAL_TTL_HOURS", "24")),
            log_path=os.getenv(
                "SG_LOG_PATH", "/var/log/security-gateway/gateway.log"
            ),
            clamdscan_bin=os.getenv("SG_CLAMDSCAN_BIN", "clamdscan"),
            hf_token_env=os.getenv("HF_TOKEN") or None,
            clamd_socket=os.getenv("SG_CLAMD_SOCKET", "/var/run/clamav/clamd.ctl"),
            clamd_max_db_age_hours=float(os.getenv("SG_CLAMD_MAX_DB_AGE_HOURS", "72")),
            require_clamav=_flag("SG_REQUIRE_CLAMAV", True),
            max_attachment_bytes=int(os.getenv("SG_MAX_ATTACHMENT_BYTES", str(25 * 1024 * 1024))),
            pdftotext_bin=os.getenv("SG_PDFTOTEXT_BIN", "pdftotext"),
            attachment_text_max_chars=int(os.getenv("SG_ATTACHMENT_TEXT_MAX_CHARS", "200000")),
            pg_max_windows=int(os.getenv("SG_PG_MAX_WINDOWS", "8")),
            pg_batch_size=int(os.getenv("SG_PG_BATCH_SIZE", "2")),
            torch_threads=int(os.getenv("SG_TORCH_THREADS", "0")),
            consumers_file=os.getenv("SG_CONSUMERS_FILE", "/etc/security-gateway/consumers.tokens"),
            auth_mode=os.getenv("SG_AUTH_MODE", "transicion").strip().lower(),
            auth_transition_until=os.getenv("SG_AUTH_TRANSITION_UNTIL") or None,
            llamaguard_mode=os.getenv("SG_LLAMAGUARD_MODE", "sombra").strip().lower(),
            llamaguard_url=os.getenv("OLLAMA_URL", "http://127.0.0.1:11434"),
            llamaguard_model=os.getenv("SG_LLAMAGUARD_MODEL", "llama-guard3:1b"),
            llamaguard_timeout_s=int(os.getenv("SG_LLAMAGUARD_TIMEOUT", "30")),
            llamaguard_keep_alive=os.getenv("SG_LLAMAGUARD_KEEP_ALIVE", "5m"),
            llamaguard_max_chunks=int(os.getenv("SG_LLAMAGUARD_MAX_CHUNKS", "4")),
            llamaguard_no_bloquea=os.getenv("SG_LLAMAGUARD_NO_BLOQUEA", "S6"),
        )
