"""Configuration for Security Gateway.

Loads from env with sane defaults. NEVER logs secrets.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


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

    @classmethod
    def load(cls) -> "Settings":
        hmac_key_path = os.getenv("SG_HMAC_KEY_PATH", "/etc/security-gateway/hmac.key")
        return cls(
            host=os.getenv("SG_HOST", "127.0.0.1"),
            port=int(os.getenv("SG_PORT", "8850")),
            version=os.getenv("SG_VERSION", "0.1.0"),
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
        )
