"""Pydantic schemas."""
from __future__ import annotations

from typing import Any, Literal
from pydantic import BaseModel, Field


CheckResult = Literal["pass", "fail"]


class ScanTextRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=64_000)
    source_id: str = Field(..., min_length=1, max_length=256)


class ScanChecks(BaseModel):
    injection: CheckResult


class ScanTextResponse(BaseModel):
    risk_score: float
    # 🔴 Sólo "pass"/"fail" como valores: cortex-comms (`servicios/gateway.py`) lee
    # cada valor y levanta si no lo entiende. Lo que no es veredicto va en `capas`.
    checks: dict[str, CheckResult]
    seal_hmac: str | None = None
    seal_ttl_hours: int | None = None
    reason: str | None = None
    consumer: str | None = None
    capas: dict[str, Any] = Field(default_factory=dict)


class ScanAttachmentResponse(BaseModel):
    # Compat: consumidores 0.3.x sólo miran `malware_scan`. Desde 0.4.0 es el
    # VEREDICTO GLOBAL del adjunto (malware + tipo + inyección): una macro o un
    # ejecutable dan "fail" aquí aunque ClamAV dijera "clean".
    malware_scan: CheckResult
    engine: str
    seal_hmac: str | None = None
    seal_ttl_hours: int | None = None
    reason: str | None = None
    verdict: CheckResult = "pass"
    quarantine: bool = False
    checks: dict[str, CheckResult] = Field(default_factory=dict)
    findings: list[dict[str, str]] = Field(default_factory=list)
    consumer: str | None = None
    capas: dict[str, Any] = Field(default_factory=dict)


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    clamav: bool          # 861: el demonio contestó PONG, no «el binario existe»
    version: str
    componentes: dict[str, Any] = Field(default_factory=dict)
