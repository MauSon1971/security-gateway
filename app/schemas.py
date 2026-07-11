"""Pydantic schemas."""
from __future__ import annotations

from typing import Literal
from pydantic import BaseModel, Field


CheckResult = Literal["pass", "fail"]


class ScanTextRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=64_000)
    source_id: str = Field(..., min_length=1, max_length=256)


class ScanChecks(BaseModel):
    injection: CheckResult


class ScanTextResponse(BaseModel):
    risk_score: float
    checks: ScanChecks
    seal_hmac: str | None = None
    seal_ttl_hours: int | None = None
    reason: str | None = None


class ScanAttachmentResponse(BaseModel):
    malware_scan: CheckResult
    engine: str
    seal_hmac: str | None = None
    seal_ttl_hours: int | None = None
    reason: str | None = None


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    clamav: bool
    version: str
