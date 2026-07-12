"""VKF · Pydantic schemas for agent HANDOFFs.

Formal contract between agents.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator


class Priority(str, Enum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"


class TaskState(str, Enum):
    pending = "pending"
    claimed = "claimed"
    in_progress = "in_progress"
    blocked = "blocked"
    completed = "completed"
    failed = "failed"
    expired = "expired"
    cancelled = "cancelled"


VALID_TRANSITIONS = {
    TaskState.pending: {TaskState.claimed, TaskState.cancelled, TaskState.expired},
    TaskState.claimed: {TaskState.in_progress, TaskState.blocked, TaskState.cancelled, TaskState.expired},
    TaskState.in_progress: {TaskState.blocked, TaskState.completed, TaskState.failed, TaskState.cancelled},
    TaskState.blocked: {TaskState.in_progress, TaskState.cancelled, TaskState.expired},
    TaskState.completed: set(),
    TaskState.failed: {TaskState.pending},
    TaskState.expired: {TaskState.pending},
    TaskState.cancelled: set(),
}


class HandoffMessage(BaseModel):
    """Contract for an agent-to-agent HANDOFF."""
    ts: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    from_agent: str = Field(..., min_length=1, max_length=50)
    to_agent: str = Field(..., min_length=1, max_length=50)
    type: str = Field(..., pattern=r"^(delegate|report|question|answer|notify|escalate)$")
    task_id: str = Field(..., min_length=1, max_length=100)
    priority: Priority = Priority.P2
    title: str = Field(..., min_length=1, max_length=500)
    payload: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str | None = None
    expires_at: datetime | None = None
    reply_to: str | None = None

    @model_validator(mode="after")
    def _auto_idempotency(self):
        if self.idempotency_key is None:
            seed = f"{self.ts.isoformat()}:{self.from_agent}:{self.to_agent}:{self.task_id}"
            self.idempotency_key = hashlib.sha256(seed.encode()).hexdigest()[:32]
        return self

    def to_jsonl(self) -> str:
        return self.model_dump_json(exclude_none=True)


def can_transition(from_state: TaskState, to_state: TaskState) -> bool:
    if from_state == to_state:
        return False
    return to_state in VALID_TRANSITIONS.get(from_state, set())


def enforce_transition(from_state: str, to_state: str) -> None:
    try:
        fs = TaskState(from_state)
        ts_ = TaskState(to_state)
    except ValueError as e:
        raise ValueError(f"unknown state: {e}") from e
    if not can_transition(fs, ts_):
        raise ValueError(f"invalid transition: {from_state} → {to_state}")
