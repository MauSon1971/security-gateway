"""Unit tests for HANDOFF schema + state machine."""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # el repo, no lo desplegado
from hooks.handoff_schema import (
    HandoffMessage,
    Priority,
    TaskState,
    can_transition,
    enforce_transition,
)


def test_handoff_message_basic():
    m = HandoffMessage(
        from_agent="NEURUS",
        to_agent="NEXUS",
        type="delegate",
        task_id="TSK-001",
        title="Deploy new module",
    )
    assert m.priority == Priority.P2
    assert m.idempotency_key is not None
    assert len(m.idempotency_key) == 32


def test_handoff_invalid_type():
    with pytest.raises(Exception):
        HandoffMessage(
            from_agent="NEURUS",
            to_agent="NEXUS",
            type="bogus",  # not in whitelist
            task_id="TSK-002",
            title="x",
        )


def test_handoff_to_jsonl_roundtrip():
    m = HandoffMessage(
        from_agent="WALLY",
        to_agent="LEGALITUS",
        type="question",
        task_id="WRK_0051",
        priority=Priority.P0,
        title="Contract review",
        payload={"doc_url": "..."},
    )
    j = m.to_jsonl()
    assert "WALLY" in j
    assert "LEGALITUS" in j
    assert "\"priority\":\"P0\"" in j


def test_state_transitions_valid():
    assert can_transition(TaskState.pending, TaskState.claimed)
    assert can_transition(TaskState.claimed, TaskState.in_progress)
    assert can_transition(TaskState.in_progress, TaskState.completed)


def test_state_transitions_invalid():
    assert not can_transition(TaskState.pending, TaskState.completed)
    assert not can_transition(TaskState.completed, TaskState.in_progress)
    assert not can_transition(TaskState.cancelled, TaskState.pending)


def test_state_retry_from_failed():
    assert can_transition(TaskState.failed, TaskState.pending)
    assert can_transition(TaskState.expired, TaskState.pending)


def test_enforce_transition_raises():
    with pytest.raises(ValueError, match="invalid transition"):
        enforce_transition("pending", "completed")


def test_enforce_transition_unknown_state():
    with pytest.raises(ValueError, match="unknown state"):
        enforce_transition("nonexistent", "pending")
