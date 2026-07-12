-- VKF Ledger · Agent contracts state machine + DLQ (Fase 12)
--
-- Provides formal contracts between agents:
--   - agent_tasks: state machine (pending → claimed → in_progress → completed | failed | expired)
--   - agent_dlq:   dead letter queue for retryable failures with backoff

CREATE SCHEMA IF NOT EXISTS vkf_ledger;
GRANT USAGE, CREATE ON SCHEMA vkf_ledger TO vektrun_user;

-- ============================================================
-- agent_tasks · lifecycle formal
-- ============================================================
CREATE TABLE IF NOT EXISTS vkf_ledger.agent_tasks (
    task_id      TEXT PRIMARY KEY,           -- external id (e.g. WRK_0051, TSK-042)
    title        TEXT NOT NULL,
    handoff_json JSONB NOT NULL,             -- Pydantic-validated payload (see hooks/handoff_schema.py)
    from_agent   TEXT NOT NULL,
    to_agent     TEXT NOT NULL,
    priority     TEXT NOT NULL DEFAULT 'P2', -- P0 | P1 | P2 | P3
    state        TEXT NOT NULL DEFAULT 'pending',
                                             -- pending | claimed | in_progress | blocked
                                             -- | completed | failed | expired | cancelled
    idempotency_key TEXT UNIQUE,             -- prevent duplicate submissions
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claimed_at   TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ,                -- if state=pending and NOW() > expires_at → auto-expire
    error        TEXT,
    result_json  JSONB,
    CHECK (priority IN ('P0','P1','P2','P3')),
    CHECK (state IN ('pending','claimed','in_progress','blocked','completed','failed','expired','cancelled'))
);

CREATE INDEX IF NOT EXISTS idx_tasks_state ON vkf_ledger.agent_tasks (state, priority, created_at);
CREATE INDEX IF NOT EXISTS idx_tasks_to_agent ON vkf_ledger.agent_tasks (to_agent, state);
CREATE INDEX IF NOT EXISTS idx_tasks_expires ON vkf_ledger.agent_tasks (expires_at)
    WHERE state IN ('pending','claimed','in_progress','blocked');

-- Transition history for audit
CREATE TABLE IF NOT EXISTS vkf_ledger.agent_task_transitions (
    id         BIGSERIAL PRIMARY KEY,
    task_id    TEXT NOT NULL REFERENCES vkf_ledger.agent_tasks(task_id) ON DELETE CASCADE,
    ts         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    from_state TEXT,
    to_state   TEXT NOT NULL,
    actor      TEXT NOT NULL,                -- who triggered (agent name or 'system')
    detail     JSONB
);

CREATE INDEX IF NOT EXISTS idx_transitions_task ON vkf_ledger.agent_task_transitions (task_id, ts DESC);

-- ============================================================
-- agent_dlq · dead letter queue with retry
-- ============================================================
CREATE TABLE IF NOT EXISTS vkf_ledger.agent_dlq (
    id           BIGSERIAL PRIMARY KEY,
    task_id      TEXT REFERENCES vkf_ledger.agent_tasks(task_id) ON DELETE CASCADE,
    agent        TEXT NOT NULL,
    error        TEXT NOT NULL,
    stack        TEXT,
    retry_count  INTEGER NOT NULL DEFAULT 0,
    next_retry_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    max_retries  INTEGER NOT NULL DEFAULT 4,   -- exponential backoff: 5min, 30min, 2h, 12h
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at  TIMESTAMPTZ,
    metadata     JSONB DEFAULT '{}'::JSONB
);

CREATE INDEX IF NOT EXISTS idx_dlq_pending ON vkf_ledger.agent_dlq (next_retry_at)
    WHERE resolved_at IS NULL AND retry_count < max_retries;

-- ============================================================
-- SLA metrics view
-- ============================================================
CREATE OR REPLACE VIEW vkf_ledger.agent_sla_daily AS
SELECT
    to_agent AS agent,
    date_trunc('day', created_at) AS day,
    count(*) FILTER (WHERE state = 'completed') AS completed,
    count(*) FILTER (WHERE state = 'failed') AS failed,
    count(*) FILTER (WHERE state = 'expired') AS expired,
    count(*) AS total,
    AVG(EXTRACT(EPOCH FROM (completed_at - created_at)))
      FILTER (WHERE state = 'completed') AS avg_duration_seconds
FROM vkf_ledger.agent_tasks
GROUP BY 1, 2
ORDER BY day DESC, agent;

-- ============================================================
-- Grants
-- ============================================================
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA vkf_ledger TO vektrun_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA vkf_ledger TO vektrun_user;
GRANT SELECT ON vkf_ledger.agent_sla_daily TO vektrun_user;

-- ============================================================
-- Migration
-- ============================================================
INSERT INTO security_gateway.schema_migrations (version)
VALUES ('003_vkf_ledger_agent_contracts')
ON CONFLICT (version) DO NOTHING;
