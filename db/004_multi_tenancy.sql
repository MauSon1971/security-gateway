-- VKF Fase D2.1 · Multi-tenancy (tenant_id + RLS + policy)
--
-- Adds tenant_id to raw_messages + agent_tasks + agent_dlq + agent_task_transitions.
-- Enables row-level security so views/queries filter automatically by
-- current_setting('vkf.tenant', true).
--
-- Default tenant 'msn' backfilled to all existing rows (single-tenant → multi-tenant).

BEGIN;

-- ============================================================
-- tenants registry
-- ============================================================
CREATE TABLE IF NOT EXISTS security_gateway.tenants (
    tenant_id     TEXT PRIMARY KEY,
    display_name  TEXT NOT NULL,
    hmac_key_id   TEXT,             -- optional per-tenant HMAC key ref (VKV)
    status        TEXT NOT NULL DEFAULT 'active',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata      JSONB NOT NULL DEFAULT '{}'::JSONB,
    CHECK (status IN ('active','suspended','archived'))
);

INSERT INTO security_gateway.tenants (tenant_id, display_name)
VALUES ('msn', 'MSN (default)')
ON CONFLICT (tenant_id) DO NOTHING;

-- ============================================================
-- raw_messages · tenant_id column + FK + index
-- ============================================================
ALTER TABLE security_gateway.raw_messages
    ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'msn'
    REFERENCES security_gateway.tenants(tenant_id) ON UPDATE CASCADE;

CREATE INDEX IF NOT EXISTS idx_rawmsg_tenant
    ON security_gateway.raw_messages (tenant_id, ingested_at DESC);

-- ============================================================
-- vkf_ledger.agent_tasks · tenant_id
-- ============================================================
ALTER TABLE vkf_ledger.agent_tasks
    ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'msn'
    REFERENCES security_gateway.tenants(tenant_id) ON UPDATE CASCADE;

CREATE INDEX IF NOT EXISTS idx_tasks_tenant
    ON vkf_ledger.agent_tasks (tenant_id, state, created_at);

ALTER TABLE vkf_ledger.agent_task_transitions
    ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'msn';

ALTER TABLE vkf_ledger.agent_dlq
    ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'msn';

-- ============================================================
-- current_tenant() helper
--
-- Returns current session tenant from GUC `vkf.tenant`, or 'msn' as fallback.
-- Use `SET LOCAL vkf.tenant = 'other'` inside a transaction to scope queries.
-- ============================================================
CREATE OR REPLACE FUNCTION security_gateway.current_tenant()
RETURNS TEXT
LANGUAGE sql
STABLE
AS $$
    SELECT COALESCE(current_setting('vkf.tenant', true), 'msn')
$$;

-- ============================================================
-- RLS enable + policy
--
-- Policy `per_tenant` restricts rows visible to the current tenant.
-- Superusers and role BYPASSRLS bypass the check (system tools ok).
-- ============================================================
ALTER TABLE security_gateway.raw_messages ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS per_tenant ON security_gateway.raw_messages;
CREATE POLICY per_tenant ON security_gateway.raw_messages
    USING (tenant_id = security_gateway.current_tenant())
    WITH CHECK (tenant_id = security_gateway.current_tenant());

ALTER TABLE vkf_ledger.agent_tasks ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS per_tenant ON vkf_ledger.agent_tasks;
CREATE POLICY per_tenant ON vkf_ledger.agent_tasks
    USING (tenant_id = security_gateway.current_tenant())
    WITH CHECK (tenant_id = security_gateway.current_tenant());

ALTER TABLE vkf_ledger.agent_dlq ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS per_tenant ON vkf_ledger.agent_dlq;
CREATE POLICY per_tenant ON vkf_ledger.agent_dlq
    USING (tenant_id = security_gateway.current_tenant())
    WITH CHECK (tenant_id = security_gateway.current_tenant());

-- Note: vektrun_user by default does NOT bypass RLS.
-- System workers must SET vkf.tenant explicitly per session/txn.

-- ============================================================
-- View: raw_messages sealed (public API) with tenant filter automatic via RLS
-- ============================================================
CREATE OR REPLACE VIEW security_gateway.raw_messages_sealed AS
SELECT * FROM security_gateway.raw_messages
WHERE sealed = true
  AND seal_ttl > NOW();

-- ============================================================
-- Grants
-- ============================================================
GRANT SELECT, INSERT, UPDATE, DELETE ON security_gateway.tenants TO vektrun_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA security_gateway TO vektrun_user;
GRANT EXECUTE ON FUNCTION security_gateway.current_tenant() TO vektrun_user;
GRANT SELECT ON security_gateway.raw_messages_sealed TO vektrun_user;

-- ============================================================
-- Migration record
-- ============================================================
INSERT INTO security_gateway.schema_migrations (version)
VALUES ('004_multi_tenancy')
ON CONFLICT (version) DO NOTHING;

COMMIT;
