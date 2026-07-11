-- Security Gateway · Schema init 001 · 2026-07-12
-- Requires: existing DB 'vektrun' with owner vektrun_user
-- Applied idempotently (IF NOT EXISTS).

CREATE SCHEMA IF NOT EXISTS security_gateway;
GRANT USAGE, CREATE ON SCHEMA security_gateway TO vektrun_user;

-- ============================================================
-- raw_messages · Captura crudo + Gateway sealing + Brain Admission
-- ============================================================
CREATE TABLE IF NOT EXISTS security_gateway.raw_messages (
    id                     BIGSERIAL PRIMARY KEY,

    -- Identidad del mensaje en el sistema origen
    external_id            TEXT NOT NULL,
    source_type            TEXT NOT NULL,   -- 'email' | 'chat' | 'webhook' | 'vault_external' | 'api'
    source_channel         TEXT,            -- 'gmail:admin@powerfans.es' | 'telegram:wally_bot' | ...

    -- Categorización de negocio (llenado post-admission por agente)
    entity_code            TEXT,            -- MAN/TPL/PWF/MSN/KUG/TSC/external
    related_wrk_id         TEXT,            -- WRK_NNNN si aplica
    related_asset_id       TEXT,

    -- Contenido crudo
    subject                TEXT,
    body                   TEXT,
    from_addr              TEXT,
    to_addrs               TEXT[],
    attachments            JSONB DEFAULT '[]'::JSONB,   -- [{name, size, hash_sha256, malware_scan, mime}]
    metadata               JSONB DEFAULT '{}'::JSONB,   -- headers, thread_id, in_reply_to, message_id, ...

    -- Timestamps
    received_at            TIMESTAMPTZ NOT NULL,
    ingested_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- ==== Security Gateway sealing ====
    sealed                 BOOLEAN NOT NULL DEFAULT FALSE,
    seal_hmac              TEXT,
    seal_ttl               TIMESTAMPTZ,
    seal_verified_at       TIMESTAMPTZ,
    checks                 JSONB DEFAULT '{}'::JSONB,   -- {"malware":"pass","injection":"pass","spam":"pass","dlp":"pass"}
    risk_score             NUMERIC(4,3),                -- 0.000 to 1.000
    malware_scan_pass      BOOLEAN,
    seal_error             TEXT,                        -- reason si sealing falló

    -- ==== Brain Admission Control ====
    admission_status       TEXT NOT NULL DEFAULT 'pending',   -- pending | admitted | quarantined | rejected | expired
    admission_rules_matched TEXT[],                            -- reglas auto-admisión que fired
    admission_decided_by   TEXT,                                -- 'auto:rule_name' | 'human:mauri' | 'ttl_expired'
    admission_decided_at   TIMESTAMPTZ,

    UNIQUE(external_id, source_channel)
);

COMMENT ON TABLE security_gateway.raw_messages IS
    'Captura crudo por COMMS_Hub. Gateway sella con HMAC. Agentes leen solo sealed=1 AND admitted.';

-- Indexes
CREATE INDEX IF NOT EXISTS idx_rawmsg_sealed_ttl
    ON security_gateway.raw_messages (sealed, seal_ttl)
    WHERE sealed = TRUE;

CREATE INDEX IF NOT EXISTS idx_rawmsg_admission
    ON security_gateway.raw_messages (admission_status, ingested_at)
    WHERE admission_status IN ('pending', 'quarantined');

CREATE INDEX IF NOT EXISTS idx_rawmsg_source
    ON security_gateway.raw_messages (source_type, source_channel);

CREATE INDEX IF NOT EXISTS idx_rawmsg_entity
    ON security_gateway.raw_messages (entity_code)
    WHERE entity_code IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_rawmsg_received
    ON security_gateway.raw_messages (received_at DESC);

-- ============================================================
-- Vistas para agentes · SOLO leer via estas (nunca raw_messages directo)
-- ============================================================

-- Vista canonical: mensajes sellados + admitidos + baja/media confianza en riesgo
CREATE OR REPLACE VIEW security_gateway.admitted_messages AS
SELECT
    id, external_id, source_type, source_channel,
    entity_code, related_wrk_id, related_asset_id,
    subject, body, from_addr, to_addrs, attachments, metadata,
    received_at, ingested_at,
    seal_hmac, seal_ttl, checks, risk_score,
    admission_status, admission_rules_matched, admission_decided_by, admission_decided_at
FROM security_gateway.raw_messages
WHERE sealed = TRUE
  AND seal_ttl > NOW()
  AND admission_status = 'admitted'
  AND (risk_score IS NULL OR risk_score < 0.5);

COMMENT ON VIEW security_gateway.admitted_messages IS
    'Agentes leen SOLO esta vista. Filtra sealed + admitted + risk_score < 0.5 + TTL vigente.';

-- Vista cuarentena para SECURITUS + Mauri (batch report 08:00)
CREATE OR REPLACE VIEW security_gateway.quarantined_messages AS
SELECT
    id, external_id, source_type, source_channel,
    entity_code,
    subject, from_addr, to_addrs,
    received_at, ingested_at,
    risk_score, checks, seal_error,
    admission_status
FROM security_gateway.raw_messages
WHERE admission_status IN ('pending', 'quarantined')
   OR (sealed = TRUE AND risk_score >= 0.5);

-- ============================================================
-- Audit log · trace decisions Gateway + Admission
-- ============================================================
CREATE TABLE IF NOT EXISTS security_gateway.audit_log (
    id           BIGSERIAL PRIMARY KEY,
    ts           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    message_id   BIGINT REFERENCES security_gateway.raw_messages(id) ON DELETE CASCADE,
    event        TEXT NOT NULL,   -- 'sealed' | 'admitted' | 'quarantined' | 'reprocessed' | 'expired' | 'error'
    actor        TEXT,            -- 'gateway' | 'admission_worker' | 'mauri' | 'securitus'
    detail       JSONB
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON security_gateway.audit_log (ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_msg ON security_gateway.audit_log (message_id);

-- ============================================================
-- Permisos
-- ============================================================
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA security_gateway TO vektrun_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA security_gateway TO vektrun_user;

-- Vistas: solo SELECT
GRANT SELECT ON security_gateway.admitted_messages TO vektrun_user;
GRANT SELECT ON security_gateway.quarantined_messages TO vektrun_user;

-- Migration metadata
CREATE TABLE IF NOT EXISTS security_gateway.schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO security_gateway.schema_migrations (version)
VALUES ('001_init')
ON CONFLICT (version) DO NOTHING;
