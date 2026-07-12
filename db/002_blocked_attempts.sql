-- VKF Bypass Detection · schema for blocked_attempts + alert trigger.
--
-- Any scan-text that gets flagged (injection or malware) counts as an "attempt".
-- If a given source_id or source_channel accumulates >5 attempts / hour → SECURITY_LOG.md alert.

CREATE TABLE IF NOT EXISTS security_gateway.blocked_attempts (
    id BIGSERIAL PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_id TEXT,
    source_channel TEXT,
    reason TEXT NOT NULL,       -- 'injection' | 'malware' | 'dlp_over_threshold'
    risk_score NUMERIC(4,3),
    pattern_matched TEXT[],     -- Capa 0 matched patterns if applicable
    metadata JSONB DEFAULT '{}'::JSONB
);

CREATE INDEX IF NOT EXISTS idx_ba_ts ON security_gateway.blocked_attempts (ts DESC);
CREATE INDEX IF NOT EXISTS idx_ba_source ON security_gateway.blocked_attempts (source_id, source_channel);
CREATE INDEX IF NOT EXISTS idx_ba_reason ON security_gateway.blocked_attempts (reason, ts DESC);

GRANT SELECT, INSERT ON security_gateway.blocked_attempts TO vektrun_user;
GRANT USAGE, SELECT ON SEQUENCE security_gateway.blocked_attempts_id_seq TO vektrun_user;

-- View: recent hourly aggregates per source
CREATE OR REPLACE VIEW security_gateway.blocked_attempts_hourly AS
SELECT
    date_trunc('hour', ts) AS hour,
    COALESCE(source_id, 'unknown') AS source_id,
    reason,
    count(*) AS attempts
FROM security_gateway.blocked_attempts
WHERE ts >= NOW() - INTERVAL '24 hours'
GROUP BY 1, 2, 3
ORDER BY hour DESC, attempts DESC;

GRANT SELECT ON security_gateway.blocked_attempts_hourly TO vektrun_user;

-- Migration record
INSERT INTO security_gateway.schema_migrations (version)
VALUES ('002_blocked_attempts')
ON CONFLICT (version) DO NOTHING;
