-- Spectr OSINT Domain Reconnaissance — PostgreSQL schema
-- Run: psql -U <user> -d <db> -f db/schema.sql

CREATE TABLE IF NOT EXISTS scans (
    id          BIGSERIAL PRIMARY KEY,
    domain      TEXT        NOT NULL,
    module      TEXT        NOT NULL CHECK (module IN ('whois', 'dns', 'subdomains', 'headers', 'full')),
    success     BOOLEAN     NOT NULL DEFAULT TRUE,
    result      JSONB       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scans_domain     ON scans (domain);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_module     ON scans (module);
CREATE INDEX IF NOT EXISTS idx_scans_result_gin ON scans USING GIN (result);
