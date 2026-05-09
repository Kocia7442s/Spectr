-- Spectr OSINT Domain Reconnaissance — PostgreSQL schema
-- Run: psql -U <user> -d <db> -f db/schema.sql
--
-- Migration note: earlier versions of this schema had
--   CHECK (module IN ('whois','dns','subdomains','headers','full'))
-- on the `module` column. That constraint blocks new modules (shodan, etc.).
-- For a database that was loaded with the old schema, run:
--   ALTER TABLE scans DROP CONSTRAINT IF EXISTS scans_module_check;
-- Fresh installs from this file will not have the constraint.

CREATE TABLE IF NOT EXISTS scans (
    id          BIGSERIAL PRIMARY KEY,
    domain      TEXT        NOT NULL,
    module      TEXT        NOT NULL,
    success     BOOLEAN     NOT NULL DEFAULT TRUE,
    result      JSONB       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scans_domain     ON scans (domain);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_module     ON scans (module);
CREATE INDEX IF NOT EXISTS idx_scans_result_gin ON scans USING GIN (result);
