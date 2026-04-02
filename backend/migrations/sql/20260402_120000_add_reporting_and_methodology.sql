-- +goose Up
-- +goose StatementBegin

-- ==================== Flow-scoped Metadata ====================
-- Single JSONB column for all flow-scoped state (methodology coverage,
-- exploit state, WAF assessment, etc.) to avoid schema churn.
ALTER TABLE flows ADD COLUMN metadata JSONB NOT NULL DEFAULT '{}';

-- ==================== Evidence Table ====================
-- Stores individual pieces of evidence from tool calls, terminal logs, etc.
CREATE TABLE evidence (
    id              BIGINT        PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    flow_id         BIGINT        NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
    subtask_id      BIGINT        NULL REFERENCES subtasks(id) ON DELETE SET NULL,
    type            TEXT          NOT NULL DEFAULT 'tool_call',
    tool_name       TEXT          NOT NULL DEFAULT '',
    command         TEXT          NOT NULL DEFAULT '',
    content         TEXT          NOT NULL DEFAULT '',
    toolcall_id     BIGINT        NULL REFERENCES toolcalls(id) ON DELETE SET NULL,
    screenshot_id   BIGINT        NULL REFERENCES screenshots(id) ON DELETE SET NULL,
    termlog_id      BIGINT        NULL REFERENCES termlogs(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ   DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMPTZ   DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX evidence_flow_id_idx ON evidence(flow_id);
CREATE INDEX evidence_subtask_id_idx ON evidence(subtask_id);
CREATE INDEX evidence_type_idx ON evidence(type);
CREATE INDEX evidence_toolcall_id_idx ON evidence(toolcall_id);

-- ==================== Finding Severity Enum ====================
CREATE TYPE finding_severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');

-- ==================== Findings Table ====================
-- Stores confirmed or suspected vulnerability findings with deduplication.
CREATE TABLE findings (
    id              BIGINT              PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    flow_id         BIGINT              NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
    subtask_id      BIGINT              NULL REFERENCES subtasks(id) ON DELETE SET NULL,
    vuln_type       TEXT                NOT NULL,
    title           TEXT                NOT NULL,
    description     TEXT                NOT NULL DEFAULT '',
    severity        finding_severity    NOT NULL DEFAULT 'medium',
    endpoint        TEXT                NOT NULL DEFAULT '',
    fingerprint     TEXT                NOT NULL,
    owasp_ref       TEXT                NOT NULL DEFAULT '',
    cwe             TEXT                NOT NULL DEFAULT '',
    cvss_base       DOUBLE PRECISION    NOT NULL DEFAULT 0.0,
    remediation     TEXT                NOT NULL DEFAULT '',
    confirmed       BOOLEAN             NOT NULL DEFAULT FALSE,
    false_positive  BOOLEAN             NOT NULL DEFAULT FALSE,
    root_cause_id   BIGINT              NULL REFERENCES findings(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ         DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMPTZ         DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX findings_flow_id_idx ON findings(flow_id);
CREATE INDEX findings_subtask_id_idx ON findings(subtask_id);
CREATE INDEX findings_vuln_type_idx ON findings(vuln_type);
CREATE INDEX findings_severity_idx ON findings(severity);
CREATE UNIQUE INDEX findings_fingerprint_flow_idx ON findings(fingerprint, flow_id);

-- ==================== Finding-Evidence Junction ====================
-- Links findings to their supporting evidence.
CREATE TABLE finding_evidence (
    id              BIGINT    PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    finding_id      BIGINT    NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    evidence_id     BIGINT    NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX finding_evidence_finding_id_idx ON finding_evidence(finding_id);
CREATE INDEX finding_evidence_evidence_id_idx ON finding_evidence(evidence_id);
CREATE UNIQUE INDEX finding_evidence_unique_idx ON finding_evidence(finding_id, evidence_id);

-- ==================== Report Status Enum ====================
CREATE TYPE report_status AS ENUM ('pending', 'generating', 'completed', 'failed');
CREATE TYPE report_format AS ENUM ('markdown', 'json');

-- ==================== Reports Table ====================
-- Stores generated penetration test reports.
CREATE TABLE reports (
    id              BIGINT          PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    flow_id         BIGINT          NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
    title           TEXT            NOT NULL,
    format          report_format   NOT NULL DEFAULT 'markdown',
    status          report_status   NOT NULL DEFAULT 'pending',
    content         TEXT            NOT NULL DEFAULT '',
    finding_count   INT             NOT NULL DEFAULT 0,
    metadata        JSONB           NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ     DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMPTZ     DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX reports_flow_id_idx ON reports(flow_id);
CREATE INDEX reports_status_idx ON reports(status);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS finding_evidence CASCADE;
DROP TABLE IF EXISTS reports CASCADE;
DROP TABLE IF EXISTS findings CASCADE;
DROP TABLE IF EXISTS evidence CASCADE;

DROP TYPE IF EXISTS report_status;
DROP TYPE IF EXISTS report_format;
DROP TYPE IF EXISTS finding_severity;

ALTER TABLE flows DROP COLUMN IF EXISTS metadata;

-- +goose StatementEnd
