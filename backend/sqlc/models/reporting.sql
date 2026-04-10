-- name: CreateEvidence :one
INSERT INTO evidence (flow_id, subtask_id, type, tool_name, command, content, toolcall_id, screenshot_id, termlog_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: GetFlowEvidence :many
SELECT * FROM evidence
WHERE flow_id = $1
ORDER BY created_at ASC;

-- name: GetSubtaskEvidence :many
SELECT * FROM evidence
WHERE subtask_id = $1
ORDER BY created_at ASC;

-- name: CreateFinding :one
INSERT INTO findings (flow_id, subtask_id, vuln_type, title, description, severity, endpoint, fingerprint, owasp_ref, cwe, cvss_base, remediation, confirmed, false_positive, root_cause_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
RETURNING *;

-- name: GetFindingByFingerprint :one
SELECT * FROM findings
WHERE fingerprint = $1 AND flow_id = $2
LIMIT 1;

-- name: GetFlowFindings :many
SELECT * FROM findings
WHERE flow_id = $1 AND false_positive = FALSE
ORDER BY
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        WHEN 'info' THEN 5
    END ASC,
    created_at ASC;

-- name: GetFlowFindingsBySeverity :many
SELECT * FROM findings
WHERE flow_id = $1 AND severity = $2 AND false_positive = FALSE
ORDER BY created_at ASC;

-- name: UpdateFindingConfirmed :exec
UPDATE findings SET confirmed = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $1;

-- name: UpdateFindingFalsePositive :exec
UPDATE findings SET false_positive = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $1;

-- name: UpdateFindingSeverity :exec
UPDATE findings SET severity = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $1;

-- name: GetFlowFindingCount :one
SELECT COUNT(*) FROM findings WHERE flow_id = $1 AND false_positive = FALSE;

-- name: CreateFindingEvidence :one
INSERT INTO finding_evidence (finding_id, evidence_id)
VALUES ($1, $2)
RETURNING *;

-- name: GetFindingEvidence :many
SELECT e.* FROM evidence e
JOIN finding_evidence fe ON fe.evidence_id = e.id
WHERE fe.finding_id = $1
ORDER BY e.created_at ASC;

-- name: CreateReport :one
INSERT INTO reports (flow_id, title, format, status, content, finding_count, metadata)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetFlowReports :many
SELECT * FROM reports
WHERE flow_id = $1
ORDER BY created_at DESC;

-- name: UpdateReportStatus :exec
UPDATE reports SET status = $2, content = $3, finding_count = $4, updated_at = CURRENT_TIMESTAMP WHERE id = $1;

-- name: UpdateFlowMetadata :exec
UPDATE flows SET metadata = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $1;

-- name: GetFlowMetadata :one
SELECT metadata FROM flows WHERE id = $1;
