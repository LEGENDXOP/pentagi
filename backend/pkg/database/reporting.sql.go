// Manual bindings for reporting.sql queries.
// These should be replaced by `sqlc generate` once the toolchain is available.

package database

import (
	"context"
	"database/sql"
	"time"
)

// Finding represents a row in the findings table.
type Finding struct {
	ID            int64          `json:"id"`
	FlowID        int64          `json:"flow_id"`
	SubtaskID     sql.NullInt64  `json:"subtask_id"`
	VulnType      string         `json:"vuln_type"`
	Title         string         `json:"title"`
	Description   string         `json:"description"`
	Severity      string         `json:"severity"`
	Endpoint      string         `json:"endpoint"`
	Fingerprint   string         `json:"fingerprint"`
	OWASPRef      string         `json:"owasp_ref"`
	CWE           string         `json:"cwe"`
	CVSSBase      float64        `json:"cvss_base"`
	Remediation   string         `json:"remediation"`
	Confirmed     bool           `json:"confirmed"`
	FalsePositive bool           `json:"false_positive"`
	RootCauseID   sql.NullInt64  `json:"root_cause_id"`
	CreatedAt     sql.NullTime   `json:"created_at"`
	UpdatedAt     sql.NullTime   `json:"updated_at"`
}

// CreateFindingParams holds parameters for CreateFinding.
type CreateFindingParams struct {
	FlowID        int64         `json:"flow_id"`
	SubtaskID     sql.NullInt64 `json:"subtask_id"`
	VulnType      string        `json:"vuln_type"`
	Title         string        `json:"title"`
	Description   string        `json:"description"`
	Severity      string        `json:"severity"`
	Endpoint      string        `json:"endpoint"`
	Fingerprint   string        `json:"fingerprint"`
	OWASPRef      string        `json:"owasp_ref"`
	CWE           string        `json:"cwe"`
	CVSSBase      float64       `json:"cvss_base"`
	Remediation   string        `json:"remediation"`
	Confirmed     bool          `json:"confirmed"`
	FalsePositive bool          `json:"false_positive"`
	RootCauseID   sql.NullInt64 `json:"root_cause_id"`
}

const createFinding = `-- name: CreateFinding :one
INSERT INTO findings (flow_id, subtask_id, vuln_type, title, description, severity, endpoint, fingerprint, owasp_ref, cwe, cvss_base, remediation, confirmed, false_positive, root_cause_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
RETURNING id, flow_id, subtask_id, vuln_type, title, description, severity, endpoint, fingerprint, owasp_ref, cwe, cvss_base, remediation, confirmed, false_positive, root_cause_id, created_at, updated_at
`

func (q *Queries) CreateFinding(ctx context.Context, arg CreateFindingParams) (Finding, error) {
	row := q.db.QueryRowContext(ctx, createFinding,
		arg.FlowID,
		arg.SubtaskID,
		arg.VulnType,
		arg.Title,
		arg.Description,
		arg.Severity,
		arg.Endpoint,
		arg.Fingerprint,
		arg.OWASPRef,
		arg.CWE,
		arg.CVSSBase,
		arg.Remediation,
		arg.Confirmed,
		arg.FalsePositive,
		arg.RootCauseID,
	)
	var i Finding
	err := row.Scan(
		&i.ID,
		&i.FlowID,
		&i.SubtaskID,
		&i.VulnType,
		&i.Title,
		&i.Description,
		&i.Severity,
		&i.Endpoint,
		&i.Fingerprint,
		&i.OWASPRef,
		&i.CWE,
		&i.CVSSBase,
		&i.Remediation,
		&i.Confirmed,
		&i.FalsePositive,
		&i.RootCauseID,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const getFindingByFingerprint = `-- name: GetFindingByFingerprint :one
SELECT id, flow_id, subtask_id, vuln_type, title, description, severity, endpoint, fingerprint, owasp_ref, cwe, cvss_base, remediation, confirmed, false_positive, root_cause_id, created_at, updated_at
FROM findings
WHERE fingerprint = $1 AND flow_id = $2
LIMIT 1
`

type GetFindingByFingerprintParams struct {
	Fingerprint string `json:"fingerprint"`
	FlowID      int64  `json:"flow_id"`
}

func (q *Queries) GetFindingByFingerprint(ctx context.Context, arg GetFindingByFingerprintParams) (Finding, error) {
	row := q.db.QueryRowContext(ctx, getFindingByFingerprint, arg.Fingerprint, arg.FlowID)
	var i Finding
	err := row.Scan(
		&i.ID,
		&i.FlowID,
		&i.SubtaskID,
		&i.VulnType,
		&i.Title,
		&i.Description,
		&i.Severity,
		&i.Endpoint,
		&i.Fingerprint,
		&i.OWASPRef,
		&i.CWE,
		&i.CVSSBase,
		&i.Remediation,
		&i.Confirmed,
		&i.FalsePositive,
		&i.RootCauseID,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const getFlowFindings = `-- name: GetFlowFindings :many
SELECT id, flow_id, subtask_id, vuln_type, title, description, severity, endpoint, fingerprint, owasp_ref, cwe, cvss_base, remediation, confirmed, false_positive, root_cause_id, created_at, updated_at
FROM findings
WHERE flow_id = $1 AND false_positive = FALSE
ORDER BY
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        WHEN 'info' THEN 5
    END ASC,
    created_at ASC
`

func (q *Queries) GetFlowFindings(ctx context.Context, flowID int64) ([]Finding, error) {
	rows, err := q.db.QueryContext(ctx, getFlowFindings, flowID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Finding
	for rows.Next() {
		var i Finding
		if err := rows.Scan(
			&i.ID,
			&i.FlowID,
			&i.SubtaskID,
			&i.VulnType,
			&i.Title,
			&i.Description,
			&i.Severity,
			&i.Endpoint,
			&i.Fingerprint,
			&i.OWASPRef,
			&i.CWE,
			&i.CVSSBase,
			&i.Remediation,
			&i.Confirmed,
			&i.FalsePositive,
			&i.RootCauseID,
			&i.CreatedAt,
			&i.UpdatedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getFlowFindingCount = `-- name: GetFlowFindingCount :one
SELECT COUNT(*) FROM findings WHERE flow_id = $1 AND false_positive = FALSE
`

func (q *Queries) GetFlowFindingCount(ctx context.Context, flowID int64) (int64, error) {
	row := q.db.QueryRowContext(ctx, getFlowFindingCount, flowID)
	var count int64
	err := row.Scan(&count)
	return count, err
}

// Ensure unused import is used.
var _ = time.Now
