package database

import (
	"context"
)

// FailRunningToolcallsBySubtask marks all running toolcalls for a subtask as failed.
// This is used for zombie cleanup when a subtask expires or finishes.
const failRunningToolcallsBySubtask = `
UPDATE toolcalls
SET status = 'failed',
    result = $1,
    duration_seconds = EXTRACT(EPOCH FROM (NOW() - created_at))
WHERE subtask_id = $2 AND status = 'running'
`

func (q *Queries) FailRunningToolcallsBySubtask(ctx context.Context, reason string, subtaskID int64) error {
	_, err := q.db.ExecContext(ctx, failRunningToolcallsBySubtask, reason, subtaskID)
	return err
}

// FailRunningToolcallsByFlow marks all running toolcalls for a flow as failed.
// This is used for zombie cleanup when a flow is stopped or finished.
const failRunningToolcallsByFlow = `
UPDATE toolcalls
SET status = 'failed',
    result = $1,
    duration_seconds = EXTRACT(EPOCH FROM (NOW() - created_at))
WHERE flow_id = $2 AND status = 'running'
`

func (q *Queries) FailRunningToolcallsByFlow(ctx context.Context, reason string, flowID int64) error {
	_, err := q.db.ExecContext(ctx, failRunningToolcallsByFlow, reason, flowID)
	return err
}

// CountRunningToolcallsByFlow returns the number of running toolcalls for a flow.
const countRunningToolcallsByFlow = `
SELECT COUNT(*)::bigint AS count
FROM toolcalls
WHERE flow_id = $1 AND status = 'running'
`

func (q *Queries) CountRunningToolcallsByFlow(ctx context.Context, flowID int64) (int64, error) {
	row := q.db.QueryRowContext(ctx, countRunningToolcallsByFlow, flowID)
	var count int64
	err := row.Scan(&count)
	return count, err
}
