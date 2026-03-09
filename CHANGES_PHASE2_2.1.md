# Phase 2 — Upgrade 2.1: DB-Backed Execution State

## Summary

Replaces filesystem-based `STATE.json` with DB-backed execution state persistence
using the existing `Context` column on the `Subtask` table. State is saved after
each tool call batch and restored on resume, so crashes no longer lose progress.

---

## Files Changed

### 1. `backend/sqlc/models/subtasks.sql`

**Added** new SQL query:
```sql
-- name: UpdateSubtaskContextWithTimestamp :exec
UPDATE subtasks
SET context = $2, updated_at = NOW()
WHERE id = $1;
```

This differs from the existing `UpdateSubtaskContext` (:one) by:
- Using `:exec` (no RETURNING — faster for fire-and-forget writes)
- Updating `updated_at = NOW()` to track when state was last persisted
- Parameter order is `($1=id, $2=context)` per the spec

### 2. `backend/pkg/database/subtasks.sql.go`

**Added** the corresponding Go method for the new SQL query:
- `UpdateSubtaskContextWithTimestamp(ctx, params) error`
- `UpdateSubtaskContextWithTimestampParams{ID int64, Context string}`

### 3. `backend/pkg/database/querier.go`

**Added** `UpdateSubtaskContextWithTimestamp` to the `Querier` interface.

### 4. `backend/pkg/controller/subtask.go`

**Added** to `SubtaskWorker` interface:
- `GetContext(ctx context.Context) (string, error)` — reads context from DB via `GetSubtask`
- `SetContext(ctx context.Context, data string) error` — writes context via `UpdateSubtaskContextWithTimestamp`

**Added** implementations on `subtaskWorker` struct for both methods.

### 5. `backend/pkg/providers/execution_state.go` *(NEW FILE)*

Defines:

**`ExecutionState` struct:**
```go
type ExecutionState struct {
    Phase         string   `json:"phase"`
    ToolCallCount int      `json:"tool_call_count"`
    FindingsCount int      `json:"findings_count"`
    AttacksDone   []string `json:"attacks_done"`
    CurrentAttack string   `json:"current_attack"`
    ErrorCount    int      `json:"error_count"`
    LastUpdate    string   `json:"last_update"`
}
```

Helper functions:
- `NewExecutionState()` — creates a fresh state for first run
- `ParseExecutionState(data string) *ExecutionState` — deserializes from JSON; returns nil on empty/malformed (safe for first-run)
- `(es *ExecutionState) ToJSON() (string, error)` — serializes to JSON
- `(es *ExecutionState) Update(metrics, phase)` — syncs state from `ExecutionMetrics`

**`AsyncStateWriter`:**
- Goroutine-based async writer with a buffered channel (cap 64)
- Coalesces rapid updates per subtask ID — only the latest state is flushed
- Flushes every 2 seconds via ticker
- Non-blocking `Write()` — drops updates if channel full (best-effort)
- `Close()` drains channel and flushes before returning
- Uses `context.Background()` for DB writes to survive parent cancellation

### 6. `backend/pkg/providers/performer.go`

**At function start (`performAgentChain`):**
- Creates `execState = NewExecutionState()`
- Creates `stateWriter = NewAsyncStateWriter(fp.db)` with deferred `Close()`
- **Resume logic:** If `subtaskID` is set, loads `subtask.Context` from DB. If it parses as valid `ExecutionState`, restores:
  - `toolCallCount` (so tool limits aren't reset)
  - `metrics.ToolCallCount`, `metrics.ErrorCount`, `metrics.UniqueCommands`, `metrics.LastToolName`
  - Logs the resume event with key counters

**After each tool call batch:**
- Calls `execState.Update(metrics, phase)` where phase is "executing" or "finishing"
- Serializes to JSON and enqueues via `stateWriter.Write(subtaskID, json)`
- Placed between metrics update and budget check — non-blocking path

### 7. `backend/pkg/providers/handlers.go`

**In `GetPentesterHandler`:**
- Before building the pentester template context, loads persisted execution state from DB for the current subtask
- Parses it via `ParseExecutionState()` and re-serializes to JSON
- Passes as `"SubtaskContext": subtaskContext` in the system template context

### 8. `backend/pkg/templates/prompts/pentester.tmpl`

**Added** conditional block between `<execution_context>` and `## LOOP PREVENTION`:
```
{{- if .SubtaskContext}}

## PERSISTED EXECUTION STATE

<subtask_context>
This is your persisted execution state from a previous run. Use it to avoid repeating work:
{{.SubtaskContext}}
</subtask_context>
{{- end}}
```

---

## Design Decisions

### Why async writes?
DB writes are I/O-bound. The agent loop processes tool calls as fast as the LLM
responds. Blocking on a DB write after every tool call would add latency to the
critical path. The `AsyncStateWriter` decouples persistence from the loop.

### Why coalescing?
If 5 tool calls fire in rapid succession, we only need the *latest* state. The
writer batches by subtask ID, so the DB sees at most 1 write per 2-second tick.

### Why `:exec` instead of `:one`?
We don't need the returned row for state writes. `:exec` avoids the scan overhead.

### Why `ParseExecutionState` returns nil on error?
First-run subtasks have empty Context. Subtasks from before this upgrade may have
non-JSON context (rendered execution context text). Both cases should be handled
gracefully without errors — the agent simply starts fresh.

### Why restore metrics on resume?
Without restoring `toolCallCount`, a crashed-and-resumed subtask would have a
fresh counter, potentially exceeding the `maxToolCallsPerSubtask` limit by running
50 *more* calls after already having done 40. Restoring ensures the hard cap works
across restarts.

---

## What's NOT Changed

- The existing `UpdateSubtaskContext` (:one) query is untouched — it's still used
  by `PrepareAgentChain` to store the rendered execution context at chain setup
- The `Subtask.Context` field semantics are backward-compatible — the column can
  hold either rendered execution context text (old) or JSON execution state (new)
- The subtask lifecycle (status transitions, completion, waiting) is unchanged
- No database schema migration needed — the `context` column already exists
