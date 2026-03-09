# CHANGES_FIXER4.md — Flow Control & Database Layer Fixes

Applied by fixer4-flowcontrol subagent.

---

## Fix 20: Finish() double-close panic prevention (sync.Once)
**File:** `backend/pkg/controller/flow.go`

**Problem:** `finish()` calls `close(fw.input)` without checking if the channel is already closed. If `Finish()` is called twice (e.g., by cleanup and by task completion), Go panics on double-close.

**Changes:**
1. Added `closeOnce sync.Once` field to `flowWorker` struct
2. Changed `close(fw.input)` → `fw.closeOnce.Do(func() { close(fw.input) })` in `finish()`

---

## Fix 21: Finish() sets error status on error paths
**File:** `backend/pkg/controller/flow.go`

**Problem:** `Finish()` sets `FlowStatusFinished` only at the very end. If any intermediate step fails (releasing executor, finishing tasks), the function returns an error with the flow still in `Running` status. On restart, the system tries to resume corrupted state.

**Changes:**
1. Changed `Finish` return signature to `(retErr error)` (named return)
2. Added `defer` that calls `fw.SetStatus(ctx, database.FlowStatusFailed)` when `retErr != nil`

---

## Fix 18: runTask waits for previous task cancellation
**File:** `backend/pkg/controller/flow.go`

**Problem:** When a new task starts, the previous task's context is cancelled, but there's no wait for it to actually finish. Two tasks can run simultaneously for a brief period, fighting over shared resources.

**Changes:**
1. Added `fw.taskWG.Wait()` after `fw.taskST()` (cancel) and before creating new task context in `runTask()`

---

## Fix 17: Subtask error handling — permanent failures vs retriable waits
**File:** `backend/pkg/controller/subtask.go`

**Problem:** When `PerformAgentChain` fails for ANY reason, the subtask was always set to `Waiting` status. Permanent failures (invalid API key, model errors) shouldn't show "waiting for input" — they need code/config fixes.

**Changes:**
1. `context.Canceled` errors → `SubtaskStatusWaiting` (user can resume)
2. All other errors → `SubtaskStatusFailed` (needs investigation)
3. Both paths still call `EnsureChainConsistency`

---

## Fix 9: Transaction-safe status propagation (Subtask→Task→Flow)
**Files:** `backend/pkg/controller/subtask.go`, `backend/pkg/controller/task.go`

**Problem:** `SetStatus` in both subtask and task workers updates the DB first (outside lock), then acquires mutex to update in-memory state. Race window exists between DB write and in-memory update. Also, calling `updater.SetStatus()` while holding the lock risks deadlock in the propagation chain.

**Changes in subtask.go `SetStatus()`:**
1. Lock mutex FIRST, then perform DB update
2. Update in-memory state while holding lock
3. Compute parent status to propagate
4. Release lock BEFORE calling `updater.SetStatus()` (prevents deadlock)
5. On DB error, unlock and return early

**Changes in task.go `SetStatus()`:**
1. Same pattern: lock first → DB update → in-memory update → unlock → propagate
2. Eliminates race window between DB and in-memory state
3. Prevents deadlock by releasing lock before flow status propagation

---

## Fix 34: PutInput returns error when no waiting subtask found
**File:** `backend/pkg/controller/task.go`

**Problem:** If a task is `Waiting` but no subtask is actually waiting, `PutInput` silently returns `nil`. The user's input disappears without any error.

**Changes:**
1. Changed loop to `return nil` immediately after successful `PutInput` to subtask
2. After loop completes without finding a waiting subtask, returns explicit error: `"task %d is waiting but no subtask is waiting for input"`

---

## Fix 25: GetTaskCompletedSubtasks excludes Running subtasks
**Files:** `backend/sqlc/models/subtasks.sql`, `backend/pkg/database/subtasks.sql.go`

**Problem:** Query filter `status != 'created' AND status != 'waiting'` includes `running` subtasks. The refiner uses this query and sees running subtasks as "completed," making incorrect planning decisions.

**Changes:**
1. Changed SQL WHERE clause from `(s.status != 'created' AND s.status != 'waiting')` to `s.status IN ('finished', 'failed')`
2. Updated both the `.sql` source and the generated `.sql.go` file

---

## Fix 36: Input validation on PutInputToAgentChain
**Files:** `backend/pkg/providers/provider.go`, `backend/pkg/providers/assistant.go`

**Problem:** User input goes directly into the agent chain with no size or emptiness validation. Malicious or accidental multi-megabyte input causes DB bloat and context overflow.

**Changes:**
1. Added `maxUserInputSize = 32 * 1024` (32KB) constant in `provider.go`
2. Added empty input check → returns `"user input is empty"` error
3. Added size check → returns `"user input exceeds maximum size"` error
4. Applied same validation to `assistantProvider.PutInputToAgentChain` in `assistant.go`

---

## Summary of files modified

| File | Fixes Applied |
|------|--------------|
| `backend/pkg/controller/flow.go` | Fix 18, Fix 20, Fix 21 |
| `backend/pkg/controller/subtask.go` | Fix 9, Fix 17 |
| `backend/pkg/controller/task.go` | Fix 9, Fix 34 |
| `backend/sqlc/models/subtasks.sql` | Fix 25 |
| `backend/pkg/database/subtasks.sql.go` | Fix 25 |
| `backend/pkg/providers/provider.go` | Fix 36 |
| `backend/pkg/providers/assistant.go` | Fix 36 |
