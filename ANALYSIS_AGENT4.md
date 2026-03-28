# Agent 4 — Flow Control & Database Analysis

## File: flow.go

### Finding 1: Context detachment loses parent cancellation propagation
- **Line(s):** 244-245, 393-394
- **Severity:** HIGH
- **Description:** Both `NewFlowWorker` and `LoadFlowWorker` create a new `context.Background()` instead of deriving from the incoming context. This means if the server shuts down or the parent context is cancelled, the flow worker's goroutine will NOT be notified. The flow worker becomes an orphan that can only be stopped via explicit `Finish()`/`Stop()` calls. If the server crashes or restarts ungracefully, these goroutines will leak until the process is killed.
- **Current Code:**
```go
ctx, cancel := context.WithCancel(context.Background())
ctx, _ = obs.Observer.NewObservation(ctx, langfuse.WithObservationTraceID(observation.TraceID()))
```
- **Proposed Fix:** This appears to be intentional (flow workers survive the HTTP request context), but it should be documented. Additionally, the server shutdown handler MUST explicitly call `Finish()` on all active flow workers. Verify this exists in the server lifecycle code.

### Finding 2: Stop() only cancels current task, does not stop the flow worker goroutine
- **Line(s):** 642-665
- **Severity:** HIGH
- **Description:** `Stop()` cancels `taskST` (the current task's context) and waits for `taskWG`, but it does NOT call `fw.cancel()` or `fw.finish()`. This means the flow worker goroutine (`fw.worker()`) continues running and will process the next input from the channel. After `Stop()`, the flow stays in whatever status it was — there's no transition to a "stopped" status. If the intent is to pause the current task, this is fine but confusing. If the intent is to stop the flow, it's incomplete.
- **Current Code:**
```go
func (fw *flowWorker) Stop(ctx context.Context) error {
    fw.taskMX.Lock()
    defer fw.taskMX.Unlock()

    fw.taskST()
    done := make(chan struct{})
    timer := time.NewTimer(stopTaskTimeout)
    defer timer.Stop()

    go func() {
        fw.taskWG.Wait()
        close(done)
    }()

    select {
    case <-timer.C:
        return fmt.Errorf("task stop timeout")
    case <-done:
        return nil
    }
}
```
- **Proposed Fix:** Either rename to `StopCurrentTask()` for clarity, or add `fw.cancel()` and status transition to `FlowStatusStopped`. Also, the `stopTaskTimeout` of 5 seconds may be too short for tasks involving LLM calls or container operations.

### Finding 3: Finish() calls finish() which closes input channel — potential panic on double close
- **Line(s):** 623-641, 672-682
- **Severity:** MEDIUM
- **Description:** `finish()` calls `close(fw.input)` without checking if the channel is already closed. If `Finish()` is called twice (e.g., once by the task completing naturally and once by flow cleanup), this will panic. The `fw.ctx.Err()` check guards against this partially (context.Canceled), but there's a race: if `cancel()` hasn't propagated yet when a second `Finish()` is called, `close()` will be called on an already-closed channel.
- **Current Code:**
```go
func (fw *flowWorker) finish() error {
    if err := fw.ctx.Err(); err != nil {
        if errors.Is(err, context.Canceled) {
            return nil
        }
        return fmt.Errorf("flow %d stop failed: %w", fw.flowCtx.FlowID, err)
    }

    fw.cancel()
    close(fw.input)
    fw.wg.Wait()

    return nil
}
```
- **Proposed Fix:** Use `sync.Once` to protect the close:
```go
type flowWorker struct {
    // ... existing fields
    closeOnce sync.Once
}

func (fw *flowWorker) finish() error {
    if err := fw.ctx.Err(); err != nil {
        if errors.Is(err, context.Canceled) {
            return nil
        }
        return fmt.Errorf("flow %d stop failed: %w", fw.flowCtx.FlowID, err)
    }

    fw.cancel()
    fw.closeOnce.Do(func() { close(fw.input) })
    fw.wg.Wait()

    return nil
}
```

### Finding 4: Finish() does not set status on error paths — flow left in limbo
- **Line(s):** 623-641
- **Severity:** HIGH
- **Description:** `Finish()` sets `FlowStatusFinished` only at the very end. If any intermediate step fails (e.g., finishing a task or releasing the executor), the function returns early with an error, leaving the flow in its previous status (likely `Running` or `Waiting`). On the next server restart, `LoadFlowWorker` will try to reload this flow (because its status is `Running`/`Waiting`), potentially causing issues with stale state.
- **Current Code:**
```go
func (fw *flowWorker) Finish(ctx context.Context) error {
    if err := fw.finish(); err != nil { return err }
    
    for _, task := range fw.tc.ListTasks(ctx) {
        if !task.IsCompleted() {
            if err := task.Finish(ctx); err != nil {
                return fmt.Errorf("failed to finish task %d: %w", task.GetTaskID(), err)
            }
        }
    }
    // ... assistant cleanup ...
    if err := fw.flowCtx.Executor.Release(ctx); err != nil {
        return fmt.Errorf("failed to release flow %d resources: %w", fw.flowCtx.FlowID, err)
    }
    if err := fw.SetStatus(ctx, database.FlowStatusFinished); err != nil {
        return fmt.Errorf("failed to set flow %d status: %w", fw.flowCtx.FlowID, err)
    }
    return nil
}
```
- **Proposed Fix:** Use a deferred status update that sets `FlowStatusFailed` on error:
```go
func (fw *flowWorker) Finish(ctx context.Context) (retErr error) {
    defer func() {
        if retErr != nil {
            _ = fw.SetStatus(ctx, database.FlowStatusFailed)
        }
    }()
    // ... rest of method
}
```

### Finding 5: processInput sends to flin.done before runTask — potential error swallowed
- **Line(s):** 753-774
- **Severity:** MEDIUM
- **Description:** In `processInput()`, when a waiting task is found, `flin.done <- nil` is sent BEFORE `fw.runTask()` is called. This means the caller of `PutInput()` gets a "success" response even though the task hasn't actually run yet. If `runTask()` subsequently fails, that error is only logged but never communicated back to the user. Similarly, for new task creation: `flin.done <- nil` is sent before `runTask()`.
- **Current Code:**
```go
flin.done <- nil
return task, fw.runTask("put input to task and run", flin.input, task)
```
- **Proposed Fix:** This appears intentional (the PutInput has a 1-second timeout, so it can't wait for full task execution). However, the error from `runTask` should be communicated via another channel (e.g., WebSocket/subscription). Verify that the `worker()` error handler does publish errors to clients.

### Finding 6: runTask cancels previous task without waiting for it
- **Line(s):** 786-800
- **Severity:** HIGH
- **Description:** In `runTask()`, the previous `taskST()` cancel function is called, then immediately a new context/cancel pair is created. But there's no wait for the previous task to actually finish. The `taskWG.Add(1)` is called for the new task, but the old task's goroutine might still be running. This creates a race condition where two tasks could be executing simultaneously for a brief period.
- **Current Code:**
```go
fw.taskMX.Lock()
fw.taskST()                              // cancel previous task
ctx, taskST := context.WithCancel(fw.ctx) // create new cancel
fw.taskST = taskST
fw.taskMX.Unlock()
// ... 
fw.taskWG.Add(1)
defer fw.taskWG.Done()
```
- **Proposed Fix:** Wait for the previous task's WaitGroup before starting the new one, or ensure tasks are truly sequential:
```go
fw.taskMX.Lock()
fw.taskST()
fw.taskWG.Wait()  // Wait for previous task to fully stop
ctx, taskST := context.WithCancel(fw.ctx)
fw.taskST = taskST
fw.taskMX.Unlock()
```

### Finding 7: ListAssistants sort comparator has int64 overflow risk
- **Line(s):** 560-562
- **Severity:** LOW
- **Description:** The sort comparator uses `int(a.GetAssistantID() - b.GetAssistantID())`. If assistant IDs are large int64 values, the subtraction could overflow when cast to int (especially on 32-bit systems, though unlikely in practice).
- **Current Code:**
```go
slices.SortFunc(assistants, func(a, b AssistantWorker) int {
    return int(a.GetAssistantID() - b.GetAssistantID())
})
```
- **Proposed Fix:** Use cmp.Compare:
```go
import "cmp"
slices.SortFunc(assistants, func(a, b AssistantWorker) int {
    return cmp.Compare(a.GetAssistantID(), b.GetAssistantID())
})
```

### Finding 8: No resource cleanup on NewFlowWorker partial failure
- **Line(s):** 110-268
- **Severity:** MEDIUM
- **Description:** `NewFlowWorker` creates multiple resources (DB flow record, executor, provider, containers). If the function fails after creating some resources but before completing (e.g., fails at `executor.Prepare`), earlier resources are not cleaned up. The flow record stays in the DB with status `Created`, and Docker containers may be left running.
- **Current Code:** Various error returns using `wrapErrorEndSpan` which only ends the span but doesn't clean up resources.
- **Proposed Fix:** Add a cleanup deferred function:
```go
func NewFlowWorker(...) (FlowWorker, error) {
    var cleanups []func()
    defer func() {
        if retErr != nil {
            for _, cleanup := range cleanups {
                cleanup()
            }
        }
    }()
    
    flow, err := fwc.db.CreateFlow(ctx, ...)
    cleanups = append(cleanups, func() {
        _ = fwc.db.UpdateFlowStatus(ctx, database.UpdateFlowStatusParams{
            Status: database.FlowStatusFailed, ID: flow.ID,
        })
    })
    // ... etc
}
```

---

## File: subtask.go

### Finding 9: Subtask Run() sets Waiting on ANY error — including permanent failures
- **Line(s):** 277-296
- **Severity:** HIGH
- **Description:** When `PerformAgentChain` fails, the subtask is always set back to `Waiting` status regardless of the error type. This means permanent failures (e.g., provider API key invalid, model not found, schema errors) will put the subtask into a "waiting for input" state, making it look like it needs user input when it actually needs a code/config fix. Only context cancellation errors should trigger waiting; other errors should set the status to `Failed`.
- **Current Code:**
```go
performResult, err := stw.subtaskCtx.Provider.PerformAgentChain(ctx, taskID, subtaskID, msgChainID)
if err != nil {
    if errors.Is(err, context.Canceled) {
        ctx = context.Background()
    }
    errChainConsistency := stw.subtaskCtx.Provider.EnsureChainConsistency(ctx, msgChainID)
    if errChainConsistency != nil {
        err = errors.Join(err, errChainConsistency)
    }
    _ = stw.SetStatus(ctx, database.SubtaskStatusWaiting)
    return fmt.Errorf("failed to perform agent chain for subtask %d: %w", subtaskID, err)
}
```
- **Proposed Fix:**
```go
if err != nil {
    if errors.Is(err, context.Canceled) {
        ctx = context.Background()
        // Cancellation → waiting (user can resume)
        _ = stw.SetStatus(ctx, database.SubtaskStatusWaiting)
    } else {
        // Permanent error → failed
        _ = stw.SetStatus(ctx, database.SubtaskStatusFailed)
    }
    errChainConsistency := stw.subtaskCtx.Provider.EnsureChainConsistency(ctx, msgChainID)
    if errChainConsistency != nil {
        err = errors.Join(err, errChainConsistency)
    }
    return fmt.Errorf("failed to perform agent chain for subtask %d: %w", subtaskID, err)
}
```

### Finding 10: SetStatus DB update and in-memory state are not atomic — race condition
- **Line(s):** 197-230
- **Severity:** HIGH
- **Description:** `SetStatus` first updates the database, then acquires the mutex to update in-memory state. Between the DB write and the mutex lock, another goroutine could read stale in-memory state (via `IsCompleted()` or `IsWaiting()`) that doesn't match the DB. Additionally, the `updater.SetStatus()` call (which propagates to the parent task) is done INSIDE the mutex lock, which could cause deadlocks if the task's `SetStatus` tries to access the subtask.
- **Current Code:**
```go
func (stw *subtaskWorker) SetStatus(ctx context.Context, status database.SubtaskStatus) error {
    _, err := stw.subtaskCtx.DB.UpdateSubtaskStatus(ctx, ...)
    if err != nil { return ... }

    stw.mx.Lock()
    defer stw.mx.Unlock()

    switch status {
    case database.SubtaskStatusRunning:
        stw.completed = false
        stw.waiting = false
        err = stw.updater.SetStatus(ctx, database.TaskStatusRunning)
    // ...
    }
}
```
- **Proposed Fix:** Lock the mutex BEFORE the DB call to ensure DB and memory are consistent from any reader's perspective. Call updater AFTER releasing the lock to prevent deadlocks.

### Finding 11: LoadSubtaskWorker picks first message chain arbitrarily
- **Line(s):** 109-112
- **Severity:** MEDIUM
- **Description:** When loading a subtask, `GetSubtaskPrimaryMsgChains` may return multiple chains, but only the first one (`msgChains[0].ID`) is used. There's no ordering guarantee, so the "wrong" chain could be picked. If the subtask was interrupted and restarted, there might be multiple chains.
- **Current Code:**
```go
msgChains, err := taskCtx.DB.GetSubtaskPrimaryMsgChains(ctx, database.Int64ToNullInt64(&subtask.ID))
if err != nil { ... }
if len(msgChains) == 0 { ... }

return &subtaskWorker{
    subtaskCtx: &SubtaskContext{
        MsgChainID: msgChains[0].ID,
```
- **Proposed Fix:** Sort by ID descending to get the most recent chain, or validate that exactly one primary chain exists.

### Finding 12: No per-subtask command budget or time tracking (confirms known issue #3)
- **Line(s):** N/A (entire file)
- **Severity:** MEDIUM
- **Description:** The `SubtaskContext` and `subtaskWorker` structs have no fields for tracking command count, execution time, or resource usage. The `SubtaskWorker` interface has `SetResult` but nothing like `IncrementCommandCount` or `RecordTimeSpent`. This means there's no way to enforce per-subtask resource limits or provide execution metrics to the refiner.
- **Current Code:** SubtaskContext only contains: MsgChainID, SubtaskID, SubtaskTitle, SubtaskDescription, TaskContext
- **Proposed Fix:** Add tracking fields:
```go
type SubtaskContext struct {
    MsgChainID         int64
    SubtaskID          int64
    SubtaskTitle       string
    SubtaskDescription string
    CommandCount       int64         // NEW
    StartedAt          time.Time     // NEW
    TimeSpent          time.Duration // NEW
    TaskContext
}
```

### Finding 13: Finish() returns error when subtask is already completed — poor idempotency
- **Line(s):** 325-332
- **Severity:** LOW
- **Description:** `Finish()` returns an error if the subtask is already completed. This makes cleanup logic brittle — the caller must check `IsCompleted()` before calling `Finish()`. An idempotent `Finish()` that silently succeeds would be more robust.
- **Current Code:**
```go
func (stw *subtaskWorker) Finish(ctx context.Context) error {
    if stw.IsCompleted() {
        return fmt.Errorf("subtask has already completed")
    }
    // ...
}
```
- **Proposed Fix:** Return `nil` instead of error when already completed.

### Finding 14: PutInput has TOCTOU race between IsCompleted/IsWaiting checks and state mutation
- **Line(s):** 245-270
- **Severity:** MEDIUM
- **Description:** `PutInput()` calls `stw.IsCompleted()` and `stw.IsWaiting()` which each acquire and release `RLock`. Then later it acquires `Lock` to set `stw.waiting = false`. Between the RLock releases and the Lock acquire, another goroutine could change the state (e.g., concurrent `SetStatus(Finished)` could complete the subtask after the `IsCompleted()` check passes).
- **Current Code:**
```go
func (stw *subtaskWorker) PutInput(ctx context.Context, input string) error {
    if stw.IsCompleted() { return ... }  // RLock/RUnlock
    if !stw.IsWaiting() { return ... }   // RLock/RUnlock
    // ... do work (no lock held) ...
    stw.mx.Lock()
    stw.waiting = false
    stw.mx.Unlock()
}
```
- **Proposed Fix:** Acquire write lock at start for the check, release before I/O, re-acquire for state mutation. Or use a single atomic state field.

---

## File: task.go

### Finding 15: Run() has unbounded subtask execution loop with weak limit
- **Line(s):** 283-310
- **Severity:** HIGH
- **Description:** The `Run()` loop continues while `len(tw.stc.ListSubtasks(ctx)) < providers.TasksNumberLimit+3`. This is a soft limit based on the TOTAL number of subtasks (including completed ones), not the number of iterations. If `RefineSubtasks` keeps adding new subtasks but also removes/completes old ones such that the total stays under the limit, the loop could run indefinitely. The `+3` magic number is undocumented. Additionally, there's no timeout or maximum iteration count — a misbehaving refiner could cause infinite loops.
- **Current Code:**
```go
for len(tw.stc.ListSubtasks(ctx)) < providers.TasksNumberLimit+3 {
    st, err := tw.stc.PopSubtask(ctx, tw)
    if err != nil { return err }
    if st == nil { break }
    if err := st.Run(ctx); err != nil { return err }
    if tw.IsWaiting() { return nil }
    if err := tw.stc.RefineSubtasks(ctx); err != nil { ... }
}
```
- **Proposed Fix:** Add explicit iteration counting:
```go
const maxSubtaskIterations = 50 // or providers.TasksNumberLimit + 3
for i := 0; i < maxSubtaskIterations; i++ {
    st, err := tw.stc.PopSubtask(ctx, tw)
    // ...
}
if i >= maxSubtaskIterations {
    return fmt.Errorf("task %d exceeded max subtask iterations", tw.taskCtx.TaskID)
}
```

### Finding 16: Task SetStatus has same DB-before-lock atomicity issue as subtask
- **Line(s):** 219-254
- **Severity:** HIGH
- **Description:** Identical to Finding 10 — `SetStatus` updates the DB, publishes to subscribers, then acquires the mutex. Between the DB update and the lock, a reader could see stale in-memory state. Also, `tw.updater.SetStatus()` (which calls `flowWorker.SetStatus()`) is called while holding the task's mutex, creating a lock ordering dependency that could deadlock with concurrent access patterns.
- **Current Code:**
```go
func (tw *taskWorker) SetStatus(ctx context.Context, status database.TaskStatus) error {
    task, err := tw.taskCtx.DB.UpdateTaskStatus(ctx, ...)
    // ... publish ...
    tw.mx.Lock()
    defer tw.mx.Unlock()
    switch status {
    case database.TaskStatusRunning:
        err = tw.updater.SetStatus(ctx, database.FlowStatusRunning) // lock held!
    // ...
    }
}
```
- **Proposed Fix:** Same as Finding 10 — lock before DB write, or call updater outside the lock.

### Finding 17: Task Finished/Failed always sets flow to Waiting — may lose error context
- **Line(s):** 245-248
- **Severity:** MEDIUM
- **Description:** When a task finishes (either `Finished` or `Failed`), the flow is always set to `FlowStatusWaiting`. This means a failed task doesn't propagate the failure to the flow — the flow just looks like it's waiting for new input. There's no way for the user to see that the previous task failed unless they check the task status specifically.
- **Current Code:**
```go
case database.TaskStatusFinished, database.TaskStatusFailed:
    tw.completed = true
    tw.waiting = false
    // the last task was done, set flow status to Waiting new user input
    err = tw.updater.SetStatus(ctx, database.FlowStatusWaiting)
```
- **Proposed Fix:** Consider differentiating:
```go
case database.TaskStatusFinished:
    tw.completed = true
    tw.waiting = false
    err = tw.updater.SetStatus(ctx, database.FlowStatusWaiting)
case database.TaskStatusFailed:
    tw.completed = true
    tw.waiting = false
    err = tw.updater.SetStatus(ctx, database.FlowStatusWaiting)
    // TODO: Consider FlowStatusError or at least log prominently
```

### Finding 18: PutInput only delivers to first waiting subtask — potential input loss
- **Line(s):** 265-278
- **Severity:** MEDIUM
- **Description:** `PutInput()` iterates through subtasks and delivers input to the FIRST non-completed, waiting subtask it finds. If multiple subtasks are somehow waiting simultaneously (which the code structure suggests shouldn't happen but isn't prevented), only the first one gets the input. More importantly, if NO waiting subtask is found, the function silently returns `nil` — the user's input is silently dropped with no error.
- **Current Code:**
```go
func (tw *taskWorker) PutInput(ctx context.Context, input string) error {
    if !tw.IsWaiting() { return fmt.Errorf("task is not waiting") }
    for _, st := range tw.stc.ListSubtasks(ctx) {
        if !st.IsCompleted() && st.IsWaiting() {
            if err := st.PutInput(ctx, input); err != nil {
                return fmt.Errorf("failed to put input to subtask %d: %w", st.GetSubtaskID(), err)
            } else {
                break
            }
        }
    }
    return nil
}
```
- **Proposed Fix:** Return an error when no waiting subtask is found:
```go
    found := false
    for _, st := range tw.stc.ListSubtasks(ctx) {
        if !st.IsCompleted() && st.IsWaiting() {
            if err := st.PutInput(ctx, input); err != nil {
                return fmt.Errorf("failed to put input to subtask %d: %w", st.GetSubtaskID(), err)
            }
            found = true
            break
        }
    }
    if !found {
        return fmt.Errorf("task %d is waiting but no subtask is waiting for input", tw.taskCtx.TaskID)
    }
    return nil
```

### Finding 19: LoadTaskWorker doesn't handle Running status change — silent continuation
- **Line(s):** 130-142
- **Severity:** MEDIUM
- **Description:** When loading a task with `TaskStatusRunning`, the task is kept as-is (not marked as completed or waiting). Unlike `LoadSubtaskWorker` which resets `Running` to `Created`, the task stays in `Running` state. This inconsistency means a loaded running task's in-memory `completed` and `waiting` are both `false`, and it will be picked up by the flow worker's "continue incomplete tasks" loop. But the subtasks underneath may have been reset to `Created`, potentially causing re-execution of work.
- **Current Code:**
```go
case database.TaskStatusRunning:
    // (no action taken - completed and waiting both default to false)
```
- **Proposed Fix:** Add explicit handling, e.g., logging or resetting to a known state.

### Finding 20: Finish() not idempotent — same issue as subtask Finding 13
- **Line(s):** 340-355
- **Severity:** LOW
- **Description:** `Finish()` returns error if task is already completed. Same poor idempotency issue as Finding 13.
- **Current Code:**
```go
func (tw *taskWorker) Finish(ctx context.Context) error {
    if tw.IsCompleted() {
        return fmt.Errorf("task has already completed")
    }
```
- **Proposed Fix:** Return `nil` when already completed.

### Finding 21: Run() swallows refine error type — always sets Waiting
- **Line(s):** 300-306
- **Severity:** MEDIUM
- **Description:** When `RefineSubtasks` fails, the task is always set to `Waiting` status regardless of the error type. Same pattern as Finding 9 — permanent errors (e.g., LLM API failure) shouldn't put the task in a waiting state.
- **Current Code:**
```go
if err := tw.stc.RefineSubtasks(ctx); err != nil {
    if errors.Is(err, context.Canceled) {
        ctx = context.Background()
    }
    _ = tw.SetStatus(ctx, database.TaskStatusWaiting)
    return fmt.Errorf("failed to refine subtasks list for the task %d: %w", tw.taskCtx.TaskID, err)
}
```
- **Proposed Fix:** Same as Finding 9 — differentiate cancellation from permanent errors.

---

## File: flows.sql.go

### Finding 22: No transaction support for multi-step flow operations
- **Line(s):** N/A (entire file — generated by sqlc)
- **Severity:** HIGH
- **Description:** All flow DB operations are individual queries with no transaction support. The `Querier` interface (used by all controllers) operates on a single `db` connection, but there's no `BeginTx`/`CommitTx` pattern available. This means multi-step operations like "create flow + create containers + update flow" are NOT atomic. If the process crashes between steps, the database is left in an inconsistent state. The `NewFlowWorker` function in flow.go does: `CreateFlow` → `GetUser` → `UpdateFlow` → `GetFlowContainers` — all as separate queries with no transaction boundary.
- **Current Code:** All queries use `q.db.QueryRowContext(ctx, ...)` directly.
- **Proposed Fix:** sqlc supports transactions via `WithTx` pattern. Add a `*sql.Tx` wrapper:
```go
func (q *Queries) WithTx(tx *sql.Tx) *Queries {
    return &Queries{db: tx}
}
```
Then wrap multi-step operations in transactions in the controller layer.

### Finding 23: UpdateFlowStatus has no status transition validation
- **Line(s):** ~580-610
- **Severity:** MEDIUM
- **Description:** `UpdateFlowStatus` accepts any status value and blindly sets it. There's no SQL constraint or application-level check to ensure valid transitions (e.g., `Created → Running → Waiting → Finished` is valid, but `Finished → Created` should be rejected). Invalid transitions could corrupt flow state.
- **Current Code:**
```sql
UPDATE flows SET status = $1 WHERE id = $2
```
- **Proposed Fix:** Either add a CHECK constraint in the migration:
```sql
-- Example trigger for valid transitions
CREATE OR REPLACE FUNCTION validate_flow_status_transition()
RETURNS TRIGGER AS $$
BEGIN
  IF OLD.status = 'finished' AND NEW.status != 'finished' THEN
    RAISE EXCEPTION 'Cannot transition from finished';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
```
Or add validation in the Go controller before calling the DB.

### Finding 24: DeleteFlow uses soft delete but queries don't filter consistently
- **Line(s):** 73-90 (DeleteFlow), various
- **Severity:** LOW
- **Description:** `DeleteFlow` uses soft delete (`SET deleted_at = CURRENT_TIMESTAMP`), and most queries filter `WHERE f.deleted_at IS NULL`. However, `GetFlow` filters on `deleted_at IS NULL` but `UpdateFlowStatus`, `UpdateFlowTitle`, `UpdateFlowLanguage`, and `UpdateFlowToolCallIDTemplate` do NOT check `deleted_at`. This means status/title updates can be applied to soft-deleted flows.
- **Current Code:**
```sql
-- GetFlow (correct):
WHERE f.id = $1 AND f.deleted_at IS NULL

-- UpdateFlowStatus (missing filter):
UPDATE flows SET status = $1 WHERE id = $2
```
- **Proposed Fix:** Add `AND deleted_at IS NULL` to all UPDATE queries, or accept that updates to soft-deleted flows are harmless.

### Finding 25: GetFlows has no pagination — potential performance issue
- **Line(s):** 160-166
- **Severity:** LOW
- **Description:** `GetFlows` returns ALL non-deleted flows without any LIMIT or pagination. For a system with many flows, this could return thousands of rows and consume significant memory.
- **Current Code:**
```sql
SELECT f.* FROM flows f WHERE f.deleted_at IS NULL ORDER BY f.created_at DESC
```
- **Proposed Fix:** Add LIMIT/OFFSET parameters or cursor-based pagination.

---

## File: subtasks.sql.go

### Finding 26: Subtask schema missing critical tracking fields (confirms known issue #3)
- **Line(s):** N/A (schema inferred from RETURNING clauses)
- **Severity:** HIGH
- **Description:** The subtask table has these fields: `id, status, title, description, result, task_id, created_at, updated_at, context`. **Missing fields:**
  - `command_count` — no way to track how many commands a subtask executed
  - `started_at` / `finished_at` — no way to measure execution duration (only `created_at`/`updated_at`)
  - `error_message` — errors are not stored; a failed subtask's `result` field may contain the last successful result, not the error
  - `retry_count` — no tracking of how many times a subtask was retried
  - `parent_subtask_id` — no support for subtask dependencies/ordering
  - `assigned_agent_type` — which agent type was assigned
- **Current Code:** Subtask struct (inferred):
```go
type Subtask struct {
    ID          int64
    Status      SubtaskStatus
    Title       string
    Description string
    Result      string
    TaskID      int64
    CreatedAt   time.Time
    UpdatedAt   time.Time
    Context     string
}
```
- **Proposed Fix:** Add migration:
```sql
ALTER TABLE subtasks
  ADD COLUMN command_count INTEGER DEFAULT 0,
  ADD COLUMN started_at TIMESTAMP,
  ADD COLUMN finished_at TIMESTAMP,
  ADD COLUMN error_message TEXT DEFAULT '',
  ADD COLUMN retry_count INTEGER DEFAULT 0;
```

### Finding 27: GetTaskCompletedSubtasks includes Running status — misleading name
- **Line(s):** ~250-275
- **Severity:** MEDIUM
- **Description:** `GetTaskCompletedSubtasks` filters `WHERE s.status != 'created' AND s.status != 'waiting'`. This means it includes `running`, `finished`, AND `failed` subtasks — not just "completed" ones. A subtask currently `running` is neither completed nor planned, yet it's returned by this query. The refiner using this query would see running subtasks as "completed", potentially making incorrect planning decisions.
- **Current Code:**
```sql
WHERE s.task_id = $1 AND (s.status != 'created' AND s.status != 'waiting') AND f.deleted_at IS NULL
```
- **Proposed Fix:** Either rename to `GetTaskNonPendingSubtasks` or fix the filter:
```sql
WHERE s.task_id = $1 AND s.status IN ('finished', 'failed') AND f.deleted_at IS NULL
```

### Finding 28: DeleteSubtask uses hard DELETE — orphaned references possible
- **Line(s):** 61-66
- **Severity:** MEDIUM
- **Description:** `DeleteSubtask` does a hard `DELETE FROM subtasks` while `DeleteFlow` uses soft delete. This inconsistency means:
  1. If there are message chains referencing a subtask_id via foreign key, the DELETE could fail or cascade-delete important data
  2. There's no audit trail for deleted subtasks
  3. The refiner's `DeleteSubtasks` (batch delete by IDs) also does hard deletes — if IDs are wrong, data is permanently lost
- **Current Code:**
```sql
DELETE FROM subtasks WHERE id = $1
DELETE FROM subtasks WHERE id = ANY($1::BIGINT[])
```
- **Proposed Fix:** Use soft delete like flows, or ensure FK cascade behavior is intentional:
```sql
UPDATE subtasks SET deleted_at = CURRENT_TIMESTAMP WHERE id = $1
```

### Finding 29: No optimistic locking on subtask status updates — lost update risk
- **Line(s):** ~550-580 (UpdateSubtaskStatus)
- **Severity:** MEDIUM
- **Description:** `UpdateSubtaskStatus` does `SET status = $1 WHERE id = $2` with no check on the current status. If two goroutines simultaneously try to update the same subtask's status (e.g., one setting `Finished` and one setting `Failed`), the last write wins with no conflict detection. Combined with the in-memory/DB race in Finding 10, this creates a scenario where the DB says `Failed` but in-memory says `Finished` (or vice versa).
- **Current Code:**
```sql
UPDATE subtasks SET status = $1 WHERE id = $2
```
- **Proposed Fix:** Add optimistic locking:
```sql
UPDATE subtasks SET status = $1 WHERE id = $2 AND status = $3 RETURNING ...
```
And check that the row was actually updated.

### Finding 30: UpdateSubtaskFinishedResult and UpdateSubtaskFailedResult bypass controller SetStatus
- **Line(s):** ~480-540
- **Severity:** MEDIUM
- **Description:** There are dedicated DB queries `UpdateSubtaskFinishedResult` and `UpdateSubtaskFailedResult` that atomically set both status and result. However, the controller code uses separate `SetStatus` + `SetResult` calls (see subtask.go `Run()` method). These atomic queries exist in the DB layer but may not be used by the controller, leading to non-atomic status+result updates. Meanwhile, someone calling these queries directly would bypass the controller's in-memory state updates and event publishing.
- **Current Code:**
```sql
-- Atomic DB queries exist:
UPDATE subtasks SET status = 'finished', result = $1 WHERE id = $2
UPDATE subtasks SET status = 'failed', result = $1 WHERE id = $2
```
- **Proposed Fix:** Use these atomic queries in the controller's completion path, and add `TaskUpdated` event publishing:
```go
func (stw *subtaskWorker) CompleteWithResult(ctx context.Context, result string, success bool) error {
    if success {
        _, err = stw.subtaskCtx.DB.UpdateSubtaskFinishedResult(ctx, ...)
    } else {
        _, err = stw.subtaskCtx.DB.UpdateSubtaskFailedResult(ctx, ...)
    }
    // Update in-memory state + publish events
}
```

### Finding 31: `context` field in subtask schema has no clear usage from controller
- **Line(s):** N/A (field present in DB, usage unclear from controller)
- **Severity:** LOW
- **Description:** The subtask table has a `context` field (string) and an `UpdateSubtaskContext` query, but the subtask controller (`subtask.go`) never reads or writes this field. The `SubtaskContext` Go struct is an in-memory struct that contains `MsgChainID`, `SubtaskID`, etc. — it's NOT backed by the DB `context` column. This confirms known issue #1: STATE.json / context data has no reliable DB backing. The DB `context` column exists but is apparently unused by the controller.
- **Current Code:**
```sql
UPDATE subtasks SET context = $1 WHERE id = $2
```
Go controller: no reference to `UpdateSubtaskContext` or reading `Context` field.
- **Proposed Fix:** Either use this field to persist subtask execution context (tool outputs, intermediate state, file system snapshots) or remove it to avoid confusion.

---

## Cross-File Findings

### Finding 32: Status propagation chain creates implicit coupling without transactions
- **Severity:** CRITICAL
- **Description:** The status propagation chain is: Subtask → Task → Flow. When a subtask status changes, it calls `updater.SetStatus()` which updates the task, which calls `fw.SetStatus()` which updates the flow. Each step is a separate DB query with no transaction. If the process crashes mid-chain:
  - Subtask: `Finished`, Task: `Running`, Flow: `Running` — inconsistent state
  - On reload, the subtask appears done but the task/flow still think they're running
  
  The chain also has the deadlock risk mentioned in Findings 10 and 16: subtask holds its mutex → calls task.SetStatus → task holds its mutex → calls flow.SetStatus. If there's ever a reverse dependency (flow → task → subtask), deadlock occurs.

### Finding 33: Refiner context is insufficient — confirms known issue #2
- **Severity:** HIGH
- **Description:** The refiner (called via `tw.stc.RefineSubtasks(ctx)` in task.go line 301) gets subtask data from the DB via `GetTaskCompletedSubtasks` and `GetTaskPlannedSubtasks`. However:
  1. `GetTaskCompletedSubtasks` only provides: id, status, title, description, result, context. It does NOT include what files were created/modified, what commands were run, or the filesystem state.
  2. There's no query to get the terminal log (commands executed) for a subtask — that data is in a separate `term_logs` table not exposed to the refiner.
  3. The `result` field may be empty for running/failed subtasks, so the refiner sees subtasks with no result and may re-plan work.
  4. The `GetTaskCompletedSubtasks` bug (Finding 27) means running subtasks appear as "completed", further confusing the refiner.

### Finding 34: No STATE.json DB backing — confirms known issue #1
- **Severity:** HIGH
- **Description:** The subtask DB schema has a `context` column (Finding 31) that could theoretically store state, but it's unused by the controller. The `SubtaskContext` in-memory struct is populated from individual fields, not from a serialized state. If the server restarts:
  1. In-memory `SubtaskContext` is reconstructed from DB fields (title, description, status)
  2. Any runtime state (what files exist, current directory, agent memory) is LOST
  3. The `LoadSubtaskWorker` only restores basic metadata, not execution state
  4. STATE.json (if it exists in the container filesystem) may survive container restart but has no DB backing
- **Proposed Fix:** Serialize execution state to the DB `context` column at checkpoints:
```go
func (stw *subtaskWorker) SaveCheckpoint(ctx context.Context) error {
    state := map[string]interface{}{
        "working_dir":    stw.subtaskCtx.Executor.GetWorkingDir(),
        "files_created":  stw.subtaskCtx.Executor.GetFilesCreated(),
        "commands_run":   stw.subtaskCtx.Executor.GetCommandCount(),
        "last_output":    stw.subtaskCtx.Executor.GetLastOutput(),
    }
    blob, _ := json.Marshal(state)
    _, err := stw.subtaskCtx.DB.UpdateSubtaskContext(ctx, database.UpdateSubtaskContextParams{
        Context: string(blob), ID: stw.subtaskCtx.SubtaskID,
    })
    return err
}
```

