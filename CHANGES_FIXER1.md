# CHANGES_FIXER1.md — Applied Fixes Log

## Fixes Applied by fixer1-performer subagent

### Fix 1: Wire up dead `toolCallCount` in performer.go
- **File:** `backend/pkg/providers/performer.go`
- **Change:** Added `toolCallCount += len(result.funcCalls)` and a limit check (`>= maxToolCallsPerSubtask`) after processing all tool calls in the `for{}` loop, before the `wantToStop` check. The constant `maxToolCallsPerSubtask = 50` already existed but was never enforced.
- **Effect:** Subtask now hard-stops after 50 tool calls, preventing infinite loops.

### Fix 15: Add context deadline check at top of agent loop in performer.go
- **File:** `backend/pkg/providers/performer.go`
- **Change:** Added `ctx.Err()` check at the top of the `for{}` loop, before calling `callWithRetries`. If the context is done (cancelled or deadline exceeded), the loop returns immediately with an error.
- **Effect:** Prevents wasted work between I/O calls when the context deadline has already passed.

### Fix 32: Don't swallow summarizer errors in performer.go
- **File:** `backend/pkg/providers/performer.go`
- **Change:** Added `summarizerFailures` counter variable. On each summarizer error, the counter increments. After 3 consecutive failures, the function returns with a fatal error instead of continuing with an ever-growing unsummarized chain. Counter resets to 0 on success.
- **Effect:** Prevents unbounded chain growth in memory when the summarizer is persistently broken, which would eventually cause OOM.

### Fix 37: Fix stream ID leaks on retry in performer.go
- **File:** `backend/pkg/providers/performer.go`
- **Change:** In `callWithRetries`, before allocating a new `streamID` on retry, the code now flushes/closes the previous abandoned stream by sending a `StreamMessageChunkTypeFlush` message. Also resets `result.funcCalls`, `result.content`, `result.info`, and `result.thinking` to avoid accumulating stale data from failed attempts.
- **Effect:** Clients no longer see abandoned streams that received partial data then went silent. Each retry properly cleans up its predecessor.

### Fix 4: Fix broken retry `select` in performSimpleChain — remove `default` case
- **File:** `backend/pkg/providers/performers.go`
- **Change:** Removed the `default:` case from the `select` statement in the retry loop of `performSimpleChain`. In Go, a `default` case makes `select` non-blocking, meaning the 5-second `time.After` delay was dead code — retries happened instantly.
- **Effect:** Failed LLM calls now actually wait 5 seconds between retries instead of hammering the provider in a tight loop.

### Fix 33: Don't drop CreateMsgChain error in performers.go
- **File:** `backend/pkg/providers/performers.go`
- **Change:** Added `if err != nil { return "", fmt.Errorf(...) }` check after the `CreateMsgChain` call at the end of `performSimpleChain`. Previously, `err` was assigned but never checked — the function always returned `nil` error.
- **Effect:** DB write failures in `performSimpleChain` are now properly propagated, preventing silent data loss during chain persistence.

### Fix 35: Handle zero-valued result structs in performers.go
- **File:** `backend/pkg/providers/performers.go`
- **Change:** Added empty-result validation after `performAgentChain` returns successfully in 6 performer functions:
  - `performCoder`: checks `codeResult.Result == ""`
  - `performInstaller`: checks `maintenanceResult.Result == ""`
  - `performMemorist`: checks `memoristResult.Result == ""`
  - `performPentester`: checks `hackResult.Result == ""`
  - `performSearcher`: checks `searchResult.Result == ""`
  - `performEnricher`: checks `enricherResult.Result == ""`
- **Effect:** If the agent chain exits via a barrier function (like `AskUser`) that doesn't populate the result struct, the caller now gets a clear error instead of silently receiving an empty string.

### Fix 3: Add global budget for recursive agent delegation
- **Files:** New file `backend/pkg/providers/budget.go`, modified `backend/pkg/providers/provider.go`, modified `backend/pkg/providers/performer.go`
- **Change:** 
  1. Created `ExecutionBudget` type with thread-safe `Consume(n)` method tracking total tool calls (max 200) and wall-clock time (max 45 min) across the entire delegation tree.
  2. Budget is attached to context via `WithBudget`/`GetBudget` using context values.
  3. In `PerformAgentChain` (provider.go), a budget is created if none exists in the context (top-level entry point). Sub-agents inherit it automatically.
  4. In the `performAgentChain` loop (performer.go), `budget.Consume()` is called after each iteration to check global limits.
- **Effect:** A single user request can no longer cascade through primary→pentester→coder→installer chains consuming unlimited resources. Total tool calls across all sub-agents capped at 200, total wall time at 45 minutes.

### Fix 22: Add sync for performResult closure access in provider.go
- **File:** `backend/pkg/providers/provider.go`
- **Change:**
  1. Replaced plain `performResult` variable with `atomic.Int32` (`performResultVal`) for thread-safe read/write from the barrier closure and the return path.
  2. Wrapped `executorAgent.End()` in a `sync.Once` (`endAgentOnce` / `endAgent` func) to prevent double-close of the agent span. The barrier's deferred `End()` and the outer function's `End()` can no longer race.
  3. Replaced the post-`performAgentChain` error path from `wrapErrorEndAgentSpan(ctx, executorAgent, ...)` to use `endAgent(...)` directly, ensuring the `sync.Once` is respected.
- **Effect:** Eliminates data race on `performResult` and prevents double-ending the agent observation span (which could corrupt tracing data).

