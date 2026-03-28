# PentAGI Telegram Notification System — Audit Report

**Date:** 2026-03-28  
**Branch:** `Updates`  
**Total notification code:** ~1,529 lines across 4 files in `backend/pkg/notifications/`

---

## 1. Architecture Summary

The Telegram notification system is a **backend-only, opt-in feature** with no frontend UI, no database storage, and no GraphQL schema involvement. It works as follows:

1. **Configuration** — 4 env vars (`TELEGRAM_NOTIFY`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `TELEGRAM_QUIET_TZ_OFFSET`) control whether notifications are active.
2. **Initialization** — On startup, `main.go` creates a `TelegramNotifier` (raw HTTP sender) and wraps it in a `NotificationManager` (filtering, batching, quiet hours, dedup).
3. **Integration** — The `NotificationManager` is passed down through `FlowController` → `flowWorkerCtx` → `notifications.WrapPublisher()`. Each flow gets a `NotifyingPublisher` decorator that intercepts flow/task/agent events and emits Telegram notifications.
4. **Message Delivery** — `TelegramNotifier` uses a buffered channel queue (100 slots), a single worker goroutine, and 3-second rate limiting between sends. Messages are sent via `POST /bot<token>/sendMessage` with HTML parse mode.
5. **Smart Container Monitoring** — The `NotifyingPublisher` also monitors terminal log output for writes to `FINDINGS.md`, `STATE.json`, and `HANDOFF.md` inside Docker containers, reads those files via `docker cp`, diffs them against previous state, and sends progress updates.

### Data Flow

```
Flow events (FlowUpdated, TaskUpdated, TerminalLogAdded, AgentLogAdded)
    ↓
NotifyingPublisher (decorator pattern, intercepts + forwards)
    ↓
NotificationManager (filtering, dedup, batching, quiet hours)
    ↓
TelegramNotifier (rate-limited queue → HTTP POST to Telegram API)
```

---

## 2. Complete File Reference

### 2.1 Core Notification Package — `backend/pkg/notifications/`

#### `telegram.go` (171 lines)
**Purpose:** Low-level Telegram Bot API HTTP client with async queue and rate limiting.

| Lines | Description |
|-------|-------------|
| 16-20 | Constants: API base URL, 3s rate limit, queue size 100, max message 4096 chars, 10s HTTP timeout |
| 23-28 | `telegramSendRequest` struct — JSON body for sendMessage |
| 30-34 | `telegramResponse` struct — minimal API response parsing |
| 37-46 | `TelegramNotifier` struct — token, chatID, HTTP client, buffered channel queue, done channel, WaitGroup |
| 49-62 | `NewTelegramNotifier()` — constructor, starts worker goroutine |
| 65-81 | `Send()` — enqueues message, truncates at 4096 chars, drops if queue full |
| 85-88 | `Close()` — signals worker shutdown, waits for drain |
| 91-114 | `worker()` — main loop: dequeue → send → rate-limit tick; drains on shutdown |
| 117-126 | `drainQueue()` — sends remaining messages at shutdown (no rate limiting) |
| 129-170 | `sendMessage()` — HTTP POST to Telegram API, error logging |

#### `notifier.go` (490 lines)
**Purpose:** Central notification hub — filtering, dedup, finding batching, quiet hours, message formatting.

| Lines | Description |
|-------|-------------|
| 14-26 | `EventType` enum: FlowStatusChange, FindingDiscovered, PhaseChange, FlowError |
| 28-34 | `FindingSeverity` enum: CRITICAL, HIGH, MEDIUM, LOW, INFO |
| 36-69 | `NotificationEvent` struct — polymorphic event payload with flow, finding, phase, and completion fields |
| 71-77 | Constants: 60s batch window, 3 finding threshold, quiet hours 0-8 |
| 79-100 | `NotificationManager` struct — telegram ref, sync.Map for dedup, batch maps, quiet TZ offset |
| 102-109 | `findingBatch` struct — accumulator for finding events per flow |
| 104-115 | `NewNotificationManager()` — constructor |
| 118-138 | `Notify()` — entry point; drops if disabled; dispatches async via goroutine |
| 141-157 | `Close()` — flushes pending batches, closes TelegramNotifier |
| 160-178 | `processEvent()` — routes events to type-specific handlers with panic recovery |
| 181-207 | `handleFlowStatus()` — running/finished/failed notifications; quiet hours suppress "running" |
| 210-271 | `handleFinding()` — severity filter (MEDIUM+), dedup by findingID, CRITICAL bypasses batch & quiet; timer-based batching |
| 274-292 | `flushBatchLocked()` — sends single or batched finding messages |
| 295-304 | `handlePhaseChange()` — quiet-hours filtered phase transition messages |
| 307-311 | `handleFlowError()` — always sends (no quiet hours filter) |
| 313-317 | `isQuietHours()` — checks if current hour (adjusted by TZ offset) is 0-8 |
| 319-417 | Message formatting functions: `formatCriticalFinding`, `formatSingleFinding`, `formatBatchFindings`, `formatPhaseChange`, `formatFlowComplete`, `formatFlowFailed`, `formatFlowError` |
| 419-433 | `formatDuration()`, `severityEmoji()` helpers |
| 435-453 | `MapSeverity()` — string → FindingSeverity conversion |
| 484-489 | `escapeHTML()` — escapes `&`, `<`, `>` for Telegram HTML mode |

#### `publisher.go` (808 lines)
**Purpose:** Decorator that wraps `FlowPublisher` to intercept events and emit notifications.

| Lines | Description |
|-------|-------------|
| 29-52 | `NotifyingPublisher` struct — wraps inner publisher, tracks state for dedup and container monitoring |
| 55-73 | `WrapPublisher()` — factory; returns raw publisher if notifier inactive |
| 77-80 | Delegated `FlowContext` methods (GetFlowID, SetFlowID, etc.) |
| 84-89 | `FlowCreated()` — pass-through, records flow start time |
| 93-103 | `FlowUpdated()` — pass-through + calls `notifyFlowStatus()` |
| 105-160 | `notifyFlowStatus()` — dedup via `sync.Map`, emits running/finished/failed events (each at most once) |
| 164-175 | `TaskUpdated()` — pass-through + notifies on task failure + scans subtasks for findings |
| 177-247 | Pass-through methods for all other publisher events (Assistant, Screenshot, Provider, APIToken, Settings, etc.) |
| 207-215 | `TerminalLogAdded()` — pass-through + detects state file writes → triggers container read |
| 222-227 | `AgentLogAdded()` — pass-through + scans agent log result for findings |
| 253-293 | `scanSubtasksForFindings()` — iterates subtasks, calls `scanTextForFindings()` |
| 295-435 | `scanTextForFindings()` — regex-free multi-pattern finding extraction (markdown headers, bracket tags, F-xxx IDs, VULN_TYPE tags, severity+context keywords) |
| 437-464 | `isFindingID()` — checks `F-001:` pattern |
| 466-517 | `checkPhaseFromContext()` — extracts "phase" from subtask context JSON, emits phase change events |
| 521-566 | `isStateFileWrite()` — detects terminal log entries indicating writes to FINDINGS.md/STATE.json/HANDOFF.md |
| 568-603 | `scheduleContainerRead()` — debounced (10s) + rate-limited (30s min) container file reading |
| 605-668 | `processContainerState()` — diffs FINDINGS.md, parses STATE.json, detects HANDOFF.md changes; rate-limits progress messages to 1 per 2 min |
| 670-695 | `diffFindings()` — simple line-count-based diff (new lines at end = appended) |
| 697-772 | `PentestState` struct + `formatStateJSON()` — parses STATE.json and formats for Telegram |
| 774-788 | `formatGenericState()` — fallback for unexpected STATE.json schemas |
| 791-808 | `formatNewFindings()` — formats delta findings with 1500 char cap |
| (end) | `hashContent()` — SHA256-based content hashing for HANDOFF.md change detection |

#### `container_reader.go` (60 lines)
**Purpose:** Reads files from Docker containers via `docker cp` (tar extraction).

| Lines | Description |
|-------|-------------|
| 17-20 | `ReadContainerFile()` — reads a single file from a container with 64KB size limit |
| 22-58 | Implementation: `CopyFromContainer` → tar reader → extract first file → return content |

### 2.2 Configuration — `backend/pkg/config/config.go`

| Lines | Description |
|-------|-------------|
| 223-227 | Config struct fields: `TelegramBotToken`, `TelegramChatID`, `TelegramNotify` (default false), `TelegramQuietTZOffset` (default 0) |

### 2.3 Application Entry Point — `backend/cmd/pentagi/main.go`

| Lines | Description |
|-------|-------------|
| 111-127 | Telegram initialization: logs config, creates `TelegramNotifier` + `NotificationManager` if all 3 env vars set, sends test ping "🔔 PentAGI notifications active" |
| 155-157 | Shutdown: calls `notifier.Close()` to flush pending messages |

### 2.4 Controller Integration — `backend/pkg/controller/`

#### `flows.go`
| Lines | Description |
|-------|-------------|
| 14 | Import `pentagi/pkg/notifications` |
| 54 | `FlowController` interface: `GetNotificationManager()` method |
| 66 | `flowController` struct: `notifier` field |
| 82-93 | `NewFlowController()` — accepts `notifier` param, stores it |
| 108-109 | `GetNotificationManager()` — getter |
| 126, 176, 223, 341 | `notifier` passed to child `flowWorkerCtx` structs when creating/loading/resuming flows |

#### `flow.go`
| Lines | Description |
|-------|-------------|
| 17 | Import `pentagi/pkg/notifications` |
| 83 | `flowWorkerCtx` struct: `notifier` field |
| 203-206 | `WrapPublisher()` call when creating a new flow run |
| 372-375 | `WrapPublisher()` call when loading/resuming an existing flow |

#### `flow_control.go`
| Lines | Description |
|-------|-------------|
| 280-285 | `notifyHandlers()` — **NOT Telegram-related.** This is an internal state-change handler dispatch for `FlowControlManager`. Named "notify" but has nothing to do with Telegram. |

### 2.5 Docker Compose — `docker-compose.yml`

| Lines | Description |
|-------|-------------|
| 97 | `TELEGRAM_NOTIFY=${TELEGRAM_NOTIFY:-false}` |
| 98 | `TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN:-}` |
| 99 | `TELEGRAM_CHAT_ID=${TELEGRAM_CHAT_ID:-}` |
| 100 | `TELEGRAM_QUIET_TZ_OFFSET=${TELEGRAM_QUIET_TZ_OFFSET:-99}` |

### 2.6 Non-Code References

| File | Lines | Description |
|------|-------|-------------|
| `README.md` | 11 | Badge linking to Telegram community group (`t.me/+Ka9i6CNwe71hMWQy`) — **not related to the notification system** |

### 2.7 Files with NO Telegram References

- **Frontend** (`frontend/`) — Zero Telegram references. No UI for configuring Telegram notifications.
- **GraphQL schema** — No queries/mutations/subscriptions for Telegram settings.
- **Database migrations** (`backend/migrations/sql/`) — No Telegram-related tables or columns.
- **`.env.example`** — Does **not** contain Telegram env vars (they're missing from the example file).
- **Tests** — No test files exist anywhere in `backend/pkg/notifications/`.

---

## 3. Problems & Issues Identified

### 🔴 Critical Issues

#### P1: Docker-Compose `TELEGRAM_QUIET_TZ_OFFSET` Default is `99`
**File:** `docker-compose.yml:100`  
**Problem:** The default value is `99`, which means quiet hours effectively never apply (hour 0-8 check at UTC+99 = nonsensical). However, `config.go:227` has `envDefault:"0"`. The docker-compose value **overrides** the Go default, so anyone using docker-compose gets broken quiet hours.  
**Impact:** Users who set `TELEGRAM_NOTIFY=true` without explicitly setting `TELEGRAM_QUIET_TZ_OFFSET` will **never** have quiet hours, even if they intended to.  
**Fix:** Change docker-compose default to empty string `${TELEGRAM_QUIET_TZ_OFFSET:-}` or `0` to match the Go default.

#### P2: `.env.example` Missing Telegram Variables
**File:** `.env.example`  
**Problem:** The 4 Telegram env vars are **not listed** in `.env.example`, making the feature undiscoverable. Users have to read the Go code or docker-compose to know these exist.  
**Fix:** Add a `# Telegram Notifications (Optional)` section to `.env.example`.

#### P3: No Unit Tests
**Files:** `backend/pkg/notifications/` (all 4 files)  
**Problem:** Zero test files. No tests for:
- Message formatting correctness
- Finding extraction patterns (high false positive risk)
- Batching/dedup logic
- Quiet hours calculation
- Rate limiting behavior
- Container file diffing
**Impact:** Any refactor is high-risk; edge cases in finding extraction are untested.

### 🟠 High-Severity Issues

#### P4: Finding Extraction Has High False Positive Risk
**File:** `publisher.go:295-435`  
**Problem:** Pattern 5 (line ~394) triggers on any line containing BOTH a severity keyword AND a context keyword. Example: `"The MEDIUM-difficulty FINDING of this research..."` would trigger a false positive. The pattern matching is very greedy.  
**Impact:** Noisy Telegram notifications for non-vulnerability text that happens to contain severity + context keywords.

#### P5: `sentFindings` sync.Map Never Cleaned Up
**File:** `notifier.go:83` (`sentFindings sync.Map`)  
**Problem:** Finding dedup keys are stored forever in the `sync.Map`. For long-running instances processing many flows with many findings, this is an unbounded memory leak.  
**Fix:** Either use a TTL-based cache or clear entries when a flow finishes.

#### P6: `emittedFindings` sync.Map Never Cleaned Up
**File:** `publisher.go:44` (`emittedFindings sync.Map`)  
**Problem:** Same as P5 but scoped per `NotifyingPublisher`. Since publishers are per-flow, this is less severe but still leaks if a single flow produces thousands of finding-like lines.

#### P7: Typo in Constant Name
**File:** `telegram.go:20`  
**Problem:** `telegramHTTPTimout` should be `telegramHTTPTimeout`.  
**Impact:** Cosmetic, but indicates lack of review.

### 🟡 Medium-Severity Issues

#### P8: Bot Token Logged in Plaintext
**File:** `main.go:123`  
**Problem:** `logrus.WithField("chat_id", cfg.TelegramChatID).Info(...)` — chat_id is logged. While chat_id is less sensitive than the bot token, the token itself flows through the URL (`telegramAPIBase + t.token`) and could appear in debug logs or error traces.  
**Recommendation:** Mask bot token in any log output.

#### P9: No Retry Logic on Telegram API Failures
**File:** `telegram.go:129-170`  
**Problem:** `sendMessage()` has no retry logic. If Telegram returns 429 (rate limited) or 5xx, the message is silently lost. The `Retry-After` header is not checked.  
**Fix:** Add exponential backoff with 1-2 retries for transient errors (429, 500, 502, 503).

#### P10: `drainQueue()` Has No Rate Limiting
**File:** `telegram.go:117-126`  
**Problem:** On shutdown, `drainQueue()` sends all remaining messages as fast as possible without the 3-second rate limit. If 100 messages are queued, this could trigger Telegram's rate limiter.  
**Fix:** Add a small delay between drain messages, or limit drain to N messages.

#### P11: Container File Reading Creates Background Context
**File:** `publisher.go:595-600`  
**Problem:** `scheduleContainerRead()` creates `context.Background()` detached from the flow context. If the application is shutting down, these reads can hang for up to 15 seconds before the timeout expires.  
**Fix:** Pass a cancellable context derived from the flow's lifecycle.

#### P12: `diffFindings()` Is Naive
**File:** `publisher.go:670-695`  
**Problem:** The diff logic assumes new content is always appended at the end. If the agent rewrites FINDINGS.md with content re-ordered, the function returns the entire file as "new". This can cause duplicate notifications for already-seen findings.

#### P13: HTML Escaping Incomplete
**File:** `notifier.go:484-489`  
**Problem:** `escapeHTML()` only escapes `&`, `<`, `>`. It doesn't escape `"` or `'`, which could cause issues in certain HTML contexts (though Telegram's HTML mode is limited, so this is low-risk in practice).

### 🟢 Low-Severity Issues

#### P14: `processContainerState` Directly Calls `telegram.Send()` Bypassing NotificationManager
**File:** `publisher.go:657-658`  
**Problem:** `p.notifier.telegram.Send(msg)` is called directly, bypassing the `NotificationManager.Notify()` pathway. This means container-based progress updates don't benefit from quiet hours filtering, batching, or any future middleware added to `Notify()`.  
**Fix:** Add a `SendRaw()` method to `NotificationManager` that respects quiet hours, or route through `Notify()` with a new event type.

#### P15: No Frontend UI for Telegram Configuration
**Problem:** Telegram settings can only be configured via env vars. There's no admin UI to:
- Enable/disable notifications
- Set bot token / chat ID
- Configure quiet hours
- View notification history

#### P16: Single Chat ID Only
**File:** `config.go:225`  
**Problem:** `TelegramChatID` is a single string. You can't send to multiple chats (e.g., separate channels for critical vs. informational).

#### P17: `lastFindingsText` Capped at 50KB But Not Documented
**File:** `publisher.go:673-676`  
**Problem:** The 50KB cap on stored findings text is a silent truncation that could cause diff issues — if findings text exceeds 50KB, the stored version is tail-truncated, and the next diff will re-emit old findings as "new".

---

## 4. Suggestions for Refactoring

### Short-Term (Bug Fixes)
1. **Fix docker-compose default** for `TELEGRAM_QUIET_TZ_OFFSET` — change `99` to `0` or empty
2. **Add Telegram vars to `.env.example`** with documentation comments
3. **Fix the typo** `telegramHTTPTimout` → `telegramHTTPTimeout`
4. **Add basic retry** (1-2 attempts) for 429/5xx in `sendMessage()`

### Medium-Term (Robustness)
5. **Add unit tests** for all formatting functions, finding extraction, batching, and quiet hours
6. **Clean up `sentFindings`** — add a periodic cleanup or use a bounded LRU cache
7. **Route container progress through NotificationManager** instead of direct `telegram.Send()`
8. **Add `Retry-After` handling** for Telegram 429 responses
9. **Improve finding extraction** — add negative patterns to reduce false positives (e.g., require findings to be in structured output sections, not arbitrary text)

### Long-Term (Features)
10. **Add a notification provider interface** — abstract `TelegramNotifier` behind an interface so you can add Discord, Slack, email, etc. later
11. **Add frontend settings page** — let users configure notification preferences in the UI
12. **Multi-channel support** — allow different chat IDs for different severity levels
13. **Notification history** — store sent notifications in the database for audit/review
14. **Per-flow notification preferences** — let users opt in/out of notifications per flow
15. **Webhook support** — generic webhook endpoint as an alternative to Telegram-specific integration

---

## 5. File Inventory Summary

| File | Lines | Role |
|------|-------|------|
| `backend/pkg/notifications/telegram.go` | 171 | Telegram HTTP client + async queue |
| `backend/pkg/notifications/notifier.go` | 490 | Notification hub (filtering, batching, formatting) |
| `backend/pkg/notifications/publisher.go` | 808 | Event interceptor decorator + container monitoring |
| `backend/pkg/notifications/container_reader.go` | 60 | Docker container file reader |
| `backend/pkg/config/config.go` | 4 lines (223-227) | Config struct fields |
| `backend/cmd/pentagi/main.go` | 17 lines (111-127, 155-157) | Init + shutdown |
| `backend/pkg/controller/flows.go` | ~15 lines scattered | NotificationManager plumbing |
| `backend/pkg/controller/flow.go` | ~8 lines scattered | WrapPublisher integration |
| `docker-compose.yml` | 4 lines (97-100) | Env var pass-through |
| **Total** | **~1,577 lines** | |

### Files with NO Telegram involvement:
- `frontend/` — completely absent
- `backend/migrations/sql/` — no migrations
- GraphQL schema — no types/queries
- `.env.example` — missing (should be added)
- Test files — none exist
