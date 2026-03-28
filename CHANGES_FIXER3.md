# CHANGES_FIXER3.md — Tools & Terminal System Fixes

Applied by: fixer3-tools subagent
Date: 2026-03-08
Files modified:
- `backend/pkg/tools/terminal.go`
- `backend/pkg/tools/tools.go`
- `backend/pkg/tools/executor.go`

---

## Fix 10: Command Blocklist in terminal.go ✅

**What:** Added `blockedCommandPatterns` — a slice of compiled regexps that catch obviously destructive commands before execution.

**Patterns blocked:**
- `curl|wget ... | sh` (pipe-to-shell)
- `rm -rf /` and `rm -fr /` (filesystem wipe)
- `mkfs /dev/...` (disk formatting)
- Fork bomb pattern `:(){ :|:& };:`
- `> /dev/sd*` (disk device overwrite)
- `shutdown`, `reboot`, `halt`, `poweroff`

**Added function:** `validateCommand(command string) error` — called at the top of `ExecCommand()` before any Docker exec is created.

**Note:** Blocklist is conservative for a pentesting tool — only blocks host/container-destructive patterns. Legitimate attack commands against targets are not blocked.

---

## Fix 11: Output Size Limit in terminal.go ✅

**What:** Added 512KB output size cap to `getExecResult()`.

**Changes:**
- `io.Copy` replaced with `io.LimitReader(resp.Reader, maxOutputSize+1)` to cap reads at 512KB+1
- After reading, if output exceeds 512KB, it's truncated with `[OUTPUT TRUNCATED: exceeded 512KB limit]` notice
- Prevents OOM from commands producing unbounded output (e.g., `find / -type f`, `cat /dev/urandom`)

---

## Fix 12: Path Restriction for WriteFile in terminal.go ✅

**What:** Added path validation at the start of `WriteFile()`.

**Rules:**
- Writes must be within `docker.WorkFolderPathInContainer` (`/work`) or `/tmp/`
- Explicitly blocks writes to `/etc/`, `/proc/`, `/sys/`, `/root/`, `/dev/` even if somehow nested under allowed prefixes
- Uses `filepath.Clean()` to prevent path traversal attacks (e.g., `/work/../../etc/passwd`)

---

## Fix 13: Concurrency Guard (Mutex) in terminal.go ✅

**What:** Added `sync.Mutex` field `mu` to the `terminal` struct. `ExecCommand()` acquires `t.mu.Lock()` at the top and defers `t.mu.Unlock()`.

**Effect:** Enforces the documented "only one command at a time" guarantee. If the LLM issues parallel tool calls, they serialize instead of interfering with each other.

---

## Fix 14: Rate Limiting for Tool Execution in executor.go ✅

**What:** Added per-tool-type rate limiters using `golang.org/x/time/rate` (already in go.mod as indirect dep).

**Rate limits:**
| Tool Type | Rate | Burst |
|-----------|------|-------|
| EnvironmentToolType (terminal, file) | 5 rps | 10 |
| SearchNetworkToolType (google, tavily, etc.) | 2 rps | 5 |
| SearchVectorDbToolType (memory, graphiti) | 5 rps | 10 |
| AgentToolType (coder, pentester, etc.) | 1 rps | 3 |

**Implementation:** Singleton `map[ToolType]*rate.Limiter` initialized via `sync.Once`. Rate check happens in `customExecutor.Execute()` before any handler invocation. Uses `limiter.Wait(ctx)` so the call blocks until the rate allows (or ctx is cancelled).

---

## Fix 30: Terminal Errors Properly Prefixed in terminal.go ✅

**What:** Changed `wrapCommandResult()` error path from `"terminal tool '%s' handled with error: %v"` to `"[ERROR] terminal tool '%s' failed: %v"`.

**Why:** The old format made errors indistinguishable from success in the tool call result string. The `[ERROR]` prefix allows the system (and downstream code) to programmatically detect that a tool call actually failed, even though it returns `(string, nil)` to avoid crashing the agent loop.

**Also:** Includes partial output (up to 4KB) when available alongside the error.

---

## Fix 31: ReadFile Limit Reduced from 100MB to 1MB in terminal.go ✅

**What:** Changed `maxReadFileSize` from `100 * 1024 * 1024` to `1 * 1024 * 1024`.

**Why:** A 100MB file sent to the LLM context would consume hundreds of thousands of tokens and degrade performance. 1MB is already generous for text files meant for LLM consumption.

**Also added:** Binary file detection — checks first 512 bytes for null bytes. If found, returns a human-readable message instead of garbage binary data: `"file 'X' appears to be binary (N bytes), cannot display as text"`.

---

## Fix 40: Release() Cleans Up All Flow Containers in tools.go ✅

**What:** Replaced the `TODO`-marked primary-only container deletion with full cleanup using `fte.db.GetFlowContainers()`.

**Changes:**
- Queries all containers for the flow from the database
- Iterates and deletes each one, collecting errors
- Falls back to primary-only deletion if the DB query fails
- Handles edge case where DB returns empty list (still tries primary)
- Logs individual container deletion failures as warnings instead of hard-failing

**Prevents:** Orphaned secondary containers leaking Docker resources after flow completion.

---

## Fix 42: Replace context.Background() with context.TODO() in tools.go ✅

**What:** Replaced all 7 `context.Background()` calls in `tools.go` with `context.TODO()`.

**Locations (7 total):**
1. `SetEmbedder()` → `pgvector.New(context.TODO(), ...)`
2-7. Six `GetFlowPrimaryContainer(context.TODO(), ...)` calls in:
   - `GetAssistantExecutor()`
   - `GetInstallerExecutor()`
   - `GetPentesterExecutor()`
   - `GetGeneratorExecutor()`
   - `GetRefinerExecutor()`
   - `GetMemoristExecutor()`

**Why `context.TODO()` instead of a proper ctx:** These are interface methods (`FlowToolsExecutor`) that don't include `ctx context.Context` in their signature. Changing the interface signature would be a larger refactor. `context.TODO()` is the Go convention signaling "a context should be passed here when the interface is updated" — unlike `context.Background()` which implies no context is needed.

**Each call has a comment:** `// Fix 42: TODO — pass ctx when interface is updated`

---

## Import Changes

### terminal.go
Added imports: `regexp`, `sync`

### executor.go
Added imports: `sync`, `golang.org/x/time/rate`

### tools.go
No new imports needed (already had `context`).

---

## Summary

| Fix | File | Type | Risk |
|-----|------|------|------|
| 10 | terminal.go | Command blocklist | Medium — may block legitimate pentest commands |
| 11 | terminal.go | Output size cap (512KB) | Low — truncation notice shown |
| 12 | terminal.go | Write path restriction | Low — only blocks sensitive paths |
| 13 | terminal.go | Mutex for serial exec | Low — enforces documented behavior |
| 14 | executor.go | Rate limiting | Medium — may slow rapid legitimate tool use |
| 30 | terminal.go | Error prefix `[ERROR]` | None — pure improvement |
| 31 | terminal.go | ReadFile 100MB→1MB + binary detect | Low — 1MB still generous for text |
| 40 | tools.go | Release() full cleanup | Low — strictly more thorough |
| 42 | tools.go | context.Background→TODO | None — signals intent, no behavior change |
