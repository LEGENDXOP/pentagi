# Phase 2 — Upgrade 2.3: Smart Reflector with Real Loop Detection

**Date:** 2026-03-09
**Status:** Implemented (pending compilation/test)

---

## Overview

Upgrades the reflector from a simple "Tool Call Workflow Enforcer" to a smart loop-detecting coordinator that can proactively intervene when the agent exhibits repetitive behavior.

## Changes

### 1. `backend/pkg/providers/helpers.go` — ToolHistory Tracker

**New types and functions added:**

- `ToolHistoryEntry` — Records a single tool invocation with truncated arguments (200 chars) and result (500 chars), error flag, and timestamp
- `ToolHistory` — Thread-safe (mutex-protected) bounded ring buffer of tool call records
- `NewToolHistory(maxSize int) *ToolHistory` — Constructor with configurable capacity (default: 50)
- `(*ToolHistory).Add(entry)` — Append with auto-truncation and eviction
- `(*ToolHistory).GetLast(n int) []ToolHistoryEntry` — Get last N entries
- `(*ToolHistory).Len() int` — Current entry count
- `(*ToolHistory).GetErrorRate(n int) float64` — Error fraction in last N calls
- `(*ToolHistory).GetPatternScore() float64` — Shannon-entropy-based diversity score (0.0 = diverse, 1.0 = all identical) over last 10 entries
- `(*ToolHistory).GetMostFrequentInLast(n int) (string, int)` — Most repeated tool name and its count
- `(*ToolHistory).FormatForPrompt() string` — Human-readable summary with warnings for LLM injection
- `(*ToolHistory).ShouldTriggerProactiveReflector(totalCalls int) (bool, string)` — Check all trigger conditions and return reason

**Added imports:** `math`, `sync`

**Trigger conditions for proactive reflector:**
1. Every 10 tool calls (periodic checkpoint)
2. Error rate > 50% in last 5 calls
3. Pattern score > 0.7 (highly repetitive tool usage)
4. Same command > 3 times in last 10 calls

### 2. `backend/pkg/providers/performer.go` — Proactive Reflector Integration

**`performAgentChain` changes:**
- Added `toolHistory = NewToolHistory(defaultToolHistorySize)` to loop state variables
- Inside tool call execution loop: every tool call result is recorded via `toolHistory.Add()` with error detection (including repeating-detector responses)
- **New proactive reflector block** after tool call batch processing:
  - Calls `toolHistory.ShouldTriggerProactiveReflector(toolCallCount)`
  - On trigger: builds synthetic status report with `toolHistory.FormatForPrompt()` and invokes `performReflector`
  - If reflector returns corrective tool calls, they replace the current result for next iteration
  - Proactive reflector failure is non-fatal (logged, execution continues)

**`performReflector` signature change:**
```go
// Before:
func (fp *flowProvider) performReflector(..., metrics ExecutionMetrics) (*callResult, error)

// After:
func (fp *flowProvider) performReflector(..., metrics ExecutionMetrics, toolHistory *ToolHistory) (*callResult, error)
```

**`performReflector` body changes:**
- Injects `ToolHistorySummary` (formatted prompt string) into reflector template context
- Injects `LoopDetection` map with pre-computed signals: `PatternScore`, `ErrorRate`, `MostFrequentTool`, `MostFrequentCount`, `IsLoopLikely`
- All 3 call sites updated to pass `toolHistory`

### 3. `backend/pkg/templates/prompts/reflector.tmpl` — Enhanced Template

**Backward compatible:** All existing format enforcement logic preserved. New sections are guarded by `{{if}}` blocks.

**New template sections:**
- `{{if .ToolHistorySummary}}` — Renders full tool execution history summary
- `{{if .LoopDetection}}` — Renders loop detection analysis with signal values
- `{{if .LoopDetection.IsLoopLikely}}` — Shows ⚠ LOOP DETECTED block with:
  - Specific criteria that triggered detection
  - Three decision options: **CONTINUE**, **CHANGE_APPROACH**, **STOP**
  - Decision guidance questions
- Enhanced `execution_metrics` block now includes `error_count`, `repeated_calls`, `last_tool`
- Conditional step 4 in agent correction section: when loop is detected, forces the reflector to choose a decision rather than just retrying

## Design Decisions

1. **Non-blocking proactive checks** — `ShouldTriggerProactiveReflector` is O(n) over a small window (max 10 entries). No network calls until trigger fires.
2. **Thread-safe ToolHistory** — Uses `sync.Mutex` since entries are added from the main agent loop (single goroutine in practice, but safe for future use).
3. **Truncation at write time** — Arguments and results are truncated on `Add()`, not on read, to bound memory usage.
4. **Shannon entropy for pattern detection** — More nuanced than counting duplicates. Detects subtle patterns like alternating between 2 tools.
5. **Non-fatal proactive reflector** — If the proactive check fails, the agent loop continues normally. This prevents the safety feature from becoming a liability.
6. **Backward compatible template** — All new sections are `{{if}}` guarded. If `ToolHistory` is nil, the template renders identically to before.

## Files Modified

| File | Type | Lines Changed (approx) |
|------|------|----------------------|
| `backend/pkg/providers/helpers.go` | Add | ~190 lines (ToolHistory types + methods) |
| `backend/pkg/providers/performer.go` | Modify | ~45 lines (proactive reflector, tool recording, signature) |
| `backend/pkg/templates/prompts/reflector.tmpl` | Rewrite | Full rewrite preserving original structure, ~160 lines |

## Testing Notes

- ToolHistory methods can be unit-tested independently (no external deps)
- Proactive reflector can be tested by mocking a ToolHistory with pathological patterns
- Template rendering can be tested by passing `LoopDetection` map with various signal values
- The `gt` template function is a Go builtin and works with `int` values from `map[string]any`
