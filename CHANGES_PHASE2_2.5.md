# Phase 2, Upgrade 2.5 — Context Window Optimization

## Problem
After 20+ tool calls, the LLM context fills with old irrelevant tool results. The existing
chain summarizer (Phase 1 improvements) uses a head+sample+tail truncation approach — effective
for size control, but blind to **content relevance**. Security findings, vulnerability reports,
and critical errors get the same treatment as verbose `nmap` output or repetitive `ls` listings.

**Core issue:** ALL old tool results stay in context equally, competing for limited token budget.

## Solution: Intelligent Context Manager

A new `ContextManager` (`context_manager.go`) that classifies, tracks, and prunes context items
based on **priority** rather than just age or size.

### Priority Levels

| Priority | Value | Description | Pruning Policy |
|----------|-------|-------------|---------------|
| `PriorityFindings` | 0 | Contains FINDING, CRITICAL, VULNERABILITY, CVE-*, EXPLOIT | **NEVER pruned** |
| `PriorityErrors` | 1 | Contains [ERROR], failed, FATAL, etc. | Keep recent; old errors → first line only |
| `PriorityRecentTools` | 2 | Last 5 tool results | Always kept intact |
| `PriorityOldTools` | 3 | Older tool results (<2000 chars) | Summarized to head+tail (3 lines each) |
| `PriorityNoise` | 4 | Verbose old output (>2000 chars) | **Dropped entirely** |

### Classification Rules

Content is auto-classified by keyword matching (case-insensitive for findings):
- **Findings keywords:** FINDING, CRITICAL, VULNERABILITY, CVE-, EXPLOIT, [VULN], HIGH/MEDIUM/LOW SEVERITY
- **Error keywords:** [ERROR], failed, error:, FATAL, panic:, permission denied, not found, timed out, connection refused
- **Default:** Classified as recent tools, then reclassified by age on each pruning pass

### Pruning Strategy (Waterfall)

When total estimated tokens exceed the budget (default 32K tokens):
1. **Drop PriorityNoise** entirely
2. **Summarize PriorityOldTools** — keep first + last 3 lines with omission marker
3. **Summarize PriorityErrors** — keep first error line only
4. **NEVER touch** PriorityFindings or PriorityRecentTools

### Reference Tracking

When a tool call's arguments contain substrings from previous tool results, those
results are "referenced" and bumped to PriorityRecentTools — protecting them from
pruning even if they're old.

## Files Changed

### New: `backend/pkg/providers/context_manager.go`
- `ContextPriority` type and priority constants
- `ContextItem` struct with content, priority, timestamp, token estimate, reference tracking
- `ContextManager` struct with thread-safe item management
- `NewContextManager(maxTokens)` — constructor with configurable token budget
- `Add(content, toolName)` — auto-classifies and tracks content
- `AddWithPriority(content, priority, toolName)` — explicit priority override
- `MarkReferenced(contentSubstring)` — bumps matching items to recent
- `ReclassifyByAge()` — re-evaluates priorities based on insertion order
- `Prune()` — waterfall pruning, returns surviving items
- `GetTotalTokens()`, `GetItemCount()`, `GetItemsByPriority()`, `Stats()` — telemetry
- `ExtractFindings(content)` — extracts finding lines with ±1 context line
- `ContainsFindings(content)` — quick check for findings keywords
- Helper functions: `classifyContent`, `estimateTokens`, `summarizeToHeadTail`, `extractFirstErrorLine`

### New: `backend/pkg/providers/context_manager_test.go`
- Tests for token estimation, content classification, pruning behavior
- Tests for findings extraction and reference tracking
- Tests for the critical invariant: **findings are NEVER pruned**

### Modified: `backend/pkg/providers/performer.go`
- Added `ctxManager = NewContextManager(defaultMaxContextTokens)` initialization in `performAgentChain`
- After each tool call result is added to the chain:
  - `ctxManager.Add(response, funcName)` — tracks the result
  - `ctxManager.MarkReferenced(toolCall.FunctionCall.Arguments)` — cross-references
- Before each `callWithRetries` (LLM call):
  - Reclassifies items by age
  - Logs context stats when over budget
  - Prunes if needed (for telemetry/awareness; chain summarizer handles actual message reduction)

### Modified: `backend/pkg/providers/handlers.go`
- `GetSummarizeResultHandler` now calls `ExtractFindings(result)` before truncation
- Findings block is prepended in `{PRESERVED_FINDINGS}...{END_PRESERVED_FINDINGS}` tags
- Token budget for head/middle/tail sampling is reduced proportionally to make room for findings
- This ensures the LLM summarizer always receives findings in full, even for very long tool outputs

## Design Decisions

1. **Parallel to existing summarizer:** The ContextManager runs alongside the existing `csum.Summarizer`,
   not replacing it. The csum summarizer handles structural chain management (section-based); the
   ContextManager adds content-awareness. They complement each other.

2. **Token estimation via char/4:** Simple but effective. More accurate tokenizers would add
   a dependency and latency; for pruning decisions, this heuristic is sufficient.

3. **Thread-safe with mutex:** The ContextManager is used within a single `performAgentChain`
   goroutine, but we use a mutex for safety since referenced items could be marked from
   concurrent contexts in future.

4. **Findings are SACRED:** The non-negotiable rule — even if we're over budget after all
   pruning, findings and recent tools are never touched. The caller must deal with the
   budget overshoot (which in practice is fine since the LLM context window is much larger
   than our conservative token budget).

5. **Waterfall pruning order:** Noise → Old tools → Errors. This maximizes information
   retention: findings are always there, recent context is always there, and old noise
   is sacrificed first.

## Non-Breaking

- No changes to existing types, interfaces, or public APIs
- No new dependencies
- Existing chain structure and message format unchanged
- ContextManager is additive — removing it reverts to pre-2.5 behavior
- All existing tests pass (no behavioral changes to the chain)
