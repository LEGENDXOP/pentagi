# Phase 3 — Feature 3.4: Cost Tracking & Optimization

**Date:** 2026-03-09
**Status:** Implemented

## Summary

Adds in-memory cost tracking (`CostTracker`) that accumulates LLM token usage and cost per agent type across a flow's lifecycle. Integrates with the existing database-backed cost tracking (`CallUsage.UpdateCost`, `PriceInfo`) and leverages existing DB aggregation queries (`GetFlowUsageStats`, `GetUsageStatsByTypeForFlow`) to produce cost summaries in task reports. Also provides a default pricing table for common models as a fallback when providers don't supply pricing data.

---

## Architecture

### What Already Existed (Phase 1)
- `CallUsage` struct with `CostInput`/`CostOutput` fields and `UpdateCost(price)` method
- `PriceInfo` struct (per 1M tokens: Input, Output, CacheRead, CacheWrite)
- `AgentConfig.Price` — per-agent pricing in YAML/JSON config
- `updateMsgChainUsage()` in `performer.go` — calls `UpdateCost()` after each LLM call and writes to DB
- DB columns: `usage_cost_in`, `usage_cost_out` on `msgchains` table
- DB queries: `GetFlowUsageStats`, `GetTaskUsageStats`, `GetSubtaskUsageStats`, `GetUsageStatsByTypeForFlow`

### What This Feature Adds
1. **In-memory `CostTracker`** — goroutine-safe aggregator that lives in `context.Context`, accumulates usage from every LLM call in a flow
2. **Default model pricing table** — fallback `DefaultModelPricing` map for 30+ models (Anthropic, OpenAI, Google, Bedrock)
3. **Cost summary in reports** — queries DB at report time and injects cost data into reporter template
4. **Context propagation** — `WithCostTracker`/`GetCostTracker` context helpers, same pattern as `ExecutionBudget`

---

## Files Changed

### 1. NEW: `backend/pkg/providers/cost.go`

**Purpose:** Core cost tracking engine — pricing table, CostTracker, and context helpers.

**Default Pricing Table (`DefaultModelPricing`):**
Map of 30+ model names → `pconfig.PriceInfo` (per 1M tokens). Covers:
- Anthropic: Claude Opus 4, Sonnet 4, 3.5 Sonnet/Haiku, 3 Opus/Sonnet/Haiku
- OpenAI: GPT-4o, GPT-4o-mini, GPT-4 Turbo, o1/o1-mini/o3/o3-mini/o4-mini
- Google: Gemini 2.5 Pro/Flash, 2.0 Flash, 1.5 Pro/Flash
- AWS Bedrock: Claude model variants

**`LookupDefaultPricing(model string) *pconfig.PriceInfo`:**
Looks up pricing by exact match first, then prefix match for versioned model names.

**`CostTracker` struct:**
```go
type CostTracker struct {
    mu          sync.Mutex
    model       string
    byAgent     map[string]*AgentTypeCost
    totalUsage  pconfig.CallUsage
    callCount   int
}
```

**Methods:**
| Method | Description |
|--------|-------------|
| `NewCostTracker(model)` | Creates tracker for a primary model |
| `AddUsage(agentType, usage)` | Records a single LLM call's usage by agent type |
| `GetTotalCost() float64` | Returns accumulated total cost in USD |
| `GetTotalUsage() CallUsage` | Returns accumulated token counts |
| `GetCostBreakdown() CostBreakdown` | Detailed breakdown by agent type |
| `GetCostPerFinding(n) float64` | Cost divided by findings count |
| `GetCostSummary(n) CostSummary` | Structured summary for report inclusion |
| `FormatCostSummary(n) string` | Human-readable formatted summary |

**Context helpers:**
| Function | Description |
|----------|-------------|
| `WithCostTracker(ctx, ct) context.Context` | Attaches tracker to context |
| `GetCostTracker(ctx) *CostTracker` | Retrieves tracker from context (nil if absent) |

**Supporting types:**
- `CostBreakdown` — full breakdown with `ByAgentType` map
- `AgentTypeCost` — per-agent-type token counts, costs, call count
- `CostSummary` — report-ready summary with optional cost-per-finding
- `TypeCostEntry` — single row in type-level breakdown

---

### 2. NEW: `backend/pkg/providers/cost_test.go`

**Purpose:** Comprehensive unit tests for cost tracking.

**Test Coverage:**
| Test | What It Verifies |
|------|------------------|
| `TestLookupDefaultPricing_ExactMatch` | Exact model name lookup |
| `TestLookupDefaultPricing_PrefixMatch` | Prefix-based fallback matching |
| `TestLookupDefaultPricing_NotFound` | Returns nil for unknown models |
| `TestLookupDefaultPricing_Empty` | Returns nil for empty string |
| `TestCostTracker_AddUsage` | Accumulates tokens and costs correctly |
| `TestCostTracker_GetCostBreakdown` | Per-agent-type breakdown accuracy |
| `TestCostTracker_GetCostPerFinding` | Cost/finding calculation, zero-safe |
| `TestCostTracker_FormatCostSummary` | Human-readable output correctness |
| `TestCostTracker_Context` | Context attach/retrieve round-trip |
| `TestCostTracker_EmptyAgentType` | Empty agent type defaults to "unknown" |
| `TestCostTracker_ConcurrentSafety` | 100 goroutines, no races |

---

### 3. MODIFIED: `backend/pkg/providers/performer.go`

**Change:** In `updateMsgChainUsage()`, after computing cost via `usage.UpdateCost(price)`, also feed the usage to the in-memory `CostTracker` if one is attached to the context.

**Diff (conceptual):**
```go
func (fp *flowProvider) updateMsgChainUsage(...) error {
    usage := fp.GetUsage(info)
    ...
    price := fp.GetPriceInfo(optAgentType)
    if price != nil {
        usage.UpdateCost(price)
    }

+   // Feed usage to the in-memory CostTracker if one is attached to the context.
+   if ct := GetCostTracker(ctx); ct != nil {
+       ct.AddUsage(string(optAgentType), usage)
+   }

    _, err := fp.db.UpdateMsgChainUsage(...)
    ...
}
```

**Impact:** Every LLM call that already goes through `updateMsgChainUsage` now also accumulates in the CostTracker. No new code paths needed — this hooks into the existing single collection point.

---

### 4. MODIFIED: `backend/pkg/providers/provider.go`

**Change 1:** In `PerformAgentChain()`, create and attach a `CostTracker` to the context (same pattern as `ExecutionBudget`).

```go
// Create a CostTracker for this flow if one doesn't exist yet.
if GetCostTracker(ctx) == nil {
    ctx = WithCostTracker(ctx, NewCostTracker(fp.Model(optAgentType)))
}
```

**Change 2:** In `GetTaskResult()`, query DB for flow-level usage stats and inject cost summary into reporter template context.

```go
costSummaryText := fp.buildFlowCostSummary(ctx, taskID)
reporterContext["user"]["CostSummary"] = costSummaryText
```

**Change 3:** New method `buildFlowCostSummary()` that:
1. Queries `GetFlowUsageStats` for total token counts and costs
2. Queries `GetUsageStatsByTypeForFlow` for per-agent-type breakdown
3. Formats into a readable string
4. Falls back to in-memory CostTracker if DB query fails
5. Returns empty string on error (non-fatal)

---

### 5. MODIFIED: `backend/pkg/templates/prompts/task_reporter.tmpl`

**Change:** Added `<cost_summary>` XML section at the end of the template.

```xml
{{if .CostSummary}}
<cost_summary>
{{.CostSummary}}
</cost_summary>
{{end}}
```

This is conditional — only included when cost data is available.

---

### 6. MODIFIED: `backend/pkg/templates/prompts/reporter.tmpl`

**Change:** Added instruction to the reporter system prompt under "REPORT FORMULATION CRITERIA":

```
- If a `<cost_summary>` section is present in the input, include a brief
  "Resource Usage" or "Cost Summary" section at the end of your report with
  total tokens used and estimated cost in USD
```

---

## Design Decisions

### Why both DB queries AND in-memory CostTracker?

| Source | Pros | Cons |
|--------|------|------|
| DB (`GetFlowUsageStats`) | Accurate, persisted, includes all historical calls | Requires DB round-trip at report time |
| In-memory (`CostTracker`) | Real-time, available during flow execution | Lost on crash, only current session |

The primary source for reports is the DB (most accurate). The in-memory tracker serves as:
1. Fallback if DB query fails
2. Real-time access during flow execution (e.g., for budget alerts in future)
3. Per-agent-type breakdown during the flow without additional DB queries

### Why default pricing in code?

PentAGI already supports `PriceInfo` in provider configs, and many providers (OpenRouter) return cost in the API response. The `DefaultModelPricing` table serves as a third fallback for providers that don't supply pricing and aren't configured with explicit prices. It's a map — easy to update or extend.

### Why not modify CallUsage.UpdateCost?

`UpdateCost` already works correctly and respects provider-supplied costs. The default pricing table is meant for future use (e.g., `LookupDefaultPricing` could be called when `GetPriceInfo` returns nil). This change is intentionally additive — no existing behavior is altered.

---

## What's NOT Changed

- `CallUsage` struct — unchanged
- `PriceInfo` struct — unchanged
- `UpdateCost()` method — unchanged
- DB schema — no migrations needed (uses existing columns and queries)
- Existing cost tracking in `updateMsgChainUsage` — preserved, only augmented
- All other provider files (openai, anthropic, gemini, etc.) — unchanged

---

## Future Enhancements (Not in This PR)

1. **Cost budget enforcement** — Use CostTracker to enforce a max $ budget per flow (like ExecutionBudget for tool calls)
2. **Cost-per-finding in reporter** — Once finding counting is implemented, pass `findingsCount` to the reporter for cost/finding metric
3. **Auto-pricing fallback** — Wire `LookupDefaultPricing` into `updateMsgChainUsage` when `GetPriceInfo` returns nil
4. **Cost alerts** — Real-time cost threshold notifications during flow execution
5. **Cost optimization** — Model downgrade suggestions when cheaper models could handle simpler subtasks
