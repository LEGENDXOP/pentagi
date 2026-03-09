# CHANGES_FIXER5.md — Template & Config Fixes Applied

## Summary
Applied 8 targeted fixes across 7 files: 5 template files (.tmpl), 1 Go config file, and the full execution context template.

---

## Fix 5: Remove compulsive Graphiti search in pentester.tmpl
**File:** `backend/pkg/templates/prompts/pentester.tmpl`

**Change 1 — Line ~12 (graphiti_search tag):**
- **Before:** `ALWAYS search Graphiti FIRST to check execution history and avoid redundant work`
- **After:** `Search Graphiti at the START of a new subtask to check execution history. Do NOT search before every individual command — only when beginning a new objective or when you suspect prior work exists for the current target.`

**Change 2 — Lines ~31-38 (when_to_search block):**
- **Before:** "ALWAYS search Graphiti BEFORE attempting any significant action" with 5 bullets covering every possible action
- **After:** "Search Graphiti at these KEY decision points (NOT before every command)" — 3 "do" bullets + 3 "don't" bullets including a rate limit of "no more than 3 times total per subtask"

**Rationale:** The old template caused the LLM to compulsively search before every single command, creating infinite search loops. The new version aligns with the primary_agent template's balanced approach ("ONLY when context is insufficient").

---

## Fix 6: Add execution metrics to template context
**Files:**
- `backend/pkg/templates/prompts/pentester.tmpl`
- `backend/pkg/templates/prompts/full_execution_context.tmpl`

**Change in full_execution_context.tmpl — added before closing `</execution_context>`:**
```
{{if .ExecutionMetrics}}
<execution_metrics>
  <tool_calls_count>{{.ExecutionMetrics.ToolCallCount}}</tool_calls_count>
  <elapsed_seconds>{{.ExecutionMetrics.ElapsedSeconds}}</elapsed_seconds>
  <unique_commands>{{.ExecutionMetrics.UniqueCommands}}</unique_commands>
</execution_metrics>
{{end}}
```

**Change in pentester.tmpl — added LOOP PREVENTION section before COMPLETION REQUIREMENTS:**
- New `<anti_loop_protocol>` block that renders execution metrics (when available) and provides 5 concrete loop-prevention rules
- Metrics are conditionally rendered via `{{if .ExecutionMetrics}}` so existing callers that don't populate this field are unaffected

**Note:** The backend code that populates `.ExecutionMetrics` in the template context needs to be implemented separately (this is the data-passing side; these templates are the consumption side). The templates gracefully handle the case where `.ExecutionMetrics` is nil.

---

## Fix 7: Add loop-detection logic to reflector.tmpl
**File:** `backend/pkg/templates/prompts/reflector.tmpl`

**Added new section "PROGRESS EVALUATION & LOOP DETECTION" before "AGENT'S INCORRECT RESPONSE":**
- Renders execution metrics (conditionally, same pattern as pentester.tmpl)
- New `<loop_detection_criteria>` block with 4 evaluation questions
- Key behavior change: if a loop is detected, the reflector is instructed to NOT simply redirect the agent to make more tool calls (which deepens loops), but instead tell it to change approach entirely or report as blocked
- Updated the "AGENT'S INCORRECT RESPONSE" instructions to include point 4: "If the agent appears stuck in a loop, tell it to change approach entirely or report as blocked"

**Rationale:** The reflector was previously just a format enforcer — when an agent produced text instead of tool calls, it simply told it to use tool calls. This made loops worse. Now it evaluates whether the agent is making progress before redirecting.

---

## Fix 8: Add filesystem state awareness to subtasks_generator.tmpl
**File:** `backend/pkg/templates/prompts/subtasks_generator.tmpl`

**Added after `</previous_subtasks>` block:**
- New `<workspace_state>` block (conditionally rendered via `{{if .WorkspaceFiles}}`) showing files in working directory with path, size, and modification time
- New `<execution_state>` block (conditionally rendered) — mirrors what the refiner already has
- New `<execution_logs>` block (conditionally rendered) — mirrors what the refiner already has
- Description text tells the generator to "avoid re-creating work that already exists"

**Note:** Like Fix 6, the backend code that populates `.WorkspaceFiles`, `.Cwd`, `.ExecutionState`, and `.ExecutionLogs` in the generator's template context needs to be implemented separately. The templates gracefully degrade when these fields are nil.

---

## Fix 19: Add deduplication guidance to subtasks_refiner.tmpl and refiner.tmpl
**Files:**
- `backend/pkg/templates/prompts/subtasks_refiner.tmpl`
- `backend/pkg/templates/prompts/refiner.tmpl`

**Change in subtasks_refiner.tmpl — added `<deduplication_guidance>` block after execution_logs:**
- Explicit instruction to compare each planned subtask against ALL completed subtask results
- Rules: FULLY achieved → REMOVE; PARTIALLY covered → MODIFY to cover remaining gap
- Semantic comparison guidance: "compare the semantic intent, not just the title"

**Change in refiner.tmpl — added new rule 3 "Completed Work Deduplication" in REFINEMENT RULES:**
- 5 sub-points covering full/partial overlap detection and removal
- Existing rules 3-5 renumbered to 4-6

**Rationale:** The refiner receives both completed and planned subtasks but was never told to compare them. It would keep redundant planned subtasks even when the work was already done.

---

## Fix 26: Add configurable execution limits to config.go
**File:** `backend/pkg/providers/pconfig/config.go`

**Added constants (before AgentConfig struct):**
```go
const (
    DefaultMaxToolCallsPerSubtask = 50
    DefaultSubtaskTimeoutSec      = 900  // 15 minutes
    DefaultMaxOutputSize          = 1048576 // 1 MB
)
```

**Added 3 new fields to AgentConfig struct:**
```go
MaxToolCallsPerSubtask int `json:"max_tool_calls_per_subtask,omitempty" yaml:"max_tool_calls_per_subtask,omitempty"`
SubtaskTimeoutSec      int `json:"subtask_timeout_sec,omitempty" yaml:"subtask_timeout_sec,omitempty"`
MaxOutputSize          int `json:"max_output_size,omitempty" yaml:"max_output_size,omitempty"`
```

**Added 3 getter methods with default fallbacks:**
- `GetMaxToolCallsPerSubtask()` → returns configured value or `DefaultMaxToolCallsPerSubtask` (50)
- `GetSubtaskTimeoutSec()` → returns configured value or `DefaultSubtaskTimeoutSec` (900)
- `GetMaxOutputSize()` → returns configured value or `DefaultMaxOutputSize` (1MB)

**Backward compatibility:** All new fields use `omitempty` tags, so existing configs without these fields will work unchanged. The getter methods handle nil receiver and zero values gracefully, always returning sensible defaults.

---

## Fix 38: Fix CallUsage.Merge to accumulate instead of overwrite
**File:** `backend/pkg/providers/pconfig/config.go`

**Before:**
```go
func (c *CallUsage) Merge(other CallUsage) {
    if other.Input > 0 { c.Input = other.Input }           // OVERWRITES
    if other.Output > 0 { c.Output = other.Output }         // OVERWRITES
    // ... same pattern for all 6 fields
}
```

**After:**
```go
func (c *CallUsage) Merge(other CallUsage) {
    c.Input += other.Input           // ACCUMULATES
    c.Output += other.Output         // ACCUMULATES
    c.CacheRead += other.CacheRead
    c.CacheWrite += other.CacheWrite
    c.CostInput += other.CostInput
    c.CostOutput += other.CostOutput
}
```

**Rationale:** Merge is used for cumulative token tracking across multiple LLM calls within a subtask. The old code only kept the LAST call's counts, making cost tracking inaccurate.

---

## Fix 39: Remove duplicate "TASK PLANNING STRATEGIES" in generator.tmpl
**File:** `backend/pkg/templates/prompts/generator.tmpl`

**Before:** Two separate `## TASK PLANNING STRATEGIES` sections at lines 127 and 143
- First: General flow + pentesting special case (4 items)
- Second: Detailed 4-phase breakdown (Research → Experimental → Selection → Execution)

**After:** Single merged `## TASK PLANNING STRATEGIES` section with 5 numbered items:
1. Research and Exploration Phase (detailed)
2. Experimental Approach Phase (detailed)
3. Solution Selection Phase (detailed)
4. Focused Execution Phase (detailed)
5. Special Case: Penetration Testing (preserved from first section)

**Rationale:** Duplicate headings confused the LLM about which strategy set to follow. The merged version combines the best content from both sections.

---

## Files Modified (7 total)
| File | Fixes Applied |
|------|--------------|
| `backend/pkg/templates/prompts/pentester.tmpl` | Fix 5, Fix 6 |
| `backend/pkg/templates/prompts/full_execution_context.tmpl` | Fix 6 |
| `backend/pkg/templates/prompts/reflector.tmpl` | Fix 7 |
| `backend/pkg/templates/prompts/subtasks_generator.tmpl` | Fix 8 |
| `backend/pkg/templates/prompts/subtasks_refiner.tmpl` | Fix 19 |
| `backend/pkg/templates/prompts/refiner.tmpl` | Fix 19 |
| `backend/pkg/providers/pconfig/config.go` | Fix 26, Fix 38 |
| `backend/pkg/templates/prompts/generator.tmpl` | Fix 39 |
