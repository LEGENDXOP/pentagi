# Phase 2 — Upgrade 2.2: Execution Metrics Pipeline

**Status: IMPLEMENTED** — All code changes applied to source files.

## Overview

Pass real-time execution metrics into every template context so that templates with
`{{if .ExecutionMetrics}}` blocks (pentester, reflector, full_execution_context) are
actually populated at runtime.

## Architecture Analysis

### Template Rendering Pipeline

The rendering pipeline has **three distinct timing patterns**:

1. **Pre-loop rendering** (pentester, coder, installer, searcher system prompts):
   - Rendered once in `handlers.go` handler functions (e.g., `GetPentesterHandler`)
   - System prompt becomes `chain[0]` via `restoreChain`
   - The `performAgentChain` loop then uses this static chain
   - **Problem**: Metrics are zero at render time since execution hasn't started

2. **In-loop rendering** (reflector):
   - Rendered inside `performReflector`, called from within the `performAgentChain` loop
   - Has access to runtime state
   - **Opportunity**: Can receive live metrics directly

3. **Context preparation** (full_execution_context):
   - Rendered by `prepareExecutionContext` before the agent loop
   - Used as a string embedded in other prompts
   - **Observation**: Only gets initial metrics (zero), but full_execution_context
     is more about task/subtask structure than runtime telemetry

### Key Decision: System Prompt Refresh

Since pentester.tmpl's `{{if .ExecutionMetrics}}` block is in the system prompt
rendered before the loop, we add a **system prompt refresh mechanism** inside
`performAgentChain`. Before each LLM call, the system message (chain[0]) is
updated with fresh metrics. This is lightweight because:
- We only re-render when metrics have changed (after tool calls)
- The system message is always `chain[0]` per the chain convention
- Go's `text/template` rendering is fast (~microseconds for a single template)

## Changes

### File 1: `backend/pkg/providers/helpers.go`

**Add `ExecutionMetrics` struct** (after the `repeatingDetector` type):

```go
// ExecutionMetrics tracks real-time execution telemetry for template rendering.
// Templates reference these fields via {{.ExecutionMetrics.FieldName}} in conditional blocks.
type ExecutionMetrics struct {
	ToolCallCount  int      `json:"tool_call_count"`
	ElapsedSeconds int      `json:"elapsed_seconds"`
	UniqueCommands []string `json:"unique_commands"`
	ErrorCount     int      `json:"error_count"`
	LastToolName   string   `json:"last_tool_name"`
	RepeatedCalls  int      `json:"repeated_calls"`
}
```

**Add helper method** to track unique commands:

```go
// AddCommand records a tool/command name, maintaining uniqueness.
func (em *ExecutionMetrics) AddCommand(name string) {
	for _, cmd := range em.UniqueCommands {
		if cmd == name {
			return
		}
	}
	em.UniqueCommands = append(em.UniqueCommands, name)
}
```

**Add `Snapshot` method** to produce a point-in-time copy for template rendering:

```go
// Snapshot returns a copy with elapsed time updated to the current moment.
func (em *ExecutionMetrics) Snapshot(startTime time.Time) ExecutionMetrics {
	snap := *em
	snap.ElapsedSeconds = int(time.Since(startTime).Seconds())
	return snap
}
```

---

### File 2: `backend/pkg/providers/performer.go`

#### 2a. Update `performAgentChain` — initialize and maintain metrics

**After the existing `toolCallCount` declaration** (around line 67), add:

```go
var (
    wantToStop           bool
    detector             = newRepeatingDetector()
    summarizerHandler    = fp.GetSummarizeResultHandler(taskID, subtaskID)
    toolCallCount        int
    summarizerFailures   int
    // Execution metrics for template rendering
    metrics              = &ExecutionMetrics{}
    metricsStartTime     = time.Now()
)
```

#### 2b. Track metrics during tool execution

**Inside the tool call loop** (after `funcName := toolCall.FunctionCall.Name` around line 170),
add metrics tracking:

```go
funcName := toolCall.FunctionCall.Name
metrics.AddCommand(funcName)
metrics.LastToolName = funcName

response, err := fp.execToolCall(ctx, chainID, idx, result, detector, executor)

if toolTypeMapping[funcName] != tools.AgentToolType {
    fp.storeToolExecutionToGraphiti(
        ctx, groupID, optAgentType, toolCall, response, err, executor, taskID, subtaskID, chainID,
    )
}

if err != nil {
    metrics.ErrorCount++
    // ... existing error handling
}
```

**After the repeating detector check in `execToolCall`** (where it returns the
"tool call is repeating" response), increment `RepeatedCalls` on the metrics.
Since `execToolCall` doesn't have access to metrics directly, we track this in
`performAgentChain` by checking detector state. Alternative: check after
`execToolCall` returns and look for the repeating response pattern.

Better approach — track in `performAgentChain` after the tool call:

```go
response, err := fp.execToolCall(ctx, chainID, idx, result, detector, executor)

// Track repeated calls by checking if response indicates repetition
if strings.HasPrefix(response, "tool call '") && strings.HasSuffix(response, "' is repeating, please try another tool") {
    metrics.RepeatedCalls++
}
```

#### 2c. Update `toolCallCount` sync with metrics

After the existing `toolCallCount += len(result.funcCalls)`:

```go
toolCallCount += len(result.funcCalls)
metrics.ToolCallCount = toolCallCount
```

#### 2d. Refresh system prompt with metrics before each LLM call

**Before `result, err := fp.callWithRetries(...)` in the main loop**, update the
system message in the chain:

```go
// Update system prompt with fresh execution metrics
if toolCallCount > 0 && len(chain) > 0 {
    if sysMsg := chain[0]; sysMsg.Role == llms.ChatMessageTypeSystem && len(sysMsg.Parts) > 0 {
        if text, ok := sysMsg.Parts[0].(llms.TextContent); ok {
            updated := injectMetricsIntoSystemPrompt(text.Text, metrics.Snapshot(metricsStartTime))
            chain[0].Parts[0] = llms.TextContent{Text: updated}
        }
    }
}
```

This requires a new helper function (see below).

#### 2e. Pass metrics to `performReflector`

Update the `performReflector` call signature to accept metrics:

```go
result, err = fp.performReflector(
    ctx, optAgentType, chainID, taskID, subtaskID,
    append(chain, reflectorMsg),
    fp.getLastHumanMessage(chain), result.content, executionContext,
    executor, 1, metrics.Snapshot(metricsStartTime))
```

---

### File 3: `backend/pkg/providers/performer.go` — `performReflector` changes

#### 3a. Update signature

```go
func (fp *flowProvider) performReflector(
	ctx context.Context,
	optOriginType pconfig.ProviderOptionsType,
	chainID int64,
	taskID, subtaskID *int64,
	chain []llms.MessageContent,
	humanMessage, content, executionContext string,
	executor tools.ContextToolsExecutor,
	iteration int,
	metrics ExecutionMetrics,      // NEW PARAMETER
) (*callResult, error) {
```

#### 3b. Add metrics to reflector context map

In the `reflectorContext` construction:

```go
reflectorContext := map[string]map[string]any{
    "user": {
        "Message":          content,
        "BarrierToolNames": executor.GetBarrierToolNames(),
    },
    "system": {
        "BarrierTools":      executor.GetBarrierTools(),
        "CurrentTime":       getCurrentTime(),
        "ExecutionContext":   executionContext,
        "ExecutionMetrics":  &metrics,           // NEW
    },
}
```

#### 3c. Update recursive call

```go
return fp.performReflector(ctx, optOriginType, chainID, taskID, subtaskID, chain,
    humanMessage, result.content, executionContext, executor, iteration+1, metrics)
```

---

### File 4: `backend/pkg/providers/helpers.go` — System prompt metrics injection

**Add helper function** for surgically injecting/updating metrics in the system prompt:

```go
// injectMetricsIntoSystemPrompt replaces or inserts the <execution_metrics> block
// in a rendered system prompt. This avoids full template re-rendering.
func injectMetricsIntoSystemPrompt(systemPrompt string, metrics ExecutionMetrics) string {
	metricsBlock := fmt.Sprintf(
		"<execution_metrics>\n"+
			"  <tool_calls_made>%d</tool_calls_made>\n"+
			"  <elapsed_seconds>%d</elapsed_seconds>\n"+
			"  <unique_commands_used>%v</unique_commands_used>\n"+
			"</execution_metrics>",
		metrics.ToolCallCount,
		metrics.ElapsedSeconds,
		metrics.UniqueCommands,
	)

	// Try to replace existing block
	startTag := "<execution_metrics>"
	endTag := "</execution_metrics>"
	startIdx := strings.Index(systemPrompt, startTag)
	endIdx := strings.Index(systemPrompt, endTag)
	if startIdx >= 0 && endIdx > startIdx {
		return systemPrompt[:startIdx] + metricsBlock + systemPrompt[endIdx+len(endTag):]
	}

	// Insert before </anti_loop_protocol> if present
	insertPoint := strings.Index(systemPrompt, "</anti_loop_protocol>")
	if insertPoint >= 0 {
		return systemPrompt[:insertPoint] + metricsBlock + "\n" + systemPrompt[insertPoint:]
	}

	// Fallback: append to end
	return systemPrompt + "\n" + metricsBlock
}
```

---

### File 5: `backend/pkg/providers/handlers.go` — Initial metrics in handler contexts

**For `GetPentesterHandler`** (and similarly for GetCoderHandler, GetInstallerHandler, etc.),
add `ExecutionMetrics` to the system context map so the initial render has the
conditional block present (even if zero-valued):

```go
"system": {
    // ... existing fields ...
    "ExecutionMetrics": &ExecutionMetrics{}, // zero-valued, will be refreshed in loop
},
```

This ensures the initial `{{if .ExecutionMetrics}}` evaluates to true and renders
the `<execution_metrics>` XML block (with zeros), which
`injectMetricsIntoSystemPrompt` can then find and replace on subsequent iterations.

---

### File 6: `backend/pkg/providers/helpers.go` — `prepareExecutionContext` changes

**Add `ExecutionMetrics` to the template context** in `prepareExecutionContext`:

```go
executionContextRaw, err := fp.prompter.RenderTemplate(templates.PromptTypeFullExecutionContext, map[string]any{
    "Task":              tasksInfo.Task,
    "Tasks":             tasksInfo.Tasks,
    "CompletedSubtasks": subtasksInfo.Completed,
    "Subtask":           subtasksInfo.Subtask,
    "PlannedSubtasks":   subtasksInfo.Planned,
    "ExecutionMetrics":  nil, // populated at runtime via reflector; nil here skips the block
})
```

Note: `prepareExecutionContext` is called before the agent loop, so metrics are
not yet available. The `{{if .ExecutionMetrics}}` guard in the template will skip
the block when nil. The reflector template (rendered in-loop) is where live
metrics actually surface.

---

## Template Field Mapping

| Template Field | Struct Field | Source |
|---|---|---|
| `.ExecutionMetrics.ToolCallCount` | `ToolCallCount` | `toolCallCount` from performAgentChain loop |
| `.ExecutionMetrics.ElapsedSeconds` | `ElapsedSeconds` | `time.Since(metricsStartTime)` computed in Snapshot() |
| `.ExecutionMetrics.UniqueCommands` | `UniqueCommands` | Tracked via AddCommand() on each tool call |
| `.ExecutionMetrics.ErrorCount` | `ErrorCount` | Incremented on tool execution errors |
| `.ExecutionMetrics.LastToolName` | `LastToolName` | Set to funcName on each tool call |
| `.ExecutionMetrics.RepeatedCalls` | `RepeatedCalls` | Detected via repeating response pattern |

## Metrics Flow Diagram

```
performAgentChain() starts
  │
  ├─ metrics = &ExecutionMetrics{}
  ├─ metricsStartTime = time.Now()
  │
  └─ LOOP:
       │
       ├─ [Refresh system prompt chain[0] with metrics.Snapshot()]
       │
       ├─ callWithRetries() → LLM call
       │
       ├─ If no tool calls → performReflector(metrics.Snapshot())
       │     └─ reflector template gets .ExecutionMetrics
       │
       ├─ For each tool call:
       │     ├─ metrics.AddCommand(funcName)
       │     ├─ metrics.LastToolName = funcName
       │     ├─ execToolCall()
       │     ├─ if error → metrics.ErrorCount++
       │     └─ if repeated → metrics.RepeatedCalls++
       │
       ├─ metrics.ToolCallCount = toolCallCount
       │
       └─ continue LOOP
```

## What This Does NOT Change

- **Template files** — no template changes needed; Phase 1 already added the blocks
- **Template required fields lists** — `ExecutionMetrics` is optional (guarded by `{{if}}`)
- **`performSimpleChain`** — only used for non-agentic single-shot calls; no metrics needed
- **Budget system** — independent concern; metrics just observe, budget enforces
- **`toolCallCount`** — still the canonical counter; `metrics.ToolCallCount` mirrors it

## Testing Considerations

1. `injectMetricsIntoSystemPrompt` should be unit-tested with:
   - System prompt containing existing `<execution_metrics>` block (replace)
   - System prompt without block but with `</anti_loop_protocol>` (insert)
   - System prompt with neither (append)
2. `ExecutionMetrics.AddCommand` should deduplicate
3. `ExecutionMetrics.Snapshot` should compute elapsed time correctly
4. Template rendering with populated `ExecutionMetrics` should produce valid XML blocks
