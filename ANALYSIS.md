# PentAGI Phase 1 — Code Analysis for Agent 2

## ARCHITECTURE OVERVIEW

```
Flow → Task → Subtasks → performAgentChain() → for{} loop → tool calls
                                                    ↑
                                                    | repeatingDetector checks each call
                                                    | execToolCall() processes each call
                                                    | barrier functions (hack_result, final_result) exit loop
```

**Key insight:** The `for{}` loop in `performAgentChain()` is INFINITE. It only exits when:
1. A barrier function is called (`executor.IsBarrierFunction(funcName)`)
2. An error occurs
3. Context is cancelled

There is NO command counter, NO time limit, NO loop detection beyond exact-match `repeatingDetector`.

---

## PROBLEM 1: repeatingDetector (CRITICAL)

### File: `backend/pkg/providers/helpers.go` (lines 38-85)

### Current Implementation:
```go
type repeatingDetector struct {
    funcCalls []llms.FunctionCall
}

func (rd *repeatingDetector) detect(toolCall llms.ToolCall) bool {
    if toolCall.FunctionCall == nil {
        return false
    }
    funcCall := rd.clearCallArguments(toolCall.FunctionCall)
    if len(rd.funcCalls) == 0 {
        rd.funcCalls = append(rd.funcCalls, funcCall)
        return false
    }
    lastToolCall := rd.funcCalls[len(rd.funcCalls)-1]
    // BUG: Only checks if LAST call is IDENTICAL (name + args)
    if lastToolCall.Name != funcCall.Name || lastToolCall.Arguments != funcCall.Arguments {
        rd.funcCalls = []llms.FunctionCall{funcCall}  // RESETS on any different call
        return false
    }
    rd.funcCalls = append(rd.funcCalls, funcCall)
    return len(rd.funcCalls) >= RepeatingToolCallThreshold  // threshold = 3
}
```

### Why It Fails:
1. **Only catches CONSECUTIVE IDENTICAL calls** — agent alternates "cat STATE.json" with "cat FINDINGS.md" → detector RESETS every time
2. **`clearCallArguments` removes `message` key** but keeps everything else — so same command with different `message` IS caught, but different commands entirely are NOT
3. **No semantic similarity** — "check STATE.json" vs "read STATE.json status" are "different" to this detector
4. **No sliding window** — it only looks at the LAST call, not patterns over time

### Proposed Fix:
Replace exact-match with a **sliding window + category-based detection**. Track last N tool calls and detect when the same CATEGORY of action repeats too often.

```go
const (
    RepeatingToolCallThreshold = 3
    SlidingWindowSize          = 10  // NEW: track last 10 calls
    CategoryRepeatThreshold    = 5   // NEW: 5+ similar calls in window = loop
)

type repeatingDetector struct {
    funcCalls    []llms.FunctionCall
    callHistory  []toolCallRecord     // NEW: sliding window
}

type toolCallRecord struct {  // NEW
    name     string
    category string  // "read_state", "terminal_attack", "search", etc.
    ts       time.Time
}

// NEW: Classify tool calls into categories
func classifyToolCall(name string, args string) string {
    // Terminal commands that read state files
    if name == "terminal" || name == "bash" || name == "execute" {
        argsLower := strings.ToLower(args)
        // Reading state/status files
        if strings.Contains(argsLower, "cat ") || strings.Contains(argsLower, "head ") ||
           strings.Contains(argsLower, "tail ") || strings.Contains(argsLower, "jq ") ||
           strings.Contains(argsLower, "grep ") {
            if strings.Contains(argsLower, "state.json") || strings.Contains(argsLower, "findings") ||
               strings.Contains(argsLower, "report") || strings.Contains(argsLower, ".cmdlog") ||
               strings.Contains(argsLower, "budget") || strings.Contains(argsLower, "evidence") {
                return "read_state"
            }
        }
        // Actual attack commands
        if strings.Contains(argsLower, "curl") || strings.Contains(argsLower, "nmap") ||
           strings.Contains(argsLower, "sqlmap") || strings.Contains(argsLower, "hydra") ||
           strings.Contains(argsLower, "nikto") || strings.Contains(argsLower, "ffuf") ||
           strings.Contains(argsLower, "nuclei") || strings.Contains(argsLower, "wpscan") {
            return "terminal_attack"
        }
        return "terminal_other"
    }
    if strings.Contains(name, "search") || strings.Contains(name, "graphiti") {
        return "search"
    }
    return "other"
}

func (rd *repeatingDetector) detect(toolCall llms.ToolCall) bool {
    if toolCall.FunctionCall == nil {
        return false
    }
    funcCall := rd.clearCallArguments(toolCall.FunctionCall)

    // Original exact-match detection (keep for backward compat)
    if len(rd.funcCalls) > 0 {
        lastToolCall := rd.funcCalls[len(rd.funcCalls)-1]
        if lastToolCall.Name == funcCall.Name && lastToolCall.Arguments == funcCall.Arguments {
            rd.funcCalls = append(rd.funcCalls, funcCall)
            if len(rd.funcCalls) >= RepeatingToolCallThreshold {
                return true
            }
        } else {
            rd.funcCalls = []llms.FunctionCall{funcCall}
        }
    } else {
        rd.funcCalls = []llms.FunctionCall{funcCall}
    }

    // NEW: Sliding window category detection
    category := classifyToolCall(funcCall.Name, funcCall.Arguments)
    rd.callHistory = append(rd.callHistory, toolCallRecord{
        name:     funcCall.Name,
        category: category,
        ts:       time.Now(),
    })

    // Keep window size bounded
    if len(rd.callHistory) > SlidingWindowSize {
        rd.callHistory = rd.callHistory[len(rd.callHistory)-SlidingWindowSize:]
    }

    // Count category occurrences in window
    categoryCount := 0
    for _, record := range rd.callHistory {
        if record.category == category {
            categoryCount++
        }
    }

    // If same category appears too often in window → loop detected
    if categoryCount >= CategoryRepeatThreshold {
        return true
    }

    return false
}
```

### Files to Change:
- `backend/pkg/providers/helpers.go` — Replace `repeatingDetector` struct and `detect()` method
- Add `import "time"` and `import "strings"` if not already present

---

## PROBLEM 2: No Command/Time Limits (CRITICAL)

### File: `backend/pkg/providers/performer.go` (lines 44-210)

### Current Loop Structure (line 94):
```go
for {
    result, err := fp.callWithRetries(ctx, chain, optAgentType, executor)
    // ... process result ...
    // ... execute tool calls ...
    if wantToStop {
        return nil
    }
    // NO COMMAND COUNTER
    // NO TIME CHECK
    // LOOPS FOREVER until barrier function or error
}
```

### Proposed Fix:
Add `context.WithTimeout` + atomic command counter at the START of `performAgentChain()`:

```go
// Add these constants at the top of performer.go
const (
    maxToolCallsPerSubtask = 50           // hard cap per subtask
    maxSubtaskDuration     = 15 * time.Minute  // hard time limit per subtask
)

// In performAgentChain(), BEFORE the for{} loop (after line 93):

// === NEW: Time limit ===
ctx, timeoutCancel := context.WithTimeout(ctx, maxSubtaskDuration)
defer timeoutCancel()

// === NEW: Command counter ===
toolCallCount := 0

// Inside the for{} loop, AFTER processing tool calls (after line 198):

// === NEW: Check command budget ===
toolCallCount += len(result.funcCalls)
if toolCallCount >= maxToolCallsPerSubtask {
    logger.Warnf("subtask reached max tool calls (%d/%d), forcing completion",
        toolCallCount, maxToolCallsPerSubtask)
    return nil  // graceful exit — subtask will be marked as finished
}
```

### Where Exactly (performer.go):
- Line 44: Function signature (no change needed)
- Line 58: Add `toolCallCount := 0` after `detector` init
- Line 93: Add `ctx, timeoutCancel := context.WithTimeout(ctx, maxSubtaskDuration)` and `defer timeoutCancel()` BEFORE the `for {`
- Line ~200 (after the `if wantToStop` block): Add `toolCallCount += len(result.funcCalls)` and the budget check

### Import Needed:
`time` should already be imported. Verify.

---

## PROBLEM 3: Rabbit Holes (linked to Problem 2)

Same fix as Problem 2 — `maxToolCallsPerSubtask = 50` and `maxSubtaskDuration = 15 * time.Minute` prevents any single subtask from running forever.

Additionally, the `repeatingDetector` improvement (Problem 1) will catch the pattern where an agent repeatedly tries variations of the same failing attack.

---

## PROBLEM 4: State Drift (MEDIUM — Phase 1 light fix)

### Current State:
- Subtask state tracked in DB: `subtask.status` (created/running/finished/failed) and `subtask.result` (free text)
- `subtasks_refiner.tmpl` only sees subtask titles/descriptions/status/results
- No filesystem awareness (doesn't see STATE.json)

### Light Fix for Phase 1:
Instead of full DB schema changes, modify `subtasks_refiner.tmpl` to include the current filesystem state in its context:

### File: `backend/pkg/templates/prompts/subtasks_refiner.tmpl`
Add this section to the template so the refiner knows what work has been done:

```
## WORKSPACE STATE AWARENESS
Before regenerating subtasks, consider the current terminal workspace state.
The agent's terminal contains files that track engagement progress.
Key files: STATE.json (current phase, attacks done), FINDINGS.md (discovered vulnerabilities).
Do NOT create subtasks that duplicate work already completed in these files.
If a subtask was marked "finished" and produced results, do NOT create a similar replacement.
```

### File: `backend/pkg/templates/prompts/pentester.tmpl`
Changes needed:
1. Remove/conditionalize the "ALWAYS search Graphiti FIRST" line (line ~20)
2. Add anti-loop instructions

Current (line ~20):
```
{{- if .GraphitiEnabled}}
<graphiti_search>ALWAYS search Graphiti FIRST to check execution history and avoid redundant work</graphiti_search>
{{- end}}
```

Change to:
```
{{- if .GraphitiEnabled}}
<graphiti_search>Search Graphiti ONLY when starting a new attack category or resuming after a break. Max 3 searches per subtask. Do NOT search before every command.</graphiti_search>
{{- end}}
```

Add new section after KNOWLEDGE MANAGEMENT:
```
## EXECUTION DISCIPLINE

<anti_loop_rules>
- NEVER read status/state files more than twice consecutively without executing an attack command between reads
- If you catch yourself wanting to "check status" or "verify progress" before acting — STOP and execute the next attack instead
- A failed attack attempt is infinitely more valuable than checking status again
- When facing multiple choices (which attack to run), pick the FIRST one and execute it. Do not deliberate.
- Sequential execution beats perfect planning
</anti_loop_rules>
```

---

## DEPENDENCY MAP

```
Problem 1 (repeatingDetector) ← standalone, no deps
Problem 2 (command counter)   ← standalone, no deps
Problem 3 (rabbit holes)      ← solved by Problem 2
Problem 4 (state drift)       ← template changes only, no Go deps
```

All fixes are INDEPENDENT — can be applied in any order.

---

## IMPLEMENTATION ORDER (safest)

1. **Problem 2 first** — Command counter + timeout in `performer.go`
   - Most impactful, simplest change (~10 lines Go)
   - Immediately stops ALL infinite loops regardless of cause
   
2. **Problem 1 second** — Semantic `repeatingDetector` in `helpers.go`
   - Catches loops BEFORE they waste 50 commands
   - More code but self-contained in one file

3. **Problem 4 third** — Template changes
   - Zero risk — only text changes in .tmpl files
   - Can be tested independently

---

## FILES TO CHANGE (summary)

| File | Change | Risk |
|------|--------|------|
| `backend/pkg/providers/performer.go` | Add timeout + command counter | LOW — additive only |
| `backend/pkg/providers/helpers.go` | Improve repeatingDetector | MEDIUM — changes existing logic |
| `backend/pkg/templates/prompts/pentester.tmpl` | Anti-loop rules, Graphiti cap | LOW — text only |
| `backend/pkg/templates/prompts/subtasks_refiner.tmpl` | Workspace awareness | LOW — text only |

Total estimated changes: ~100 lines of Go code + ~20 lines of template text.
