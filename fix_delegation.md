# Fix: Delegation Blocking Doom Loop

## Root Cause Analysis

### The Problem
When agents approach their subtask time limit (<15 minutes remaining), `checkDelegationAllowed()` returns a "DELEGATION BLOCKED" message. This message is returned as a **successful tool result** (`return msg, nil`), not an error. The LLM receives it as conversational text, acknowledges it, but then tries delegation again with a slightly rephrased question — 26+ times in Flow 15, wasting 20 minutes.

### Why the Repeating Detector Doesn't Catch It

The `repeatingDetector.detect()` uses a `(name + args)` hash to detect repeats. Each delegation attempt has a **different `question` field** (the LLM rephrases each time), so the hash never matches. The `clearCallArguments()` function only strips the `"message"` key — `"question"` is preserved, making each delegation call appear unique.

Additionally, delegation tools aren't classified as read-only or write operations, so they DO go through `detect()` — but the varying arguments mean the threshold is never reached.

### The Core Design Flaw

**The system returns delegation blocks as informational text and trusts the LLM to stop.** But LLMs don't reliably follow "do NOT retry" instructions, especially under pressure (approaching deadline, incomplete work). The LLM perceives delegation as the correct strategy and keeps trying with different phrasings, hoping one will work.

The current approach has three layers of defense, all of which fail:
1. **Message text says "Do NOT retry"** → LLM ignores it
2. **Repeating detector** → can't detect it (different args each time)
3. **Time warning injection** → fires once at <20 min, but by then the loop is already running

### Evidence

**Flow 15 (Subtask 95):** 26 blocked delegation attempts over 20 minutes (messages 1439-1507). Each attempt had "Only Xm remaining" with decreasing time. The pentester agent kept trying to delegate HTTP recon to coder/installer instead of running `curl` commands directly.

**Flow 17 (Subtask 105):** 10+ blocked delegations to installer (to fix playwright-extra). Each attempt was blocked due to time pressure, but the agent kept retrying.

### The Delegation Call Chain

```
LLM calls "coder" tool with question="write a script to..."
  → execToolCall() in performer.go
    → repeatingDetector.detect() → false (unique args)
    → executor.Execute() → GetCoderHandler in handlers.go
      → checkDelegationAllowed() → "DELEGATION BLOCKED: Only 10m remaining..."
      → return msg, nil  ← SUCCESS, not error
    → response added to chain as tool result
  → LLM sees response, rephrases, tries again
```

---

## Proposed Fix: Multi-Layer Delegation Block Enforcement

The fix has **three components** that work together. Any one of them would significantly reduce the loop, but all three together make it robust.

### Fix 1: Delegation Block Counter in Handler (Primary Fix)

Track consecutive delegation blocks per agent type within a single `performAgentChain` execution. After N blocked attempts (2 is sufficient — the first tells the agent, the second confirms it understood), replace the informational message with a **hard synthetic directive** that forces the agent to use direct tools.

**File: `handlers.go`**

Add a delegation block tracker that lives in the handler closure:

```go
// delegationBlockTracker tracks consecutive blocked delegation attempts
// within a single agent chain execution. After maxBlocks attempts, the
// response escalates from informational to imperative.
type delegationBlockTracker struct {
	counts map[string]int // agent_name → consecutive block count
	mu     sync.Mutex
}

func newDelegationBlockTracker() *delegationBlockTracker {
	return &delegationBlockTracker{
		counts: make(map[string]int),
	}
}

const maxDelegationBlocksBeforeEscalation = 2

// recordBlock increments the block count for the given agent and returns
// the escalated response if the threshold has been exceeded.
// Returns (escalatedMsg, shouldEscalate).
func (dt *delegationBlockTracker) recordBlock(agentName, baseMsg string) (string, bool) {
	dt.mu.Lock()
	defer dt.mu.Unlock()
	dt.counts[agentName]++
	count := dt.counts[agentName]

	if count > maxDelegationBlocksBeforeEscalation {
		totalAttempts := 0
		for _, c := range dt.counts {
			totalAttempts += c
		}
		return fmt.Sprintf(
			"DELEGATION PERMANENTLY BLOCKED (attempt %d for %s, %d total across all agents). "+
				"The %s agent is NOT available — this will NOT change no matter how you rephrase the request. "+
				"You MUST complete the remaining work DIRECTLY:\n"+
				"- Use the terminal tool to run commands (curl, nmap, python3, etc.)\n"+
				"- Use heredoc to write files: cat > /work/file.md << 'EOF' ... EOF\n"+
				"- Use the file tool with action=update_file to create/update files\n"+
				"If your current subtask objective requires delegation that is blocked, "+
				"summarize what you've accomplished so far and call the result tool to finish.",
			count, agentName, totalAttempts, agentName,
		), true
	}
	return baseMsg, false
}
```

Then modify each delegation handler to use it. The tracker needs to be created once per `performAgentChain` execution and passed through context or through the handler closures. The cleanest approach is to create it in the handler factory and share it via closure:

**Changes to `GetCoderHandler`, `GetInstallerHandler`, `GetPentesterHandler`:**

```diff
 func (fp *flowProvider) GetCoderHandler(ctx context.Context, taskID, subtaskID *int64) (tools.ExecutorHandler, error) {
+	// Shared delegation block tracker across all handlers in this chain.
+	// This is safe because each performAgentChain creates its own set of handlers.
+	delegationTracker := getDelegationTracker(ctx)
+
 	// ... existing code ...

 	coderHandler := func(ctx context.Context, action tools.CoderAction) (string, error) {
 		if msg := checkDelegationAllowed(ctx, "coder"); msg != "" {
 			logrus.WithContext(ctx).WithField("depth", getNestingDepth(ctx)).Warn("coder delegation blocked: " + msg)
-			return msg, nil
+			escalated, _ := delegationTracker.recordBlock("coder", msg)
+			return escalated, nil
 		}
```

The tracker should be stored in context so all handlers in the same chain share state:

```go
// delegationTrackerKey is a context key for the per-chain delegation block tracker.
type delegationTrackerKey struct{}

// withDelegationTracker attaches a delegation tracker to the context.
func withDelegationTracker(ctx context.Context, dt *delegationBlockTracker) context.Context {
	return context.WithValue(ctx, delegationTrackerKey{}, dt)
}

// getDelegationTracker retrieves the delegation tracker from context.
// Returns a new tracker if none is found (defensive — should always be set).
func getDelegationTracker(ctx context.Context) *delegationBlockTracker {
	if dt, ok := ctx.Value(delegationTrackerKey{}).(*delegationBlockTracker); ok {
		return dt
	}
	return newDelegationBlockTracker()
}
```

And attach it in `performAgentChain` (in `performer.go`):

```diff
 func (fp *flowProvider) performAgentChain(
 	ctx context.Context,
 	// ... params ...
 ) error {
+	// Create a per-chain delegation block tracker so that handlers can
+	// count consecutive blocked delegation attempts and escalate responses.
+	ctx = withDelegationTracker(ctx, newDelegationBlockTracker())
+
 	// ... rest of function ...
```

### Fix 2: Teach the Repeating Detector About Delegation Tools (Secondary Fix)

The `clearCallArguments` function currently only strips the `"message"` key. For delegation tools (coder, installer, pentester, maintenance), the `"question"` field should ALSO be stripped so that all delegation calls to the same agent type hash identically. This lets the existing repeat detector catch the pattern.

**File: `helpers.go`**

```diff
 func (rd *repeatingDetector) clearCallArguments(toolCall *llms.FunctionCall) llms.FunctionCall {
 	var v map[string]any
 	if err := json.Unmarshal([]byte(toolCall.Arguments), &v); err != nil {
 		return *toolCall
 	}

 	delete(v, "message")
+
+	// For delegation tools, strip the "question" field so that repeated
+	// delegation attempts (with different phrasings) hash to the same key.
+	// This allows the repeating detector to catch delegation loops where
+	// the agent retries with rephrased questions.
+	switch toolCall.Name {
+	case "coder", "installer", "maintenance", "pentester":
+		delete(v, "question")
+	}

 	canonical, err := json.Marshal(v)
 	if err != nil {
 		return *toolCall
 	}

 	return llms.FunctionCall{
 		Name:      toolCall.Name,
 		Arguments: string(canonical),
 	}
 }
```

With this change, all `coder` calls will hash to `coder + {}`, hitting the repeat threshold after `RepeatingToolCallThreshold` (likely 3-4) consecutive attempts. The detector will then return the "tool call is repeating, please try another tool" message.

**Note:** This fix alone isn't sufficient because the repeat detector uses a sliding window and threshold — it takes several attempts before triggering. Fix 1 is faster (triggers on attempt 3). But Fix 2 provides a backstop and also prevents the tools from being executed (saving the overhead of entering the handler).

### Fix 3: Inject Delegation-Specific Warning Earlier (Tertiary Fix)

The current time warning in `performAgentChain` fires at <20 minutes. But by then, the agent may have already been looping for several minutes. Add a **delegation-specific escalation injection** that fires when the delegation tracker detects repeated blocks.

**File: `performer.go`** — in the main `performAgentChain` loop, after processing tool call results:

```diff
+		// Check if delegation blocks are accumulating and inject a corrective
+		// human-role message. This is a belt-and-suspenders approach on top of
+		// the escalated handler responses from delegationBlockTracker.
+		delegationTracker := getDelegationTracker(ctx)
+		if totalBlocks := delegationTracker.totalBlocks(); totalBlocks >= 3 && !delegationEscalationInjected {
+			delegationEscalationInjected = true
+			escalationMsg := fmt.Sprintf(
+				"[DELEGATION UNAVAILABLE — %d attempts blocked]\n"+
+					"All agent delegation (coder, installer, pentester, maintenance) is currently blocked due to time constraints. "+
+					"These tools WILL NOT work for the remainder of this subtask.\n\n"+
+					"AVAILABLE alternatives:\n"+
+					"1. terminal — run any command directly (curl, python3, nmap, etc.)\n"+
+					"2. file (action=update_file) — write/update files directly\n"+
+					"3. terminal with heredoc — cat > /work/file.md << 'EOF' ... EOF\n"+
+					"4. Result tool — save your findings and finish the subtask\n\n"+
+					"Choose one of these alternatives NOW.",
+				totalBlocks,
+			)
+			chain = append(chain, llms.MessageContent{
+				Role: llms.ChatMessageTypeHuman,
+				Parts: []llms.ContentPart{
+					llms.TextContent{Text: escalationMsg},
+				},
+			})
+			if err := fp.updateMsgChain(ctx, chainID, chain, rollLastUpdateTime()); err != nil {
+				logger.WithError(err).Error("failed to update msg chain after delegation escalation")
+			}
+			logger.WithField("total_blocks", totalBlocks).Warn("injected delegation escalation message")
+		}
```

Add the `totalBlocks()` method to the tracker:

```go
func (dt *delegationBlockTracker) totalBlocks() int {
	dt.mu.Lock()
	defer dt.mu.Unlock()
	total := 0
	for _, c := range dt.counts {
		total += c
	}
	return total
}
```

And declare the flag at the top of `performAgentChain`:

```diff
 	var (
 		wantToStop           bool
 		detector             = newRepeatingDetector()
 		// ... existing vars ...
+		delegationEscalationInjected bool
 	)
```

---

## Complete Diff Summary

### `handlers.go`

```go
// ADD: New type and constructor (before checkDelegationAllowed or at package level)

type delegationBlockTracker struct {
	counts map[string]int
	mu     sync.Mutex
}

func newDelegationBlockTracker() *delegationBlockTracker {
	return &delegationBlockTracker{
		counts: make(map[string]int),
	}
}

const maxDelegationBlocksBeforeEscalation = 2

func (dt *delegationBlockTracker) recordBlock(agentName, baseMsg string) (string, bool) {
	dt.mu.Lock()
	defer dt.mu.Unlock()
	dt.counts[agentName]++
	count := dt.counts[agentName]

	if count > maxDelegationBlocksBeforeEscalation {
		totalAttempts := 0
		for _, c := range dt.counts {
			totalAttempts += c
		}
		return fmt.Sprintf(
			"DELEGATION PERMANENTLY BLOCKED (attempt %d for %s, %d total across all agents). "+
				"The %s agent is NOT available — this will NOT change no matter how you rephrase the request. "+
				"You MUST complete the remaining work DIRECTLY:\n"+
				"- Use the terminal tool to run commands (curl, nmap, python3, etc.)\n"+
				"- Use heredoc to write files: cat > /work/file.md << 'EOF' ... EOF\n"+
				"- Use the file tool with action=update_file to create/update files\n"+
				"If your current subtask objective requires delegation that is blocked, "+
				"summarize what you've accomplished so far and call the result tool to finish.",
			count, agentName, totalAttempts, agentName,
		), true
	}
	return baseMsg, false
}

func (dt *delegationBlockTracker) totalBlocks() int {
	dt.mu.Lock()
	defer dt.mu.Unlock()
	total := 0
	for _, c := range dt.counts {
		total += c
	}
	return total
}

// Context key for sharing tracker across handlers in the same chain
type delegationTrackerKey struct{}

func withDelegationTracker(ctx context.Context, dt *delegationBlockTracker) context.Context {
	return context.WithValue(ctx, delegationTrackerKey{}, dt)
}

func getDelegationTracker(ctx context.Context) *delegationBlockTracker {
	if dt, ok := ctx.Value(delegationTrackerKey{}).(*delegationBlockTracker); ok {
		return dt
	}
	return newDelegationBlockTracker()
}
```

**In `GetCoderHandler`:**
```diff
 	coderHandler := func(ctx context.Context, action tools.CoderAction) (string, error) {
 		if msg := checkDelegationAllowed(ctx, "coder"); msg != "" {
 			logrus.WithContext(ctx).WithField("depth", getNestingDepth(ctx)).Warn("coder delegation blocked: " + msg)
-			return msg, nil
+			escalated, _ := getDelegationTracker(ctx).recordBlock("coder", msg)
+			return escalated, nil
 		}
```

**In `GetInstallerHandler`:**
```diff
 	installerHandler := func(ctx context.Context, action tools.MaintenanceAction) (string, error) {
 		if msg := checkDelegationAllowed(ctx, "installer"); msg != "" {
 			logrus.WithContext(ctx).WithField("depth", getNestingDepth(ctx)).Warn("installer delegation blocked: " + msg)
-			return msg, nil
+			escalated, _ := getDelegationTracker(ctx).recordBlock("installer", msg)
+			return escalated, nil
 		}
```

**In `GetPentesterHandler`:**
```diff
 	pentesterHandler := func(ctx context.Context, action tools.PentesterAction) (string, error) {
 		if msg := checkDelegationAllowed(ctx, "pentester"); msg != "" {
 			logrus.WithContext(ctx).WithField("depth", getNestingDepth(ctx)).Warn("pentester delegation blocked: " + msg)
-			return msg, nil
+			escalated, _ := getDelegationTracker(ctx).recordBlock("pentester", msg)
+			return escalated, nil
 		}
```

### `performer.go`

**At the start of `performAgentChain`:**
```diff
 func (fp *flowProvider) performAgentChain(
 	ctx context.Context,
 	optAgentType pconfig.ProviderOptionsType,
 	chainID int64,
 	taskID, subtaskID *int64,
 	chain []llms.MessageContent,
 	executor tools.ContextToolsExecutor,
 	summarizer csum.Summarizer,
 ) error {
+	// Per-chain delegation block tracker shared via context with all handlers.
+	ctx = withDelegationTracker(ctx, newDelegationBlockTracker())
+
 	ctx, span := obs.Observer.NewSpan(ctx, obs.SpanKindInternal, "providers.flowProvider.performAgentChain")
 	defer span.End()

 	var (
 		wantToStop           bool
 		detector             = newRepeatingDetector()
 		// ... existing vars ...
+		delegationEscalationInjected bool
 	)
```

**After the tool call processing loop (after `chain = append(chain, llms.MessageContent{...})` for the tool response), add:**
```diff
+		// Delegation loop breaker: if delegation blocks are accumulating,
+		// inject a one-time human-role directive telling the agent to stop.
+		if dt := getDelegationTracker(ctx); dt.totalBlocks() >= 3 && !delegationEscalationInjected {
+			delegationEscalationInjected = true
+			escalationMsg := fmt.Sprintf(
+				"[DELEGATION UNAVAILABLE — %d attempts blocked]\n"+
+					"All agent delegation (coder, installer, pentester, maintenance) is currently blocked due to time constraints. "+
+					"These tools WILL NOT work for the remainder of this subtask.\n\n"+
+					"AVAILABLE alternatives:\n"+
+					"1. terminal — run any command directly (curl, python3, nmap, etc.)\n"+
+					"2. file (action=update_file) — write/update files directly\n"+
+					"3. terminal with heredoc — cat > /work/file.md << 'EOF' ... EOF\n"+
+					"4. Result tool — save your findings and finish the subtask\n\n"+
+					"Choose one of these alternatives NOW.",
+				dt.totalBlocks(),
+			)
+			chain = append(chain, llms.MessageContent{
+				Role: llms.ChatMessageTypeHuman,
+				Parts: []llms.ContentPart{
+					llms.TextContent{Text: escalationMsg},
+				},
+			})
+			if err := fp.updateMsgChain(ctx, chainID, chain, rollLastUpdateTime()); err != nil {
+				logger.WithError(err).Error("failed to update msg chain after delegation escalation")
+			}
+			logger.WithField("total_blocks", dt.totalBlocks()).Warn("injected delegation escalation message into chain")
+		}
```

### `helpers.go`

**In `clearCallArguments`:**
```diff
 func (rd *repeatingDetector) clearCallArguments(toolCall *llms.FunctionCall) llms.FunctionCall {
 	var v map[string]any
 	if err := json.Unmarshal([]byte(toolCall.Arguments), &v); err != nil {
 		return *toolCall
 	}

 	delete(v, "message")
+
+	// Strip "question" from delegation tools so repeated delegation
+	// attempts (with rephrased questions) hash identically for detection.
+	switch toolCall.Name {
+	case "coder", "installer", "maintenance", "pentester":
+		delete(v, "question")
+	}

 	canonical, err := json.Marshal(v)
```

### Import Addition

`handlers.go` needs `"sync"` added to imports:

```diff
 import (
 	"context"
 	"encoding/json"
 	"errors"
 	"fmt"
 	"strings"
+	"sync"
 	"time"
```

---

## How the Three Fixes Work Together

**Scenario: Agent hits 15-minute mark and tries to delegate to coder**

| Attempt | Fix 1 (tracker) | Fix 2 (detector) | Fix 3 (injection) |
|---------|-----------------|-------------------|--------------------|
| 1 | Returns original "DELEGATION BLOCKED" msg | Adds `coder + {}` to history (1/threshold) | — |
| 2 | Returns original msg (count=2) | History: 2/threshold | — |
| 3 | **ESCALATES**: "PERMANENTLY BLOCKED, attempt 3" | History: 3/threshold, **may trigger detect()** | **INJECTS** human-role "DELEGATION UNAVAILABLE" |
| 4+ | Escalated msg on every attempt | `detect()` returns true → "tool call is repeating" | Already injected (one-time) |

After attempt 3:
- The agent sees THREE separate signals: the escalated tool response, the injected human message, AND potentially the repeat detector blocking the call entirely
- The combination makes it extremely unlikely the LLM continues trying

**Expected improvement:** From 26 blocked attempts (20 minutes wasted) to maximum 3-4 attempts (<2 minutes), with the agent pivoting to direct terminal commands.

---

## Caveats and Considerations

### 1. Handler Factory Timing
The delegation tracker is created in `performAgentChain` and attached to context. The handlers (GetCoderHandler, etc.) are created BEFORE `performAgentChain` is called — they're passed via the `executor`. But since the handlers receive `ctx` as a parameter on each invocation (not at creation time), the tracker will be available via `getDelegationTracker(ctx)` when the handler is actually called.

### 2. False Positives on Fix 2
Stripping the `"question"` field from delegation tools means that even LEGITIMATE sequential delegation calls (different work items delegated to the same agent type) will trigger the repeat detector. However, this is acceptable because:
- Legitimate delegation would only be blocked after threshold (3-4) consecutive calls to the same agent
- In practice, agents interleave delegation with terminal/file calls
- The scenario where an agent legitimately needs to call the same delegation tool 4+ times in a row without any other tool call in between is extremely rare

### 3. Thread Safety
The `delegationBlockTracker` uses a `sync.Mutex` because in theory multiple goroutines could call handlers concurrently (if the LLM returns multiple tool calls in one response). This is defensive — in practice, tool calls are processed sequentially in the `for idx, toolCall := range result.funcCalls` loop.

### 4. Tracker Lifetime
The tracker is per-`performAgentChain` invocation, which is per-subtask. It resets between subtasks, which is correct — delegation may be available in a future subtask with more time.

### 5. Does NOT Address the Refiner Memory Loop
The Flow 15/17 reports also mention the refiner agent spending 50+ minutes querying memorist repeatedly. That's a separate issue (memorist backend being unreachable + no circuit breaker). This fix specifically targets the delegation blocking loop. The memorist issue needs its own fix (circuit breaker with exponential backoff on memorist failures).

### 6. Alternative Considered: Return Error Instead of Message
One option is to change `return msg, nil` to `return "", fmt.Errorf(msg)`. This would cause `execToolCall` to return an error, which propagates up and terminates the agent chain. However, this is too aggressive — it would kill the entire subtask instead of letting the agent pivot to alternative approaches. The escalation approach is better because it gives the agent a chance to complete work using direct tools.

### 7. Alternative Considered: Remove Delegation Tools From Available Tool List
When time is low, we could dynamically remove the coder/installer/pentester tools from the executor's tool list. This would prevent the LLM from even seeing (and therefore calling) these tools. However, this requires changes to the executor interface and the LLM tool configuration, which is more invasive. The tracker approach achieves the same goal with less architectural change.

---

## Testing Strategy

1. **Unit test for `delegationBlockTracker`**: Verify count tracking, escalation threshold, thread safety, totalBlocks()
2. **Unit test for `clearCallArguments` with delegation tools**: Verify that question field is stripped for coder/installer/pentester/maintenance but preserved for other tools
3. **Integration test**: Mock a scenario where `checkDelegationAllowed` returns blocked, call the handler 5 times, verify escalation fires on attempt 3 and the total blocks count is accurate
4. **End-to-end validation**: Run a test flow with reduced SUBTASK_MAX_DURATION (e.g., 20 minutes) and verify that the delegation loop is broken within 3 attempts
