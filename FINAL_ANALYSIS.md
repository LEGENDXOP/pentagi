# PentAGI — Final Code Analysis & Improvement Plan

**Consolidated from 5 independent audits · 149 raw findings → 42 unique actionable fixes**

## How to Read This
- **Problem:** What's broken (in simple terms, like explaining to a friend)
- **Current:** What happens now (bad behavior)
- **Fixed:** What will happen after the fix (good behavior)
- **Files:** Which files to change
- **Code:** Exact changes needed

---

## 🔴 CRITICAL FIXES (Must Do — These Cause Real Failures)

### Fix 1: Agent loop has NO tool-call limit — can run thousands of commands forever

**Problem:** The agent has an infinite `for{}` loop that processes tool calls. There's a variable `toolCallCount` and a constant `maxToolCallsPerSubtask = 50` — but *neither is ever used*. The variable is declared and forgotten. The loop only exits on errors, barrier functions, or context timeout. If the LLM keeps making tool calls that don't hit a barrier, the agent runs forever burning tokens and compute.

**Current:** Agent executes unlimited tool calls per subtask. A stuck agent can make 500+ calls before the 15-minute timeout kills it — or longer if nested sub-agents each get their own timeout.

**Fixed:** Hard limit enforced — after 50 tool calls, the subtask is forcefully terminated with a clear error message.

**Files:** `internal/app/services/conductor/performer.go` lines 63, 101-230

**Code Change:**
```go
// OLD (line 63 — variable declared but never used):
var (
    wantToStop        bool
    detector          = &repeatingDetector{}
    summarizerHandler = fp.GetSummarizeResultHandler(taskID, subtaskID)
    toolCallCount     int  // <-- DEAD CODE
)
// ... for { ... } loop with no toolCallCount logic

// NEW:
var (
    wantToStop        bool
    detector          = &repeatingDetector{}
    summarizerHandler = fp.GetSummarizeResultHandler(taskID, subtaskID)
    toolCallCount     int
)
// ... inside the for{} loop, after processing tool calls (~line 197):
toolCallCount += len(result.funcCalls)
if toolCallCount >= maxToolCallsPerSubtask {
    logger.WithField("tool_call_count", toolCallCount).
        Warn("reached max tool calls per subtask, forcing stop")
    return fmt.Errorf("subtask tool call limit reached (%d calls)", toolCallCount)
}
```

---

### Fix 2: Repeating-command detector is trivially bypassed — only catches exact duplicates

**Problem:** The system has a "repeating detector" meant to catch agents stuck in loops. But it only detects *consecutive identical* calls. If an agent alternates between two commands — like reading `STATE.json` then `FINDINGS.md` then `STATE.json` again, ad infinitum — the detector *never* triggers. It resets its counter every time it sees a different call.

**Current:** Agent alternating between 2 commands runs forever. Detector only catches exact repetition like: `ls`, `ls`, `ls`.

**Fixed:** Sliding-window detector catches patterns over the last 10 calls, including alternation and near-duplicates.

**Files:** `internal/app/services/conductor/helpers.go` lines 40-63

**Code Change:**
```go
// OLD:
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
    if lastToolCall.Name != funcCall.Name || lastToolCall.Arguments != funcCall.Arguments {
        rd.funcCalls = []llms.FunctionCall{funcCall}  // RESET on any different call!
        return false
    }
    rd.funcCalls = append(rd.funcCalls, funcCall)
    return len(rd.funcCalls) >= RepeatingToolCallThreshold
}

// NEW:
const repeatingWindowSize = 10

type repeatingDetector struct {
    history   []llms.FunctionCall
    threshold int
}

func newRepeatingDetector() *repeatingDetector {
    return &repeatingDetector{threshold: RepeatingToolCallThreshold}
}

func (rd *repeatingDetector) detect(toolCall llms.ToolCall) bool {
    if toolCall.FunctionCall == nil {
        return false
    }
    funcCall := rd.clearCallArguments(toolCall.FunctionCall)
    rd.history = append(rd.history, funcCall)
    if len(rd.history) > repeatingWindowSize {
        rd.history = rd.history[len(rd.history)-repeatingWindowSize:]
    }
    // Count frequency of each (name, args) pair in window
    freq := make(map[string]int)
    for _, fc := range rd.history {
        key := fc.Name + "\x00" + fc.Arguments
        freq[key]++
        if freq[key] >= rd.threshold {
            return true
        }
    }
    return false
}
```

Also fix `clearCallArguments` to produce canonical JSON (current code uses non-deterministic `fmt.Sprintf("%v")`):
```go
// OLD (helpers.go ~line 75-80):
for _, k := range keys {
    buffer.WriteString(fmt.Sprintf("%s: %v\n", k, v[k]))
}

// NEW:
canonical, err := json.Marshal(v)
if err != nil {
    return *toolCall
}
return llms.FunctionCall{
    Name:      toolCall.Name,
    Arguments: string(canonical),
}
```

---

### Fix 3: Recursive agent delegation has NO global budget — agents spawn agents infinitely

**Problem:** The pentester can delegate to the coder, which can delegate to the installer, which runs its own agent chain. Each sub-agent gets its own 15-minute timeout and its own (unused) tool-call counter. A single user request can trigger a cascade of 4+ agent chains, each running for 15 minutes with unlimited tool calls. Total: 60+ minutes of LLM calls with no global limit.

**Current:** User asks one question → primary agent → pentester (15 min) → coder (15 min) → installer (15 min) → adviser (15 min). No shared budget.

**Fixed:** Shared budget tracker limits total tool calls and wall-clock time across the entire delegation tree.

**Files:** `internal/app/services/conductor/performers.go` (entire file), `internal/app/services/conductor/performer.go`

**Code Change:**
```go
// NEW: Add to provider.go or a new budget.go file
type ExecutionBudget struct {
    mu              sync.Mutex
    totalToolCalls  int
    maxToolCalls    int
    startTime       time.Time
    maxDuration     time.Duration
}

func NewExecutionBudget(maxCalls int, maxDuration time.Duration) *ExecutionBudget {
    return &ExecutionBudget{
        maxToolCalls: maxCalls,
        maxDuration:  maxDuration,
        startTime:    time.Now(),
    }
}

func (b *ExecutionBudget) Consume(n int) error {
    b.mu.Lock()
    defer b.mu.Unlock()
    b.totalToolCalls += n
    if b.totalToolCalls > b.maxToolCalls {
        return fmt.Errorf("global tool call budget exceeded (%d/%d)", b.totalToolCalls, b.maxToolCalls)
    }
    if time.Since(b.startTime) > b.maxDuration {
        return fmt.Errorf("global time budget exceeded (%v/%v)", time.Since(b.startTime), b.maxDuration)
    }
    return nil
}

// Pass budget through context:
type budgetKey struct{}

func WithBudget(ctx context.Context, b *ExecutionBudget) context.Context {
    return context.WithValue(ctx, budgetKey{}, b)
}

func GetBudget(ctx context.Context) *ExecutionBudget {
    if b, ok := ctx.Value(budgetKey{}).(*ExecutionBudget); ok {
        return b
    }
    return nil
}

// In performAgentChain, after processing tool calls:
if budget := GetBudget(ctx); budget != nil {
    if err := budget.Consume(len(result.funcCalls)); err != nil {
        return err
    }
}
```

---

### Fix 4: `performSimpleChain` retry has broken `select` — retries happen instantly with no delay

**Problem:** There's a retry loop with a 5-second delay between retries. But the `select` statement has a `default` case, which in Go means "don't wait, proceed immediately." The 5-second `time.After` is dead code — it never fires. On failure, retries happen as fast as possible in a tight loop, hammering the LLM provider.

**Current:** Failed LLM calls are retried instantly with zero delay, creating a rapid-fire retry storm.

**Fixed:** 5-second delay between retries actually works as intended.

**Files:** `internal/app/services/conductor/performers.go` lines 801-822

**Code Change:**
```go
// OLD:
select {
case <-ctx.Done():
    return "", ctx.Err()
case <-time.After(time.Second * 5):
default:  // <-- THIS MAKES THE SELECT NON-BLOCKING
}

// NEW:
select {
case <-ctx.Done():
    return "", ctx.Err()
case <-time.After(time.Second * 5):
    // intentional delay between retries
}
```

---

### Fix 5: Template says "ALWAYS search Graphiti FIRST" — creates compulsive search loop

**Problem:** The pentester prompt template says "ALWAYS search Graphiti FIRST to check execution history" and reinforces it with 5 bullet points covering every possible action. The LLM interprets this literally — before EVERY command, it runs a Graphiti search. Each search returns results that might suggest more searching. Combined with the broken loop detector (Fix 2), this creates an infinite search loop.

The assistant template has the SAME problem: "ALWAYS attempt to retrieve from memory FIRST." But the primary_agent template correctly says "ONLY when context is insufficient."

**Current:** Three templates, three contradictory memory philosophies. Pentester and assistant compulsively search before every action.

**Fixed:** All templates use the same balanced approach — search only when current context is insufficient.

**Files:**
- `internal/app/services/conductor/templates/pentester.tmpl` lines 10, 31-38
- `internal/app/services/conductor/templates/assistant.tmpl` lines 66-72

**Code Change (pentester.tmpl):**
```
{{!-- OLD (line 10): --}}
<graphiti_search>ALWAYS search Graphiti FIRST to check execution history and avoid redundant work</graphiti_search>

{{!-- NEW: --}}
<graphiti_search>Search Graphiti at the START of a new subtask to check execution history. Do NOT search before every individual command — only when beginning a new objective or when you suspect prior work exists for the current target.</graphiti_search>

{{!-- OLD (lines 31-38): --}}
<when_to_search>
ALWAYS search Graphiti BEFORE attempting any significant action:
- Before running reconnaissance tools → Check what was already discovered
- Before exploitation attempts → Find similar successful exploits
- When encountering errors → See how similar errors were resolved
- When planning attacks → Review successful attack chains
- After discovering entities → Understand their relationships
</when_to_search>

{{!-- NEW: --}}
<when_to_search>
Search Graphiti at these KEY decision points (NOT before every command):
- At the START of a new subtask → Check what was already discovered about the target
- When STUCK or encountering repeated errors → See how similar errors were resolved
- When pivoting to a new attack vector → Review if this path was already explored
DO NOT search Graphiti:
- Before every individual command execution
- When you already have the information you need in the current context
- More than 3 times total per subtask unless genuinely needed
</when_to_search>
```

**Code Change (assistant.tmpl):**
```
{{!-- OLD: --}}
<memory_protocol>
- ALWAYS attempt to retrieve relevant information from memory FIRST using {{.MemoristToolName}}
...
</memory_protocol>

{{!-- NEW: --}}
<memory_protocol>
- Use {{.MemoristToolName}} ONLY when information in the current context is insufficient
- If the current conversation and execution context contain all necessary information, a memory search is NOT required
- Only store valuable, novel, and reusable knowledge that would benefit future tasks
- Use specific, semantic search queries with relevant keywords for effective retrieval
</memory_protocol>
```

---

### Fix 6: No execution metrics passed to templates — loop detection is structurally impossible

**Problem:** None of the prompt templates receive information about how many tool calls have been made, how long the subtask has been running, or how many times the plan has been refined. Even with perfect prompt engineering, the agent CAN'T detect it's in a loop because it doesn't know it's been running for 200 commands already. This is the fundamental infrastructure gap.

**Current:** Templates have zero visibility into execution progress. No template can say "I've made 50 calls, time to stop."

**Fixed:** Backend passes execution metrics to all templates; templates include loop-prevention instructions.

**Files:**
- `internal/app/services/conductor/templates/full_execution_context.tmpl`
- `internal/app/services/conductor/performer.go` (pass metrics to template context)
- `internal/app/services/conductor/templates/pentester.tmpl` (add anti-loop section)

**Code Change (full_execution_context.tmpl — add at end):**
```
{{if .ExecutionMetrics}}
<execution_metrics>
  <tool_calls_count>{{.ExecutionMetrics.ToolCallCount}}</tool_calls_count>
  <elapsed_seconds>{{.ExecutionMetrics.ElapsedSeconds}}</elapsed_seconds>
  <unique_commands>{{.ExecutionMetrics.UniqueCommands}}</unique_commands>
</execution_metrics>
{{end}}
```

**Code Change (pentester.tmpl — add new section):**
```
## LOOP PREVENTION
<anti_loop_protocol>
- Track the number of commands executed in this subtask. After 15 commands without meaningful progress, STOP and report what you've tried.
- If you find yourself searching Graphiti more than 3 times for the same subtask, STOP searching and work with what you have.
- If the same tool fails 3 times (even with different flags), switch to a completely different tool or approach.
- "Meaningful progress" means: new information discovered, new access gained, or a confirmed dead-end.
- If no progress after pivoting twice, report the subtask as blocked with a detailed explanation.
</anti_loop_protocol>
```

---

### Fix 7: No actual loop-detection reflector exists — the "reflector" is just a format enforcer

**Problem:** Despite the filename `reflector.tmpl`, this template does NOT reflect on progress or detect loops. It's actually a "Tool Call Format Enforcer" — when an agent outputs text instead of a tool call, this template just tells it to use structured tool calls. There is ZERO loop detection in the entire template system.

**Current:** When an agent is stuck, the "reflector" just redirects it to make more tool calls — potentially *deepening* the loop.

**Fixed:** Either repurpose the reflector or add a new progress evaluator that can detect stalls and force subtask termination.

**Files:** `internal/app/services/conductor/templates/reflector.tmpl`, `internal/app/services/conductor/performer.go` lines 120-145

**Code Change:** Add a new template `loop_detector.tmpl` or add loop-detection logic to the reflector:
```
# PROGRESS EVALUATOR

You are reviewing the agent's recent actions to determine if meaningful progress is being made.

## RECENT ACTIONS
{{.RecentActions}}

## EVALUATION CRITERIA
1. Has the agent produced NEW information in the last 5 actions?
2. Are the last 3 actions semantically different from each other?
3. Has the agent been searching the same knowledge base repeatedly?
4. Is the agent making progress toward the subtask objective?

## DECISION
- CONTINUE: If meaningful progress is being made
- REDIRECT: If the agent is stuck, suggest a different approach
- STOP: If the agent is in a clear loop, recommend marking the subtask as blocked
```

And in `performer.go`, track total reflector invocations across the entire subtask (not just per-call):
```go
// OLD: reflector iteration always starts at 1
result, err = fp.performReflector(ctx, ..., 1)  // always starts at iteration=1

// NEW: track across entire subtask
var totalReflectorCalls int
// ... in loop when calling reflector ...
totalReflectorCalls++
if totalReflectorCalls > maxTotalReflectorCalls {
    return fmt.Errorf("exceeded total reflector limit (%d)", maxTotalReflectorCalls)
}
```

---

### Fix 8: Subtask generator is blind to filesystem state — re-creates work that already exists

**Problem:** When generating the initial subtask plan, the generator only sees task metadata and previous results. It has NO idea what files already exist in the working directory. If a previous task already ran `nmap` and saved results to `/tmp/nmap_results.txt`, the generator doesn't know and will plan a subtask to re-run that scan.

The *refiner* has `{{.ExecutionState}}` and `{{.ExecutionLogs}}`, but the *generator* has neither. This asymmetry means the initial plan is always created blind.

**Current:** Generator plans from scratch every time, ignoring existing artifacts. Refiner has context but generator doesn't.

**Fixed:** Generator receives workspace file listing and can plan around existing work.

**Files:**
- `internal/app/services/conductor/templates/subtasks_generator.tmpl`
- Backend code that populates template context (to add `.WorkspaceFiles` variable)

**Code Change (subtasks_generator.tmpl — add at end):**
```
{{if .WorkspaceFiles}}
<workspace_state>
  <working_directory>{{.Cwd}}</working_directory>
  {{range .WorkspaceFiles}}
  <file>
    <path>{{.Path}}</path>
    <size>{{.Size}}</size>
    <modified>{{.Modified}}</modified>
  </file>
  {{end}}
</workspace_state>
{{end}}
```

Backend needs to list the working directory before calling the generator and populate `.WorkspaceFiles`.

---

### Fix 9: Status propagation chain (Subtask→Task→Flow) has no transactions — crash = inconsistent state

**Problem:** When a subtask finishes, it updates its own DB status, then calls the task to update ITS status, then the task calls the flow to update ITS status. Each is a separate DB query with no transaction. If the process crashes between steps, you get: Subtask=Finished, Task=Running, Flow=Running. On restart, the system tries to re-run a finished subtask.

Also, each `SetStatus` updates the DB FIRST, then acquires a mutex to update in-memory state. Between those two operations, another goroutine can read stale in-memory state.

**Current:** No transactional guarantees. Crash = inconsistent state that confuses the reload logic.

**Fixed:** Either wrap in transactions or make status updates idempotent with proper ordering.

**Files:**
- `internal/app/services/conductor/subtask.go` `SetStatus()` method (~lines 197-230)
- `internal/app/services/conductor/task.go` `SetStatus()` method (~lines 219-254)
- Database layer needs `WithTx` support

**Code Change (subtask.go SetStatus — fix lock ordering):**
```go
// OLD:
func (stw *subtaskWorker) SetStatus(ctx context.Context, status database.SubtaskStatus) error {
    _, err := stw.subtaskCtx.DB.UpdateSubtaskStatus(ctx, ...)  // DB first
    if err != nil { return ... }
    stw.mx.Lock()          // Lock second — race window!
    defer stw.mx.Unlock()
    // ... update in-memory + call updater while holding lock (deadlock risk)
}

// NEW:
func (stw *subtaskWorker) SetStatus(ctx context.Context, status database.SubtaskStatus) error {
    stw.mx.Lock()  // Lock FIRST
    _, err := stw.subtaskCtx.DB.UpdateSubtaskStatus(ctx, ...)
    if err != nil {
        stw.mx.Unlock()
        return err
    }
    // Update in-memory state
    switch status {
    case database.SubtaskStatusRunning:
        stw.completed = false
        stw.waiting = false
    // ... other cases
    }
    stw.mx.Unlock()  // Unlock BEFORE calling updater to prevent deadlock
    
    // Propagate to parent (outside lock)
    return stw.updater.SetStatus(ctx, parentStatus)
}
```

---


## 🟠 HIGH PRIORITY (Should Do — Significant Improvements)

### Fix 10: Terminal tool accepts ANY command — no blocklist or safety net

**Problem:** The terminal tool takes whatever command string the LLM gives it and runs `sh -c <command>` in the container. Zero filtering. The container also has `NET_RAW` capability (and optionally `NET_ADMIN`). A prompt-injected or hallucinating LLM can run `rm -rf /`, install backdoors, exfiltrate data via curl, or pivot to other hosts.

**Current:** Any command executes without validation. Container has elevated network capabilities.

**Fixed:** Command blocklist prevents obviously dangerous commands. (Container isolation still provides base protection.)

**Files:** `internal/app/services/conductor/terminal.go` lines 127-132

**Code Change:**
```go
// NEW: Add before ExecCommand execution
var blockedPatterns = []*regexp.Regexp{
    regexp.MustCompile(`(?i)(curl|wget).*\|\s*(ba)?sh`),   // pipe-to-shell
    regexp.MustCompile(`(?i)nc\s+-[el]`),                   // reverse shells
    regexp.MustCompile(`(?i)/dev/(tcp|udp)/`),               // bash reverse shells
    regexp.MustCompile(`(?i)rm\s+-rf\s+/\s*$`),             // rm -rf /
    regexp.MustCompile(`(?i)mkfs\s+/dev/`),                  // format disks
    regexp.MustCompile(`(?i):\(\)\{\s*:\|:&\s*\};:`),       // fork bomb
}

func validateCommand(command string) error {
    for _, pattern := range blockedPatterns {
        if pattern.MatchString(command) {
            return fmt.Errorf("command blocked by security policy: matches pattern %s", pattern.String())
        }
    }
    return nil
}

// In ExecCommand, before creating the exec:
if err := validateCommand(command); err != nil {
    return "", err
}
```

**Note:** For a pentesting tool, some "dangerous" commands are legitimate. Consider a configurable blocklist or a per-flow safety level (aggressive vs. restricted).

---

### Fix 11: Terminal output has no size limit — unbounded memory usage

**Problem:** When a command produces output, it's read entirely into a `bytes.Buffer` with no cap. A command like `cat /dev/urandom | xxd` or `find / -type f` can produce gigabytes of output before the timeout kills it. The entire output sits in memory.

**Current:** Unbounded memory allocation per command. A single verbose command can OOM the host.

**Fixed:** Output capped at 1MB with truncation notice.

**Files:** `internal/app/services/conductor/terminal.go` lines 207-219

**Code Change:**
```go
// OLD:
dst := bytes.Buffer{}
go func() {
    _, copyErr := io.Copy(&dst, resp.Reader)
    errChan <- copyErr
}()

// NEW:
const maxOutputSize = 1 * 1024 * 1024 // 1 MB
dst := bytes.Buffer{}
go func() {
    limitedReader := io.LimitReader(resp.Reader, maxOutputSize+1)
    _, copyErr := io.Copy(&dst, limitedReader)
    errChan <- copyErr
}()

// After reading, check for truncation:
output := dst.String()
if len(output) > maxOutputSize {
    output = output[:maxOutputSize] + "\n\n[OUTPUT TRUNCATED: exceeded 1MB limit]"
}
```

---

### Fix 12: WriteFile has no path restriction — LLM can write to sensitive system paths

**Problem:** The LLM controls the file path for writes. It can write to `/etc/passwd`, `/root/.ssh/authorized_keys`, `/usr/bin/malicious`, etc. inside the container. Combined with `NET_RAW`/`NET_ADMIN` capabilities, writing a malicious script and executing it could enable container escape or lateral movement.

**Current:** LLM can write files anywhere in the container filesystem.

**Fixed:** Writes restricted to the working directory.

**Files:** `internal/app/services/conductor/terminal.go` lines 338-390

**Code Change:**
```go
// NEW: Add at start of WriteFile
func (t *terminal) WriteFile(ctx context.Context, flowID int64, content string, path string) (string, error) {
    cleanPath := filepath.Clean(path)
    if !strings.HasPrefix(cleanPath, docker.WorkFolderPathInContainer) && !strings.HasPrefix(cleanPath, "/tmp/") {
        return "", fmt.Errorf("write path must be within %s or /tmp/, got: %s", docker.WorkFolderPathInContainer, path)
    }
    // ... rest of method
}
```

---

### Fix 13: No concurrency guard on terminal — "one command at a time" claim is unenforced

**Problem:** The terminal tool description says "only one command can be executed at a time." But there's no mutex or semaphore. If the LLM issues multiple tool calls in parallel (which langchain supports), they run simultaneously and can interfere with each other.

**Current:** Multiple commands can execute concurrently despite the documented guarantee.

**Fixed:** Mutex enforces serial execution.

**Files:** `internal/app/services/conductor/terminal.go`

**Code Change:**
```go
// OLD:
type terminal struct {
    flowID       int64
    containerID  string
    // ...
}

// NEW:
type terminal struct {
    mu           sync.Mutex  // enforce serial execution
    flowID       int64
    containerID  string
    // ...
}

func (t *terminal) ExecCommand(ctx context.Context, ...) (string, error) {
    t.mu.Lock()
    defer t.mu.Unlock()
    // ... rest of method
}
```

---

### Fix 14: No rate limiting on any tool execution

**Problem:** The LLM can call any tool (terminal, search engines, browser, Graphiti) as fast as it wants. External APIs like Google, Tavily, and Perplexity have real cost implications and rate limits. Internal tools like terminal can overload the Docker host. There's a `ToolType` classification system but it's only used for display — no enforcement.

**Current:** Zero rate limiting. A loop can make 100 Google searches per minute.

**Fixed:** Per-tool-type rate limiters prevent runaway API costs and resource exhaustion.

**Files:** `internal/app/services/conductor/tools.go` (executor creation), `internal/app/services/conductor/registry.go` (tool types)

**Code Change:**
```go
// NEW: Rate-limiting wrapper
import "golang.org/x/time/rate"

func NewRateLimitedHandler(handler ExecutorHandler, rps float64, burst int) ExecutorHandler {
    limiter := rate.NewLimiter(rate.Limit(rps), burst)
    return func(ctx context.Context, name string, args json.RawMessage) (string, error) {
        if err := limiter.Wait(ctx); err != nil {
            return "", fmt.Errorf("rate limit exceeded for tool %s: %w", name, err)
        }
        return handler(ctx, name, args)
    }
}

// Apply in executor factory methods:
handlers[GoogleToolName] = NewRateLimitedHandler(google.Handle, 2, 5)    // 2 rps, burst 5
handlers[TerminalToolName] = NewRateLimitedHandler(term.Handle, 5, 10)   // 5 rps, burst 10
handlers[BrowserToolName] = NewRateLimitedHandler(browser.Handle, 2, 3)  // 2 rps, burst 3
```

---

### Fix 15: Context timeout not checked at top of agent loop — work continues after deadline

**Problem:** The agent loop creates a `context.WithTimeout` but never explicitly checks `ctx.Err()` at the top of each iteration. The timeout only takes effect when an underlying I/O call happens to respect the context. Between calls, the loop keeps doing work after the deadline.

**Current:** After timeout, the loop continues until the next I/O operation checks the context (could be several iterations later).

**Fixed:** Explicit check at top of every loop iteration.

**Files:** `internal/app/services/conductor/performer.go` lines 97-101

**Code Change:**
```go
// OLD:
for {
    result, err := fp.callWithRetries(ctx, chain, optAgentType, executor)
    // ...
}

// NEW:
for {
    if err := ctx.Err(); err != nil {
        logger.WithError(err).Warn("context cancelled/timed out in agent chain loop")
        return fmt.Errorf("agent chain loop terminated: %w", err)
    }
    result, err := fp.callWithRetries(ctx, chain, optAgentType, executor)
    // ...
}
```

---

### Fix 16: `getTasksInfo` mutates the database-returned slice in-place — potential data corruption

**Problem:** Classic Go gotcha: `append(slice[:i], slice[i+1:]...)` modifies the underlying array. The slice returned by `fp.db.GetFlowTasks` is mutated. If the database layer caches or reuses returned slices, this corrupts shared state.

**Current:** The original DB result slice is silently modified, potentially affecting other code that holds a reference to it.

**Fixed:** Create a new slice instead of mutating.

**Files:** `internal/app/services/conductor/helpers.go` lines 112-118

**Code Change:**
```go
// OLD:
for idx, t := range info.Tasks {
    if t.ID == taskID {
        info.Task = t
        info.Tasks = append(info.Tasks[:idx], info.Tasks[idx+1:]...)
        break
    }
}

// NEW:
otherTasks := make([]database.Task, 0, len(info.Tasks)-1)
for _, t := range info.Tasks {
    if t.ID == taskID {
        info.Task = t
    } else {
        otherTasks = append(otherTasks, t)
    }
}
info.Tasks = otherTasks
```

---

### Fix 17: Subtask error handling always sets Waiting — even for permanent failures

**Problem:** When `PerformAgentChain` fails for ANY reason, the subtask is set to `Waiting` status. But permanent failures (invalid API key, model not found, schema errors) shouldn't put the subtask in a "waiting for input" state — it needs a code/config fix, not user input. Only cancellation errors should trigger waiting.

**Current:** API key expired? Subtask shows "waiting for input." User is confused.

**Fixed:** Cancellation → Waiting (user can resume). Other errors → Failed (needs investigation).

**Files:** `internal/app/services/conductor/subtask.go` lines 277-296

**Code Change:**
```go
// OLD:
if err != nil {
    if errors.Is(err, context.Canceled) {
        ctx = context.Background()
    }
    _ = stw.SetStatus(ctx, database.SubtaskStatusWaiting)  // always Waiting
    return ...
}

// NEW:
if err != nil {
    if errors.Is(err, context.Canceled) {
        ctx = context.Background()
        _ = stw.SetStatus(ctx, database.SubtaskStatusWaiting)
    } else {
        _ = stw.SetStatus(ctx, database.SubtaskStatusFailed)
    }
    return ...
}
```

---

### Fix 18: `runTask` cancels previous task without waiting — two tasks can run simultaneously

**Problem:** When a new task starts, the previous task's context is cancelled, but there's no wait for it to actually finish. The new task starts immediately. For a brief period, two tasks can be executing concurrently, fighting over shared resources.

**Current:** Previous task cancelled but not awaited → brief concurrent execution window.

**Fixed:** Wait for previous task to fully stop before starting the new one.

**Files:** `internal/app/services/conductor/flow.go` lines 786-800

**Code Change:**
```go
// OLD:
fw.taskMX.Lock()
fw.taskST()                              // cancel previous
ctx, taskST := context.WithCancel(fw.ctx) // start new immediately
fw.taskST = taskST
fw.taskMX.Unlock()

// NEW:
fw.taskMX.Lock()
fw.taskST()       // cancel previous
fw.taskWG.Wait()   // wait for it to actually stop
ctx, taskST := context.WithCancel(fw.ctx)
fw.taskST = taskST
fw.taskMX.Unlock()
```

---

### Fix 19: Refiner doesn't deduplicate against completed work — regenerates finished subtasks

**Problem:** The refiner sees completed subtask results AND planned subtasks, but is never told to COMPARE them. If subtask #3 already completed a port scan, the refiner doesn't check whether planned subtask #6 ("scan ports") is now redundant. It keeps the plan as-is or even adds more scanning subtasks.

**Current:** Refiner regenerates work that's already done because it never checks for overlap.

**Fixed:** Explicit deduplication instruction in refiner template.

**Files:** `internal/app/services/conductor/templates/refiner.tmpl` (~line 88)

**Code Change:**
```
{{!-- NEW: Add after REFINEMENT RULES section --}}
6. **Completed Work Deduplication**
   - Before modifying the plan, compare each planned subtask against ALL completed subtask results
   - If a planned subtask's objective is FULLY or SUBSTANTIALLY achieved by completed results, REMOVE it
   - If a planned subtask is PARTIALLY covered, MODIFY it to only cover the remaining gap
   - Never create new subtasks that duplicate work already successfully completed
   - When in doubt, check the completed subtask's <result> field for evidence of completion
```

---

### Fix 20: Finish() can panic on double-close of channel

**Problem:** `finish()` calls `close(fw.input)` without checking if the channel is already closed. If `Finish()` is called twice (e.g., by cleanup and by task completion), this panics the process.

**Current:** Double close = panic = server crash.

**Fixed:** Use `sync.Once` to protect channel close.

**Files:** `internal/app/services/conductor/flow.go` lines 672-682

**Code Change:**
```go
// OLD:
func (fw *flowWorker) finish() error {
    // ...
    fw.cancel()
    close(fw.input)  // PANICS if called twice!
    fw.wg.Wait()
    return nil
}

// NEW:
type flowWorker struct {
    // ... existing fields
    closeOnce sync.Once
}

func (fw *flowWorker) finish() error {
    // ...
    fw.cancel()
    fw.closeOnce.Do(func() { close(fw.input) })
    fw.wg.Wait()
    return nil
}
```

---

### Fix 21: Finish() doesn't set status on error paths — flow left in limbo

**Problem:** `Finish()` sets `FlowStatusFinished` only at the very end. If any intermediate step fails (releasing executor, finishing tasks), the function returns an error with the flow still in `Running` status. On next restart, the system tries to reload this "running" flow with stale state.

**Current:** Failed cleanup leaves flow in `Running` → restart tries to resume corrupted state.

**Fixed:** Deferred error handler sets `FlowStatusFailed` on any error path.

**Files:** `internal/app/services/conductor/flow.go` lines 623-641

**Code Change:**
```go
// OLD:
func (fw *flowWorker) Finish(ctx context.Context) error {
    if err := fw.finish(); err != nil { return err }
    // ... more steps that can fail ...
    if err := fw.SetStatus(ctx, database.FlowStatusFinished); err != nil { return err }
    return nil
}

// NEW:
func (fw *flowWorker) Finish(ctx context.Context) (retErr error) {
    defer func() {
        if retErr != nil {
            _ = fw.SetStatus(ctx, database.FlowStatusFailed)
        }
    }()
    if err := fw.finish(); err != nil { return err }
    // ... more steps ...
    return fw.SetStatus(ctx, database.FlowStatusFinished)
}
```

---

### Fix 22: `performResult` accessed via closure without synchronization

**Problem:** The `performResult` variable is written inside a barrier closure and read after `performAgentChain` returns. While currently sequential, the `executorAgent.End()` in a `defer` inside the barrier creates a window where the variable could be read before the defer completes. Also, `executorAgent.End()` can be called TWICE — once from the barrier's defer and once from the outer function.

**Current:** Potential data race on `performResult`. Agent span ended twice.

**Fixed:** Atomic access for result, `sync.Once` for span ending.

**Files:** `internal/app/services/conductor/provider.go` lines 711-838

**Code Change:**
```go
// OLD:
performResult := PerformResultError
// ... closure writes performResult ...
return performResult, nil

// NEW:
var performResult atomic.Int32
performResult.Store(int32(PerformResultError))
// ... in closure:
performResult.Store(int32(PerformResultDone))
// ... after chain:
return PerformResult(performResult.Load()), nil

// For double-end protection:
var endOnce sync.Once
endAgent := func(opts ...langfuse.AgentEndOption) {
    endOnce.Do(func() { executorAgent.End(opts...) })
}
```

---

### Fix 23: `GetMemoristHandler` has variable shadowing and format string bugs

**Problem:** `subtaskID := action.SubtaskID.Int64()` shadows the outer closure parameter `subtaskID *int64`. The error message uses `%d` with a pointer (`*int64`), printing the memory address instead of the value. Also has grammar errors ("user no specified task").

**Current:** Confusing variable shadowing, error messages show memory addresses, broken English.

**Fixed:** Distinct variable names, proper dereferencing, fixed grammar.

**Files:** `internal/app/services/conductor/handlers.go` lines 449-457

**Code Change:**
```go
// OLD:
subtaskID := action.SubtaskID.Int64()
// ...
executionDetails += fmt.Sprintf("user no specified task, using current task '%d'\n", taskID)

// NEW:
requestedSubtaskID := action.SubtaskID.Int64()
// ...
executionDetails += fmt.Sprintf("user did not specify a task, using current task '%d'\n", *taskID)
```

---

### Fix 24: Summarizer silently drops the MIDDLE of large results

**Problem:** When a tool result exceeds `2*msgSummarizerLimit`, the code keeps the first and last N bytes and puts `{TRUNCATED}` in the middle. For a pentesting tool, the middle of a vulnerability scan is often the most important part. There's a TODO saying "here need to summarize result by chunks in iterations" — it was never implemented.

**Current:** Middle of large outputs (potentially containing critical findings) is silently dropped.

**Fixed:** Chunked summarization processes the entire result.

**Files:** `internal/app/services/conductor/handlers.go` lines 869-875

**Code Change:**
```go
// OLD:
// TODO: here need to summarize result by chunks in iterations
if len(result) > 2*msgSummarizerLimit {
    result = database.SanitizeUTF8(
        result[:msgSummarizerLimit] +
            "\n\n{TRUNCATED}...\n\n" +
            result[len(result)-msgSummarizerLimit:],
    )
}

// NEW: Chunked summarization
if len(result) > 2*msgSummarizerLimit {
    chunks := splitIntoChunks(result, msgSummarizerLimit)
    var summaries []string
    for i, chunk := range chunks {
        summary, err := summarizeChunk(ctx, chunk)
        if err != nil {
            logger.WithError(err).Warnf("failed to summarize chunk %d/%d", i+1, len(chunks))
            summaries = append(summaries, chunk[:min(len(chunk), 1024)]+"...[summarization failed]")
            continue
        }
        summaries = append(summaries, summary)
    }
    result = strings.Join(summaries, "\n\n---\n\n")
}
```

---

### Fix 25: `GetTaskCompletedSubtasks` includes Running subtasks — misleading the refiner

**Problem:** The query `GetTaskCompletedSubtasks` filters `WHERE status != 'created' AND status != 'waiting'`, which includes `running` subtasks. The refiner uses this query and sees running subtasks as "completed," making incorrect planning decisions.

**Current:** Refiner thinks running subtasks are done → may remove/replace them mid-execution.

**Fixed:** Only truly completed subtasks are returned.

**Files:** Database queries (sqlc) — `subtasks.sql`

**Code Change:**
```sql
-- OLD:
WHERE s.task_id = $1 AND (s.status != 'created' AND s.status != 'waiting') AND f.deleted_at IS NULL

-- NEW:
WHERE s.task_id = $1 AND s.status IN ('finished', 'failed') AND f.deleted_at IS NULL
```

Or rename the query to `GetTaskNonPendingSubtasks` if the current behavior is intended.

---

### Fix 26: Config has no execution limits — all safety relies on LLM self-discipline

**Problem:** The `AgentConfig` struct has LLM parameters (temperature, max_tokens) but ZERO execution control parameters. There's no way to configure `max_tool_calls`, `subtask_timeout`, `max_refinements`, or `command_timeout`. These limits exist only as soft guidance in prompt text, which the LLM can ignore.

**Current:** All safety boundaries are prompt-level suggestions that the LLM can violate.

**Fixed:** Hard limits configurable in the agent config, enforced at the Go level.

**Files:** `internal/app/services/conductor/config/config.go` lines 191-230

**Code Change:**
```go
// OLD:
type AgentConfig struct {
    Model       string  `json:"model,omitempty" yaml:"model,omitempty"`
    MaxTokens   int     `json:"max_tokens,omitempty" yaml:"max_tokens,omitempty"`
    Temperature float64 `json:"temperature,omitempty" yaml:"temperature,omitempty"`
    // ... only LLM params
}

// NEW:
type AgentConfig struct {
    Model       string  `json:"model,omitempty" yaml:"model,omitempty"`
    MaxTokens   int     `json:"max_tokens,omitempty" yaml:"max_tokens,omitempty"`
    Temperature float64 `json:"temperature,omitempty" yaml:"temperature,omitempty"`
    // ... existing LLM params ...
    
    // Execution limits (enforced at Go level, not prompt level)
    MaxToolCalls   int `json:"max_tool_calls,omitempty" yaml:"max_tool_calls,omitempty"`     // default: 50
    SubtaskTimeout int `json:"subtask_timeout_sec,omitempty" yaml:"subtask_timeout_sec,omitempty"` // default: 900
    MaxRefinements int `json:"max_refinements,omitempty" yaml:"max_refinements,omitempty"`   // default: 10
    CommandTimeout int `json:"command_timeout_sec,omitempty" yaml:"command_timeout_sec,omitempty"` // default: 300
}
```

---

### Fix 27: `prepareExecutionContext` proceeds with nil subtask pointer — downstream nil dereference

**Problem:** After sorting subtasks and searching for the current subtask ID, if the ID isn't found, `subtasksInfo.Subtask` remains nil. The code proceeds to use it in template rendering without a nil check, which can cause nil pointer dereferences or confusing template output.

**Current:** Missing subtask → nil pointer → potential panic in template rendering.

**Fixed:** Explicit nil check with error/warning.

**Files:** `internal/app/services/conductor/helpers.go` lines 596-601

**Code Change:**
```go
// OLD:
for i, subtask := range subtasks {
    if subtask.ID == subtaskID {
        subtasksInfo.Subtask = &subtask
        subtasksInfo.Planned = subtasks[i+1:]
        subtasksInfo.Completed = subtasks[:i]
        break
    }
}
// (no check if subtask was found)

// NEW:
for i, subtask := range subtasks {
    if subtask.ID == subtaskID {
        subtasksInfo.Subtask = &subtask
        subtasksInfo.Planned = subtasks[i+1:]
        subtasksInfo.Completed = subtasks[:i]
        break
    }
}
if subtasksInfo.Subtask == nil {
    logger.WithField("subtask_id", subtaskID).Error("subtask not found in task's subtask list")
    return "", fmt.Errorf("subtask %d not found in task's subtask list", subtaskID)
}
```

---

### Fix 28: Reorder-after-remove silently puts subtask in wrong position

**Problem:** In the subtask patch system, if a `reorder` operation references a subtask that was `remove`d in the same patch, `calculateInsertIndex` silently falls back to appending at the end. The reordered subtask ends up in the wrong position with no warning.

**Current:** Reorder references removed subtask → subtask silently goes to end of list.

**Fixed:** Detect and warn when afterID references a removed subtask.

**Files:** `internal/app/services/conductor/subtask_patch.go` lines 152-181, 229-238

**Code Change:**
```go
// OLD:
func calculateInsertIndex(afterID *int64, idToIdx map[int64]int, length int) int {
    // ... returns length when not found (silent)
}

// NEW:
func calculateInsertIndex(afterID *int64, idToIdx map[int64]int, removed map[int64]bool, length int) (int, error) {
    if afterID == nil || *afterID == 0 {
        return 0, nil
    }
    if idx, ok := idToIdx[*afterID]; ok {
        return idx + 1, nil
    }
    if removed[*afterID] {
        return length, fmt.Errorf("afterID %d was removed in this patch", *afterID)
    }
    return length, fmt.Errorf("afterID %d not found", *afterID)
}
```

---

### Fix 29: `fixToolCallArgs` doesn't validate the fixed result

**Problem:** When a tool call has bad arguments, the system asks an LLM to fix them. But it never validates that the fix is actually valid JSON or matches the expected schema. If the fixer LLM also produces invalid output, this creates an infinite fix-retry loop.

**Current:** Fixer produces invalid JSON → retry → fixer again → invalid again → loop until max retries.

**Fixed:** Validate the fix before using it.

**Files:** `internal/app/services/conductor/handlers.go` lines 899-936

**Code Change:**
```go
// NEW: After getting fixerResult
var fixedArgs map[string]any
if err := json.Unmarshal([]byte(toolCallFixerResult), &fixedArgs); err != nil {
    return nil, fmt.Errorf("tool call fixer produced invalid JSON: %w", err)
}
return json.RawMessage(toolCallFixerResult), nil
```

---

### Fix 30: Terminal errors converted to success — error tracking is blind

**Problem:** `wrapCommandResult` takes errors from command execution and returns them as `(errorMessage, nil)`. The caller never sees an error, considers the tool call successful, and records it as success in the DB. Error metrics won't count these failures.

**Current:** `rm: permission denied` is recorded as a successful tool call with the error as "output."

**Fixed:** Keep returning nil error (to not crash the agent loop) but structure the response so the system can distinguish errors from success.

**Files:** `internal/app/services/conductor/terminal.go` lines 63-77

**Code Change:**
```go
// OLD:
func (t *terminal) wrapCommandResult(ctx context.Context, args json.RawMessage, name, result string, err error) (string, error) {
    if err != nil {
        return fmt.Sprintf("terminal tool '%s' handled with error: %v", name, err), nil
    }
    return result, nil
}

// NEW:
func (t *terminal) wrapCommandResult(ctx context.Context, args json.RawMessage, name, result string, err error) (string, error) {
    if err != nil {
        // Prefix with [ERROR] so the system can detect and track tool failures
        errMsg := fmt.Sprintf("[ERROR] terminal tool '%s' failed: %v", name, err)
        if result != "" {
            errMsg += fmt.Sprintf("\nPartial output:\n%s", result[:min(len(result), 4096)])
        }
        return errMsg, nil
    }
    return result, nil
}
```

---

### Fix 31: ReadFile allows 100MB files — way too large for LLM context

**Problem:** `ReadFile` allows reading files up to 100MB. This entire content gets sent to the LLM. A 100MB text file = hundreds of thousands of tokens. Also no binary file detection — reading a compiled binary produces garbage.

**Current:** Agent reads a 50MB log file → context window explodes → LLM degrades or errors.

**Fixed:** Reasonable limit (256KB) with binary detection.

**Files:** `internal/app/services/conductor/terminal.go` lines 306-308

**Code Change:**
```go
// OLD:
const maxReadFileSize int64 = 100 * 1024 * 1024 // 100 MB

// NEW:
const maxReadFileSize int64 = 256 * 1024 // 256 KB for LLM consumption

// After reading content, check for binary:
func isBinary(data []byte) bool {
    for _, b := range data[:min(len(data), 512)] {
        if b == 0 {
            return true
        }
    }
    return false
}

// In ReadFile, after reading file content:
if isBinary(fileContent) {
    return fmt.Sprintf("file '%s' appears to be binary (%d bytes), cannot display as text", 
        tarHeader.Name, tarHeader.Size), nil
}
```

---


## 🟡 MEDIUM PRIORITY (Quality Improvements with Clear Fixes)

### Fix 32: Summarizer errors swallowed — chain grows unbounded in memory

**Problem:** When `summarizer.SummarizeChain()` fails, the error is logged but the loop continues with the full (unsummarized) chain. Over many iterations, the chain grows without bound, eventually causing OOM.

**Files:** `internal/app/services/conductor/performer.go` lines 206-225

**Fix:** Track consecutive failures; abort after 3:
```go
summarizerFailures++
if summarizerFailures >= 3 {
    return fmt.Errorf("chain summarization repeatedly failed: %w", err)
}
```

---

### Fix 33: `CreateMsgChain` error silently dropped in `performSimpleChain`

**Problem:** At the end of `performSimpleChain`, the DB write error is assigned to `err` but never checked. The function returns the in-memory result regardless. Chain data may be lost on recovery.

**Files:** `internal/app/services/conductor/performers.go` lines 862-873

**Fix:**
```go
// OLD:
_, err = fp.db.CreateMsgChain(ctx, ...)
return strings.Join(parts, "\n\n"), nil  // err silently dropped

// NEW:
_, err = fp.db.CreateMsgChain(ctx, ...)
if err != nil {
    return "", fmt.Errorf("failed to create msg chain: %w", err)
}
return strings.Join(parts, "\n\n"), nil
```

---

### Fix 34: `PutInput` silently drops user input when no waiting subtask is found

**Problem:** If a task says it's `Waiting` but no subtask is actually waiting, `PutInput` silently returns `nil`. The user's input disappears.

**Files:** `internal/app/services/conductor/task.go` lines 265-278

**Fix:** Return error when no waiting subtask found:
```go
found := false
for _, st := range tw.stc.ListSubtasks(ctx) {
    if !st.IsCompleted() && st.IsWaiting() {
        if err := st.PutInput(ctx, input); err != nil {
            return err
        }
        found = true
        break
    }
}
if !found {
    return fmt.Errorf("task %d is waiting but no subtask is waiting for input", tw.taskCtx.TaskID)
}
```

---

### Fix 35: Zero-valued result structs returned silently when barrier fires on wrong tool

**Problem:** All performer functions declare a result struct (e.g., `codeResult`), then call `performAgentChain`. If the agent calls `wantToStop` on a non-result barrier tool (like `AskUser`), the chain exits successfully but the result struct is zero-valued. The caller gets an empty string silently.

**Files:** `internal/app/services/conductor/performers.go` lines 365-435 (and similar in all performer functions)

**Fix:** Validate after chain completion:
```go
if codeResult.Result == "" {
    return "", fmt.Errorf("agent chain completed without producing a code result")
}
```

---

### Fix 36: No input validation on `PutInputToAgentChain` — unbounded user input

**Problem:** User input goes directly into the chain with no size limit. A malicious user could inject a multi-megabyte string causing DB bloat and context overflow.

**Files:** `internal/app/services/conductor/provider.go` lines 843-858

**Fix:**
```go
const maxUserInputSize = 32 * 1024 // 32KB
if len(input) > maxUserInputSize {
    return fmt.Errorf("user input exceeds maximum size (%d > %d)", len(input), maxUserInputSize)
}
```

---

### Fix 37: Stream IDs leaked on retry — client sees abandoned streams

**Problem:** Each LLM call retry creates a new `streamID`. The first stream receives partial data then goes silent when the retry starts. No cleanup or error notification is sent on the abandoned stream.

**Files:** `internal/app/services/conductor/performer.go` lines 396-410

**Fix:** Either reuse the same streamID and send a "reset" chunk on retry, or send an error chunk on the abandoned stream before creating a new one.

---

### Fix 38: `CallUsage.Merge` overwrites instead of accumulating token counts

**Problem:** The `Merge` method replaces values instead of summing them. For cumulative token tracking across multiple calls in a subtask, only the LAST call's counts are recorded.

**Files:** `internal/app/services/conductor/config/config.go` lines 82-99

**Fix:** If cumulative tracking is intended:
```go
func (c *CallUsage) Merge(other CallUsage) {
    c.Input += other.Input
    c.Output += other.Output
    c.CacheRead += other.CacheRead
    c.CacheWrite += other.CacheWrite
    c.CostInput += other.CostInput
    c.CostOutput += other.CostOutput
}
```

---

### Fix 39: `generator.tmpl` has duplicate "TASK PLANNING STRATEGIES" sections

**Problem:** Two sections with the same heading. First has a pentesting special case, second has more detail. LLM gets confused about which to follow.

**Files:** `internal/app/services/conductor/templates/generator.tmpl` (~lines 95-140)

**Fix:** Merge into one coherent section combining the pentesting case from the first and detail from the second.

---

### Fix 40: Release() only deletes primary container — secondary containers become orphans

**Problem:** The `Release` method has a TODO saying "delete all flow containers" but only deletes the primary one. Spawned containers leak.

**Files:** `internal/app/services/conductor/tools.go` lines 424-433

**Fix:**
```go
func (fte *flowToolsExecutor) Release(ctx context.Context) error {
    if fte.store != nil {
        fte.store.Close()
    }
    containers, err := fte.db.GetFlowContainers(ctx, fte.flowID)
    if err != nil {
        logrus.WithError(err).Warn("failed to list flow containers for cleanup")
    }
    var errs []error
    for _, cnt := range containers {
        if err := fte.docker.DeleteContainer(ctx, cnt.LocalID.String, cnt.ID); err != nil {
            errs = append(errs, err)
        }
    }
    if len(containers) == 0 {
        if err := fte.docker.DeleteContainer(ctx, fte.primaryLID, fte.primaryID); err != nil {
            errs = append(errs, err)
        }
    }
    return errors.Join(errs...)
}
```

---

### Fix 41: `wrapError` panics on nil error

**Problem:** `wrapError` calls `err.Error()` and `fmt.Errorf("%w", err)` without a nil check. If accidentally called with nil, it produces `%!w(<nil>)` or panics.

**Files:** `internal/app/services/conductor/handlers.go` lines 23-49

**Fix:**
```go
func wrapError(ctx context.Context, msg string, err error) error {
    if err == nil {
        logrus.WithContext(ctx).Error(msg)
        return errors.New(msg)
    }
    logrus.WithContext(ctx).WithError(err).Error(msg)
    return fmt.Errorf("%s: %w", msg, err)
}
```

---

### Fix 42: `context.Background()` used instead of passed context in 7+ locations

**Problem:** Multiple executor methods use `context.Background()` for DB calls instead of the caller's context. No timeout propagation, no cancellation, no tracing.

**Files:** `internal/app/services/conductor/tools.go` lines 385, 502, 792, 992, 1272, 1340, 1407

**Fix:** Replace all `context.Background()` with the caller's context. Requires adding `ctx context.Context` parameter to methods that don't have it.

---

## Implementation Order

Apply changes in this order to minimize risk of breaking things:

1. **Fix 4** — Broken `select` (one-line fix, zero risk, immediate benefit)
2. **Fix 15** — Context check at loop top (one-line, zero risk)
3. **Fix 20** — `sync.Once` for channel close (prevents panics)
4. **Fix 1** — Enable the tool call limit (the code is already there, just unused)
5. **Fix 2** — Rewrite repeating detector (critical safety fix)
6. **Fix 41** — nil-safe `wrapError` (defensive, zero risk)
7. **Fix 16** — Fix slice mutation (data corruption risk)
8. **Fix 33** — Don't drop DB errors (one-line fix)
9. **Fix 27** — Nil subtask check (prevents panics)
10. **Fix 17** — Differentiate Waiting vs Failed status
11. **Fix 5** — Template memory philosophy alignment (prompt-only changes)
12. **Fix 19** — Refiner deduplication instruction (prompt-only)
13. **Fix 39** — Merge duplicate template sections (prompt-only)
14. **Fix 11** — Terminal output size limit
15. **Fix 31** — ReadFile size limit reduction
16. **Fix 13** — Terminal mutex
17. **Fix 10** — Command blocklist
18. **Fix 12** — WriteFile path restriction
19. **Fix 30** — Structured error responses from terminal
20. **Fix 3** — Global execution budget (significant architecture change)
21. **Fix 14** — Rate limiting (needs per-tool configuration)
22. **Fix 9** — Status propagation locking (careful concurrency change)
23. **Fix 18** — Wait for previous task before starting new one
24. **Fix 21** — Flow status on error paths
25. **Fix 6** — Execution metrics to templates (needs backend + template changes)
26. **Fix 8** — Generator filesystem awareness (needs backend work)
27. **Fix 26** — Config execution limits
28. **Fix 22** — Atomic performResult + sync.Once for span ending
29. **Fixes 34-40** — Remaining medium-priority fixes

---

## Risk Assessment

| Fix | Risk | What Could Break |
|-----|------|------------------|
| 1 (tool call limit) | **Medium** — Legitimate complex subtasks might need >50 calls | Make limit configurable; start at 50, tune based on real usage |
| 2 (detector rewrite) | **Medium** — Might false-positive on tools that legitimately repeat with different args | Test with real agent transcripts before deploying |
| 3 (global budget) | **High** — Shared budget could starve legitimate sub-agents | Need fair allocation, not just first-come-first-served |
| 4 (select fix) | **None** — Pure bug fix, delay was always intended | — |
| 5 (template changes) | **Low** — LLM behavior change is unpredictable | A/B test with sample tasks |
| 9 (status locking) | **High** — Changing lock ordering in concurrent code | Extensive testing needed; possible deadlocks if done wrong |
| 10 (command blocklist) | **Medium** — May block legitimate pentesting commands | Make blocklist configurable; provide escape hatch |
| 11 (output limit) | **Low** — Some commands legitimately produce >1MB | Increase limit if needed; always show truncation notice |
| 14 (rate limiting) | **Medium** — May slow down legitimate rapid tool use | Tune per-tool limits based on real patterns |
| 18 (wait for prev task) | **Medium** — Adds latency to task switching | Previous task should stop quickly after cancellation |
| 25 (SQL query fix) | **Medium** — Refiner behavior will change (sees fewer subtasks) | May need to adjust refiner logic if it depends on seeing running subtasks |

---

## Summary Statistics

- **🔴 CRITICAL:** 9 fixes (Fixes 1-9) — These cause real failures: infinite loops, data corruption, wasted compute
- **🟠 HIGH:** 22 fixes (Fixes 10-31) — Significant improvements: security, reliability, correctness
- **🟡 MEDIUM:** 11 fixes (Fixes 32-42) — Quality improvements with clear value

**Top 3 systemic issues (fixing these addresses multiple findings):**
1. **The infinite loop cluster** (Fixes 1, 2, 3, 6, 7, 15, 26) — No hard limits anywhere in the execution stack
2. **Template-LLM coordination** (Fixes 5, 6, 7, 8, 19) — Prompts cause loops, lack metrics, lack deduplication
3. **Concurrency & state management** (Fixes 9, 18, 20, 21, 22) — Races, panics, inconsistent state on crash
