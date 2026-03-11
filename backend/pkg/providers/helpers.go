package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"pentagi/pkg/cast"
	"pentagi/pkg/csum"
	"pentagi/pkg/database"
	"pentagi/pkg/docker"
	obs "pentagi/pkg/observability"
	"pentagi/pkg/observability/langfuse"
	"pentagi/pkg/providers/pconfig"
	"pentagi/pkg/templates"
	"pentagi/pkg/tools"

	"github.com/sirupsen/logrus"
	"github.com/vxcontrol/langchaingo/llms"
)

const (
	RepeatingToolCallThreshold   = 3
	maxQASectionsAfterRestore    = 3
	keepQASectionsAfterRestore   = 1
	lastSecBytesAfterRestore     = 16 * 1024 // 16 KB
	maxBPBytesAfterRestore       = 8 * 1024  // 8 KB
	maxQABytesAfterRestore       = 20 * 1024 // 20 KB
	msgLogResultSummarySizeLimit = 70 * 1024 // 70 KB
	msgLogResultEntrySizeLimit   = 1024      // 1 KB
)

const repeatingWindowSize = 10

type repeatingDetector struct {
	history    []llms.FunctionCall
	threshold  int
	readCounts map[string]int // per-file path → read count this subtask
}

func newRepeatingDetector() *repeatingDetector {
	return &repeatingDetector{
		threshold:  RepeatingToolCallThreshold,
		readCounts: make(map[string]int),
	}
}

func (rd *repeatingDetector) detect(toolCall llms.ToolCall) bool {
	if toolCall.FunctionCall == nil {
		return false
	}

	funcCall := rd.clearCallArguments(toolCall.FunctionCall)

	// Exempt read-only file operations — agents legitimately re-read state files
	// like HANDOFF.md, STATE.json across subtask boundaries. Blocking these
	// causes death loops where the agent can't bootstrap.
	if rd.isReadOnlyCall(funcCall) {
		return false
	}

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

// isReadOnlyCall returns true for tool calls that only read data (file reads,
// cat commands, state checks). These should never be blocked by repeat detection
// because agents need to re-read shared state files (HANDOFF.md, STATE.json,
// FINDINGS.md) at the start of each subtask.
func (rd *repeatingDetector) isReadOnlyCall(fc llms.FunctionCall) bool {
	// file tool with read_file action
	if fc.Name == "file" {
		if strings.Contains(fc.Arguments, `"read_file"`) {
			return true
		}
	}
	// terminal tool running cat/head/tail/jq read commands
	if fc.Name == "terminal" {
		args := fc.Arguments
		// Match common read-only patterns in the input field
		for _, pattern := range []string{
			`"cat `, `"head `, `"tail `, `"jq `, `"cat /work/`,
			`"ls `, `"wc `, `"grep `, `"find `,
		} {
			if strings.Contains(args, pattern) {
				return true
			}
		}
	}
	return false
}

// readOnlyCmdPattern matches read-only shell commands (cat, head, tail) followed by a file path.
// It captures the first non-option argument as the file path.
var readOnlyCmdPattern = regexp.MustCompile(`(?:^|\s)(cat|head|tail)\s+(?:-[^\s]*\s+)*([^\s|;&>]+)`)

// checkReadCap enforces a soft cap on per-file read operations. Read-only calls
// are exempt from the repeat detector's detect() method to let agents bootstrap,
// but without a cap they can read the same file 20+ times in infinite loops.
//
// Returns (blocked, message):
//   - ≤2 reads:  (false, "")         — free, no warning
//   - 3-5 reads: (false, "⚠️ ...")   — warning prepended to tool result
//   - >5 reads:  (true, "BLOCKED...") — synthetic response, tool NOT executed
func (rd *repeatingDetector) checkReadCap(funcCall llms.FunctionCall) (bool, string) {
	if !rd.isReadOnlyCall(funcCall) {
		return false, ""
	}

	filePath := extractReadFilePath(funcCall)
	if filePath == "" {
		return false, ""
	}

	// Normalize to base name so /work/STATE.json and STATE.json count together.
	key := filepath.Base(filePath)

	if rd.readCounts == nil {
		rd.readCounts = make(map[string]int)
	}
	rd.readCounts[key]++
	count := rd.readCounts[key]

	switch {
	case count <= 2:
		return false, ""
	case count <= 5:
		return false, fmt.Sprintf(
			"⚠️ WARNING: You've read '%s' %d times. Content unchanged. Move to actual testing.",
			key, count,
		)
	default:
		return true, fmt.Sprintf(
			"BLOCKED: Read of '%s' denied — already read %d times this subtask. "+
				"The file content has not changed. Proceed with testing using the information you already have.",
			key, count,
		)
	}
}

// resetReadCounts clears the per-file read counter, intended for subtask boundaries.
func (rd *repeatingDetector) resetReadCounts() {
	rd.readCounts = make(map[string]int)
}

// extractReadFilePath extracts the file path from a read-only tool call.
// Handles both "file" tool with read_file action and "terminal" tool with cat/head/tail.
func extractReadFilePath(fc llms.FunctionCall) string {
	switch fc.Name {
	case "file":
		// Parse {"action":"read_file","path":"/work/STATE.json",...}
		var args map[string]interface{}
		if err := json.Unmarshal([]byte(fc.Arguments), &args); err != nil {
			return ""
		}
		if action, ok := args["action"].(string); ok && action == "read_file" {
			if p, ok := args["path"].(string); ok {
				return p
			}
		}
	case "terminal":
		// Parse {"input":"cat /work/STATE.json 2>/dev/null || echo NO",...}
		var args map[string]interface{}
		if err := json.Unmarshal([]byte(fc.Arguments), &args); err != nil {
			return ""
		}
		input, ok := args["input"].(string)
		if !ok {
			return ""
		}
		// Match cat/head/tail commands and extract the file path argument.
		matches := readOnlyCmdPattern.FindStringSubmatch(input)
		if len(matches) >= 3 {
			return matches[2]
		}
	}
	return ""
}

func (rd *repeatingDetector) clearCallArguments(toolCall *llms.FunctionCall) llms.FunctionCall {
	var v map[string]any
	if err := json.Unmarshal([]byte(toolCall.Arguments), &v); err != nil {
		return *toolCall
	}

	delete(v, "message")

	canonical, err := json.Marshal(v)
	if err != nil {
		return *toolCall
	}

	return llms.FunctionCall{
		Name:      toolCall.Name,
		Arguments: string(canonical),
	}
}

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

// AddCommand records a tool/command name, maintaining uniqueness.
func (em *ExecutionMetrics) AddCommand(name string) {
	for _, cmd := range em.UniqueCommands {
		if cmd == name {
			return
		}
	}
	em.UniqueCommands = append(em.UniqueCommands, name)
}

// Snapshot returns a copy with elapsed time updated to the current moment.
func (em *ExecutionMetrics) Snapshot(startTime time.Time) ExecutionMetrics {
	snap := *em
	snap.ElapsedSeconds = int(time.Since(startTime).Seconds())
	return snap
}

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

// ToolHistoryEntry records a single tool invocation with truncated payload.
type ToolHistoryEntry struct {
	Name      string    `json:"name"`
	Arguments string    `json:"arguments"` // truncated to maxToolHistoryArgLen chars
	Result    string    `json:"result"`    // truncated to maxToolHistoryResLen chars
	IsError   bool      `json:"is_error"`
	Timestamp time.Time `json:"timestamp"`
}

const (
	maxToolHistoryArgLen = 200
	maxToolHistoryResLen = 500
	defaultToolHistorySize = 50
)

// minCallsBetweenReflector is the cooldown: after the proactive reflector fires,
// it will not fire again until at least this many new tool calls have been recorded.
const minCallsBetweenReflector = 3

// ToolHistory is a thread-safe, bounded ring of recent tool call records.
type ToolHistory struct {
	mu                     sync.Mutex
	entries                []ToolHistoryEntry
	maxSize                int
	callsSinceLastReflect  int  // incremented on Add, reset on MarkReflectorFired
	reflectorFiredAtLeast  bool // true once MarkReflectorFired has been called at least once
}

// NewToolHistory creates a new tool history tracker with the given capacity.
func NewToolHistory(maxSize int) *ToolHistory {
	if maxSize <= 0 {
		maxSize = defaultToolHistorySize
	}
	return &ToolHistory{
		entries:                make([]ToolHistoryEntry, 0, maxSize),
		maxSize:                maxSize,
		callsSinceLastReflect:  minCallsBetweenReflector, // allow first trigger without waiting
	}
}

// MarkReflectorFired resets the cooldown counter. Call this every time the
// proactive reflector actually fires.
func (th *ToolHistory) MarkReflectorFired() {
	th.mu.Lock()
	defer th.mu.Unlock()
	th.callsSinceLastReflect = 0
	th.reflectorFiredAtLeast = true
}

// cooldownReady returns true if enough calls have been made since the last reflector.
// Must be called with th.mu held.
func (th *ToolHistory) cooldownReady() bool {
	return th.callsSinceLastReflect >= minCallsBetweenReflector
}

// Add appends an entry, evicting the oldest when at capacity.
// Arguments and Result are automatically truncated.
func (th *ToolHistory) Add(entry ToolHistoryEntry) {
	if len(entry.Arguments) > maxToolHistoryArgLen {
		entry.Arguments = entry.Arguments[:maxToolHistoryArgLen] + "…"
	}
	if len(entry.Result) > maxToolHistoryResLen {
		entry.Result = entry.Result[:maxToolHistoryResLen] + "…"
	}

	th.mu.Lock()
	defer th.mu.Unlock()

	th.entries = append(th.entries, entry)
	if len(th.entries) > th.maxSize {
		th.entries = th.entries[len(th.entries)-th.maxSize:]
	}
	th.callsSinceLastReflect++
}

// GetLast returns the last n entries (fewer if history is shorter).
func (th *ToolHistory) GetLast(n int) []ToolHistoryEntry {
	th.mu.Lock()
	defer th.mu.Unlock()

	if n <= 0 || len(th.entries) == 0 {
		return nil
	}
	if n > len(th.entries) {
		n = len(th.entries)
	}
	out := make([]ToolHistoryEntry, n)
	copy(out, th.entries[len(th.entries)-n:])
	return out
}

// Len returns the current number of entries.
func (th *ToolHistory) Len() int {
	th.mu.Lock()
	defer th.mu.Unlock()
	return len(th.entries)
}

// GetErrorRate returns the fraction of entries that are errors in the last n calls.
func (th *ToolHistory) GetErrorRate(n int) float64 {
	last := th.GetLast(n)
	if len(last) == 0 {
		return 0
	}
	errCount := 0
	for _, e := range last {
		if e.IsError {
			errCount++
		}
	}
	return float64(errCount) / float64(len(last))
}

// GetPatternScore returns a score from 0.0 (all unique tool calls) to 1.0
// (all identical tool calls) over the last 10 entries.
// It measures how repetitive the recent tool usage is.
//
// Unlike the original name-only entropy, this version also considers argument
// diversity when a single tool name dominates the window. This prevents false
// positives for tools like "terminal" that are used with many different arguments.
func (th *ToolHistory) GetPatternScore() float64 {
	last := th.GetLast(repeatingWindowSize)
	if len(last) <= 1 {
		return 0.0
	}

	// Count frequency of each tool name
	nameFreq := make(map[string]int)
	for _, e := range last {
		nameFreq[e.Name]++
	}

	n := float64(len(last))

	// If a single tool name accounts for >60% of calls, use (name+args) as the
	// dedup key instead of just the name. This way, "terminal" called 10 times
	// with 10 different commands scores low (diverse), while "terminal" called
	// 10 times with the same command scores high (repetitive).
	useArgAware := false
	for _, count := range nameFreq {
		if float64(count)/n > 0.6 {
			useArgAware = true
			break
		}
	}

	freq := make(map[string]int)
	if useArgAware {
		for _, e := range last {
			// Combine name + truncated arguments as the key
			key := e.Name + "\x00" + e.Arguments
			freq[key]++
		}
	} else {
		for _, e := range last {
			freq[e.Name]++
		}
	}

	// Shannon entropy normalized to [0,1]
	var entropy float64
	for _, count := range freq {
		p := float64(count) / n
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	// Max entropy when all keys are unique
	maxEntropy := math.Log2(n)
	if maxEntropy == 0 {
		return 1.0 // single entry, trivially "all same"
	}

	// Invert: low entropy => high pattern score
	return 1.0 - (entropy / maxEntropy)
}

// GetMostFrequentInLast returns the tool name that appears most often in the last n entries
// and its count. Returns ("", 0) on empty history.
func (th *ToolHistory) GetMostFrequentInLast(n int) (string, int) {
	last := th.GetLast(n)
	if len(last) == 0 {
		return "", 0
	}
	freq := make(map[string]int)
	bestName := ""
	bestCount := 0
	for _, e := range last {
		freq[e.Name]++
		if freq[e.Name] > bestCount {
			bestCount = freq[e.Name]
			bestName = e.Name
		}
	}
	return bestName, bestCount
}

// FormatForPrompt renders a human-readable summary of the last 10 entries
// suitable for injection into an LLM prompt.
func (th *ToolHistory) FormatForPrompt() string {
	last := th.GetLast(repeatingWindowSize)
	if len(last) == 0 {
		return "No tool calls recorded yet."
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("=== Last %d Tool Calls ===\n", len(last)))

	errCount := 0
	nameFreq := make(map[string]int)
	for i, e := range last {
		nameFreq[e.Name]++
		status := "OK"
		if e.IsError {
			status = "ERROR"
			errCount++
		}
		b.WriteString(fmt.Sprintf("[%d] %s | %s | args: %s\n",
			i+1, e.Name, status, e.Arguments))
		if e.IsError && e.Result != "" {
			b.WriteString(fmt.Sprintf("     error: %s\n", e.Result))
		}
	}

	b.WriteString(fmt.Sprintf("\n--- Summary ---\n"))
	b.WriteString(fmt.Sprintf("Total: %d | Errors: %d (%.0f%%)\n", len(last), errCount,
		float64(errCount)/float64(len(last))*100))
	b.WriteString(fmt.Sprintf("Pattern Score: %.2f (0=diverse, 1=repetitive)\n", th.GetPatternScore()))

	// Show frequency breakdown
	b.WriteString("Tool frequency: ")
	parts := make([]string, 0, len(nameFreq))
	for name, count := range nameFreq {
		parts = append(parts, fmt.Sprintf("%s×%d", name, count))
	}
	b.WriteString(strings.Join(parts, ", "))
	b.WriteString("\n")

	// Detect repetition warnings
	mostFreqName, mostFreqCount := th.GetMostFrequentInLast(repeatingWindowSize)
	if mostFreqCount > 3 {
		b.WriteString(fmt.Sprintf("⚠ WARNING: '%s' called %d times in last %d — possible loop!\n",
			mostFreqName, mostFreqCount, len(last)))
	}

	return b.String()
}

// ShouldTriggerProactiveReflector checks whether tool history warrants a proactive
// reflector invocation. Returns (shouldTrigger, reason).
//
// Cooldown: after the reflector fires, at least minCallsBetweenReflector new tool
// calls must be recorded before it can fire again (except for periodic checkpoints
// and critical error rates). This prevents the "reflector storm" where the same
// condition fires the reflector every single call once triggered.
func (th *ToolHistory) ShouldTriggerProactiveReflector(totalCalls int) (bool, string) {
	th.mu.Lock()
	cooldownOK := th.cooldownReady()
	th.mu.Unlock()

	// Trigger 1: Every 10 tool calls (periodic checkpoint) — always fires, ignores cooldown
	if totalCalls > 0 && totalCalls%10 == 0 {
		return true, fmt.Sprintf("periodic checkpoint at %d tool calls", totalCalls)
	}

	// Trigger 2: Error rate > 50% in last 5 calls — fires even during cooldown (critical)
	if th.Len() >= 5 {
		errorRate := th.GetErrorRate(5)
		if errorRate > 0.5 {
			return true, fmt.Sprintf("high error rate %.0f%% in last 5 calls", errorRate*100)
		}
	}

	// All remaining triggers respect the cooldown
	if !cooldownOK {
		return false, ""
	}

	// Trigger 3: Pattern score > 0.90 (highly repetitive, argument-aware)
	// Raised from 0.7 to 0.90 because GetPatternScore now considers argument
	// diversity for dominant tools. A score of 0.90+ means the agent is truly
	// repeating the same calls with the same arguments.
	if th.Len() >= 5 {
		score := th.GetPatternScore()
		if score > 0.90 {
			return true, fmt.Sprintf("high pattern score %.2f (repetitive tool usage)", score)
		}
	}

	// Trigger 4: Same (name+args) pair repeated > 3 times in last 10
	// Previously this checked tool NAME only, which false-triggered for tools
	// like "terminal" that are used with many different arguments.
	// Now checks (name+args) deduplication so diverse usage doesn't trigger.
	if th.Len() >= 5 {
		last := th.GetLast(repeatingWindowSize)
		pairFreq := make(map[string]int)
		bestKey := ""
		bestCount := 0
		for _, e := range last {
			key := e.Name + "\x00" + e.Arguments
			pairFreq[key]++
			if pairFreq[key] > bestCount {
				bestCount = pairFreq[key]
				bestKey = e.Name
			}
		}
		if bestCount > 3 {
			return true, fmt.Sprintf("'%s' called with same arguments %d times in last %d calls", bestKey, bestCount, len(last))
		}
	}

	return false, ""
}

// filterReflectorSuggestions removes read-only state file checks from reflector
// corrective tool calls. This prevents the reflector from suggesting "check STATE.json"
// or "review FINDINGS.md" which causes the agent to enter an infinite read loop.
func filterReflectorSuggestions(suggestions []llms.ToolCall) []llms.ToolCall {
	filtered := make([]llms.ToolCall, 0, len(suggestions))
	for _, tc := range suggestions {
		if isStateReadCall(tc) {
			continue // skip read-only state checks from reflector
		}
		filtered = append(filtered, tc)
	}
	if len(filtered) == 0 && len(suggestions) > 0 {
		// All suggestions were filtered out — this means reflector only suggested reads.
		// Don't inject anything; the agent will continue on its own.
		return nil
	}
	return filtered
}

// isStateReadCall returns true if the tool call is a read-only operation targeting
// state files (STATE.json, FINDINGS.md, HANDOFF.md, RESUME.md). These are the
// files the reflector commonly (and incorrectly) suggests re-reading.
func isStateReadCall(tc llms.ToolCall) bool {
	if tc.FunctionCall == nil {
		return false
	}
	args := strings.ToLower(tc.FunctionCall.Arguments)
	stateFiles := []string{"state.json", "findings.md", "handoff.md", "resume.md"}
	readPatterns := []string{`"cat `, `"read_file"`, `"head `, `"tail `, `"cat /work/`}

	for _, f := range stateFiles {
		if strings.Contains(args, f) {
			for _, p := range readPatterns {
				if strings.Contains(args, p) {
					return true
				}
			}
		}
	}
	return false
}

// buildResumeContent generates the RESUME.md content string from tool history and metrics.
func buildResumeContent(toolHistory *ToolHistory, metrics *ExecutionMetrics) string {
	last10 := toolHistory.GetLast(10)
	if len(last10) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("# RESUME CONTEXT (auto-generated — do not modify)\n")
	sb.WriteString(fmt.Sprintf("## Generated at: %s\n", time.Now().UTC().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("## Tool calls completed: %d\n\n", metrics.ToolCallCount))

	sb.WriteString("## Last 10 Actions Taken\n")
	for i, entry := range last10 {
		status := "OK"
		if entry.IsError {
			status = "ERROR"
		}
		argSnippet := entry.Arguments
		if len(argSnippet) > 150 {
			argSnippet = argSnippet[:150] + "..."
		}
		sb.WriteString(fmt.Sprintf("%d. [%s] %s — %s\n", i+1, status, entry.Name, argSnippet))
	}

	sb.WriteString("\n## FILES ALREADY READ (DO NOT re-read)\n")
	sb.WriteString("STATE.json, FINDINGS.md, HANDOFF.md — all already verified.\n")
	sb.WriteString("\n## INSTRUCTION ON RESUME\n")
	sb.WriteString("If you are resuming after a timeout:\n")
	sb.WriteString("1. Read THIS file (RESUME.md) ONCE\n")
	sb.WriteString("2. DO NOT re-read STATE.json, FINDINGS.md, or HANDOFF.md\n")
	sb.WriteString("3. DO NOT re-run bootstrap (jq install, mkdir evidence)\n")
	sb.WriteString("4. Continue from where the last action left off\n")

	return sb.String()
}

func (fp *flowProvider) getTasksInfo(ctx context.Context, taskID int64) (*tasksInfo, error) {
	var (
		err  error
		info tasksInfo
	)

	ctx, observation := obs.Observer.NewObservation(ctx)
	evaluator := observation.Evaluator(
		langfuse.WithEvaluatorName("get tasks info"),
		langfuse.WithEvaluatorInput(map[string]any{
			"task_id": taskID,
		}),
	)
	ctx, _ = evaluator.Observation(ctx)

	info.Tasks, err = fp.db.GetFlowTasks(ctx, fp.flowID)
	if err != nil {
		return nil, wrapErrorEndEvaluatorSpan(ctx, evaluator, "failed to get flow tasks", err)
	}

	otherTasks := make([]database.Task, 0, len(info.Tasks))
	for _, t := range info.Tasks {
		if t.ID == taskID {
			info.Task = t
		} else {
			otherTasks = append(otherTasks, t)
		}
	}
	info.Tasks = otherTasks

	info.Subtasks, err = fp.db.GetFlowSubtasks(ctx, fp.flowID)
	if err != nil {
		return nil, wrapErrorEndEvaluatorSpan(ctx, evaluator, "failed to get flow subtasks", err)
	}

	evaluator.End(
		langfuse.WithEvaluatorOutput(map[string]any{
			"task":           info.Task,
			"subtasks":       info.Subtasks,
			"tasks_count":    len(info.Tasks),
			"subtasks_count": len(info.Subtasks),
		}),
		langfuse.WithEvaluatorStatus("success"),
		langfuse.WithEvaluatorLevel(langfuse.ObservationLevelDebug),
	)

	return &info, nil
}

func (fp *flowProvider) getSubtasksInfo(taskID int64, subtasks []database.Subtask) *subtasksInfo {
	var info subtasksInfo
	for _, subtask := range subtasks {
		if subtask.TaskID != taskID && taskID != 0 {
			continue
		}

		switch subtask.Status {
		case database.SubtaskStatusCreated:
			info.Planned = append(info.Planned, subtask)
		case database.SubtaskStatusFinished, database.SubtaskStatusFailed:
			info.Completed = append(info.Completed, subtask)
		default:
			info.Subtask = &subtask
		}
	}

	return &info
}

func (fp *flowProvider) updateMsgChainResult(chain []llms.MessageContent, name, result string) ([]llms.MessageContent, error) {
	if len(chain) == 0 {
		return []llms.MessageContent{llms.TextParts(llms.ChatMessageTypeHuman, result)}, nil
	}

	ast, err := cast.NewChainAST(chain, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create chain ast: %w", err)
	}

	lastSection := ast.Sections[len(ast.Sections)-1]
	if len(lastSection.Body) == 0 {
		ast.AppendHumanMessage(result)
		return ast.Messages(), nil
	}

	lastBody := lastSection.Body[len(lastSection.Body)-1]
	switch lastBody.Type {
	case cast.Completion, cast.Summarization:
		ast.AppendHumanMessage(result)
		return ast.Messages(), nil
	case cast.RequestResponse:
		for _, msg := range lastBody.ToolMessages {
			for pdx, part := range msg.Parts {
				toolCallResp, ok := part.(llms.ToolCallResponse)
				if !ok {
					continue
				}

				if toolCallResp.Name == name {
					toolCallResp.Content = result
					msg.Parts[pdx] = toolCallResp
					return ast.Messages(), nil
				}
			}
		}

		ast.AppendHumanMessage(result)
		return ast.Messages(), nil
	default:
		return nil, fmt.Errorf("unknown message type: %d", lastBody.Type)
	}
}

// Makes chain consistent by adding default responses for any pending tool calls
func (fp *flowProvider) ensureChainConsistency(chain []llms.MessageContent) ([]llms.MessageContent, error) {
	if len(chain) == 0 {
		return chain, nil
	}

	ast, err := cast.NewChainAST(chain, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create chain ast: %w", err)
	}

	return ast.Messages(), nil
}

// validateAndRepairChain scans the message chain for orphaned tool_use blocks
// (tool_use without a matching tool_result) and inserts synthetic tool_result
// messages to satisfy provider requirements (e.g. Anthropic requires every
// tool_use to have a corresponding tool_result immediately after).
//
// This is a critical safety net that prevents 400 errors from the Anthropic API.
// The corruption typically happens when:
// 1. An AI message with multiple tool_use blocks is saved to DB
// 2. Tool execution fails partway through the batch
// 3. The function returns before all tool_results are added
// 4. On resume/retry, the chain has orphaned tool_use blocks
//
// Uses NewChainAST with force=true which handles all edge cases including
// orphaned tool_use, unmatched tool_result, and incomplete request-response pairs.
// Returns the repaired chain and the number of synthetic tool_results inserted.
func validateAndRepairChain(chain []llms.MessageContent) ([]llms.MessageContent, int) {
	if len(chain) == 0 {
		return chain, 0
	}

	// Count orphaned tool_use blocks before repair
	orphanCount := countOrphanedToolUses(chain)
	if orphanCount == 0 {
		return chain, 0
	}

	// Use NewChainAST with force=true to repair the chain.
	// This handles all consistency issues including:
	// - tool_use without tool_result → adds FallbackResponseContent
	// - tool_result without tool_use → adds fallback tool_use
	// - incomplete request-response pairs
	ast, err := cast.NewChainAST(chain, true)
	if err != nil {
		// If even forced AST creation fails, return original chain unchanged.
		// This shouldn't happen in practice since force=true is very permissive.
		return chain, 0
	}

	return ast.Messages(), orphanCount
}

// countOrphanedToolUses counts tool_use blocks that don't have matching tool_result blocks.
// This is a lightweight check that avoids full AST parsing.
func countOrphanedToolUses(chain []llms.MessageContent) int {
	// Collect all tool_use IDs from AI messages
	toolUseIDs := make(map[string]bool)
	for _, msg := range chain {
		if msg.Role == llms.ChatMessageTypeAI {
			for _, part := range msg.Parts {
				if tc, ok := part.(llms.ToolCall); ok && tc.FunctionCall != nil && tc.ID != "" {
					toolUseIDs[tc.ID] = true
				}
			}
		}
	}

	if len(toolUseIDs) == 0 {
		return 0
	}

	// Remove IDs that have matching tool_result
	for _, msg := range chain {
		if msg.Role == llms.ChatMessageTypeTool {
			for _, part := range msg.Parts {
				if resp, ok := part.(llms.ToolCallResponse); ok {
					delete(toolUseIDs, resp.ToolCallID)
				}
			}
		}
	}

	return len(toolUseIDs)
}

func (fp *flowProvider) getTaskPrimaryAgentChainSummary(
	ctx context.Context,
	taskID int64,
	summarizerHandler tools.SummarizeHandler,
) (string, error) {
	ctx, observation := obs.Observer.NewObservation(ctx)
	evaluator := observation.Evaluator(
		langfuse.WithEvaluatorName("get task primary agent chain summary"),
		langfuse.WithEvaluatorInput(map[string]any{
			"task_id": taskID,
		}),
	)
	ctx, _ = evaluator.Observation(ctx)

	msgChain, err := fp.db.GetFlowTaskTypeLastMsgChain(ctx, database.GetFlowTaskTypeLastMsgChainParams{
		FlowID: fp.flowID,
		TaskID: database.Int64ToNullInt64(&taskID),
		Type:   database.MsgchainTypePrimaryAgent,
	})
	if err != nil || isEmptyChain(msgChain.Chain) {
		return "", wrapErrorEndEvaluatorSpan(ctx, evaluator, "failed to get task primary agent chain", err)
	}

	chain := []llms.MessageContent{}
	if err := json.Unmarshal(msgChain.Chain, &chain); err != nil {
		return "", wrapErrorEndEvaluatorSpan(ctx, evaluator, "failed to unmarshal task primary agent chain", err)
	}

	ast, err := cast.NewChainAST(chain, true)
	if err != nil {
		return "", wrapErrorEndEvaluatorSpan(ctx, evaluator, "failed to create refiner chain ast", err)
	}

	var humanMessages, aiMessages []llms.MessageContent
	for _, section := range ast.Sections {
		if section.Header.HumanMessage != nil {
			humanMessages = append(humanMessages, *section.Header.HumanMessage)
		}
		for _, pair := range section.Body {
			aiMessages = append(aiMessages, pair.Messages()...)
		}
	}

	humanSummary, err := csum.GenerateSummary(ctx, summarizerHandler, humanMessages, nil)
	if err != nil {
		return "", wrapErrorEndEvaluatorSpan(ctx, evaluator, "failed to generate human summary", err)
	}

	aiSummary, err := csum.GenerateSummary(ctx, summarizerHandler, humanMessages, aiMessages)
	if err != nil {
		return "", wrapErrorEndEvaluatorSpan(ctx, evaluator, "failed to generate ai summary", err)
	}

	summary := fmt.Sprintf(`## Task Summary

### User Requirements
*Summarized input from user:*

%s

### Execution Results
*Summarized actions and outcomes:*

%s`, humanSummary, aiSummary)

	evaluator.End(
		langfuse.WithEvaluatorOutput(summary),
		langfuse.WithEvaluatorStatus("success"),
		langfuse.WithEvaluatorLevel(langfuse.ObservationLevelDebug),
	)

	return summary, nil
}

func (fp *flowProvider) getTaskMsgLogsSummary(
	ctx context.Context,
	taskID int64,
	summarizerHandler tools.SummarizeHandler,
) (string, error) {
	ctx, observation := obs.Observer.NewObservation(ctx)
	evaluator := observation.Evaluator(
		langfuse.WithEvaluatorName("get task msg logs summary"),
		langfuse.WithEvaluatorInput(map[string]any{
			"task_id": taskID,
			"flow_id": fp.flowID,
		}),
	)
	ctx, _ = evaluator.Observation(ctx)

	msgLogs, err := fp.db.GetTaskMsgLogs(ctx, database.Int64ToNullInt64(&taskID))
	if err != nil {
		return "", wrapErrorEndEvaluatorSpan(ctx, evaluator, "failed to get task msg logs", err)
	}

	if len(msgLogs) == 0 {
		evaluator.End(
			langfuse.WithEvaluatorOutput("no msg logs"),
			langfuse.WithEvaluatorStatus("success"),
			langfuse.WithEvaluatorLevel(langfuse.ObservationLevelDebug),
		)
		return "no msg logs", nil
	}

	// truncate msg logs result to cut down the size the message to summarize
	for _, msgLog := range msgLogs {
		if len(msgLog.Result) > msgLogResultEntrySizeLimit {
			msgLog.Result = msgLog.Result[:msgLogResultEntrySizeLimit] + textTruncateMessage
		}
	}

	message, err := fp.prompter.RenderTemplate(templates.PromptTypeExecutionLogs, map[string]any{
		"MsgLogs": msgLogs,
	})
	if err != nil {
		return "", wrapErrorEndEvaluatorSpan(ctx, evaluator, "failed to render task msg logs template", err)
	}

	for l := len(msgLogs) / 2; l > 2; l /= 2 {
		if len(message) < msgLogResultSummarySizeLimit {
			break
		}

		msgLogs = msgLogs[len(msgLogs)-l:]
		message, err = fp.prompter.RenderTemplate(templates.PromptTypeExecutionLogs, map[string]any{
			"MsgLogs": msgLogs,
		})
		if err != nil {
			return "", wrapErrorEndEvaluatorSpan(ctx, evaluator, "failed to render task msg logs template", err)
		}
	}

	summary, err := summarizerHandler(ctx, message)
	if err != nil {
		return "", wrapErrorEndEvaluatorSpan(ctx, evaluator, "failed to summarize task msg logs", err)
	}

	evaluator.End(
		langfuse.WithEvaluatorOutput(summary),
		langfuse.WithEvaluatorStatus("success"),
		langfuse.WithEvaluatorLevel(langfuse.ObservationLevelDebug),
	)

	return summary, nil
}

func (fp *flowProvider) restoreChain(
	ctx context.Context,
	taskID, subtaskID *int64,
	optAgentType pconfig.ProviderOptionsType,
	msgChainType database.MsgchainType,
	systemPrompt, humanPrompt string,
) (int64, []llms.MessageContent, error) {
	ctx, observation := obs.Observer.NewObservation(ctx)

	// Get raw chain from DB for observation input
	msgChain, err := fp.db.GetFlowTaskTypeLastMsgChain(ctx, database.GetFlowTaskTypeLastMsgChainParams{
		FlowID: fp.flowID,
		TaskID: database.Int64ToNullInt64(taskID),
		Type:   msgChainType,
	})

	var rawChain []llms.MessageContent
	if err == nil && !isEmptyChain(msgChain.Chain) {
		json.Unmarshal(msgChain.Chain, &rawChain)
	}

	metadata := langfuse.Metadata{
		"msg_chain_type": string(msgChainType),
		"msg_chain_id":   msgChain.ID,
		"agent_type":     string(optAgentType),
	}
	if taskID != nil {
		metadata["task_id"] = *taskID
	}
	if subtaskID != nil {
		metadata["subtask_id"] = *subtaskID
	}

	chainObs := observation.Chain(
		langfuse.WithChainName("restore message chain"),
		langfuse.WithChainInput(rawChain),
		langfuse.WithChainMetadata(metadata),
	)
	ctx, observation = chainObs.Observation(ctx)
	wrapErrorWithEvent := func(msg string, err error) error {
		observation.Event(
			langfuse.WithEventName("error on restoring message chain"),
			langfuse.WithEventInput(rawChain),
			langfuse.WithEventMetadata(metadata),
			langfuse.WithEventStatus(err.Error()),
			langfuse.WithEventLevel(langfuse.ObservationLevelWarning),
		)

		if err != nil {
			logrus.WithContext(ctx).WithError(err).Warn(msg)
			return fmt.Errorf("%s: %w", msg, err)
		}

		logrus.WithContext(ctx).Warn(msg)
		return errors.New(msg)
	}

	var chain []llms.MessageContent
	fallback := func() {
		chain = []llms.MessageContent{
			llms.TextParts(llms.ChatMessageTypeSystem, systemPrompt),
		}
		if humanPrompt != "" {
			chain = append(chain, llms.TextParts(llms.ChatMessageTypeHuman, humanPrompt))
		}
	}

	if err != nil || isEmptyChain(msgChain.Chain) {
		fallback()
	} else {
		err = func() error {
			err = json.Unmarshal(msgChain.Chain, &chain)
			if err != nil {
				return wrapErrorWithEvent("failed to unmarshal msg chain", err)
			}

			ast, err := cast.NewChainAST(chain, true)
			if err != nil {
				return wrapErrorWithEvent("failed to create refiner chain ast", err)
			}

			if len(ast.Sections) == 0 {
				return wrapErrorWithEvent("failed to get sections from refiner chain ast", nil)
			}

			systemMessage := llms.TextParts(llms.ChatMessageTypeSystem, systemPrompt)
			ast.Sections[0].Header.SystemMessage = &systemMessage
			if humanPrompt != "" {
				lastSection := ast.Sections[len(ast.Sections)-1]
				if len(lastSection.Body) == 0 {
					// do not add a new human message if the previous human message is not yet completed
					lastSection.Header.HumanMessage = nil
				} else {
					lastBody := lastSection.Body[len(lastSection.Body)-1]
					if lastBody.Type == cast.RequestResponse && len(lastBody.ToolMessages) == 0 {
						// prevent using incomplete chain without tool call response
						lastSection.Body = lastSection.Body[:len(lastSection.Body)-1]
					}
				}
				ast.AppendHumanMessage(humanPrompt)
			}

			if err := ast.NormalizeToolCallIDs(fp.tcIDTemplate); err != nil {
				return wrapErrorWithEvent("failed to normalize tool call IDs", err)
			}

			if err := ast.ClearReasoning(); err != nil {
				return wrapErrorWithEvent("failed to clear reasoning", err)
			}

			summarizeHandler := fp.GetSummarizeResultHandler(taskID, subtaskID)
			summarizer := csum.NewSummarizer(csum.SummarizerConfig{
				PreserveLast:   true,
				UseQA:          true,
				SummHumanInQA:  true,
				LastSecBytes:   lastSecBytesAfterRestore,
				MaxBPBytes:     maxBPBytesAfterRestore,
				MaxQASections:  maxQASectionsAfterRestore,
				MaxQABytes:     maxQABytesAfterRestore,
				KeepQASections: keepQASectionsAfterRestore,
			})

			chain, err = summarizer.SummarizeChain(ctx, summarizeHandler, ast.Messages(), fp.tcIDTemplate)
			if err != nil {
				_ = wrapErrorWithEvent("failed to summarize chain", err) // non critical error, just log it
				chain = ast.Messages()
			}

			return nil
		}()
		if err != nil {
			fallback()
		}
	}

	chainObs.End(
		langfuse.WithChainOutput(chain),
		langfuse.WithChainStatus("success"),
	)

	chainBlob, err := json.Marshal(chain)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to marshal msg chain: %w", err)
	}

	msgChain, err = fp.db.CreateMsgChain(ctx, database.CreateMsgChainParams{
		Type:          msgChainType,
		Model:         fp.Model(optAgentType),
		ModelProvider: string(fp.Type()),
		Chain:         chainBlob,
		FlowID:        fp.flowID,
		TaskID:        database.Int64ToNullInt64(taskID),
		SubtaskID:     database.Int64ToNullInt64(subtaskID),
	})
	if err != nil {
		return 0, nil, fmt.Errorf("failed to create msg chain: %w", err)
	}

	return msgChain.ID, chain, nil
}

// Eliminates code duplication by abstracting database operations on message chains
func (fp *flowProvider) processChain(
	ctx context.Context,
	msgChainID int64,
	logger *logrus.Entry,
	transform func([]llms.MessageContent) ([]llms.MessageContent, error),
) error {
	msgChain, err := fp.db.GetMsgChain(ctx, msgChainID)
	if err != nil {
		logger.WithError(err).Error("failed to get message chain")
		return fmt.Errorf("failed to get message chain %d: %w", msgChainID, err)
	}

	var chain []llms.MessageContent
	if err := json.Unmarshal(msgChain.Chain, &chain); err != nil {
		logger.WithError(err).Error("failed to unmarshal message chain")
		return fmt.Errorf("failed to unmarshal message chain %d: %w", msgChainID, err)
	}

	updatedChain, err := transform(chain)
	if err != nil {
		logger.WithError(err).Error("failed to transform chain")
		return fmt.Errorf("failed to transform chain: %w", err)
	}

	chainBlob, err := json.Marshal(updatedChain)
	if err != nil {
		logger.WithError(err).Error("failed to marshal updated chain")
		return fmt.Errorf("failed to marshal updated chain %d: %w", msgChainID, err)
	}

	_, err = fp.db.UpdateMsgChain(ctx, database.UpdateMsgChainParams{
		Chain: chainBlob,
		ID:    msgChainID,
	})
	if err != nil {
		logger.WithError(err).Error("failed to update message chain")
		return fmt.Errorf("failed to update message chain %d: %w", msgChainID, err)
	}

	return nil
}

func (fp *flowProvider) prepareExecutionContext(ctx context.Context, taskID, subtaskID int64) (string, error) {
	ctx, observation := obs.Observer.NewObservation(ctx)
	evaluator := observation.Evaluator(
		langfuse.WithEvaluatorName("prepare execution context"),
		langfuse.WithEvaluatorInput(map[string]any{
			"task_id":    taskID,
			"subtask_id": subtaskID,
			"flow_id":    fp.flowID,
		}),
	)
	ctx, _ = evaluator.Observation(ctx)

	tasksInfo, err := fp.getTasksInfo(ctx, taskID)
	if err != nil {
		return "", wrapErrorEndEvaluatorSpan(ctx, evaluator, "failed to get tasks info", err)
	}

	subtasksInfo := fp.getSubtasksInfo(taskID, tasksInfo.Subtasks)
	if subtasksInfo.Subtask == nil {
		subtasks := make([]database.Subtask, 0, len(subtasksInfo.Planned)+len(subtasksInfo.Completed))
		subtasks = append(subtasks, subtasksInfo.Planned...)
		subtasks = append(subtasks, subtasksInfo.Completed...)
		slices.SortFunc(subtasks, func(a, b database.Subtask) int {
			return int(a.ID - b.ID)
		})

		for i, subtask := range subtasks {
			if subtask.ID == subtaskID {
				subtasksInfo.Subtask = &subtask
				subtasksInfo.Planned = subtasks[i+1:]
				subtasksInfo.Completed = subtasks[:i]
				break
			}
		}
	}

	if subtasksInfo.Subtask == nil {
		logrus.WithField("subtask_id", subtaskID).Error("subtask not found in task's subtask list")
		return "", fmt.Errorf("subtask %d not found in task's subtask list", subtaskID)
	}

	executionContextRaw, err := fp.prompter.RenderTemplate(templates.PromptTypeFullExecutionContext, map[string]any{
		"Task":              tasksInfo.Task,
		"Tasks":             tasksInfo.Tasks,
		"CompletedSubtasks": subtasksInfo.Completed,
		"Subtask":           subtasksInfo.Subtask,
		"PlannedSubtasks":   subtasksInfo.Planned,
		// ExecutionMetrics is nil at context preparation time (before agent loop);
		// the {{if .ExecutionMetrics}} guard in the template safely skips the block.
	})
	if err != nil {
		return "", wrapErrorEndEvaluatorSpan(ctx, evaluator, "failed to render execution context", err)
	}

	summarizeHandler := fp.GetSummarizeResultHandler(&taskID, &subtaskID)
	executionContext, err := summarizeHandler(ctx, executionContextRaw)
	if err != nil {
		return "", wrapErrorEndEvaluatorSpan(ctx, evaluator, "failed to summarize execution context", err)
	}

	evaluator.End(
		langfuse.WithEvaluatorOutput(executionContext),
		langfuse.WithEvaluatorStatus("success"),
		langfuse.WithEvaluatorLevel(langfuse.ObservationLevelDebug),
	)

	return executionContext, nil
}

func (fp *flowProvider) getExecutionContext(ctx context.Context, taskID, subtaskID *int64) (string, error) {
	if taskID != nil && subtaskID != nil {
		return fp.getExecutionContextBySubtask(ctx, *taskID, *subtaskID)
	}

	if taskID != nil {
		return fp.getExecutionContextByTask(ctx, *taskID)
	}

	return fp.getExecutionContextByFlow(ctx)
}

func (fp *flowProvider) getExecutionContextBySubtask(ctx context.Context, taskID, subtaskID int64) (string, error) {
	subtask, err := fp.db.GetSubtask(ctx, subtaskID)
	if err == nil && subtask.TaskID == taskID && subtask.Context != "" {
		return subtask.Context, nil
	}

	return fp.getExecutionContextByTask(ctx, taskID)
}

func (fp *flowProvider) getExecutionContextByTask(ctx context.Context, taskID int64) (string, error) {
	tasksInfo, err := fp.getTasksInfo(ctx, taskID)
	if err != nil {
		return fp.getExecutionContextByFlow(ctx)
	}

	subtasksInfo := fp.getSubtasksInfo(taskID, tasksInfo.Subtasks)
	executionContext, err := fp.prompter.RenderTemplate(templates.PromptTypeShortExecutionContext, map[string]any{
		"Task":              tasksInfo.Task,
		"Tasks":             tasksInfo.Tasks,
		"CompletedSubtasks": subtasksInfo.Completed,
		"Subtask":           subtasksInfo.Subtask,
		"PlannedSubtasks":   subtasksInfo.Planned,
	})
	if err != nil {
		return fp.getExecutionContextByFlow(ctx)
	}

	return executionContext, nil
}

func (fp *flowProvider) getExecutionContextByFlow(ctx context.Context) (string, error) {
	tasks, err := fp.db.GetFlowTasks(ctx, fp.flowID)
	if err != nil {
		return "", fmt.Errorf("failed to get flow tasks: %w", err)
	}

	if len(tasks) == 0 {
		return "flow has no tasks, it's using in assistant mode", nil
	}

	subtasks, err := fp.db.GetFlowSubtasks(ctx, fp.flowID)
	if err != nil {
		return "", fmt.Errorf("failed to get flow subtasks: %w", err)
	}

	for tid := len(tasks) - 1; tid >= 0; tid-- {
		taskID := tasks[tid].ID

		subtasksInfo := fp.getSubtasksInfo(taskID, subtasks)
		executionContext, err := fp.prompter.RenderTemplate(templates.PromptTypeShortExecutionContext, map[string]any{
			"Task":              tasks[tid],
			"Tasks":             tasks,
			"CompletedSubtasks": subtasksInfo.Completed,
			"Subtask":           subtasksInfo.Subtask,
			"PlannedSubtasks":   subtasksInfo.Planned,
		})
		if err != nil {
			continue
		}

		return executionContext, nil
	}

	subtasksInfo := fp.getSubtasksInfo(0, subtasks)
	executionContext, err := fp.prompter.RenderTemplate(templates.PromptTypeShortExecutionContext, map[string]any{
		"Tasks":             tasks,
		"CompletedSubtasks": subtasksInfo.Completed,
		"Subtask":           subtasksInfo.Subtask,
		"PlannedSubtasks":   subtasksInfo.Planned,
	})
	if err != nil {
		return "", fmt.Errorf("failed to render execution context: %w", err)
	}

	return executionContext, nil
}

func (fp *flowProvider) subtasksToMarkdown(subtasks []tools.SubtaskInfo) string {
	var buffer strings.Builder
	for sid, subtask := range subtasks {
		buffer.WriteString(fmt.Sprintf("# Subtask %d\n\n", sid+1))
		buffer.WriteString(fmt.Sprintf("## %s\n\n%s\n\n", subtask.Title, subtask.Description))
	}

	return buffer.String()
}

func (fp *flowProvider) getContainerPortsDescription() string {
	ports := docker.GetPrimaryContainerPorts(fp.flowID)
	var buffer strings.Builder
	buffer.WriteString("This container has the following ports which bind to the host:\n")
	for _, port := range ports {
		buffer.WriteString(fmt.Sprintf("* %s:%d -> %d/tcp (in container)\n", fp.publicIP, port, port))
	}
	if fp.publicIP == "0.0.0.0" {
		buffer.WriteString("you need to discover the public IP yourself via the following command:\n")
		buffer.WriteString("`curl -s https://api.ipify.org` or `curl -s ipinfo.io/ip` or `curl -s ifconfig.me`\n")
	}
	buffer.WriteString("you can listen these ports the container inside and receive connections from the internet.")
	return buffer.String()
}

func getCurrentTime() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

func isEmptyChain(msgChain json.RawMessage) bool {
	var msgList []llms.MessageContent

	if err := json.Unmarshal(msgChain, &msgList); err != nil {
		return true
	}

	return len(msgList) == 0
}
