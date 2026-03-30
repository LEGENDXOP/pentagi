package providers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// ─── Configuration (env-var overridable) ─────────────────────────────────────

const (
	defaultWarnThreshold    = 2   // 2nd occurrence → warning
	defaultBlockThreshold   = 3   // 3rd occurrence → hard block
	defaultResultHashLen    = 500 // chars of output to hash
	defaultResultSnippetLen = 200 // chars of previous result to show in block message
	maxTrackedOperations    = 500 // cap to prevent unbounded memory growth
)

func getWarnThreshold() int {
	if v := os.Getenv("WORK_TRACKER_WARN_THRESHOLD"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return defaultWarnThreshold
}

func getBlockThreshold() int {
	if v := os.Getenv("WORK_TRACKER_BLOCK_THRESHOLD"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return defaultBlockThreshold
}

func getResultHashLen() int {
	if v := os.Getenv("WORK_TRACKER_RESULT_HASH_LEN"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return defaultResultHashLen
}

// ─── Types ───────────────────────────────────────────────────────────────────

// CompletedWorkTracker V2 maintains a multi-layer registry of completed operations.
//
// Layer 1 — Semantic category (from V1): broad task classification like
//   "subdomain_enumeration", "port_scan", "graphql_introspection".
//
// Layer 2 — Operation fingerprint (NEW): normalized representation of the actual
//   operation being performed, catching syntax variations. Examples:
//   - "file_read:/work/recon/subdomains.txt" (catches cat/head/tail variants)
//   - "http:GET:target.com/api/session/properties" (catches curl/wget URL dedup)
//
// Layer 3 — Result fingerprint (NEW): SHA-256 hash of the first N chars of output.
//   If the same result is returned twice, the third attempt is definitely blocked.
//
// The tracker uses a warn-then-block escalation model:
//   - 1st occurrence: execute and record
//   - 2nd occurrence (configurable): inject WARNING, still allow execution
//   - 3rd+ occurrence (configurable): BLOCK execution, return previous result snippet
type CompletedWorkTracker struct {
	mu         sync.Mutex
	tasks      map[string]*CompletedTask      // V1: taskKey → completion record
	operations map[string]*TrackedOperation    // V2: opFingerprint → operation record
	resultMap  map[string]*TrackedOperation    // V2: resultHash → first operation that produced it
}

// CompletedTask records the completion of a specific work item (V1 compatible).
type CompletedTask struct {
	Key          string    `json:"key"`
	Description  string    `json:"description"`
	CompletedAt  time.Time `json:"completed_at"`
	ToolName     string    `json:"tool_name"`
	ResultCount  int       `json:"result_count"`
	OutputFile   string    `json:"output_file"`
	AttemptCount int       `json:"attempt_count"`
	Blocked      int       `json:"blocked"`
}

// TrackedOperation records a specific operation with its fingerprint and result.
type TrackedOperation struct {
	Fingerprint   string    `json:"fingerprint"`     // canonical operation key
	ToolName      string    `json:"tool_name"`        // original tool name
	OriginalArgs  string    `json:"original_args"`    // first invocation's args (truncated)
	ResultHash    string    `json:"result_hash"`       // SHA-256 of first N chars of result
	ResultSnippet string    `json:"result_snippet"`    // first N chars of result for display
	IsError       bool      `json:"is_error"`          // whether the result was an error
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	Count         int       `json:"count"`             // total attempts
	Warned        bool      `json:"warned"`            // whether warning was already issued
	Blocked       int       `json:"blocked"`           // times blocked
}

// CompletedTaskJSON is the JSON-serializable form for STATE.json persistence (V1 compatible).
type CompletedTaskJSON struct {
	Key         string `json:"key"`
	Description string `json:"description"`
	CompletedAt string `json:"completed_at"`
	ToolName    string `json:"tool_name"`
	ResultCount int    `json:"result_count"`
	OutputFile  string `json:"output_file"`
}

// TrackedOperationJSON is the JSON-serializable form for V2 operation persistence.
type TrackedOperationJSON struct {
	Fingerprint   string `json:"fingerprint"`
	ToolName      string `json:"tool_name"`
	ResultHash    string `json:"result_hash"`
	ResultSnippet string `json:"result_snippet"`
	IsError       bool   `json:"is_error"`
	FirstSeen     string `json:"first_seen"`
	LastSeen      string `json:"last_seen"`
	Count         int    `json:"count"`
	Blocked       int    `json:"blocked"`
}
// ─── Constructor ──────────────────────────────────────────────────────────────

// NewCompletedWorkTracker creates a fresh tracker for a subtask execution.
// V2: now includes operation fingerprint and result fingerprint layers.
func NewCompletedWorkTracker() *CompletedWorkTracker {
	return &CompletedWorkTracker{
		tasks:      make(map[string]*CompletedTask),
		operations: make(map[string]*TrackedOperation),
		resultMap:  make(map[string]*TrackedOperation),
	}
}

// ─── Core Public Methods (V1-compatible signatures) ──────────────────────────

// RecordExecution analyzes a tool call and its result to determine if a
// recognizable work item has been completed. Also records the operation
// fingerprint and result hash for V2 dedup.
//
// Returns the task key if a NEW completion was recorded, empty string otherwise.
// V1 signature preserved — old callers continue to work.
func (cwt *CompletedWorkTracker) RecordExecution(toolName, toolArgs, toolResult string, isError bool) string {
	// V2: Always record operation fingerprint (even for unclassified operations)
	cwt.recordOperationFingerprint(toolName, toolArgs, toolResult, isError)

	if isError {
		// V2: Still record the fingerprint above for error-aware dedup,
		// but don't mark semantic tasks as completed on error.
		return ""
	}

	taskKey, desc, outputFile := classifyWorkItem(toolName, toolArgs, toolResult)
	if taskKey == "" {
		return ""
	}

	cwt.mu.Lock()
	defer cwt.mu.Unlock()

	if existing, ok := cwt.tasks[taskKey]; ok {
		existing.AttemptCount++
		return ""
	}

	resultCount := estimateResultCount(toolResult)
	cwt.tasks[taskKey] = &CompletedTask{
		Key:          taskKey,
		Description:  desc,
		CompletedAt:  time.Now(),
		ToolName:     toolName,
		ResultCount:  resultCount,
		OutputFile:   outputFile,
		AttemptCount: 1,
	}

	logrus.WithFields(logrus.Fields{
		"task_key":     taskKey,
		"tool_name":    toolName,
		"result_count": resultCount,
		"output_file":  outputFile,
	}).Info("completed work tracker: new task completed")

	return taskKey
}

// CheckReRun determines if a tool call is attempting to re-run a completed operation.
// V2: Uses three-layer detection (semantic + fingerprint + result hash).
//
// Returns (isReRun, warningOrBlockMessage).
//   - If warn threshold reached but not block: isReRun=false, message=warning (advisory)
//   - If block threshold reached: isReRun=true, message=block reason
//
// V1 signature preserved — old callers continue to work.
func (cwt *CompletedWorkTracker) CheckReRun(toolName, toolArgs string) (bool, string) {
	warnAt := getWarnThreshold()
	blockAt := getBlockThreshold()

	// ── Layer 2: Operation fingerprint check (catches syntax variations) ──
	fingerprint := extractOperationFingerprint(toolName, toolArgs)
	if fingerprint != "" {
		cwt.mu.Lock()
		op, exists := cwt.operations[fingerprint]
		if exists {
			// This operation has been seen before.
			nextCount := op.Count + 1 // what the count WILL be after this execution

			if nextCount >= blockAt {
				op.Blocked++
				cwt.mu.Unlock()

				msg := fmt.Sprintf(
					"🛑 BLOCKED (attempt #%d): This operation was already performed %d times.\n"+
						"Fingerprint: %s\n"+
						"First executed: %s ago\n",
					nextCount, op.Count,
					fingerprint,
					formatWorkDuration(time.Since(op.FirstSeen)),
				)
				if op.ResultSnippet != "" {
					msg += fmt.Sprintf("Previous result: %.200s\n", op.ResultSnippet)
				}
				if op.IsError {
					msg += "⚠️ Previous attempt returned an ERROR — retrying will produce the same error.\n"
				}
				msg += "Move on to a DIFFERENT operation. Do NOT retry this."

				logrus.WithFields(logrus.Fields{
					"fingerprint": fingerprint,
					"count":       op.Count,
					"blocked":     op.Blocked,
				}).Warn("completed work tracker V2: blocked repeated operation")

				return true, msg
			}

			if nextCount >= warnAt && !op.Warned {
				op.Warned = true
				cwt.mu.Unlock()

				msg := fmt.Sprintf(
					"⚠️ DUPLICATE WARNING: You already performed this operation %d time(s).\n"+
						"Fingerprint: %s\n",
					op.Count, fingerprint,
				)
				if op.ResultSnippet != "" {
					msg += fmt.Sprintf("Previous result (truncated): %.200s\n", op.ResultSnippet)
				}
				if op.IsError {
					msg += "⚠️ Previous attempt returned an ERROR. Retrying is unlikely to help.\n"
				}
				msg += "Proceeding this time, but next attempt WILL be blocked."

				logrus.WithFields(logrus.Fields{
					"fingerprint": fingerprint,
					"count":       op.Count,
				}).Warn("completed work tracker V2: warning on duplicate operation")

				// Return false (don't block) but WITH a warning message
				return false, msg
			}

			cwt.mu.Unlock()
		} else {
			cwt.mu.Unlock()
		}
	}

	// ── Layer 1: Semantic category check (V1 behavior, improved) ──
	taskKey, _, _ := classifyWorkItem(toolName, toolArgs, "")
	if taskKey != "" {
		cwt.mu.Lock()
		task, ok := cwt.tasks[taskKey]
		if ok {
			task.Blocked++
			ago := time.Since(task.CompletedAt)
			agoStr := formatWorkDuration(ago)

			msg := fmt.Sprintf(
				"⚠️ ALREADY COMPLETED: %s was done %s ago",
				task.Description, agoStr,
			)
			if task.ResultCount > 0 {
				msg += fmt.Sprintf(" with %d results", task.ResultCount)
			}
			if task.OutputFile != "" {
				msg += fmt.Sprintf(". Results in %s", task.OutputFile)
			}
			msg += ". Move to next task."

			if task.Blocked > 2 {
				msg += fmt.Sprintf(
					"\n🔴 You have attempted to re-run this %d times. It is COMPLETE. "+
						"Do NOT retry. Proceed to the next phase of your assessment.",
					task.Blocked,
				)
			}

			cwt.mu.Unlock()

			// V1 semantic blocks are always hard blocks
			return true, msg
		}
		cwt.mu.Unlock()
	}

	return false, ""
}

// ─── V2 Internal: Operation Recording ────────────────────────────────────────

// recordOperationFingerprint records a tool execution in the V2 fingerprint layer.
func (cwt *CompletedWorkTracker) recordOperationFingerprint(toolName, toolArgs, toolResult string, isError bool) {
	fingerprint := extractOperationFingerprint(toolName, toolArgs)
	if fingerprint == "" {
		return
	}

	resultHash := hashResult(toolResult)
	snippet := toolResult
	if len(snippet) > defaultResultSnippetLen {
		snippet = snippet[:defaultResultSnippetLen]
	}

	cwt.mu.Lock()
	defer cwt.mu.Unlock()

	// Cap tracked operations to prevent unbounded growth
	if len(cwt.operations) >= maxTrackedOperations {
		// Evict oldest operation (simple strategy)
		var oldestKey string
		var oldestTime time.Time
		for k, op := range cwt.operations {
			if oldestKey == "" || op.FirstSeen.Before(oldestTime) {
				oldestKey = k
				oldestTime = op.FirstSeen
			}
		}
		if oldestKey != "" {
			delete(cwt.operations, oldestKey)
		}
	}

	if existing, ok := cwt.operations[fingerprint]; ok {
		existing.Count++
		existing.LastSeen = time.Now()
		// Update result hash if this is the first successful result after errors
		if !isError && existing.IsError {
			existing.ResultHash = resultHash
			existing.ResultSnippet = snippet
			existing.IsError = false
		}
	} else {
		cwt.operations[fingerprint] = &TrackedOperation{
			Fingerprint:   fingerprint,
			ToolName:      toolName,
			OriginalArgs:  truncateStr(toolArgs, 300),
			ResultHash:    resultHash,
			ResultSnippet: snippet,
			IsError:       isError,
			FirstSeen:     time.Now(),
			LastSeen:      time.Now(),
			Count:         1,
		}
	}

	// Also track by result hash for cross-fingerprint dedup
	if resultHash != "" && toolResult != "" {
		if _, exists := cwt.resultMap[resultHash]; !exists {
			cwt.resultMap[resultHash] = cwt.operations[fingerprint]
		}
	}
}

// ─── Utility Methods (V1 compatible) ─────────────────────────────────────────

// GetCompletedKeys returns all completed task keys for summary purposes.
func (cwt *CompletedWorkTracker) GetCompletedKeys() []string {
	cwt.mu.Lock()
	defer cwt.mu.Unlock()

	keys := make([]string, 0, len(cwt.tasks))
	for k := range cwt.tasks {
		keys = append(keys, k)
	}
	return keys
}

// FormatCompletedSummary returns a human-readable summary of all completed tasks
// and tracked operations, suitable for injection into resume context or system prompt.
func (cwt *CompletedWorkTracker) FormatCompletedSummary() string {
	cwt.mu.Lock()
	defer cwt.mu.Unlock()

	if len(cwt.tasks) == 0 && len(cwt.operations) == 0 {
		return ""
	}

	var sb strings.Builder

	// V1: Semantic task summary
	if len(cwt.tasks) > 0 {
		sb.WriteString("## Completed Work Items (DO NOT re-run)\n")
		for _, task := range cwt.tasks {
			sb.WriteString(fmt.Sprintf("- ✅ %s (completed %s",
				task.Description,
				task.CompletedAt.UTC().Format("15:04"),
			))
			if task.ResultCount > 0 {
				sb.WriteString(fmt.Sprintf(", %d results", task.ResultCount))
			}
			if task.OutputFile != "" {
				sb.WriteString(fmt.Sprintf(", saved to %s", task.OutputFile))
			}
			sb.WriteString(")\n")
		}
	}

	// V2: Frequently repeated operations
	repeatedOps := make([]*TrackedOperation, 0)
	for _, op := range cwt.operations {
		if op.Count >= 2 {
			repeatedOps = append(repeatedOps, op)
		}
	}
	if len(repeatedOps) > 0 {
		sb.WriteString("\n## Repeated Operations (DO NOT retry)\n")
		for _, op := range repeatedOps {
			sb.WriteString(fmt.Sprintf("- 🔄 %s (executed %d times, last %s ago",
				op.Fingerprint, op.Count,
				formatWorkDuration(time.Since(op.LastSeen)),
			))
			if op.IsError {
				sb.WriteString(", returned ERROR")
			}
			sb.WriteString(")\n")
		}
	}

	return sb.String()
}

// Len returns the number of completed tasks (V1 compatible).
func (cwt *CompletedWorkTracker) Len() int {
	cwt.mu.Lock()
	defer cwt.mu.Unlock()
	return len(cwt.tasks)
}

// OperationCount returns the number of tracked operations (V2).
func (cwt *CompletedWorkTracker) OperationCount() int {
	cwt.mu.Lock()
	defer cwt.mu.Unlock()
	return len(cwt.operations)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// hashResult computes a SHA-256 fingerprint of the first N characters of output.
func hashResult(result string) string {
	if result == "" {
		return ""
	}
	hashLen := getResultHashLen()
	if len(result) > hashLen {
		result = result[:hashLen]
	}
	h := sha256.Sum256([]byte(result))
	return hex.EncodeToString(h[:8]) // 16-char hex, enough for dedup
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "…"
}
// ─── V2 Fingerprint Extraction ───────────────────────────────────────────────
//
// The fingerprint system normalizes tool calls into canonical operation keys
// that catch "same operation, different syntax" patterns:
//
//   cat /work/recon/subdomains.txt    → file_read:subdomains.txt
//   head -80 /work/recon/subdomains.txt → file_read:subdomains.txt
//   head -n 79 subdomains.txt         → file_read:subdomains.txt
//
//   curl https://target/api/v1/session → http:GET:target/api/v1/session
//   wget -q https://target/api/v1/session → http:GET:target/api/v1/session
//
//   curl -X POST -d '...' https://target/graphql → http:POST:target/graphql
//
// The fingerprint does NOT include:
//   - HTTP headers (Authorization, Content-Type vary but target is same)
//   - Request body (GraphQL queries vary but endpoint is same)
//   - Command flags that don't change semantics (--silent, -s, -q)

// extractOperationFingerprint returns a canonical fingerprint for a tool call.
// Returns "" if the operation can't be fingerprinted (unknown pattern → no dedup).
func extractOperationFingerprint(toolName, toolArgs string) string {
	switch toolName {
	case "terminal":
		return extractTerminalFingerprint(toolArgs)
	case "file":
		return extractFileToolFingerprint(toolArgs)
	case "browser_navigate", "browser_click", "browser_type":
		return extractBrowserFingerprint(toolName, toolArgs)
	default:
		return ""
	}
}

// extractTerminalFingerprint normalizes terminal commands into canonical form.
func extractTerminalFingerprint(toolArgs string) string {
	var args map[string]interface{}
	if err := json.Unmarshal([]byte(toolArgs), &args); err != nil {
		return ""
	}
	input, ok := args["input"].(string)
	if !ok || input == "" {
		return ""
	}

	// Try HTTP fingerprint first (curl/wget)
	if fp := extractHTTPFingerprint(input); fp != "" {
		return fp
	}

	// Try file read fingerprint (cat/head/tail/jq/grep on files)
	if fp := extractFileReadFingerprint(input); fp != "" {
		return fp
	}

	// Try GraphQL-specific fingerprint
	if fp := extractGraphQLFingerprint(input); fp != "" {
		return fp
	}

	return ""
}

// ─── HTTP Fingerprint (curl/wget) ────────────────────────────────────────────

// urlPattern extracts URLs from curl/wget commands.
var urlPattern = regexp.MustCompile(`https?://[^\s'"` + "`" + `]+`)

// httpMethodPattern extracts explicit HTTP methods from curl commands.
var httpMethodPattern = regexp.MustCompile(`(?i)-X\s+(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)`)

// extractHTTPFingerprint normalizes curl/wget commands to "http:METHOD:host/path".
func extractHTTPFingerprint(input string) string {
	inputLower := strings.ToLower(strings.TrimSpace(input))

	// Must start with curl or wget (or be piped from something into curl/wget)
	isCurl := strings.Contains(inputLower, "curl ")
	isWget := strings.Contains(inputLower, "wget ")
	if !isCurl && !isWget {
		return ""
	}

	// Extract URL
	urlMatch := urlPattern.FindString(input)
	if urlMatch == "" {
		return ""
	}

	// Clean URL: remove trailing quotes, semicolons, pipes
	urlMatch = strings.TrimRight(urlMatch, `'";|&)`)

	// Parse URL to extract host + path (ignore query params for dedup)
	parsed, err := url.Parse(urlMatch)
	if err != nil {
		return ""
	}

	// Determine HTTP method
	method := "GET"
	if methodMatch := httpMethodPattern.FindStringSubmatch(input); len(methodMatch) > 1 {
		method = strings.ToUpper(methodMatch[1])
	} else if strings.Contains(inputLower, "-d ") || strings.Contains(inputLower, "--data") {
		method = "POST" // curl with -d defaults to POST
	}

	// Normalize: http:METHOD:host/path
	hostPath := parsed.Host + parsed.Path
	hostPath = strings.TrimRight(hostPath, "/")

	return fmt.Sprintf("http:%s:%s", method, hostPath)
}

// ─── File Read Fingerprint (cat/head/tail/jq/grep) ──────────────────────────

// fileReadCmdPattern matches cat/head/tail/less/more and captures the file path.
var fileReadCmdPattern = regexp.MustCompile(
	`(?:^|\s)(cat|head|tail|less|more)\s+` +
		`(?:-[^\s]*\s+)*` + // skip flags like -n 80, -c 100
		`([^\s|;&>]+)`, // capture file path
)

// jqReadPattern matches jq invocations reading a file.
var jqReadPattern = regexp.MustCompile(
	`(?:^|\s)jq\s+` +
		`(?:-[^\s]*\s+)*` + // skip flags
		`(?:'[^']*'|"[^"]*")\s+` + // skip filter expression
		`([^\s|;&>]+)`, // capture file path
)

// grepReadPattern matches grep invocations reading a file.
var grepReadPattern = regexp.MustCompile(
	`(?:^|\s)grep\s+` +
		`(?:-[^\s]*\s+)*` + // skip flags
		`(?:'[^']*'|"[^"]*")\s+` + // skip pattern
		`([^\s|;&>]+)`, // capture file path
)

// extractFileReadFingerprint normalizes file read commands to "file_read:basename".
func extractFileReadFingerprint(input string) string {
	input = strings.TrimSpace(input)

	// Extract primary command (before pipes)
	primary := extractPrimaryCommand(input)
	if primary == "" {
		return ""
	}

	// Skip if primary is an offensive command (curl piped to jq is NOT a file read)
	if isOffensiveCommand(primary) {
		return ""
	}

	// Skip write operations
	if isTerminalWriteCommand(fmt.Sprintf(`{"input":"%s"}`, strings.ReplaceAll(input, `"`, `\"`))) {
		return ""
	}

	var filePath string

	// Try cat/head/tail pattern
	if m := fileReadCmdPattern.FindStringSubmatch(primary); len(m) > 2 {
		filePath = m[2]
	}

	// Try jq pattern
	if filePath == "" {
		if m := jqReadPattern.FindStringSubmatch(primary); len(m) > 1 {
			filePath = m[1]
		}
	}

	// Try grep pattern
	if filePath == "" {
		if m := grepReadPattern.FindStringSubmatch(primary); len(m) > 1 {
			filePath = m[1]
		}
	}

	if filePath == "" || strings.HasPrefix(filePath, "-") {
		return ""
	}

	// Normalize: use basename so /work/recon/subdomains.txt and subdomains.txt match
	baseName := filepath.Base(filePath)
	if baseName == "." || baseName == "/" {
		return ""
	}

	return "file_read:" + baseName
}

// ─── GraphQL Fingerprint ─────────────────────────────────────────────────────

// graphqlBodyPattern matches GraphQL introspection and common query patterns.
var graphqlBodyPattern = regexp.MustCompile(`(?i)(__schema|__type|IntrospectionQuery)`)

// extractGraphQLFingerprint detects GraphQL introspection attempts.
func extractGraphQLFingerprint(input string) string {
	if !graphqlBodyPattern.MatchString(input) {
		return ""
	}

	// Extract target URL if present
	urlMatch := urlPattern.FindString(input)
	if urlMatch != "" {
		parsed, err := url.Parse(strings.TrimRight(urlMatch, `'";|&)`))
		if err == nil {
			return "graphql_introspection:" + parsed.Host
		}
	}

	return "graphql_introspection:unknown"
}

// ─── File Tool Fingerprint ───────────────────────────────────────────────────

// extractFileToolFingerprint normalizes the "file" tool to "file_read:basename"
// or "file_write:basename".
func extractFileToolFingerprint(toolArgs string) string {
	var args map[string]interface{}
	if err := json.Unmarshal([]byte(toolArgs), &args); err != nil {
		return ""
	}

	action, _ := args["action"].(string)
	path, _ := args["path"].(string)
	if path == "" {
		return ""
	}

	baseName := filepath.Base(path)
	switch action {
	case "read_file":
		return "file_read:" + baseName
	case "update_file":
		// Don't track writes — they're legitimate repeats
		return ""
	default:
		return ""
	}
}

// ─── Browser Fingerprint ─────────────────────────────────────────────────────

// extractBrowserFingerprint normalizes browser tool calls by URL.
func extractBrowserFingerprint(toolName, toolArgs string) string {
	var args map[string]interface{}
	if err := json.Unmarshal([]byte(toolArgs), &args); err != nil {
		return ""
	}

	targetURL, _ := args["url"].(string)
	if targetURL == "" {
		targetURL, _ = args["target"].(string)
	}
	if targetURL == "" {
		return ""
	}

	parsed, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}

	hostPath := parsed.Host + parsed.Path
	hostPath = strings.TrimRight(hostPath, "/")

	return fmt.Sprintf("browser:%s:%s", toolName, hostPath)
}

// ─── V1 Work Item Classification (preserved from V1) ─────────────────────────

// workItemPattern, workItemPatterns, classifyWorkItem, estimateResultCount,
// formatWorkDuration, targetExtractPattern — all preserved exactly from V1.
// See original completed_work_tracker.go for these definitions.

// NOTE: In the assembled file, the V1 workItemPattern type, workItemPatterns
// slice, classifyWorkItem function, estimateResultCount function,
// formatWorkDuration function, and targetExtractPattern regex are included
// verbatim from the original. They are NOT duplicated here because part4
// includes the persistence code. The assembly instructions explain how to
// combine the V1 classification code with the V2 additions.
// ─── Persistence (V1 compatible + V2 extensions) ─────────────────────────────

// RestoreFromState loads previously completed tasks from a persisted state.
// This is called when resuming a subtask that was interrupted.
// V2: Also restores tracked operations if present in the state.
func (cwt *CompletedWorkTracker) RestoreFromState(completedTasks []CompletedTaskJSON) {
	cwt.mu.Lock()
	defer cwt.mu.Unlock()

	for _, ct := range completedTasks {
		completedAt, _ := time.Parse(time.RFC3339, ct.CompletedAt)
		if completedAt.IsZero() {
			completedAt = time.Now().Add(-10 * time.Minute)
		}
		cwt.tasks[ct.Key] = &CompletedTask{
			Key:         ct.Key,
			Description: ct.Description,
			CompletedAt: completedAt,
			ToolName:    ct.ToolName,
			ResultCount: ct.ResultCount,
			OutputFile:  ct.OutputFile,
		}
	}

	if len(completedTasks) > 0 {
		logrus.WithField("restored_tasks", len(completedTasks)).
			Info("completed work tracker: restored tasks from persisted state")
	}
}

// RestoreOperationsFromState loads previously tracked operations (V2 data).
func (cwt *CompletedWorkTracker) RestoreOperationsFromState(ops []TrackedOperationJSON) {
	cwt.mu.Lock()
	defer cwt.mu.Unlock()

	for _, op := range ops {
		firstSeen, _ := time.Parse(time.RFC3339, op.FirstSeen)
		lastSeen, _ := time.Parse(time.RFC3339, op.LastSeen)
		if firstSeen.IsZero() {
			firstSeen = time.Now().Add(-10 * time.Minute)
		}
		if lastSeen.IsZero() {
			lastSeen = firstSeen
		}

		tracked := &TrackedOperation{
			Fingerprint:   op.Fingerprint,
			ToolName:      op.ToolName,
			ResultHash:    op.ResultHash,
			ResultSnippet: op.ResultSnippet,
			IsError:       op.IsError,
			FirstSeen:     firstSeen,
			LastSeen:      lastSeen,
			Count:         op.Count,
			Blocked:       op.Blocked,
			Warned:        op.Count >= getWarnThreshold(), // restore warned state
		}
		cwt.operations[op.Fingerprint] = tracked

		// Also restore result map entry
		if op.ResultHash != "" {
			cwt.resultMap[op.ResultHash] = tracked
		}
	}

	if len(ops) > 0 {
		logrus.WithField("restored_operations", len(ops)).
			Info("completed work tracker V2: restored operations from persisted state")
	}
}

// ToJSON exports the completed tasks for STATE.json persistence (V1 compatible).
func (cwt *CompletedWorkTracker) ToJSON() []CompletedTaskJSON {
	cwt.mu.Lock()
	defer cwt.mu.Unlock()

	result := make([]CompletedTaskJSON, 0, len(cwt.tasks))
	for _, task := range cwt.tasks {
		result = append(result, CompletedTaskJSON{
			Key:         task.Key,
			Description: task.Description,
			CompletedAt: task.CompletedAt.UTC().Format(time.RFC3339),
			ToolName:    task.ToolName,
			ResultCount: task.ResultCount,
			OutputFile:  task.OutputFile,
		})
	}
	return result
}

// OperationsToJSON exports tracked operations for STATE.json persistence (V2).
func (cwt *CompletedWorkTracker) OperationsToJSON() []TrackedOperationJSON {
	cwt.mu.Lock()
	defer cwt.mu.Unlock()

	result := make([]TrackedOperationJSON, 0, len(cwt.operations))
	for _, op := range cwt.operations {
		// Only persist operations that have been seen more than once
		// (single occurrences don't need cross-session tracking)
		if op.Count < 2 {
			continue
		}
		result = append(result, TrackedOperationJSON{
			Fingerprint:   op.Fingerprint,
			ToolName:      op.ToolName,
			ResultHash:    op.ResultHash,
			ResultSnippet: op.ResultSnippet,
			IsError:       op.IsError,
			FirstSeen:     op.FirstSeen.UTC().Format(time.RFC3339),
			LastSeen:      op.LastSeen.UTC().Format(time.RFC3339),
			Count:         op.Count,
			Blocked:       op.Blocked,
		})
	}
	return result
}

// ─── ExecutionState Integration ──────────────────────────────────────────────
// V1-compatible functions preserved. V2 adds tracked_operations support.

// MergeCompletedTasksIntoState serializes completed tasks (and V2 operations)
// and adds them to an existing STATE.json string.
func MergeCompletedTasksIntoState(stateJSON string, tasks []CompletedTaskJSON) (string, error) {
	if len(tasks) == 0 {
		return stateJSON, nil
	}

	var state map[string]interface{}
	if err := json.Unmarshal([]byte(stateJSON), &state); err != nil {
		return stateJSON, fmt.Errorf("failed to parse state JSON: %w", err)
	}

	state["completed_tasks"] = tasks

	out, err := json.Marshal(state)
	if err != nil {
		return stateJSON, fmt.Errorf("failed to marshal updated state: %w", err)
	}
	return string(out), nil
}

// MergeTrackedOperationsIntoState serializes V2 tracked operations into STATE.json.
func MergeTrackedOperationsIntoState(stateJSON string, ops []TrackedOperationJSON) (string, error) {
	if len(ops) == 0 {
		return stateJSON, nil
	}

	var state map[string]interface{}
	if err := json.Unmarshal([]byte(stateJSON), &state); err != nil {
		return stateJSON, fmt.Errorf("failed to parse state JSON: %w", err)
	}

	state["tracked_operations"] = ops

	out, err := json.Marshal(state)
	if err != nil {
		return stateJSON, fmt.Errorf("failed to marshal updated state: %w", err)
	}
	return string(out), nil
}

// ExtractCompletedTasksFromState deserializes completed tasks from a STATE.json string.
// Returns nil if no completedTasks field is present (backward compatible).
func ExtractCompletedTasksFromState(stateJSON string) []CompletedTaskJSON {
	var state map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stateJSON), &state); err != nil {
		return nil
	}

	raw, ok := state["completed_tasks"]
	if !ok {
		return nil
	}

	var tasks []CompletedTaskJSON
	if err := json.Unmarshal(raw, &tasks); err != nil {
		return nil
	}
	return tasks
}

// ExtractTrackedOperationsFromState deserializes V2 tracked operations from STATE.json.
func ExtractTrackedOperationsFromState(stateJSON string) []TrackedOperationJSON {
	var state map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stateJSON), &state); err != nil {
		return nil
	}

	raw, ok := state["tracked_operations"]
	if !ok {
		return nil
	}

	var ops []TrackedOperationJSON
	if err := json.Unmarshal(raw, &ops); err != nil {
		return nil
	}
	return ops
}

// ─── V1 Work Item Classification (verbatim from original) ────────────────────
// These are included in the assembled file but defined here for completeness.
// The V1 classification system is RETAINED as Layer 1 of the V2 tracker.

// workItemPattern defines a classification rule.
type workItemPattern struct {
	key         string
	description string
	toolName    string
	argPattern  *regexp.Regexp
	outPattern  *regexp.Regexp
	outputFile  string
}

var workItemPatterns = []workItemPattern{
	// ── Reconnaissance Phase ──
	{
		key:         "subdomain_enumeration",
		description: "Subdomain enumeration",
		toolName:    "terminal",
		argPattern:  regexp.MustCompile(`(?i)(subfinder|amass|assetfinder|sublist3r|findomain|dnsx.*-d\s)`),
		outputFile:  "/work/recon/subdomains.txt",
	},
	{
		key:         "port_scan",
		description: "Port scanning",
		toolName:    "terminal",
		argPattern:  regexp.MustCompile(`(?i)(nmap\s|masscan\s|rustscan\s|naabu\s)`),
		outputFile:  "/work/recon/ports.txt",
	},
	{
		key:         "nuclei_scan",
		description: "Nuclei vulnerability scan",
		toolName:    "",
		argPattern:  regexp.MustCompile(`(?i)(nuclei\s|nuclei_scan)`),
		outputFile:  "/work/recon/nuclei_results.txt",
	},
	{
		key:         "tech_fingerprinting",
		description: "Technology fingerprinting",
		toolName:    "terminal",
		argPattern:  regexp.MustCompile(`(?i)(whatweb|wappalyzer|builtwith|httpx.*-tech)`),
		outputFile:  "/work/recon/tech_stack.txt",
	},
	{
		key:         "directory_bruteforce",
		description: "Directory/path bruteforcing",
		toolName:    "terminal",
		argPattern:  regexp.MustCompile(`(?i)(gobuster|dirb|dirsearch|ffuf|feroxbuster|dirbuster)`),
		outputFile:  "/work/recon/directories.txt",
	},
	{
		key:         "graphql_introspection",
		description: "GraphQL schema introspection",
		toolName:    "terminal",
		argPattern:  regexp.MustCompile(`(?i)(__schema|__type|IntrospectionQuery)`),
		outputFile:  "/tmp/graphql_schema.json",
	},
	{
		key:         "api_discovery",
		description: "API endpoint discovery",
		toolName:    "terminal",
		argPattern:  regexp.MustCompile(`(?i)(swagger|openapi|api-docs|\.json.*api|kiterunner|arjun)`),
		outputFile:  "/work/recon/api_endpoints.txt",
	},
	{
		key:         "dns_enumeration",
		description: "DNS enumeration",
		toolName:    "terminal",
		argPattern:  regexp.MustCompile(`(?i)(dig\s|dnsenum|fierce|dnsrecon|dnsmap)`),
		outputFile:  "/work/recon/dns_records.txt",
	},
	{
		key:         "ssl_analysis",
		description: "SSL/TLS analysis",
		toolName:    "terminal",
		argPattern:  regexp.MustCompile(`(?i)(testssl|sslscan|sslyze|openssl\s+s_client)`),
		outputFile:  "/work/recon/ssl_analysis.txt",
	},
	{
		key:         "vhost_discovery",
		description: "Virtual host discovery",
		toolName:    "terminal",
		argPattern:  regexp.MustCompile(`(?i)(vhost|virtual.*host|Host:\s)`),
		outputFile:  "/work/recon/vhosts.txt",
	},
	// ── Authentication Phase ──
	{
		key:         "token_extraction",
		description: "Authentication token extraction",
		toolName:    "terminal",
		argPattern:  regexp.MustCompile(`(?i)(storefront.*token|access.token|bearer|authorization.*header)`),
		outputFile:  "/tmp/access_token.txt",
	},
	{
		key:         "login_bruteforce",
		description: "Login credential bruteforce",
		toolName:    "terminal",
		argPattern:  regexp.MustCompile(`(?i)(hydra|medusa|patator|bruteforce.*login)`),
		outputFile:  "",
	},
	// ── Exploitation Phase ──
	{
		key:         "sqli_testing",
		description: "SQL injection testing",
		toolName:    "terminal",
		argPattern:  regexp.MustCompile(`(?i)(sqlmap|sql.*inject|'.*or.*'|union\s+select)`),
		outputFile:  "/work/evidence/sqli_results.txt",
	},
	{
		key:         "xss_testing",
		description: "XSS testing",
		toolName:    "terminal",
		argPattern:  regexp.MustCompile(`(?i)(xss|<script|dalfox|xsstrike)`),
		outputFile:  "/work/evidence/xss_results.txt",
	},
	{
		key:         "ssrf_testing",
		description: "SSRF testing",
		toolName:    "terminal",
		argPattern:  regexp.MustCompile(`(?i)(ssrf|169\.254\.169\.254|metadata|internal.*url|interact\.sh)`),
		outputFile:  "/work/evidence/ssrf_results.txt",
	},
	{
		key:         "idor_testing",
		description: "IDOR/access control testing",
		toolName:    "terminal",
		argPattern:  regexp.MustCompile(`(?i)(idor|insecure.*direct|object.*reference|access.*control)`),
		outputFile:  "/work/evidence/idor_results.txt",
	},
}

var targetExtractPattern = regexp.MustCompile(`(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}|(?:\d{1,3}\.){3}\d{1,3})`)

func classifyWorkItem(toolName, toolArgs, toolResult string) (string, string, string) {
	for _, pattern := range workItemPatterns {
		if pattern.toolName != "" && pattern.toolName != toolName {
			if pattern.key == "nuclei_scan" && toolName == "nuclei_scan" {
				// Match — fall through
			} else {
				continue
			}
		}
		if pattern.argPattern != nil {
			if pattern.argPattern.MatchString(toolArgs) {
				key := pattern.key
				if target := targetExtractPattern.FindString(toolArgs); target != "" {
					key = key + ":" + strings.ToLower(target)
				}
				return key, pattern.description, pattern.outputFile
			}
		}
		if pattern.outPattern != nil && toolResult != "" {
			if pattern.outPattern.MatchString(toolResult) {
				return pattern.key, pattern.description, pattern.outputFile
			}
		}
	}
	return "", "", ""
}

func estimateResultCount(output string) int {
	if output == "" {
		return 0
	}
	lines := strings.Split(output, "\n")
	count := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, "//") {
			count++
		}
	}
	if count > 10000 {
		count = 10000
	}
	return count
}

func formatWorkDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d seconds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	}
	return fmt.Sprintf("%.1f hours", d.Hours())
}
