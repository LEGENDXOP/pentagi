package providers

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// CompletedWorkTracker maintains a registry of completed work items (recon tasks,
// exploitation phases, etc.) within a subtask. It prevents the "Intra-Subtask
// Context Amnesia" problem where the agent forgets it already ran subdomain
// enumeration, port scanning, etc. and re-runs them from scratch.
//
// The tracker operates at a SEMANTIC level — it doesn't just count tool calls
// or file reads (the existing repeatingDetector and TerminalOutputCache handle
// those). Instead, it classifies tool executions into named work items like
// "subdomain_enumeration", "port_scan", "graphql_introspection" and tracks
// their completion state.
//
// Integration points:
//   - Created per performAgentChain invocation (same scope as TerminalOutputCache)
//   - Fed tool call names + arguments after each execution
//   - Queried before each tool execution to check for re-runs
//   - Serialized to STATE.json via ExecutionState.CompletedTasks
//
// The tracker is intentionally CONSERVATIVE about what it considers "completed":
//   - A task must have produced non-error output to be marked complete
//   - Only well-known recon/attack patterns are classified (unknown tools pass through)
//   - The agent can override completion by explicitly requesting a re-run
type CompletedWorkTracker struct {
	mu    sync.Mutex
	tasks map[string]*CompletedTask // taskKey → completion record
}

// CompletedTask records the completion of a specific work item.
type CompletedTask struct {
	Key          string    `json:"key"`           // canonical task name (e.g., "subdomain_enumeration")
	Description  string    `json:"description"`   // human-readable description
	CompletedAt  time.Time `json:"completed_at"`  // when the task was marked complete
	ToolName     string    `json:"tool_name"`      // which tool completed it (e.g., "terminal")
	ResultCount  int       `json:"result_count"`   // approximate number of results (0 if unknown)
	OutputFile   string    `json:"output_file"`    // where results were saved (if known)
	AttemptCount int       `json:"attempt_count"`  // how many times this task was attempted
	Blocked      int       `json:"blocked"`        // how many re-run attempts were blocked
}

// CompletedTaskJSON is the JSON-serializable form for STATE.json persistence.
type CompletedTaskJSON struct {
	Key         string `json:"key"`
	Description string `json:"description"`
	CompletedAt string `json:"completed_at"`
	ToolName    string `json:"tool_name"`
	ResultCount int    `json:"result_count"`
	OutputFile  string `json:"output_file"`
}

// NewCompletedWorkTracker creates a fresh tracker for a subtask execution.
func NewCompletedWorkTracker() *CompletedWorkTracker {
	return &CompletedWorkTracker{
		tasks: make(map[string]*CompletedTask),
	}
}

// RestoreFromState loads previously completed tasks from a persisted state.
// This is called when resuming a subtask that was interrupted.
func (cwt *CompletedWorkTracker) RestoreFromState(completedTasks []CompletedTaskJSON) {
	cwt.mu.Lock()
	defer cwt.mu.Unlock()

	for _, ct := range completedTasks {
		completedAt, _ := time.Parse(time.RFC3339, ct.CompletedAt)
		if completedAt.IsZero() {
			completedAt = time.Now().Add(-10 * time.Minute) // assume recent
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

// ToJSON exports the completed tasks for STATE.json persistence.
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

// RecordExecution analyzes a tool call and its result to determine if a
// recognizable work item has been completed. If a matching task pattern is
// found and the result indicates success, the task is marked as completed.
//
// Returns the task key if a NEW completion was recorded, empty string otherwise.
func (cwt *CompletedWorkTracker) RecordExecution(toolName, toolArgs, toolResult string, isError bool) string {
	if isError {
		return "" // errors don't complete tasks
	}

	taskKey, desc, outputFile := classifyWorkItem(toolName, toolArgs, toolResult)
	if taskKey == "" {
		return "" // not a recognizable work item
	}

	cwt.mu.Lock()
	defer cwt.mu.Unlock()

	if existing, ok := cwt.tasks[taskKey]; ok {
		existing.AttemptCount++
		return "" // already completed
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

// CheckReRun determines if a tool call is attempting to re-run a completed task.
// Returns (isReRun, warningMessage). If isReRun is true, the warningMessage should
// be injected into the message chain (it won't block execution — that's the
// caller's choice, but the message gives the LLM enough context to stop).
//
// The message format matches the existing chain injection style used by
// read-cap warnings and delegation blocks.
func (cwt *CompletedWorkTracker) CheckReRun(toolName, toolArgs string) (bool, string) {
	taskKey, _, _ := classifyWorkItem(toolName, toolArgs, "")
	if taskKey == "" {
		return false, ""
	}

	cwt.mu.Lock()
	defer cwt.mu.Unlock()

	task, ok := cwt.tasks[taskKey]
	if !ok {
		return false, ""
	}

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

	return true, msg
}

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

// FormatCompletedSummary returns a human-readable summary of all completed tasks,
// suitable for injection into the resume context or system prompt.
func (cwt *CompletedWorkTracker) FormatCompletedSummary() string {
	cwt.mu.Lock()
	defer cwt.mu.Unlock()

	if len(cwt.tasks) == 0 {
		return ""
	}

	var sb strings.Builder
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
	return sb.String()
}

// Len returns the number of completed tasks.
func (cwt *CompletedWorkTracker) Len() int {
	cwt.mu.Lock()
	defer cwt.mu.Unlock()
	return len(cwt.tasks)
}

// ─── Work Item Classification ────────────────────────────────────────────────
// The classifier maps tool calls to semantic work items using pattern matching
// on tool names, arguments, and output content. Each work item has a canonical
// key, a human-readable description, and an optional output file path.
//
// Classification is intentionally conservative — we only classify patterns we've
// observed in real flows (Flows 23-38). Unknown tool calls pass through without
// classification, which is safe (they just won't be tracked for re-run detection).

// workItemPattern defines a classification rule.
type workItemPattern struct {
	key         string         // canonical task key
	description string         // human-readable description
	toolName    string         // required tool name ("" = any)
	argPattern  *regexp.Regexp // regex on tool arguments (nil = skip)
	outPattern  *regexp.Regexp // regex on tool output (nil = skip arg check)
	outputFile  string         // known output file path (may contain %s for dynamic)
}

// workItemPatterns are ordered by specificity — more specific patterns first.
// The first match wins. Order matters because some tools (like "terminal")
// can match multiple patterns depending on their arguments.
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
		argPattern:  regexp.MustCompile(`(?i)(__schema|__type|IntrospectionQuery|graphql)`),
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

// targetExtractPattern extracts a target host/IP/URL from tool arguments.
// Used to differentiate work items that target different hosts (e.g., nmap host1
// vs nmap host2 should be separate "port_scan" items).
var targetExtractPattern = regexp.MustCompile(`(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}|(?:\d{1,3}\.){3}\d{1,3})`)

// classifyWorkItem matches a tool execution against known work item patterns.
// Returns (taskKey, description, outputFile) or ("", "", "") if no match.
//
// The taskKey includes target differentiation for scan/attack patterns so that
// the same tool type targeting different hosts is NOT considered a re-run.
// For example, "nmap host1" → "port_scan:host1" and "nmap host2" → "port_scan:host2"
// are separate work items. This prevents blocking legitimate multi-target scanning.
func classifyWorkItem(toolName, toolArgs, toolResult string) (string, string, string) {
	for _, pattern := range workItemPatterns {
		// Check tool name if specified
		if pattern.toolName != "" && pattern.toolName != toolName {
			// Special case: nuclei_scan can come via the dedicated tool or terminal
			if pattern.key == "nuclei_scan" && toolName == "nuclei_scan" {
				// Match — fall through
			} else {
				continue
			}
		}

		// Check argument pattern
		if pattern.argPattern != nil {
			if pattern.argPattern.MatchString(toolArgs) {
				key := pattern.key
				// Append target host to key for scan/attack patterns to allow
				// the same tool type on different targets. Without this, running
				// nmap on host1 blocks nmap on host2.
				if target := targetExtractPattern.FindString(toolArgs); target != "" {
					key = key + ":" + strings.ToLower(target)
				}
				return key, pattern.description, pattern.outputFile
			}
		}

		// Check output pattern (for cases where we classify based on result content)
		if pattern.outPattern != nil && toolResult != "" {
			if pattern.outPattern.MatchString(toolResult) {
				return pattern.key, pattern.description, pattern.outputFile
			}
		}
	}

	return "", "", ""
}

// estimateResultCount gives a rough count of results from tool output.
// Uses simple heuristics: count non-empty lines, cap at 10000.
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

// formatWorkDuration returns a human-friendly duration string for work tracker.
func formatWorkDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d seconds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	}
	return fmt.Sprintf("%.1f hours", d.Hours())
}

// ─── ExecutionState Integration ─────────────────────────────────────────────
// These functions add completedTasks support to the existing ExecutionState
// struct without modifying its interface. The V2 version of execution_state.go
// adds a CompletedTasks field directly.

// MergeCompletedTasksIntoState serializes completed tasks and adds them to
// an existing STATE.json string. Used when the caller has an ExecutionState
// but needs to add tracker data for persistence.
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
