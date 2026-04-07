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
	history         []llms.FunctionCall
	threshold       int
	readCounts      map[string]int // per-file path → read count this subtask
	totalBlocks     int            // total read blocks across ALL files this subtask
	allReadsBlocked bool           // after 5 total blocks, block ALL reads (even new files)
	globalReadCount int            // total read operations across all files (regardless of detection)
	maxGlobalReads  int            // hard limit on total reads per subtask
}

func newRepeatingDetector() *repeatingDetector {
	return &repeatingDetector{
		threshold:      RepeatingToolCallThreshold,
		readCounts:     make(map[string]int),
		maxGlobalReads: 60,
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

	// Exempt write operations — agents legitimately write/append to FINDINGS.md,
	// STATE.json, HANDOFF.md multiple times during a subtask. This is normal
	// workflow (updating findings, recording state), not a loop. Blocking writes
	// causes deadlocks where the agent cannot save progress.
	if isWriteOperation(funcCall) {
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

// isWriteOperation returns true for tool calls that perform write/create/update
// operations. These must NEVER be blocked by repeat detection because agents
// legitimately write to the same files multiple times during normal workflow
// (e.g., appending findings, updating state, writing handoff notes).
//
// This covers:
//   - file tool with update_file action (the only write action for the file tool)
//   - terminal tool with shell write patterns (redirects, heredocs, tee, mv, cp)
//   - barrier/completion tools (hack_result, done) — these signal task completion
func isWriteOperation(fc llms.FunctionCall) bool {
	switch fc.Name {
	// file tool: update_file is a write operation
	case "file":
		if strings.Contains(fc.Arguments, `"update_file"`) {
			return true
		}

	// terminal tool: detect shell write patterns in the input command
	case "terminal":
		if isTerminalWriteCommand(fc.Arguments) {
			return true
		}

	// Barrier/completion tools should never be blocked as "repeating"
	case "hack_result", "done":
		return true
	}

	return false
}

// writeCommandPattern matches shell commands that write to files.
// It detects output redirects (>, >>), heredocs (<<), tee, mv, cp, mkdir, chmod, install.
// The pattern is designed to avoid false-positives on read-only commands:
//   - Output redirect uses a negative lookbehind-like [^<] to avoid matching <<
//   - Heredoc << is matched separately as it always indicates a write
var writeCommandPattern = regexp.MustCompile(
	`(?:` +
		`(?:^|[^<])>>?\s` + // output redirect: > file or >> file (but not <<)
		`|<<[-']?\s*` + // heredoc: << EOF, <<- EOF, <<'EOF'
		`|\|\s*tee\b` + // pipe to tee
		`|^\s*tee\b` + // tee at start of command
		`|\bmv\s` + // mv command
		`|\bcp\s` + // cp command
		`|\bmkdir\s` + // mkdir command
		`|\bchmod\s` + // chmod command
		`|\binstall\s` + // install command
		`|\bprintf\s.*>` + // printf with redirect
		`)`,
)

// isTerminalWriteCommand checks if a terminal tool's arguments contain a shell
// command that writes to files. This is used to exempt writes from both repeat
// detection and read-cap counting.
func isTerminalWriteCommand(args string) bool {
	// Parse the input field from the terminal tool arguments
	var termArgs map[string]interface{}
	if err := json.Unmarshal([]byte(args), &termArgs); err != nil {
		return false
	}
	input, ok := termArgs["input"].(string)
	if !ok || input == "" {
		return false
	}

	// Check for output redirects: >, >> (but not << which is heredoc input)
	// This catches: echo "x" > file, cat >> file, jq '.x' f > /tmp/s.json
	if writeCommandPattern.MatchString(input) {
		return true
	}

	return false
}

// isReadOnlyCall returns true ONLY when the PRIMARY command (first command before
// any pipe) is a file-read operation. Commands that use read-like tools (grep, jq,
// awk) for output processing of non-file-read primary commands (curl, nmap, nuclei)
// are NOT reads.
//
// Examples:
//   - `curl ... | grep token` → primary is `curl` → NOT a read
//   - `cat /work/STATE.json | jq .` → primary is `cat` → IS a read
//   - `nmap -sV target | tee evidence.txt` → primary is `nmap` → NOT a read
//
// IMPORTANT: Commands that contain read-like patterns (cat, head, jq) but actually
// WRITE to files (via redirects, heredocs, tee) must NOT be classified as reads.
func (rd *repeatingDetector) isReadOnlyCall(fc llms.FunctionCall) bool {
	// file tool with read_file action
	if fc.Name == "file" {
		return strings.Contains(fc.Arguments, `"read_file"`)
	}

	// Only analyse terminal tool commands
	if fc.Name != "terminal" {
		return false
	}

	// First check: if the command is a write operation, it's NOT a read.
	if isTerminalWriteCommand(fc.Arguments) {
		return false
	}

	var termArgs map[string]interface{}
	if err := json.Unmarshal([]byte(fc.Arguments), &termArgs); err != nil {
		return false // Can't parse → don't classify as read (safe default)
	}
	input, ok := termArgs["input"].(string)
	if !ok || input == "" {
		return false
	}

	// Extract the PRIMARY command (first command before any pipe/&&/;).
	primaryCmd := extractPrimaryCommand(input)

	// If the primary command is a known offensive/network tool, NOT a read.
	if isOffensiveCommand(primaryCmd) {
		return false
	}

	// Check if the primary command is a read-only command
	return isReadCommand(primaryCmd)
}

// extractPrimaryCommand returns the first command in a pipeline, stripped of
// leading whitespace and environment variable assignments. For compound commands
// (&&, ||, ;), returns the first segment.
func extractPrimaryCommand(input string) string {
	// Split on pipe first, but not || (logical OR)
	segment := input
	for i := 0; i < len(input); i++ {
		if input[i] == '|' {
			if i+1 < len(input) && input[i+1] == '|' {
				// This is ||, split here
				segment = input[:i]
				break
			}
			// This is a single pipe
			segment = input[:i]
			break
		}
	}

	// Split on && and ;
	for _, sep := range []string{"&&", ";"} {
		if idx := strings.Index(segment, sep); idx > 0 {
			segment = segment[:idx]
		}
	}

	return strings.TrimSpace(segment)
}

// offensiveCommands are tools whose primary purpose is network interaction,
// scanning, or exploitation. These should NEVER be classified as "reads"
// even when their pipelines include grep/jq/awk for output processing.
var offensiveCommands = map[string]bool{
	"curl": true, "wget": true, "http": true, "https": true,
	"nmap": true, "nuclei": true, "subfinder": true, "httpx": true, "ffuf": true,
	"gobuster": true, "dirb": true, "nikto": true, "sqlmap": true, "wfuzz": true,
	"amass": true, "masscan": true, "rustscan": true, "feroxbuster": true,
	"hydra": true, "john": true, "hashcat": true, "medusa": true,
	"msfconsole": true, "msfvenom": true,
	"testssl.sh": true, "sslscan": true, "sslyze": true,
	"dig": true, "nslookup": true, "host": true, "whois": true,
	"nc": true, "ncat": true, "netcat": true, "socat": true,
	"openssl": true, "ssh": true, "scp": true,
	"python3": true, "python": true, "ruby": true, "perl": true,
	"echo": true, "printf": true,
}

// isOffensiveCommand checks if the primary command segment starts with a known
// offensive/network tool. Skips VAR=value env-var prefixes.
//
// Special case: python3/python/perl are offensive by default, but if the command
// contains open() on a tracked state file, it's a file read, not offensive.
func isOffensiveCommand(primaryCmd string) bool {
	words := strings.Fields(primaryCmd)
	for _, word := range words {
		// Skip VAR=value prefixes (e.g., TOKEN=xxx curl ...)
		if strings.Contains(word, "=") && !strings.HasPrefix(word, "-") {
			continue
		}
		cmd := filepath.Base(word) // handle /usr/bin/curl → curl

		// Special: python3/python/perl are offensive UNLESS they open() tracked files
		if cmd == "python3" || cmd == "python" || cmd == "perl" {
			if containsTrackedFileOpen(primaryCmd) {
				return false // It's a file read disguised as a script
			}
			return true // Offensive (payload generation, exploitation, etc.)
		}

		return offensiveCommands[cmd]
	}
	return false
}

// readCommands are tools whose primary purpose is reading file contents.
var readCommands = map[string]bool{
	"cat": true, "head": true, "tail": true, "less": true, "more": true,
	"jq": true, "grep": true, "awk": true, "sed": true,
	"wc": true, "ls": true, "find": true, "file": true, "stat": true,
	"strings": true, "xxd": true, "hexdump": true,
}

// isReadCommand checks if the primary command segment starts with a known
// read-only tool. Handles VAR=value prefixes and special cases (sed -i).
func isReadCommand(primaryCmd string) bool {
	words := strings.Fields(primaryCmd)
	for _, word := range words {
		// Skip VAR=value prefixes
		if strings.Contains(word, "=") && !strings.HasPrefix(word, "-") {
			continue
		}
		cmd := filepath.Base(word)

		// Special: python3/python/perl in offensiveCommands take precedence,
		// but if the command contains open() on a tracked file, it's a read.
		if cmd == "python3" || cmd == "python" || cmd == "perl" {
			return containsTrackedFileOpen(primaryCmd)
		}

		// sed with -i is a write, not a read
		if cmd == "sed" && strings.Contains(primaryCmd, " -i") {
			return false
		}

		return readCommands[cmd]
	}
	return false
}

// containsTrackedFileOpen checks if a python/perl command opens a tracked state file.
func containsTrackedFileOpen(cmd string) bool {
	cmdLower := strings.ToLower(cmd)
	for _, tracked := range []string{
		"state.json", "findings.md", "handoff.md", "resume.md", "report.md",
	} {
		if strings.Contains(cmdLower, tracked) && strings.Contains(cmdLower, "open(") {
			return true
		}
	}
	return false
}

// readOnlyCmdPatterns matches various read-only shell commands and captures the file path.
var readOnlyCmdPatterns = []*regexp.Regexp{
	// cat/head/tail [-flags] FILE
	regexp.MustCompile(`(?:^|\s)(cat|head|tail)\s+(?:-[^\s]*\s+)*([^\s|;&>]+)`),
	// sed [-flags] 'pattern' FILE
	regexp.MustCompile(`(?:^|\s)sed\s+(?:-[^\s]*\s+)*(?:'[^']*'|"[^"]*")\s+([^\s|;&>]+)`),
	// awk 'program' FILE
	regexp.MustCompile(`(?:^|\s)awk\s+(?:-[^\s]*\s+)*(?:'[^']*'|"[^"]*")\s+([^\s|;&>]+)`),
	// grep [-flags] 'pattern' FILE
	regexp.MustCompile(`(?:^|\s)grep\s+(?:-[^\s]*\s+)*(?:'[^']*'|"[^"]*")\s+([^\s|;&>]+)`),
	// jq 'filter' FILE
	regexp.MustCompile(`(?:^|\s)jq\s+(?:-[^\s]*\s+)*(?:'[^']*'|"[^"]*")\s+([^\s|;&>]+)`),
	// python3 -c "with open('FILE')" or open("FILE")
	regexp.MustCompile(`open\(\s*['"]([^'"]+)['"]\s*\)`),
	// wc [-flags] FILE
	regexp.MustCompile(`(?:^|\s)wc\s+(?:-[^\s]*\s+)*([^\s|;&>]+)`),
	// less/more FILE
	regexp.MustCompile(`(?:^|\s)(?:less|more)\s+([^\s|;&>]+)`),
}

// checkReadCap enforces a soft cap on per-file read operations. Read-only calls
// are exempt from the repeat detector's detect() method to let agents bootstrap,
// but without a cap they can read the same file 20+ times in infinite loops.
//
// Returns (blocked, message):
//   - ≤3 reads:  (false, "")         — free reads (initial + verify-after-write + re-verify)
//   - 4-5 reads: (false, "⚠️ ...")   — warning prepended to tool result
//   - >5 reads:  (true, "BLOCKED...") — synthetic response, tool NOT executed
func (rd *repeatingDetector) checkReadCap(funcCall llms.FunctionCall) (bool, string) {
	if !rd.isReadOnlyCall(funcCall) {
		return false, ""
	}

	// Exempt evidence files — agents legitimately read these during report compilation.
	// Check BEFORE incrementing global counter so evidence reads are truly free.
	filePath := extractReadFilePath(funcCall)
	if filePath != "" && isEvidencePath(filePath) {
		return false, ""
	}

	// Global read counter: absolute backstop regardless of per-file tracking
	rd.globalReadCount++
	if rd.globalReadCount > rd.maxGlobalReads {
		return true, fmt.Sprintf(
			"🛑 ABSOLUTE READ LIMIT: You have made %d read operations this subtask (limit: %d). "+
				"ALL file reads are now blocked. You have ALL the information you need. "+
				"STOP reading and take action — write your findings or call the result tool.",
			rd.globalReadCount, rd.maxGlobalReads,
		)
	}

	if filePath == "" {
		return false, ""
	}

	// Normalize to base name so /work/STATE.json and STATE.json count together.
	key := filepath.Base(filePath)

	// After 6 total blocks: hard-block ALL reads, even first reads of new files.
	if rd.allReadsBlocked {
		rd.totalBlocks++
		return true, fmt.Sprintf(
			"🛑 HARD BLOCK: ALL file reads are disabled for this subtask (total blocks: %d). "+
				"File '%s' was NOT read. You have been repeatedly blocked and MUST stop reading files. "+
				"Use the information you already have. Your NEXT tool call MUST be an offensive action "+
				"(nmap, curl, nuclei_scan, browser_navigate) — NOT a file read.",
			rd.totalBlocks, key,
		)
	}

	if rd.readCounts == nil {
		rd.readCounts = make(map[string]int)
	}
	rd.readCounts[key]++
	count := rd.readCounts[key]

	switch {
	case count <= 3:
		// Free reads: initial bootstrap + verify-after-write + re-verify (was: 2, now: 3)
		return false, ""
	case count <= 5:
		// Warning zone (was: 4, now: 5)
		return false, fmt.Sprintf(
			"⚠️ WARNING: You've read '%s' %d times. The content has NOT changed since your first read. "+
				"STOP reading this file. Instead, you MUST now:\n"+
				"1. Write your findings/report using the 'file' tool with 'update_file'\n"+
				"2. OR execute an offensive action (curl, nmap, nuclei_scan)\n"+
				"3. OR call the result tool if you've completed the task\n"+
				"Reading this file again WILL be blocked.",
			key, count,
		)
	default:
		// Per-file block — also escalate totalBlocks
		rd.totalBlocks++

		// After 8 total blocks: engage hard block for ALL future reads (was: 6, now: 8)
		if rd.totalBlocks >= 8 {
			rd.allReadsBlocked = true
			return true, fmt.Sprintf(
				"🛑 HARD BLOCK ENGAGED: Read of '%s' denied (read %d times). "+
					"You have now been blocked %d times total across all files. "+
					"ALL file reads are now DISABLED for the rest of this subtask — even new files. "+
					"STOP reading files. You already have all the information you need. "+
					"Your NEXT tool call MUST be an offensive action (nmap, curl, nuclei_scan, browser_navigate).",
				key, count, rd.totalBlocks,
			)
		}

		// After 5 total blocks: critical escalation (was: 4, now: 5)
		if rd.totalBlocks >= 5 {
			return true, fmt.Sprintf(
				"🛑 CRITICAL: You have been blocked from reading files %d times. STOP ALL FILE READS IMMEDIATELY. "+
					"Read of '%s' denied (read %d times). "+
					"You already have all the information you need. Your NEXT tool call MUST be "+
					"an offensive action (nmap, curl, nuclei_scan, browser_navigate) — NOT a file read. "+
					"If you read another file, it will also be blocked.",
				rd.totalBlocks, key, count,
			)
		}

		// Standard block (totalBlocks 1-3)
		return true, fmt.Sprintf(
			"BLOCKED: Read of '%s' denied — already read %d times this subtask. "+
				"The file content has not changed. Proceed with testing using the information you already have. "+
				"(Total blocks so far: %d — further blocks will escalate to hard restrictions.)",
			key, count, rd.totalBlocks,
		)
	}
}

// resetReadCounts clears all read-cap state, intended for subtask boundaries.
// Resets per-file counters, total block count, and the allReadsBlocked flag.
func (rd *repeatingDetector) resetReadCounts() {
	rd.readCounts = make(map[string]int)
	rd.totalBlocks = 0
	rd.allReadsBlocked = false
	rd.globalReadCount = 0
}

// extractReadFilePath extracts the file path from a read-only tool call.
// Handles both "file" tool with read_file action and "terminal" tool with cat/head/tail.
//
// IMPORTANT: Only extracts paths from the PRIMARY command segment (before pipes).
// Does NOT match tracked filenames that appear in URLs, write destinations, or
// pipe targets. This prevents false-positive read counting on write/network commands.
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

		// CRITICAL: Only extract file paths from the PRIMARY command segment.
		// Don't match filenames that appear in pipe targets, URLs, or write destinations.
		primaryCmd := extractPrimaryCommand(input)

		// If primary command is offensive, there's no file path to extract
		if isOffensiveCommand(primaryCmd) {
			return ""
		}

		// Try regex patterns on PRIMARY command only (not full pipeline)
		for _, pattern := range readOnlyCmdPatterns {
			matches := pattern.FindStringSubmatch(primaryCmd)
			if len(matches) >= 2 {
				candidate := matches[len(matches)-1]
				if candidate != "" && !strings.HasPrefix(candidate, "-") {
					return candidate
				}
			}
		}

		// Fallback: ONLY match tracked files when the primary command is a read command.
		// This prevents matching tracked filenames in URLs or write targets.
		if isReadCommand(primaryCmd) {
			primaryLower := strings.ToLower(primaryCmd)
			for _, tracked := range []string{
				"findings.md", "state.json", "handoff.md", "resume.md", "report.md",
			} {
				if strings.Contains(primaryLower, tracked) {
					return tracked
				}
			}

			// Also track temp files that are commonly re-read (tokens, schemas,
			// captured output). This extends read-cap coverage to /tmp/ files
			// which were previously invisible to the cap — allowing agents to
			// read /tmp/access_token.txt 20x without triggering any limit.
			if strings.HasPrefix(strings.TrimSpace(primaryCmd), "cat ") {
				parts := strings.Fields(primaryCmd)
				if len(parts) >= 2 && strings.HasPrefix(parts[1], "/") {
					candidate := parts[1]
					// Strip shell operators/redirections that may be appended
					candidate = strings.TrimRight(candidate, ";|&")
					if candidate != "" {
						return candidate
					}
				}
			}
		}
	}
	return ""
}

// isEvidencePath returns true for file paths under the evidence directory.
// Evidence files should never count against the read cap — agents legitimately
// read these during report compilation.
func isEvidencePath(path string) bool {
	normalized := strings.ToLower(path)
	return strings.Contains(normalized, "/evidence/") ||
		strings.HasPrefix(normalized, "evidence/")
}

func (rd *repeatingDetector) clearCallArguments(toolCall *llms.FunctionCall) llms.FunctionCall {
	var v map[string]any
	if err := json.Unmarshal([]byte(toolCall.Arguments), &v); err != nil {
		return *toolCall
	}

	delete(v, "message")

	// For delegation tools, we keep "question" because it contains the unique
	// task description that differentiates legitimate calls. Only "message"
	// (the large identical prompt template) is stripped above. Without
	// "question", all calls hash identically (e.g. 'coder{}'), which triggers
	// the repeating detector after just 3 calls and blocks all subsequent use.
	switch toolCall.Name {
	case "coder", "installer", "maintenance", "pentester":
		// "question" preserved intentionally — see comment above
	}

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
// timeRemainingMinutes is injected when >= 0 (pass -1 to omit).
func injectMetricsIntoSystemPrompt(systemPrompt string, metrics ExecutionMetrics, timeRemainingMinutes int) string {
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
		systemPrompt = systemPrompt[:startIdx] + metricsBlock + systemPrompt[endIdx+len(endTag):]
	} else {
		// Insert before </anti_loop_protocol> if present
		insertPoint := strings.Index(systemPrompt, "</anti_loop_protocol>")
		if insertPoint >= 0 {
			systemPrompt = systemPrompt[:insertPoint] + metricsBlock + "\n" + systemPrompt[insertPoint:]
		} else {
			// Fallback: append to end
			systemPrompt = systemPrompt + "\n" + metricsBlock
		}
	}

	// Inject or replace the <time_remaining> block so agents can prioritize graceful completion.
	if timeRemainingMinutes >= 0 {
		urgency := "normal"
		switch {
		case timeRemainingMinutes < 5:
			urgency = "CRITICAL"
		case timeRemainingMinutes < 10:
			urgency = "LOW"
		case timeRemainingMinutes < 20:
			urgency = "MODERATE"
		}

		delegationNote := ""
		if timeRemainingMinutes < 15 {
			delegationNote = "\n  <delegation>BLOCKED — use terminal/file tool directly</delegation>"
		} else if timeRemainingMinutes < 25 {
			delegationNote = "\n  <delegation>DISCOURAGED — prefer terminal/file tool for speed</delegation>"
		}

		timeBlock := fmt.Sprintf(
			"<time_remaining>\n"+
				"  <minutes>%d</minutes>\n"+
				"  <urgency>%s</urgency>%s\n"+
				"</time_remaining>",
			timeRemainingMinutes,
			urgency,
			delegationNote,
		)

		trStartTag := "<time_remaining>"
		trEndTag := "</time_remaining>"
		trStartIdx := strings.Index(systemPrompt, trStartTag)
		trEndIdx := strings.Index(systemPrompt, trEndTag)
		if trStartIdx >= 0 && trEndIdx > trStartIdx {
			systemPrompt = systemPrompt[:trStartIdx] + timeBlock + systemPrompt[trEndIdx+len(trEndTag):]
		} else {
			// Insert after </execution_metrics> if present
			metricsEndIdx := strings.Index(systemPrompt, endTag)
			if metricsEndIdx >= 0 {
				insertAt := metricsEndIdx + len(endTag)
				systemPrompt = systemPrompt[:insertAt] + "\n" + timeBlock + systemPrompt[insertAt:]
			} else {
				systemPrompt = systemPrompt + "\n" + timeBlock
			}
		}
	}

	return systemPrompt
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

// trackedStateFiles are the files that the agent writes findings/state into
// during subtask execution. These are vulnerable to truncation when a `cat >`
// or heredoc write is interrupted by a context deadline or timeout.
var trackedStateFiles = []string{
	"FINDINGS.md",
	"STATE.json",
	"HANDOFF.md",
}

// isTrackedFileWrite returns the base filename if the tool call is a write
// operation targeting one of the tracked state files. Returns "" if not a
// tracked file write.
//
// Supports both terminal tool (shell commands with redirects/heredocs) and
// file tool (update_file action).
func isTrackedFileWrite(funcName string, funcArgs json.RawMessage) string {
	switch funcName {
	case "terminal":
		var termArgs map[string]interface{}
		if err := json.Unmarshal(funcArgs, &termArgs); err != nil {
			return ""
		}
		input, ok := termArgs["input"].(string)
		if !ok || input == "" {
			return ""
		}
		// Only check if the command is a write operation
		if !writeCommandPattern.MatchString(input) {
			return ""
		}
		// Check if any tracked file is mentioned in the command
		inputLower := strings.ToLower(input)
		for _, f := range trackedStateFiles {
			if strings.Contains(inputLower, strings.ToLower(f)) {
				return f
			}
		}

	case "file":
		var fileArgs map[string]interface{}
		if err := json.Unmarshal(funcArgs, &fileArgs); err != nil {
			return ""
		}
		action, _ := fileArgs["action"].(string)
		if action != "update_file" {
			return ""
		}
		path, _ := fileArgs["path"].(string)
		if path == "" {
			return ""
		}
		base := filepath.Base(path)
		for _, f := range trackedStateFiles {
			if strings.EqualFold(base, f) {
				return f
			}
		}
	}

	return ""
}

// buildBackupCommand builds a shell command that creates .bak copies of tracked
// state files before a write operation. The command is designed to never fail —
// if the source file doesn't exist, the cp is silently skipped.
func buildBackupCommand(filename string) string {
	// Back up the specific file being written to.
	// The `2>/dev/null || true` ensures the command always succeeds even
	// if the file doesn't exist yet (first write).
	return fmt.Sprintf(
		"cp /work/%s /work/%s.bak 2>/dev/null || true",
		filename, filename,
	)
}

// buildRestoreCheckCommand builds a shell command that checks all tracked state
// files and restores from .bak if the file is 0 bytes but .bak has content.
// Output is a newline-separated list of restored filenames (empty if none restored).
func buildRestoreCheckCommand() string {
	var parts []string
	for _, f := range trackedStateFiles {
		// Check: file exists AND is 0 bytes AND .bak exists AND .bak is >0 bytes
		parts = append(parts, fmt.Sprintf(
			`if [ -f /work/%s ] && [ ! -s /work/%s ] && [ -s /work/%s.bak ]; then cp /work/%s.bak /work/%s && echo "restored:%s"; fi`,
			f, f, f, f, f, f,
		))
	}
	return strings.Join(parts, "; ")
}
