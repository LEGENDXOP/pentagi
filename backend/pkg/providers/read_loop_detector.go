package providers

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// ReadLoopDetector detects the specific "re-read loop" pattern observed in
// Flow 24 where the agent cycles through the same set of files repeatedly:
//
//   read summary.md → read FINDINGS.md → read STATE.json →
//   check recon_runner.py → search storefront token → repeat
//
// Unlike the existing repeatingDetector (which tracks individual tool call
// repetition) and ToolHistory (which tracks entropy/frequency), this detector
// identifies CYCLIC patterns — sequences of tool calls that form a repeating
// cycle regardless of the specific arguments.
//
// The key insight from Flow 24 is that the loop wasn't repeating a SINGLE
// call — it was repeating a SEQUENCE of 3-5 different calls in the same order.
// The repeatingDetector's per-call window missed this because each individual
// call appeared only once per cycle. ToolHistory's pattern score caught it
// eventually but only after many cycles (high entropy until the window fills).
//
// Detection Algorithm:
//  1. Maintain a sliding window of recent tool call "signatures" (name + file path)
//  2. Search for the shortest repeating cycle of length ≥ cycleMinLength
//  3. If a cycle repeats ≥ cycleRepeatThreshold times, fire the loop alert
//  4. After firing, enter a cooldown period to avoid spamming the chain
//
// Configuration:
//   - LOOP_CYCLE_MIN_LENGTH: minimum cycle length (default: 3)
//   - LOOP_CYCLE_THRESHOLD: minimum repetitions to trigger (default: 3)
//   - LOOP_WINDOW_SIZE: number of recent calls to analyze (default: 30)
//   - LOOP_COOLDOWN_CALLS: calls to skip after firing (default: 5)
type ReadLoopDetector struct {
	mu sync.Mutex

	// Configuration (set at creation, read from env)
	cycleMinLength       int // minimum number of distinct calls in a cycle
	cycleRepeatThreshold int // how many times the cycle must repeat to trigger
	windowSize           int // how many recent signatures to keep
	cooldownCalls        int // calls to skip after firing an alert

	// State
	signatures           []string    // recent tool call signatures
	timestamps           []time.Time // parallel to signatures
	callsSinceLastAlert  int         // cooldown counter
	totalAlertsGenerated int         // lifetime alert count for this subtask
	lastAlertCycle       string      // fingerprint of last detected cycle (avoid re-alerting same cycle)
}

// ReadLoopDetectorConfig holds configuration for the loop detector.
type ReadLoopDetectorConfig struct {
	CycleMinLength       int
	CycleRepeatThreshold int
	WindowSize           int
	CooldownCalls        int
}

// DefaultReadLoopDetectorConfig returns the default configuration, which can
// be overridden by environment variables.
func DefaultReadLoopDetectorConfig() ReadLoopDetectorConfig {
	config := ReadLoopDetectorConfig{
		CycleMinLength:       3,
		CycleRepeatThreshold: 4,
		WindowSize:           40,
		CooldownCalls:        8,
	}

	// Allow env var overrides for tuning in production
	if v := os.Getenv("LOOP_CYCLE_MIN_LENGTH"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 2 {
			config.CycleMinLength = n
		}
	}
	if v := os.Getenv("LOOP_CYCLE_THRESHOLD"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 2 {
			config.CycleRepeatThreshold = n
		}
	}
	if v := os.Getenv("LOOP_WINDOW_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 10 {
			config.WindowSize = n
		}
	}
	if v := os.Getenv("LOOP_COOLDOWN_CALLS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			config.CooldownCalls = n
		}
	}

	return config
}

// NewReadLoopDetector creates a detector with the given configuration.
func NewReadLoopDetector(config ReadLoopDetectorConfig) *ReadLoopDetector {
	return &ReadLoopDetector{
		cycleMinLength:       config.CycleMinLength,
		cycleRepeatThreshold: config.CycleRepeatThreshold,
		windowSize:           config.WindowSize,
		cooldownCalls:        config.CooldownCalls,
		signatures:           make([]string, 0, config.WindowSize),
		timestamps:           make([]time.Time, 0, config.WindowSize),
		callsSinceLastAlert:  config.CooldownCalls, // allow immediate first detection
	}
}

// NewDefaultReadLoopDetector creates a detector with default/env-configured settings.
func NewDefaultReadLoopDetector() *ReadLoopDetector {
	return NewReadLoopDetector(DefaultReadLoopDetectorConfig())
}

// Record adds a tool call to the detection window. Call this after every
// tool execution (successful or not). The signature is extracted from the
// tool name and arguments.
//
// The signature format is: "toolName:normalizedTarget"
// Examples:
//   - "terminal:read_state.json" (file read)
//   - "terminal:read_findings.md" (file read)
//   - "file:read_subdomains.txt" (file tool read)
//   - "search:storefront+token" (web search)
//
// Offensive/write operations are filtered out — they don't participate in
// read-loop detection because they represent actual progress.
func (rld *ReadLoopDetector) Record(toolName, toolArgs string) {
	sig := extractLoopSignature(toolName, toolArgs)
	if sig == "" {
		return // not a trackable operation (offensive/write/unknown)
	}

	rld.mu.Lock()
	defer rld.mu.Unlock()

	rld.signatures = append(rld.signatures, sig)
	rld.timestamps = append(rld.timestamps, time.Now())

	// Trim to window size
	if len(rld.signatures) > rld.windowSize {
		excess := len(rld.signatures) - rld.windowSize
		rld.signatures = rld.signatures[excess:]
		rld.timestamps = rld.timestamps[excess:]
	}

	rld.callsSinceLastAlert++
}

// LoopAlert contains the details of a detected loop for chain injection.
type LoopAlert struct {
	CycleLength int      // number of distinct calls in the cycle
	RepeatCount int      // how many times the cycle repeated
	CycleFiles  []string // the files/targets in the cycle
	Message     string   // formatted message for chain injection
	TotalAlerts int      // lifetime alerts generated this subtask
}

// Check analyzes the current window for repeating cycles.
// Returns nil if no loop is detected or if in cooldown.
//
// This is the hot path — called after every Record(). It's optimized
// to return early in the common case (no loop) and only does full
// cycle detection when enough signatures have accumulated.
func (rld *ReadLoopDetector) Check() *LoopAlert {
	rld.mu.Lock()
	defer rld.mu.Unlock()

	// Not enough data for any cycle detection
	minRequired := rld.cycleMinLength * rld.cycleRepeatThreshold
	if len(rld.signatures) < minRequired {
		return nil
	}

	// Cooldown check
	if rld.callsSinceLastAlert < rld.cooldownCalls {
		return nil
	}

	// Search for the shortest repeating cycle
	maxCycleLen := len(rld.signatures) / rld.cycleRepeatThreshold
	for cycleLen := rld.cycleMinLength; cycleLen <= maxCycleLen; cycleLen++ {
		if alert := rld.detectCycleOfLength(cycleLen); alert != nil {
			// Check if this is the same cycle we already alerted on
			cycleFingerprint := strings.Join(rld.signatures[len(rld.signatures)-cycleLen:], "|")
			if cycleFingerprint == rld.lastAlertCycle && rld.callsSinceLastAlert < rld.cooldownCalls*2 {
				continue // same cycle, give it more cooldown
			}

			rld.callsSinceLastAlert = 0
			rld.totalAlertsGenerated++
			rld.lastAlertCycle = cycleFingerprint
			alert.TotalAlerts = rld.totalAlertsGenerated
			alert.Message = rld.formatAlertMessage(alert)

			logrus.WithFields(logrus.Fields{
				"cycle_length": alert.CycleLength,
				"repeat_count": alert.RepeatCount,
				"cycle_files":  alert.CycleFiles,
				"total_alerts": alert.TotalAlerts,
				"window_size":  len(rld.signatures),
			}).Warn("read loop detector: cyclic pattern detected")

			return alert
		}
	}

	return nil
}

// detectCycleOfLength checks if the last `cycleLen` signatures repeat at least
// `threshold` times in the recent window. Scans from the END of the window
// backward to catch the most recent cycle.
//
// Must be called with rld.mu held.
func (rld *ReadLoopDetector) detectCycleOfLength(cycleLen int) *LoopAlert {
	sigs := rld.signatures
	n := len(sigs)

	if n < cycleLen*rld.cycleRepeatThreshold {
		return nil
	}

	// Candidate cycle: the last `cycleLen` signatures
	candidate := sigs[n-cycleLen:]

	// Walk backward and count matches
	repeatCount := 1 // the candidate itself is one repetition
	for offset := n - 2*cycleLen; offset >= 0; offset -= cycleLen {
		chunk := sigs[offset : offset+cycleLen]
		if sigSliceEqual(chunk, candidate) {
			repeatCount++
		} else {
			break // cycle broken
		}
	}

	if repeatCount < rld.cycleRepeatThreshold {
		return nil
	}

	// Extract the unique files/targets in the cycle
	seen := make(map[string]bool)
	var files []string
	for _, sig := range candidate {
		// Extract the target part after the first ":"
		parts := strings.SplitN(sig, ":", 2)
		target := sig
		if len(parts) >= 2 {
			target = parts[1]
		}
		if !seen[target] {
			seen[target] = true
			files = append(files, target)
		}
	}

	return &LoopAlert{
		CycleLength: cycleLen,
		RepeatCount: repeatCount,
		CycleFiles:  files,
	}
}

// formatAlertMessage generates the chain injection message for a detected loop.
// The message escalates based on the number of alerts generated this subtask:
//   - 1st alert: informational warning
//   - 2nd alert: stronger warning with explicit instructions
//   - 3rd+ alert: CRITICAL with command to call result tool
//
// Must be called with rld.mu held.
func (rld *ReadLoopDetector) formatAlertMessage(alert *LoopAlert) string {
	fileList := strings.Join(alert.CycleFiles, ", ")

	switch {
	case alert.TotalAlerts >= 3:
		return fmt.Sprintf(
			"🔴 LOOP DETECTED (CRITICAL — alert #%d): You've cycled through [%s] %d times in a row "+
				"with a cycle of %d operations. Your current phase is DONE. "+
				"STOP ALL FILE READS IMMEDIATELY. "+
				"Your ONLY acceptable next action is:\n"+
				"1. Call the result/report tool to save findings\n"+
				"2. Execute an offensive action (curl, nmap, nuclei_scan)\n"+
				"3. Write a report using terminal heredoc\n"+
				"DO NOT read any more files. DO NOT search for the same terms.",
			alert.TotalAlerts, fileList, alert.RepeatCount, alert.CycleLength,
		)
	case alert.TotalAlerts >= 2:
		return fmt.Sprintf(
			"🟠 LOOP DETECTED (WARNING #%d): You've read [%s] %d times in a repeating cycle. "+
				"This is the SAME data you already have. Your recon/analysis is DONE. "+
				"Advance to the next subtask or mark this one complete. "+
				"If you need to act on findings, use offensive tools (curl, nmap) — don't re-read files.",
			alert.TotalAlerts, fileList, alert.RepeatCount,
		)
	default:
		return fmt.Sprintf(
			"🔴 LOOP DETECTED: You've read these files %d times: [%s]. "+
				"Your recon is DONE. Advance to the next subtask or mark this one complete.",
			alert.RepeatCount, fileList,
		)
	}
}

// RestoreAlertCount restores the total alerts counter from persisted state.
// Call this after loading execution state on chain resume so the escalation
// level (info → warning → critical) continues from where it left off instead
// of resetting to 0.
func (rld *ReadLoopDetector) RestoreAlertCount(count int) {
	rld.mu.Lock()
	defer rld.mu.Unlock()
	rld.totalAlertsGenerated = count
}

// GetStats returns detection statistics for logging.
func (rld *ReadLoopDetector) GetStats() (windowSize int, totalAlerts int) {
	rld.mu.Lock()
	defer rld.mu.Unlock()
	return len(rld.signatures), rld.totalAlertsGenerated
}

// ─── Signature Extraction ───────────────────────────────────────────────────

// extractLoopSignature converts a tool call into a trackable signature for
// cycle detection. Returns "" for operations that shouldn't participate in
// loop detection (offensive tools, write operations, delegation).
func extractLoopSignature(toolName, toolArgs string) string {
	switch toolName {
	case "terminal":
		return extractTerminalLoopSig(toolArgs)
	case "file":
		return extractFileLoopSig(toolArgs)
	case "search", "search_code", "search_guide":
		return extractSearchLoopSig(toolName, toolArgs)
	case "memorist":
		return "memorist:query"
	case "graphiti_search":
		return "graphiti:search"

	// Offensive/action tools — NOT tracked for read-loop detection
	case "nuclei_scan", "browser_navigate", "browser_click",
		"hack_result", "done", "code_result", "maintenance_result",
		"coder", "installer", "maintenance", "pentester",
		"interactsh_get_url", "interactsh_poll":
		return ""

	default:
		return ""
	}
}

// extractTerminalLoopSig normalizes a terminal command into a loop-trackable signature.
func extractTerminalLoopSig(toolArgs string) string {
	var args map[string]interface{}
	if err := json.Unmarshal([]byte(toolArgs), &args); err != nil {
		return ""
	}

	input, ok := args["input"].(string)
	if !ok || input == "" {
		return ""
	}

	// Skip write operations — they represent progress
	if isTerminalWriteCommand(toolArgs) {
		return ""
	}

	// Skip offensive commands — they represent progress
	primaryCmd := extractPrimaryCommand(input)
	if isOffensiveCommand(primaryCmd) {
		return ""
	}

	// Classify as a read and extract the target
	if isReadCommand(primaryCmd) {
		target := extractLoopReadTarget(primaryCmd)
		if target != "" {
			return "terminal:read_" + normalizeLoopFilename(target)
		}
		return "terminal:read_unknown"
	}

	// Python/script that reads files
	if strings.Contains(strings.ToLower(input), "open(") {
		return "terminal:script_read"
	}

	return ""
}

// extractFileLoopSig normalizes a file tool call.
func extractFileLoopSig(toolArgs string) string {
	var args map[string]interface{}
	if err := json.Unmarshal([]byte(toolArgs), &args); err != nil {
		return ""
	}

	action, _ := args["action"].(string)
	path, _ := args["path"].(string)

	switch action {
	case "read_file":
		return "file:read_" + normalizeLoopFilename(path)
	case "update_file":
		return "" // writes are progress, not tracked
	default:
		return ""
	}
}

// extractSearchLoopSig normalizes a search tool call.
func extractSearchLoopSig(toolName, toolArgs string) string {
	var args map[string]interface{}
	if err := json.Unmarshal([]byte(toolArgs), &args); err != nil {
		return toolName + ":unknown"
	}

	query, _ := args["question"].(string)
	if query == "" {
		query, _ = args["query"].(string)
	}
	if query == "" {
		return toolName + ":unknown"
	}

	// Normalize the query: lowercase, collapse whitespace, take first 50 chars
	normalized := strings.ToLower(strings.TrimSpace(query))
	normalized = strings.Join(strings.Fields(normalized), "+")
	if len(normalized) > 50 {
		normalized = normalized[:50]
	}

	return toolName + ":" + normalized
}

// extractLoopReadTarget extracts the filename/path from a read command's primary segment.
func extractLoopReadTarget(primaryCmd string) string {
	words := strings.Fields(primaryCmd)
	for i := len(words) - 1; i >= 1; i-- {
		word := words[i]
		// Skip flags
		if strings.HasPrefix(word, "-") {
			continue
		}
		// Skip shell operators
		if word == "2>/dev/null" || word == "||" || word == "&&" || word == ";" {
			continue
		}
		// Skip common builtins
		if word == "echo" || word == "true" || word == "false" {
			continue
		}
		// This is likely the file path
		if strings.Contains(word, "/") || strings.Contains(word, ".") {
			return word
		}
	}
	return ""
}

// normalizeLoopFilename reduces a file path to its base name for comparison.
func normalizeLoopFilename(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "unknown"
	}
	// Strip everything before the last /
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		path = path[idx+1:]
	}
	if path == "" {
		return "unknown"
	}
	return strings.ToLower(path)
}

// sigSliceEqual compares two string slices for equality.
func sigSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
