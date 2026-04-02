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

// ReadLoopDetector v2 — Proactive cyclic pattern detection with escalation.
//
// Changes from v1:
//   - Lower default thresholds: cycleRepeatThreshold=2 (was 4), cooldownCalls=3 (was 8)
//   - Checkpoint-aware: tracks STATE.json/RESUME.md reads AND writes as checkpoint ops
//   - Fast-path checkpoint detection: fires if last N calls are all checkpoint file ops
//   - Escalating response: warning → strong warning → HARD BLOCK (with ShouldBlock())
//   - Fuzzy cycle matching: 80%+ signature match counts as a cycle repeat
//   - RecordSystemWrite(): lets performer register system-generated file writes
//   - ShouldBlock(): returns true after maxAlertsBeforeBlock alerts — performer uses
//     this to reject all further read tool calls
//
// Configuration (env vars):
//   - LOOP_CYCLE_MIN_LENGTH: minimum cycle length (default: 2)
//   - LOOP_CYCLE_THRESHOLD: minimum repetitions to trigger (default: 2)
//   - LOOP_WINDOW_SIZE: recent signatures to analyze (default: 30)
//   - LOOP_COOLDOWN_CALLS: calls to skip after alert (default: 3)
//   - LOOP_CHECKPOINT_WINDOW: window for checkpoint-specific detection (default: 8)
//   - LOOP_MAX_ALERTS_BEFORE_BLOCK: alerts before ShouldBlock()=true (default: 3)
type ReadLoopDetector struct {
	mu sync.Mutex

	// Configuration
	cycleMinLength       int
	cycleRepeatThreshold int
	windowSize           int
	cooldownCalls        int
	checkpointWindow     int // window size for checkpoint-specific fast detection
	maxAlertsBeforeBlock int // after this many alerts, ShouldBlock() returns true

	// State
	signatures           []string
	timestamps           []time.Time
	callsSinceLastAlert  int
	totalAlertsGenerated int
	lastAlertCycle       string

	// Checkpoint tracking: STATE.json, RESUME.md reads/writes by both agent and system
	checkpointOps []string // recent checkpoint operation signatures

	// Per-file blocking: only files that participated in a detected cycle are blocked.
	blockedFiles map[string]bool
}

// ReadLoopDetectorConfig holds configuration for the loop detector.
type ReadLoopDetectorConfig struct {
	CycleMinLength       int
	CycleRepeatThreshold int
	WindowSize           int
	CooldownCalls        int
	CheckpointWindow     int
	MaxAlertsBeforeBlock int
}

// DefaultReadLoopDetectorConfig returns the default configuration, overridable by env vars.
func DefaultReadLoopDetectorConfig() ReadLoopDetectorConfig {
	config := ReadLoopDetectorConfig{
		CycleMinLength:       2,  // v2: lowered from 3 → catch 2-step cycles
		CycleRepeatThreshold: 2,  // v2: lowered from 4 → fire after 2 full cycles
		WindowSize:           30, // v2: lowered from 40 → tighter window
		CooldownCalls:        3,  // v2: lowered from 8 → much shorter cooldown
		CheckpointWindow:     8,  // v2: new — fast-path checkpoint detection window
		MaxAlertsBeforeBlock: 3,  // v2: new — hard block after 3 alerts
	}

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
	if v := os.Getenv("LOOP_CHECKPOINT_WINDOW"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 4 {
			config.CheckpointWindow = n
		}
	}
	if v := os.Getenv("LOOP_MAX_ALERTS_BEFORE_BLOCK"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			config.MaxAlertsBeforeBlock = n
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
		checkpointWindow:     config.CheckpointWindow,
		maxAlertsBeforeBlock: config.MaxAlertsBeforeBlock,
		signatures:           make([]string, 0, config.WindowSize),
		timestamps:           make([]time.Time, 0, config.WindowSize),
		checkpointOps:        make([]string, 0, config.CheckpointWindow),
		callsSinceLastAlert:  config.CooldownCalls, // allow immediate first detection
		blockedFiles:         make(map[string]bool),
	}
}

// NewDefaultReadLoopDetector creates a detector with default/env-configured settings.
func NewDefaultReadLoopDetector() *ReadLoopDetector {
	return NewReadLoopDetector(DefaultReadLoopDetectorConfig())
}

// Record adds a tool call to the detection window.
// Signature format: "toolName:normalizedTarget"
func (rld *ReadLoopDetector) Record(toolName, toolArgs string) {
	sig := extractLoopSignature(toolName, toolArgs)
	if sig == "" {
		return
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

	// v2: Track checkpoint operations separately for fast-path detection
	if isCheckpointSignature(sig) {
		rld.checkpointOps = append(rld.checkpointOps, sig)
		if len(rld.checkpointOps) > rld.checkpointWindow {
			rld.checkpointOps = rld.checkpointOps[len(rld.checkpointOps)-rld.checkpointWindow:]
		}
	}
}

// RecordSystemWrite records a system-generated file write (e.g., the performer
// writing STATE.json every 5 calls or RESUME.md every 10 calls). These don't
// go through normal Record() but should be tracked for checkpoint cycle detection.
//
// This method does NOT add to the main signature window (which would pollute
// cycle detection), but DOES add to the checkpoint ops window.
func (rld *ReadLoopDetector) RecordSystemWrite(filename string) {
	sig := "system:write_" + normalizeLoopFilename(filename)

	rld.mu.Lock()
	defer rld.mu.Unlock()

	rld.checkpointOps = append(rld.checkpointOps, sig)
	if len(rld.checkpointOps) > rld.checkpointWindow {
		rld.checkpointOps = rld.checkpointOps[len(rld.checkpointOps)-rld.checkpointWindow:]
	}
}

// LoopAlert contains the details of a detected loop for chain injection.
type LoopAlert struct {
	CycleLength int      // number of distinct calls in the cycle
	RepeatCount int      // how many times the cycle repeated
	CycleFiles  []string // the files/targets in the cycle
	Message     string   // formatted message for chain injection
	TotalAlerts int      // lifetime alerts generated this subtask
	IsBlock     bool     // v2: true if this alert should BLOCK further reads
}

// Check analyzes the current window for repeating cycles.
// Returns nil if no loop is detected or if in cooldown.
func (rld *ReadLoopDetector) Check() *LoopAlert {
	rld.mu.Lock()
	defer rld.mu.Unlock()

	// v2: Fast-path checkpoint detection — fires even during cooldown
	if alert := rld.checkCheckpointLoop(); alert != nil {
		rld.callsSinceLastAlert = 0
		rld.totalAlertsGenerated++
		alert.TotalAlerts = rld.totalAlertsGenerated
		alert.IsBlock = rld.totalAlertsGenerated >= rld.maxAlertsBeforeBlock
		alert.Message = rld.formatAlertMessage(alert)
		for _, f := range alert.CycleFiles {
			rld.blockedFiles[normalizeLoopFilename(f)] = true
		}

		logrus.WithFields(logrus.Fields{
			"cycle_length": alert.CycleLength,
			"repeat_count": alert.RepeatCount,
			"cycle_files":  alert.CycleFiles,
			"total_alerts": alert.TotalAlerts,
			"is_block":     alert.IsBlock,
			"detection":    "checkpoint_fast_path",
		}).Warn("read loop detector: checkpoint cycle detected")

		return alert
	}

	// Standard cycle detection
	minRequired := rld.cycleMinLength * rld.cycleRepeatThreshold
	if len(rld.signatures) < minRequired {
		return nil
	}

	// Cooldown check (v2: much shorter cooldown of 3 calls)
	if rld.callsSinceLastAlert < rld.cooldownCalls {
		return nil
	}

	// Search for the shortest repeating cycle
	maxCycleLen := len(rld.signatures) / rld.cycleRepeatThreshold
	if maxCycleLen > 8 {
		maxCycleLen = 8 // cap search to avoid O(n²) on large windows
	}

	for cycleLen := rld.cycleMinLength; cycleLen <= maxCycleLen; cycleLen++ {
		if alert := rld.detectCycleOfLength(cycleLen); alert != nil {
			// v2: Don't skip same-cycle with extra cooldown — escalate instead
			cycleFingerprint := strings.Join(rld.signatures[len(rld.signatures)-cycleLen:], "|")

			// Only skip if SAME cycle AND we haven't escalated past warning level
			if cycleFingerprint == rld.lastAlertCycle && rld.totalAlertsGenerated < 2 {
				continue
			}

			rld.callsSinceLastAlert = 0
			rld.totalAlertsGenerated++
			rld.lastAlertCycle = cycleFingerprint
			alert.TotalAlerts = rld.totalAlertsGenerated
			alert.IsBlock = rld.totalAlertsGenerated >= rld.maxAlertsBeforeBlock
			alert.Message = rld.formatAlertMessage(alert)
			for _, f := range alert.CycleFiles {
				rld.blockedFiles[normalizeLoopFilename(f)] = true
			}

			logrus.WithFields(logrus.Fields{
				"cycle_length": alert.CycleLength,
				"repeat_count": alert.RepeatCount,
				"cycle_files":  alert.CycleFiles,
				"total_alerts": alert.TotalAlerts,
				"is_block":     alert.IsBlock,
				"window_size":  len(rld.signatures),
			}).Warn("read loop detector: cyclic pattern detected")

			return alert
		}
	}

	return nil
}

// ShouldBlock returns true if the detector has fired enough alerts that the
// performer should reject all further read-only tool calls. This provides a
// hard enforcement mechanism beyond just injecting warning messages.
func (rld *ReadLoopDetector) ShouldBlock() bool {
	rld.mu.Lock()
	defer rld.mu.Unlock()
	return rld.totalAlertsGenerated >= rld.maxAlertsBeforeBlock
}

// ShouldBlockFile returns true only if the specific file was part of a detected
// cycle. Files that were never in a cycle always pass through.
func (rld *ReadLoopDetector) ShouldBlockFile(filename string) bool {
	rld.mu.Lock()
	defer rld.mu.Unlock()
	if rld.totalAlertsGenerated < rld.maxAlertsBeforeBlock {
		return false
	}
	return rld.blockedFiles[normalizeLoopFilename(filename)]
}

// checkCheckpointLoop detects the specific pattern where the agent is stuck in
// a checkpoint-read-checkpoint loop (STATE.json → RESUME.md → read file → repeat).
//
// This is a fast-path that doesn't require full cycle detection — it simply checks
// if the last N checkpoint operations are dominated by reads of the same files.
//
// Must be called with rld.mu held.
func (rld *ReadLoopDetector) checkCheckpointLoop() *LoopAlert {
	if len(rld.checkpointOps) < 4 {
		return nil
	}

	// Count unique checkpoint files in the last checkpointWindow operations
	opCounts := make(map[string]int)
	for _, op := range rld.checkpointOps {
		opCounts[op]++
	}

	// If any single checkpoint file has been read 3+ times in the window, it's a loop
	var loopFiles []string
	maxCount := 0
	for sig, count := range opCounts {
		if count > maxCount {
			maxCount = count
		}
		if count >= 3 && strings.Contains(sig, "read_") {
			// Extract the file part
			parts := strings.SplitN(sig, ":", 2)
			if len(parts) >= 2 {
				loopFiles = append(loopFiles, strings.TrimPrefix(parts[1], "read_"))
			}
		}
	}

	if len(loopFiles) == 0 {
		return nil
	}

	// Additional check: the checkpoint ops should show a pattern, not just high counts.
	// If the agent reads state.json 3x but each time after a genuine write, that's OK.
	// We check: are there more reads than writes in the checkpoint window?
	readCount := 0
	writeCount := 0
	for _, op := range rld.checkpointOps {
		if strings.Contains(op, "read_") {
			readCount++
		} else if strings.Contains(op, "write_") {
			writeCount++
		}
	}

	// If reads outnumber writes by at least 2:1, it's a checkpoint loop
	if readCount < writeCount*2 {
		return nil
	}

	return &LoopAlert{
		CycleLength: len(loopFiles),
		RepeatCount: maxCount,
		CycleFiles:  loopFiles,
	}
}

// detectCycleOfLength checks if the last `cycleLen` signatures repeat at least
// `threshold` times. v2 adds fuzzy matching: 80%+ match counts as a repeat.
//
// Must be called with rld.mu held.
func (rld *ReadLoopDetector) detectCycleOfLength(cycleLen int) *LoopAlert {
	sigs := rld.signatures
	n := len(sigs)

	if n < cycleLen*rld.cycleRepeatThreshold {
		return nil
	}

	candidate := sigs[n-cycleLen:]

	// Walk backward and count matches (exact + fuzzy)
	repeatCount := 1
	for offset := n - 2*cycleLen; offset >= 0; offset -= cycleLen {
		end := offset + cycleLen
		if end > n {
			break
		}
		chunk := sigs[offset:end]

		if sigSliceEqual(chunk, candidate) {
			repeatCount++
		} else if sigSliceFuzzyMatch(chunk, candidate, 0.8) {
			// v2: fuzzy match — 80% of signatures match
			repeatCount++
		} else {
			break
		}
	}

	if repeatCount < rld.cycleRepeatThreshold {
		return nil
	}

	// Extract unique files/targets
	seen := make(map[string]bool)
	var files []string
	for _, sig := range candidate {
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

// formatAlertMessage generates the chain injection message with v2 escalation:
//   - Alert 1: Warning with gentle redirection
//   - Alert 2: Strong warning with explicit action items
//   - Alert 3+: CRITICAL BLOCK with only allowed actions listed
//
// Must be called with rld.mu held.
func (rld *ReadLoopDetector) formatAlertMessage(alert *LoopAlert) string {
	fileList := strings.Join(alert.CycleFiles, ", ")

	switch {
	case alert.TotalAlerts >= 3:
		return fmt.Sprintf(
			"🛑 LOOP DETECTED — HARD BLOCK (alert #%d): You've cycled through [%s] %d times "+
				"in a repeating cycle of %d operations. ALL FILE READS ARE NOW BLOCKED.\n\n"+
				"Your information gathering is COMPLETE. You have read these files multiple times "+
				"and the content has NOT changed. Further reads will be rejected.\n\n"+
				"YOUR ONLY ALLOWED ACTIONS:\n"+
				"1. Call the result/report tool to save findings\n"+
				"2. Execute an offensive action (curl, nmap, nuclei_scan, browser_navigate)\n"+
				"3. Write a report/findings using terminal heredoc or file tool\n\n"+
				"ANY file read tool call will be rejected until you take a non-read action.",
			alert.TotalAlerts, fileList, alert.RepeatCount, alert.CycleLength,
		)
	case alert.TotalAlerts == 2:
		return fmt.Sprintf(
			"🟠 LOOP DETECTED — FINAL WARNING (alert #%d): You are STILL cycling through [%s] "+
				"(%d repetitions of the same %d-step sequence).\n\n"+
				"This is your LAST WARNING before all file reads are blocked.\n\n"+
				"The data in these files has NOT changed since your first read. "+
				"You MUST now do ONE of these:\n"+
				"• Execute an offensive tool (curl, nmap, nuclei_scan)\n"+
				"• Write your findings to a report\n"+
				"• Call the result tool to complete this subtask\n\n"+
				"DO NOT read [%s] again. The next loop detection will BLOCK all reads.",
			alert.TotalAlerts, fileList, alert.RepeatCount, alert.CycleLength, fileList,
		)
	default:
		return fmt.Sprintf(
			"⚠️ LOOP DETECTED (alert #%d): You've read [%s] %d times in a repeating %d-step cycle. "+
				"You already have all the data from these files. "+
				"Advance to your next action — execute an offensive tool, write findings, or complete the subtask. "+
				"Continuing to re-read these files will trigger escalating restrictions.",
			alert.TotalAlerts, fileList, alert.RepeatCount, alert.CycleLength,
		)
	}
}

// RestoreAlertCount restores the total alerts counter from persisted state.
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

// ─── Checkpoint File Detection ──────────────────────────────────────────────

// checkpointFiles are files that the system writes periodically and the agent
// reads on resume/bootstrap. These create a strong checkpoint-read-checkpoint
// loop pattern that deserves fast-path detection.
var checkpointFiles = map[string]bool{
	"state.json": true,
	"resume.md":  true,
	"handoff.md": true,
}

// isCheckpointSignature returns true if the signature refers to a checkpoint file
// read or write operation.
func isCheckpointSignature(sig string) bool {
	sigLower := strings.ToLower(sig)
	for f := range checkpointFiles {
		if strings.Contains(sigLower, f) {
			return true
		}
	}
	return false
}

// ─── Signature Extraction (unchanged public API) ────────────────────────────

// extractLoopSignature converts a tool call into a trackable signature.
// Returns "" for operations that shouldn't participate in loop detection.
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

	if isTerminalWriteCommand(toolArgs) {
		// v2: Track writes to checkpoint files so we can detect write-read loops
		primaryCmd := extractPrimaryCommand(input)
		target := extractLoopReadTarget(primaryCmd)
		if target != "" {
			normalized := normalizeLoopFilename(target)
			if checkpointFiles[normalized] {
				return "terminal:write_" + normalized
			}
		}
		return ""
	}

	primaryCmd := extractPrimaryCommand(input)
	if isOffensiveCommand(primaryCmd) {
		return ""
	}

	if isReadCommand(primaryCmd) {
		target := extractLoopReadTarget(primaryCmd)
		if target != "" {
			return "terminal:read_" + normalizeLoopFilename(target)
		}
		return "terminal:read_unknown"
	}

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
		// v2: Track writes to checkpoint files
		normalized := normalizeLoopFilename(path)
		if checkpointFiles[normalized] {
			return "file:write_" + normalized
		}
		return ""
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
		if strings.HasPrefix(word, "-") {
			continue
		}
		if word == "2>/dev/null" || word == "||" || word == "&&" || word == ";" {
			continue
		}
		if word == "echo" || word == "true" || word == "false" {
			continue
		}
		// v2: Match both absolute paths AND relative paths with extensions
		if strings.Contains(word, "/") || strings.Contains(word, ".") {
			return word
		}
	}
	return ""
}

// normalizeLoopFilename reduces a file path to its lowercase base name.
func normalizeLoopFilename(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "unknown"
	}
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		path = path[idx+1:]
	}
	if path == "" {
		return "unknown"
	}
	return strings.ToLower(path)
}

// ─── Slice Comparison Helpers ───────────────────────────────────────────────

// sigSliceEqual compares two string slices for exact equality.
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

// sigSliceFuzzyMatch returns true if at least `threshold` fraction of elements
// in `a` match the corresponding elements in `b`.
// v2: Enables detection of cycles where the agent occasionally inserts a
// different command between the main loop steps.
func sigSliceFuzzyMatch(a, b []string, threshold float64) bool {
	if len(a) != len(b) || len(a) == 0 {
		return false
	}

	matchCount := 0
	for i := range a {
		if a[i] == b[i] {
			matchCount++
		}
	}

	return float64(matchCount)/float64(len(a)) >= threshold
}
