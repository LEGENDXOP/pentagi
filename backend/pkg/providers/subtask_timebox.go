package providers

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vxcontrol/langchaingo/llms"
)

// ─── Subtask Time-Boxing Configuration ──────────────────────────────────────
//
// Problem: In flows 23/24, the recon subtask consumed the ENTIRE flow runtime
// (2.5hrs and 1.7hrs). 9-10 exploitation subtasks were planned but NEVER
// started because recon never finished — the agent keeps finding new things
// to explore and never declares "done."
//
// Solution: Per-subtask-type time limits that are enforced independently of
// the global budget. When a subtask approaches its type-specific deadline,
// a warning is injected. When the deadline is reached, the subtask is force-
// finished with whatever findings exist, and execution advances to the next
// subtask.
//
// This operates at the performer/orchestrator level — NOT inside individual
// agent chains.
// ─────────────────────────────────────────────────────────────────────────────

// ─── Configurable Constants ─────────────────────────────────────────────────

const (
	// DefaultReconMaxDuration is the maximum time for reconnaissance subtasks.
	// Set to 45 min: pentesters need 40-50 tool calls for thorough recon,
	// which at ~45sec/call average takes ~37 min plus LLM overhead.
	DefaultReconMaxDuration = 45 * time.Minute

	// DefaultExploitMaxDuration is the maximum time for exploitation subtasks.
	// Set to 60 min: multi-step exploit chains (primary→pentester→coder→installer)
	// generate 100+ combined tool calls across 4 agents. 35 min caused 78%
	// expiration rate in Flow 19.
	DefaultExploitMaxDuration = 60 * time.Minute

	// DefaultReportMaxDuration is the maximum time for report/documentation subtasks.
	// Fix SURGEON-C #1: Reduced from 45 min to 15 min. Report subtasks should be
	// write-only (compile findings → markdown → result tool). The 45 min budget
	// enabled death spiral loops (write→read→verify→rewrite) consuming 94 min in
	// Flow 53. With the pre-generated report from ReportGenerator, 15 min is ample.
	DefaultReportMaxDuration = 15 * time.Minute

	// DefaultGenericMaxDuration is the fallback for subtasks that don't match
	// a known category.
	DefaultGenericMaxDuration = 35 * time.Minute

	// TimeboxWarningBuffer is how many minutes before the deadline the
	// "TIME WARNING: N minutes remaining" message is injected.
	TimeboxWarningBuffer = 5 * time.Minute

	// TimeboxCriticalBuffer is the threshold for the critical (final) warning.
	TimeboxCriticalBuffer = 2 * time.Minute
)

// SubtaskCategory classifies subtasks into broad categories for time budgeting.
type SubtaskCategory int

const (
	SubtaskCategoryRecon       SubtaskCategory = iota // reconnaissance, scanning, discovery
	SubtaskCategoryExploit                            // exploitation, attack, testing
	SubtaskCategoryReport                             // reporting, documentation
	SubtaskCategoryGeneric                            // everything else
)

func (c SubtaskCategory) String() string {
	switch c {
	case SubtaskCategoryRecon:
		return "recon"
	case SubtaskCategoryExploit:
		return "exploit"
	case SubtaskCategoryReport:
		return "report"
	default:
		return "generic"
	}
}

// ─── Environment variable overrides ─────────────────────────────────────────

// getReconMaxDuration returns the recon subtask timeout, configurable via
// SUBTASK_RECON_MAX_DURATION env var (value in minutes).
func getReconMaxDuration() time.Duration {
	if v := os.Getenv("SUBTASK_RECON_MAX_DURATION"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Minute
		}
	}
	return DefaultReconMaxDuration
}

// getExploitMaxDuration returns the exploit subtask timeout, configurable via
// SUBTASK_EXPLOIT_MAX_DURATION env var (value in minutes).
func getExploitMaxDuration() time.Duration {
	if v := os.Getenv("SUBTASK_EXPLOIT_MAX_DURATION"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Minute
		}
	}
	return DefaultExploitMaxDuration
}

// getReportMaxDuration returns the report subtask timeout, configurable via
// SUBTASK_REPORT_MAX_DURATION env var (value in minutes).
func getReportMaxDuration() time.Duration {
	if v := os.Getenv("SUBTASK_REPORT_MAX_DURATION"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Minute
		}
	}
	return DefaultReportMaxDuration
}

// getGenericMaxDuration returns the generic subtask timeout, configurable via
// SUBTASK_GENERIC_MAX_DURATION env var (value in minutes).
func getGenericMaxDuration() time.Duration {
	if v := os.Getenv("SUBTASK_GENERIC_MAX_DURATION"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Minute
		}
	}
	return DefaultGenericMaxDuration
}

// ─── Subtask Classification ─────────────────────────────────────────────────

// reconKeywords triggers classification as reconnaissance.
var reconKeywords = []string{
	"recon", "reconnaissance", "discovery", "enumeration", "scan",
	"fingerprint", "footprint", "information gathering", "port scan",
	"service detection", "subdomain", "dns enum", "network mapping",
	"host discovery", "identify", "detect services", "probe",
}

// exploitKeywords triggers classification as exploitation.
var exploitKeywords = []string{
	"exploit", "exploitation", "attack", "penetrat", "injection",
	"xss", "sqli", "rce", "command injection", "privilege escalation",
	"payload", "reverse shell", "brute force", "credential",
	"vulnerability testing", "proof of concept", "poc", "bypass",
	"authentication bypass", "ssrf", "csrf", "lfi", "rfi",
}

// reportKeywords triggers classification as reporting.
var reportKeywords = []string{
	"report", "document", "summary", "findings", "remediation",
	"final report", "compile", "consolidate",
}

// ClassifySubtask determines the category of a subtask from its title and
// description. Title keywords carry 3x weight because the title is the
// primary intent signal — descriptions often contain cross-category terms
// (e.g., a report subtask's description mentioning "penetration test").
func ClassifySubtask(title, description string) SubtaskCategory {
	titleLower := strings.ToLower(title)
	descLower := strings.ToLower(description)

	// Title keywords carry 3x weight — title is the primary intent signal.
	// Description adds supplementary context but shouldn't overwhelm title.
	reconScore := countKeywordHits(titleLower, reconKeywords)*3 + countKeywordHits(descLower, reconKeywords)
	exploitScore := countKeywordHits(titleLower, exploitKeywords)*3 + countKeywordHits(descLower, exploitKeywords)
	reportScore := countKeywordHits(titleLower, reportKeywords)*3 + countKeywordHits(descLower, reportKeywords)

	// Require at least one keyword hit to classify; otherwise generic.
	maxScore := max(reconScore, max(exploitScore, reportScore))
	if maxScore == 0 {
		return SubtaskCategoryGeneric
	}

	// Priority: report > exploit > recon (report is most specific/actionable)
	switch maxScore {
	case reportScore:
		return SubtaskCategoryReport
	case exploitScore:
		return SubtaskCategoryExploit
	case reconScore:
		return SubtaskCategoryRecon
	default:
		return SubtaskCategoryGeneric
	}
}

func countKeywordHits(text string, keywords []string) int {
	count := 0
	for _, kw := range keywords {
		if strings.Contains(text, kw) {
			count++
		}
	}
	return count
}

// GetMaxDurationForCategory returns the time limit for a given subtask category.
func GetMaxDurationForCategory(cat SubtaskCategory) time.Duration {
	switch cat {
	case SubtaskCategoryRecon:
		return getReconMaxDuration()
	case SubtaskCategoryExploit:
		return getExploitMaxDuration()
	case SubtaskCategoryReport:
		return getReportMaxDuration()
	default:
		return getGenericMaxDuration()
	}
}

// ─── Timebox State Tracker ──────────────────────────────────────────────────

// SubtaskTimebox tracks time-boxing state for a single subtask execution.
// It is created at the start of performAgentChain and consulted each loop
// iteration to determine if warnings or forced completion should occur.
type SubtaskTimebox struct {
	Category    SubtaskCategory
	MaxDuration time.Duration
	StartTime   time.Time

	warningInjected  bool // 5-min warning injected
	criticalInjected bool // 2-min warning injected
}

// NewSubtaskTimebox creates a timebox tracker for a subtask. If title/description
// are empty, falls back to the existing getSubtaskMaxDuration() behavior.
func NewSubtaskTimebox(title, description string) *SubtaskTimebox {
	cat := ClassifySubtask(title, description)
	maxDur := GetMaxDurationForCategory(cat)

	return &SubtaskTimebox{
		Category:    cat,
		MaxDuration: maxDur,
		StartTime:   time.Now(),
	}
}

// Elapsed returns how long this subtask has been running.
func (tb *SubtaskTimebox) Elapsed() time.Duration {
	return time.Since(tb.StartTime)
}

// Remaining returns time left before the deadline. Returns 0 if expired.
func (tb *SubtaskTimebox) Remaining() time.Duration {
	r := tb.MaxDuration - tb.Elapsed()
	if r < 0 {
		return 0
	}
	return r
}

// IsExpired returns true if the subtask has exceeded its time limit.
func (tb *SubtaskTimebox) IsExpired() bool {
	return tb.Elapsed() >= tb.MaxDuration
}

// CheckWarning returns a warning message to inject into the chain, if any.
// Returns empty string if no warning is needed. Warnings are one-shot —
// once injected, they won't fire again.
func (tb *SubtaskTimebox) CheckWarning() string {
	remaining := tb.Remaining()

	// Critical warning: 2 minutes remaining
	if !tb.criticalInjected && remaining > 0 && remaining <= TimeboxCriticalBuffer {
		tb.criticalInjected = true
		tb.warningInjected = true // skip normal warning if critical fires first
		return fmt.Sprintf(
			"[TIMEBOX CRITICAL — %s SUBTASK: %d SECONDS REMAINING]\n"+
				"⛔ Your time for this subtask is ALMOST UP.\n"+
				"IMMEDIATELY call the result/report tool to save ALL findings.\n"+
				"Do NOT start any new scans, exploits, or delegations.\n"+
				"If you don't save now, your work will be auto-saved with whatever exists.",
			strings.ToUpper(tb.Category.String()),
			int(remaining.Seconds()),
		)
	}

	// Normal warning: 5 minutes remaining
	if !tb.warningInjected && remaining > 0 && remaining <= TimeboxWarningBuffer {
		tb.warningInjected = true
		return fmt.Sprintf(
			"[TIMEBOX WARNING — %s SUBTASK: %d MINUTES REMAINING]\n"+
				"⚠ You have approximately %d minutes left for this subtask.\n"+
				"Begin wrapping up:\n"+
				"1. Save your current findings using the result/report tool\n"+
				"2. Do NOT start new long-running scans\n"+
				"3. Summarize what you've found and what remains to be done\n"+
				"The system will auto-advance to the next subtask when time expires.",
			strings.ToUpper(tb.Category.String()),
			int(remaining.Minutes()),
			int(remaining.Minutes()),
		)
	}

	return ""
}

// ForceFinishContext bundles all data sources available at the time of a
// force-finish, so BuildForceFinishResult can compose a comprehensive result
// that preserves tool outputs even when the agent didn't call hack_result.
type ForceFinishContext struct {
	ToolCallCount    int
	ExecState        *ExecutionState
	Chain            []llms.MessageContent  // full message chain with tool results
	ToolHistory      *ToolHistory           // recent tool call history
	FindingRegistry  *FindingRegistry       // registered findings (if any)
	CompletedWork    *CompletedWorkTracker  // completed work items
}

// BuildForceFinishResult creates a comprehensive result string for when the
// timebox expires and the subtask must be force-finished. It extracts all
// available findings, scan results, file paths, and tool outputs from the
// execution context so that data survives even if the agent never called
// hack_result.
func (tb *SubtaskTimebox) BuildForceFinishResult(toolCallCount int, execState *ExecutionState) string {
	// Backward-compatible: delegate to the enhanced version with nil context.
	return tb.BuildForceFinishResultFull(&ForceFinishContext{
		ToolCallCount: toolCallCount,
		ExecState:     execState,
	})
}

// BuildForceFinishResultFull creates a comprehensive result from all available
// data sources. This is the enhanced version that preserves tool outputs.
func (tb *SubtaskTimebox) BuildForceFinishResultFull(ffc *ForceFinishContext) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("[TIMEBOX EXPIRED — %s subtask force-finished after %s]\n\n",
		tb.Category.String(), tb.Elapsed().Round(time.Second)))
	sb.WriteString(fmt.Sprintf("Category: %s\n", tb.Category.String()))
	sb.WriteString(fmt.Sprintf("Time limit: %s\n", tb.MaxDuration))
	sb.WriteString(fmt.Sprintf("Actual duration: %s\n", tb.Elapsed().Round(time.Second)))
	sb.WriteString(fmt.Sprintf("Tool calls made: %d\n\n", ffc.ToolCallCount))

	execState := ffc.ExecState
	if execState != nil {
		sb.WriteString(fmt.Sprintf("Phase reached: %s\n", execState.Phase))
		if len(execState.AttacksDone) > 0 {
			sb.WriteString(fmt.Sprintf("Tools/attacks executed: %s\n", strings.Join(execState.AttacksDone, ", ")))
		}
		sb.WriteString(fmt.Sprintf("Errors encountered: %d\n", execState.ErrorCount))
	}

	// --- Registered findings (from FindingRegistry) ---
	if ffc.FindingRegistry != nil && ffc.FindingRegistry.GetFindingCount() > 0 {
		findings := ffc.FindingRegistry.GetFindings()
		sb.WriteString(fmt.Sprintf("\n## Registered Findings (%d)\n\n", len(findings)))
		for i, f := range findings {
			sb.WriteString(fmt.Sprintf("### Finding %d: %s\n", i+1, f.VulnType))
			if f.Severity != "" {
				sb.WriteString(fmt.Sprintf("Severity: %s\n", f.Severity))
			}
			if f.Endpoint != "" {
				sb.WriteString(fmt.Sprintf("Endpoint: %s\n", f.Endpoint))
			}
			if f.Description != "" {
				desc := f.Description
				if len(desc) > 500 {
					desc = desc[:500] + "..."
				}
				sb.WriteString(fmt.Sprintf("Details: %s\n", desc))
			}
			sb.WriteString("\n")
		}
	}

	// --- Completed work items ---
	if ffc.CompletedWork != nil {
		summary := ffc.CompletedWork.FormatCompletedSummary()
		if summary != "" {
			sb.WriteString("\n## Completed Work\n\n")
			sb.WriteString(summary)
			sb.WriteString("\n")
		}
	}

	// --- Extract findings and scan results from tool history ---
	if ffc.ToolHistory != nil && ffc.ToolHistory.Len() > 0 {
		entries := ffc.ToolHistory.GetLast(ffc.ToolHistory.Len())
		var scanResults []string
		var filePaths []string
		seenPaths := make(map[string]bool)

		for _, entry := range entries {
			if entry.IsError {
				continue
			}
			// Extract scan/finding results from tool outputs
			if isSignificantToolResult(entry.Name, entry.Result) {
				snippet := entry.Result
				if len(snippet) > 300 {
					snippet = snippet[:300] + "..."
				}
				scanResults = append(scanResults, fmt.Sprintf("[%s] %s", entry.Name, snippet))
			}
			// Extract file paths written to /work/
			for _, path := range extractWorkPaths(entry.Result) {
				if !seenPaths[path] {
					seenPaths[path] = true
					filePaths = append(filePaths, path)
				}
			}
			for _, path := range extractWorkPaths(entry.Arguments) {
				if !seenPaths[path] {
					seenPaths[path] = true
					filePaths = append(filePaths, path)
				}
			}
		}

		if len(filePaths) > 0 {
			sb.WriteString("\n## Files Created/Modified\n\n")
			for _, p := range filePaths {
				sb.WriteString(fmt.Sprintf("- %s\n", p))
			}
		}

		if len(scanResults) > 0 {
			// Limit to most recent 15 significant results to avoid bloat
			if len(scanResults) > 15 {
				scanResults = scanResults[len(scanResults)-15:]
			}
			sb.WriteString("\n## Significant Tool Outputs (auto-collected)\n\n")
			for _, r := range scanResults {
				sb.WriteString(r)
				sb.WriteString("\n\n")
			}
		}
	}

	// --- Extract findings from message chain tool results ---
	if len(ffc.Chain) > 0 {
		chainFindings := extractFindingsFromChain(ffc.Chain)
		if len(chainFindings) > 0 {
			sb.WriteString("\n## Key Findings from Tool Results\n\n")
			for _, f := range chainFindings {
				sb.WriteString(fmt.Sprintf("- **%s**: %s\n", f.toolName, f.summary))
			}
			sb.WriteString("\n")
		}
	}

	// --- Resume context from execution state ---
	if execState != nil && execState.ResumeContext != "" {
		sb.WriteString("\n--- Resume Context ---\n")
		sb.WriteString(execState.ResumeContext)
		sb.WriteString("\n")
	}

	sb.WriteString("\n⚠ This subtask was force-finished due to time constraints. ")
	sb.WriteString("Remaining work should be addressed in subsequent subtasks or ")
	sb.WriteString("a future flow run.")

	return sb.String()
}

// chainFinding represents a finding extracted from the message chain.
type chainFinding struct {
	toolName string
	summary  string
}

// extractFindingsFromChain scans tool result messages in the chain for
// vulnerability indicators, scan findings, and significant discoveries.
// Returns at most 20 findings.
func extractFindingsFromChain(chain []llms.MessageContent) []chainFinding {
	var findings []chainFinding
	const maxFindings = 20

	// Patterns that indicate a finding in tool output
	findingPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)\[VULN(?:ERABILITY)?[_:]\s*([^\]]+)\]`),
		regexp.MustCompile(`(?i)\[FINDING\]\s*(.+)`),
		regexp.MustCompile(`(?i)(critical|high|medium)\s+severity`),
		regexp.MustCompile(`(?i)CVE-\d{4}-\d+`),
		regexp.MustCompile(`(?i)(?:sql injection|xss|ssrf|idor|rce|lfi|rfi|xxe|csrf)\s+(?:found|detected|confirmed|discovered)`),
		regexp.MustCompile(`(?i)\[\+\]\s+(.+)`), // nuclei-style positive findings
	}

	for _, msg := range chain {
		if msg.Role != llms.ChatMessageTypeTool {
			continue
		}
		for _, part := range msg.Parts {
			resp, ok := part.(llms.ToolCallResponse)
			if !ok || resp.Content == "" {
				continue
			}

			for _, pattern := range findingPatterns {
				matches := pattern.FindAllString(resp.Content, 5)
				for _, match := range matches {
					if len(findings) >= maxFindings {
						return findings
					}
					findings = append(findings, chainFinding{
						toolName: resp.Name,
						summary:  truncStr(match, 200),
					})
				}
			}
		}
	}

	return findings
}

// isSignificantToolResult returns true if a tool result likely contains
// scan findings, vulnerabilities, or other meaningful output worth preserving.
func isSignificantToolResult(toolName, result string) bool {
	if result == "" || len(result) < 20 {
		return false
	}

	// Always capture results from offensive tools
	offensiveTools := map[string]bool{
		"nuclei_scan": true, "browser_navigate": true,
	}
	if offensiveTools[toolName] {
		return true
	}

	// Check for vulnerability/finding indicators in the result
	lower := strings.ToLower(result)
	indicators := []string{
		"vuln", "finding", "critical", "high", "medium",
		"cve-", "injection", "xss", "ssrf", "idor",
		"open port", "exposed", "leaked", "token",
		"[+]", "severity", "exploit",
		"200 ok", "401", "403", "500",
	}
	for _, ind := range indicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}

	return false
}

// workPathRegex matches file paths under /work/.
var workPathRegex = regexp.MustCompile(`/work/[\w./-]+`)

// extractWorkPaths extracts unique file paths under /work/ from text.
func extractWorkPaths(text string) []string {
	matches := workPathRegex.FindAllString(text, 30)
	var paths []string
	for _, m := range matches {
		// Filter out obviously non-file matches
		if len(m) > 6 && !strings.HasSuffix(m, "/") {
			paths = append(paths, m)
		}
	}
	return paths
}

// truncStr truncates a string to maxLen characters.
func truncStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// ─── Context Key for Subtask Metadata ───────────────────────────────────────

// subtaskMetaKey is a context key for passing subtask title/description into
// performAgentChain without changing its signature.
type subtaskMetaKey struct{}

// SubtaskMeta carries subtask title and description through context.
type SubtaskMeta struct {
	Title       string
	Description string
}

// WithSubtaskMeta attaches subtask metadata to a context.
func WithSubtaskMeta(ctx context.Context, title, description string) context.Context {
	return context.WithValue(ctx, subtaskMetaKey{}, &SubtaskMeta{
		Title:       title,
		Description: description,
	})
}

// GetSubtaskMeta retrieves subtask metadata from context. Returns nil if not set.
func GetSubtaskMeta(ctx context.Context) *SubtaskMeta {
	if m, ok := ctx.Value(subtaskMetaKey{}).(*SubtaskMeta); ok {
		return m
	}
	return nil
}

// ─── Integration Helper ─────────────────────────────────────────────────────

// ShouldUseTimebox returns true if per-subtask-type time-boxing should be
// enabled. Controlled by SUBTASK_TIMEBOX_ENABLED env var (default: true).
// This allows operators to disable the feature without code changes.
func ShouldUseTimebox() bool {
	v := os.Getenv("SUBTASK_TIMEBOX_ENABLED")
	if v == "" {
		return true // enabled by default
	}
	v = strings.ToLower(v)
	return v == "1" || v == "true" || v == "yes"
}

// LogTimeboxCreation logs the timebox creation for observability.
func LogTimeboxCreation(logger *logrus.Entry, tb *SubtaskTimebox, subtaskID *int64) {
	fields := logrus.Fields{
		"timebox_category":     tb.Category.String(),
		"timebox_max_duration": tb.MaxDuration.String(),
	}
	if subtaskID != nil {
		fields["subtask_id"] = *subtaskID
	}
	logger.WithFields(fields).Info("subtask timebox created")
}
