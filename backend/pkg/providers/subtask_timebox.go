package providers

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
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
	// Recon is the primary offender: the agent keeps discovering new endpoints,
	// subdomains, and services, never declaring "done."
	DefaultReconMaxDuration = 30 * time.Minute

	// DefaultExploitMaxDuration is the maximum time for exploitation subtasks.
	// Raised from 25 to 35 min: multi-step exploit chains (SSRF→internal→RCE)
	// and retry-after-failure patterns need the extra headroom.
	DefaultExploitMaxDuration = 35 * time.Minute

	// DefaultGenericMaxDuration is the fallback for subtasks that don't match
	// a known category (reporting, enumeration, etc.).
	// Raised from 20 to 25 min: mixed recon/exploit subtasks need more room.
	DefaultGenericMaxDuration = 25 * time.Minute

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
// description. Uses simple keyword matching — no ML, no external calls.
func ClassifySubtask(title, description string) SubtaskCategory {
	combined := strings.ToLower(title + " " + description)

	// Score each category by keyword hits. Highest score wins.
	reconScore := countKeywordHits(combined, reconKeywords)
	exploitScore := countKeywordHits(combined, exploitKeywords)
	reportScore := countKeywordHits(combined, reportKeywords)

	// Require at least one keyword hit to classify; otherwise generic.
	maxScore := max(reconScore, max(exploitScore, reportScore))
	if maxScore == 0 {
		return SubtaskCategoryGeneric
	}

	switch maxScore {
	case reconScore:
		return SubtaskCategoryRecon
	case exploitScore:
		return SubtaskCategoryExploit
	case reportScore:
		return SubtaskCategoryReport
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
		// Reports should be fast — use generic or shorter.
		return getGenericMaxDuration()
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

// BuildForceFinishResult creates a partial result string for when the timebox
// expires and the subtask must be force-finished. It includes the category,
// elapsed time, and instructions for what the partial result contains.
func (tb *SubtaskTimebox) BuildForceFinishResult(toolCallCount int, execState *ExecutionState) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("[TIMEBOX EXPIRED — %s subtask force-finished after %s]\n\n",
		tb.Category.String(), tb.Elapsed().Round(time.Second)))
	sb.WriteString(fmt.Sprintf("Category: %s\n", tb.Category.String()))
	sb.WriteString(fmt.Sprintf("Time limit: %s\n", tb.MaxDuration))
	sb.WriteString(fmt.Sprintf("Actual duration: %s\n", tb.Elapsed().Round(time.Second)))
	sb.WriteString(fmt.Sprintf("Tool calls made: %d\n\n", toolCallCount))

	if execState != nil {
		sb.WriteString(fmt.Sprintf("Phase reached: %s\n", execState.Phase))
		if len(execState.AttacksDone) > 0 {
			sb.WriteString(fmt.Sprintf("Tools/attacks executed: %s\n", strings.Join(execState.AttacksDone, ", ")))
		}
		sb.WriteString(fmt.Sprintf("Errors encountered: %d\n", execState.ErrorCount))
		if execState.ResumeContext != "" {
			sb.WriteString("\n--- Resume Context ---\n")
			sb.WriteString(execState.ResumeContext)
			sb.WriteString("\n")
		}
	}

	sb.WriteString("\n⚠ This subtask was force-finished due to time constraints. ")
	sb.WriteString("Remaining work should be addressed in subsequent subtasks or ")
	sb.WriteString("a future flow run.")

	return sb.String()
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
