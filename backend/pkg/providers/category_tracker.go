package providers

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// CategoryTracker monitors which attack categories have been tested during a
// pentesting engagement and enforces time allocation across P0/P1/P2 categories.
// It is instantiated per-subtask inside performAgentChain and is goroutine-safe.
//
// Key responsibilities:
//   - Classify tool calls into attack categories based on tool name + arguments
//   - Track cumulative time spent per category
//   - Alert when P0 (critical) categories haven't been tested at the 50% mark
//   - Provide advisory warnings when agent works on low-priority categories
//     while high-priority ones remain untested
//
// This is advisory-only in v1 — warnings never block tool execution.
type CategoryTracker struct {
	startTime          time.Time
	totalBudgetMinutes int

	// categoryTime tracks cumulative time spent per attack category.
	categoryTime map[string]time.Duration

	// categoryLastStart records when the agent started working on the current
	// category. Zero value means the category is not currently active.
	categoryLastStart map[string]time.Time

	// activeCategory is the currently active attack category.
	activeCategory string

	// categoryHasFindings tracks categories where actual vulnerabilities were found.
	categoryHasFindings map[string]bool

	// halfwayAlertSent prevents duplicate halfway alerts.
	halfwayAlertSent bool

	// p0AlertSent prevents duplicate P0 alerts.
	p0AlertSent bool

	mu sync.Mutex
}

// CoverageAlert holds information about missing P0 coverage, suitable
// for injection as an advisory message into the agent chain.
type CoverageAlert struct {
	// MissingP0 lists P0 categories that have NOT been tested yet.
	MissingP0 []string
	// TestedP0 lists P0 categories that HAVE been tested.
	TestedP0 []string
	// ElapsedPercent is the percentage of total budget elapsed (0-100).
	ElapsedPercent int
	// FormattedMsg is the full advisory message for prompt injection.
	FormattedMsg string
}

// P0 categories are the highest-priority attack categories that MUST be tested
// in every engagement. If these haven't been touched by the 50% time mark,
// the tracker generates an advisory alert.
var p0Categories = []string{
	"auth_acquisition",
	"idor",
	"ssrf",
	"sqli",
	"payment_logic",
}

// P1 categories are important but secondary to P0.
var p1Categories = []string{
	"business_logic",
	"race_conditions",
	"ato_chains",
	"api_attacks",
	"data_harvest",
}

// categoryClassificationRules maps tool names and argument patterns to attack
// categories. The first matching rule wins (order matters for specificity).
type classificationRule struct {
	// ToolName matches the tool name exactly (empty string matches any tool).
	ToolName string
	// ArgKeywords are substrings to match in tool arguments (case-insensitive).
	// If multiple keywords, ALL must match.
	ArgKeywords []string
	// Category is the attack category to classify as.
	Category string
}

// classificationRules defines tool call → category mappings. More specific rules
// come first. These use tool names from the registry (registry.go constants).
var classificationRules = []classificationRule{
	// SQLi detection
	{ToolName: "nuclei_scan", ArgKeywords: []string{"sqli"}, Category: "sqli"},
	{ToolName: "terminal", ArgKeywords: []string{"sqlmap"}, Category: "sqli"},
	{ToolName: "terminal", ArgKeywords: []string{"nosql"}, Category: "sqli"},
	{ToolName: "terminal", ArgKeywords: []string{"ghauri"}, Category: "sqli"},

	// Auth / credential testing
	{ToolName: "terminal", ArgKeywords: []string{"hydra"}, Category: "auth_acquisition"},
	{ToolName: "terminal", ArgKeywords: []string{"jwt_tool"}, Category: "auth_acquisition"},
	{ToolName: "terminal", ArgKeywords: []string{"jwt"}, Category: "auth_acquisition"},
	{ToolName: "nuclei_scan", ArgKeywords: []string{"auth"}, Category: "auth_acquisition"},
	{ToolName: "nuclei_scan", ArgKeywords: []string{"login"}, Category: "auth_acquisition"},
	{ToolName: "terminal", ArgKeywords: []string{"brute"}, Category: "auth_acquisition"},
	{ToolName: "terminal", ArgKeywords: []string{"cred"}, Category: "auth_acquisition"},
	{ToolName: "terminal", ArgKeywords: []string{"password"}, Category: "auth_acquisition"},

	// SSRF testing
	{ToolName: "terminal", ArgKeywords: []string{"ssrfmap"}, Category: "ssrf"},
	{ToolName: "terminal", ArgKeywords: []string{"gopherus"}, Category: "ssrf"},
	{ToolName: "terminal", ArgKeywords: []string{"169.254"}, Category: "ssrf"},
	{ToolName: "terminal", ArgKeywords: []string{"metadata"}, Category: "ssrf"},
	{ToolName: "nuclei_scan", ArgKeywords: []string{"ssrf"}, Category: "ssrf"},
	{ToolName: "interactsh_url", ArgKeywords: nil, Category: "ssrf"},
	{ToolName: "interactsh_poll", ArgKeywords: nil, Category: "ssrf"},

	// IDOR testing
	{ToolName: "nuclei_scan", ArgKeywords: []string{"idor"}, Category: "idor"},
	{ToolName: "terminal", ArgKeywords: []string{"idor"}, Category: "idor"},

	// XSS testing
	{ToolName: "nuclei_scan", ArgKeywords: []string{"xss"}, Category: "xss"},
	{ToolName: "terminal", ArgKeywords: []string{"dalfox"}, Category: "xss"},
	{ToolName: "terminal", ArgKeywords: []string{"xsstrike"}, Category: "xss"},

	// Data harvest
	{ToolName: "terminal", ArgKeywords: []string{"git-dumper"}, Category: "data_harvest"},
	{ToolName: "terminal", ArgKeywords: []string{"trufflehog"}, Category: "data_harvest"},
	{ToolName: "terminal", ArgKeywords: []string{"gitleaks"}, Category: "data_harvest"},
	{ToolName: "terminal", ArgKeywords: []string{".git"}, Category: "data_harvest"},
	{ToolName: "terminal", ArgKeywords: []string{".env"}, Category: "data_harvest"},
	{ToolName: "terminal", ArgKeywords: []string{"swagger"}, Category: "data_harvest"},
	{ToolName: "nuclei_scan", ArgKeywords: []string{"exposure"}, Category: "data_harvest"},
	{ToolName: "nuclei_scan", ArgKeywords: []string{"token"}, Category: "data_harvest"},

	// Race conditions
	{ToolName: "race_condition_test", ArgKeywords: nil, Category: "race_conditions"},
	{ToolName: "terminal", ArgKeywords: []string{"race"}, Category: "race_conditions"},

	// Business logic
	{ToolName: "terminal", ArgKeywords: []string{"coupon"}, Category: "business_logic"},
	{ToolName: "terminal", ArgKeywords: []string{"price"}, Category: "payment_logic"},
	{ToolName: "terminal", ArgKeywords: []string{"payment"}, Category: "payment_logic"},
	{ToolName: "terminal", ArgKeywords: []string{"refund"}, Category: "payment_logic"},
	{ToolName: "terminal", ArgKeywords: []string{"withdraw"}, Category: "payment_logic"},

	// API attacks
	{ToolName: "terminal", ArgKeywords: []string{"graphql"}, Category: "api_attacks"},
	{ToolName: "nuclei_scan", ArgKeywords: []string{"api"}, Category: "api_attacks"},

	// ATO chains
	{ToolName: "terminal", ArgKeywords: []string{"oauth"}, Category: "ato_chains"},
	{ToolName: "terminal", ArgKeywords: []string{"reset"}, Category: "ato_chains"},

	// RCE vectors
	{ToolName: "terminal", ArgKeywords: []string{"reverse shell"}, Category: "rce"},
	{ToolName: "terminal", ArgKeywords: []string{"web shell"}, Category: "rce"},
	{ToolName: "nuclei_scan", ArgKeywords: []string{"rce"}, Category: "rce"},
	{ToolName: "nuclei_scan", ArgKeywords: []string{"cve"}, Category: "rce"},

	// File upload
	{ToolName: "terminal", ArgKeywords: []string{"upload"}, Category: "file_upload"},

	// Recon (not an attack category but useful for tracking)
	{ToolName: "nuclei_scan", ArgKeywords: nil, Category: "recon"},
	{ToolName: "terminal", ArgKeywords: []string{"nmap"}, Category: "recon"},
	{ToolName: "terminal", ArgKeywords: []string{"subfinder"}, Category: "recon"},
	{ToolName: "terminal", ArgKeywords: []string{"httpx"}, Category: "recon"},
	{ToolName: "terminal", ArgKeywords: []string{"katana"}, Category: "recon"},
	{ToolName: "terminal", ArgKeywords: []string{"dirsearch"}, Category: "recon"},
	{ToolName: "terminal", ArgKeywords: []string{"ffuf"}, Category: "recon"},
	{ToolName: "terminal", ArgKeywords: []string{"gobuster"}, Category: "recon"},
}

// defaultCategory is used when no classification rule matches.
const defaultCategory = "general_testing"

// NewCategoryTracker creates a new CategoryTracker for a subtask with the
// given total time budget in minutes.
func NewCategoryTracker(totalBudgetMinutes int) *CategoryTracker {
	return &CategoryTracker{
		startTime:           time.Now(),
		totalBudgetMinutes:  totalBudgetMinutes,
		categoryTime:        make(map[string]time.Duration),
		categoryLastStart:   make(map[string]time.Time),
		categoryHasFindings: make(map[string]bool),
	}
}

// RecordToolCall classifies a tool call and records time spent on the detected
// attack category. If the category changes from the previous tool call, the
// previous category's timer is stopped and the new one is started.
func (ct *CategoryTracker) RecordToolCall(toolName string, args string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	category := ct.classifyToolCall(toolName, args)

	now := time.Now()

	// If switching categories, accumulate time for the old category.
	if ct.activeCategory != "" && ct.activeCategory != category {
		if start, ok := ct.categoryLastStart[ct.activeCategory]; ok && !start.IsZero() {
			ct.categoryTime[ct.activeCategory] += now.Sub(start)
		}
	}

	// Start timing the new category.
	ct.activeCategory = category
	ct.categoryLastStart[category] = now
}

// RecordFindingInCategory marks a category as having produced actual findings.
// This is used in combination with FindingTracker — when a VULN_TYPE is detected,
// the corresponding category should be marked.
func (ct *CategoryTracker) RecordFindingInCategory(category string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.categoryHasFindings[category] = true
}

// CheckP0Coverage checks whether P0 categories have been tested, considering
// elapsed time vs total budget. Returns a CoverageAlert if P0 gaps are detected
// at or past the 50% mark. Returns nil if no alert is needed.
//
// This check is idempotent after the first alert — it will return nil on
// subsequent calls once the halfway alert has been sent.
func (ct *CategoryTracker) CheckP0Coverage(elapsed time.Duration, total time.Duration) *CoverageAlert {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if ct.halfwayAlertSent {
		return nil
	}

	if total <= 0 {
		return nil
	}

	elapsedPercent := int(elapsed.Minutes() / total.Minutes() * 100)
	if elapsedPercent < 50 {
		return nil
	}

	// Calculate P0 coverage.
	var missing, tested []string
	for _, p0 := range p0Categories {
		if ct.categoryTime[p0] > 0 || ct.categoryHasFindings[p0] {
			tested = append(tested, p0)
		} else {
			missing = append(missing, p0)
		}
	}

	// If all P0 categories have been touched, no alert needed.
	if len(missing) == 0 {
		ct.halfwayAlertSent = true // don't alert again
		return nil
	}

	ct.halfwayAlertSent = true

	// Build alert message.
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[SYSTEM-AUTO: P0 COVERAGE ALERT — %d%% time used]\n\n", elapsedPercent))
	sb.WriteString("The following P0 (critical) attack categories have NOT been tested yet:\n")
	for _, m := range missing {
		sb.WriteString(fmt.Sprintf("  ❌ %s\n", m))
	}
	if len(tested) > 0 {
		sb.WriteString("\nAlready tested P0 categories:\n")
		for _, t := range tested {
			sb.WriteString(fmt.Sprintf("  ✅ %s\n", t))
		}
	}
	sb.WriteString("\n⚠️ PRIORITIZE the missing P0 categories immediately. ")
	sb.WriteString("These have the highest payout potential and must be tested before time runs out.")

	return &CoverageAlert{
		MissingP0:      missing,
		TestedP0:       tested,
		ElapsedPercent: elapsedPercent,
		FormattedMsg:   sb.String(),
	}
}

// ShouldWarnP1 checks if the agent is currently working on a P1/P2 category
// while P0 categories remain untested. Returns a warning message if so.
// Returns empty strings if no warning is needed.
//
// This is advisory-only and rate-limited: it only fires once per subtask.
func (ct *CategoryTracker) ShouldWarnP1(toolName string, args string) (warn bool, message string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if ct.p0AlertSent {
		return false, ""
	}

	category := ct.classifyToolCall(toolName, args)

	// Only warn if the current category is NOT a P0 category.
	if ct.isP0(category) {
		return false, ""
	}

	// Check if any P0 categories are still untested.
	var untestedP0 []string
	for _, p0 := range p0Categories {
		if ct.categoryTime[p0] == 0 && !ct.categoryHasFindings[p0] {
			untestedP0 = append(untestedP0, p0)
		}
	}

	if len(untestedP0) == 0 {
		return false, ""
	}

	ct.p0AlertSent = true

	msg := fmt.Sprintf(
		"[SYSTEM-AUTO: PRIORITY WARNING] You are testing category '%s' (P1/P2) but P0 categories %s have not been tested. Consider switching to P0 categories first.",
		category, strings.Join(untestedP0, ", "),
	)
	return true, msg
}

// GetTimeReport returns a formatted summary of time spent per attack category,
// suitable for inclusion in execution metrics or system prompt.
func (ct *CategoryTracker) GetTimeReport() string {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	// Finalize active category's time for accurate reporting.
	snapshot := ct.snapshotTimes()

	if len(snapshot) == 0 {
		return "No attack categories tested yet."
	}

	var sb strings.Builder
	sb.WriteString("Attack category time allocation:\n")

	// Report P0 categories first.
	sb.WriteString("  P0 (Critical):\n")
	for _, cat := range p0Categories {
		d := snapshot[cat]
		status := "NOT STARTED"
		if d > 0 {
			status = formatDuration(d)
		}
		finding := ""
		if ct.categoryHasFindings[cat] {
			finding = " [FINDINGS]"
		}
		sb.WriteString(fmt.Sprintf("    %s: %s%s\n", cat, status, finding))
	}

	// Report P1 categories.
	sb.WriteString("  P1 (Important):\n")
	for _, cat := range p1Categories {
		d := snapshot[cat]
		if d > 0 {
			finding := ""
			if ct.categoryHasFindings[cat] {
				finding = " [FINDINGS]"
			}
			sb.WriteString(fmt.Sprintf("    %s: %s%s\n", cat, formatDuration(d), finding))
		}
	}

	// Report other categories that had time.
	sb.WriteString("  Other:\n")
	for cat, d := range snapshot {
		if d <= 0 || ct.isP0(cat) || ct.isP1(cat) {
			continue
		}
		finding := ""
		if ct.categoryHasFindings[cat] {
			finding = " [FINDINGS]"
		}
		sb.WriteString(fmt.Sprintf("    %s: %s%s\n", cat, formatDuration(d), finding))
	}

	return sb.String()
}

// GetP0Status returns which P0 categories have been covered and which are missing.
func (ct *CategoryTracker) GetP0Status() (covered []string, missing []string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	for _, p0 := range p0Categories {
		if ct.categoryTime[p0] > 0 || ct.categoryHasFindings[p0] {
			covered = append(covered, p0)
		} else {
			missing = append(missing, p0)
		}
	}
	return covered, missing
}

// GetActiveCategory returns the currently active attack category.
func (ct *CategoryTracker) GetActiveCategory() string {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	return ct.activeCategory
}

// ─── Internal helpers ────────────────────────────────────────────────────────

// classifyToolCall determines the attack category for a tool call based on
// the tool name and arguments. Must be called with ct.mu held.
func (ct *CategoryTracker) classifyToolCall(toolName string, args string) string {
	lowerArgs := strings.ToLower(args)
	lowerTool := strings.ToLower(toolName)

	for _, rule := range classificationRules {
		// Match tool name (empty = any tool).
		if rule.ToolName != "" && lowerTool != strings.ToLower(rule.ToolName) {
			continue
		}

		// Match all argument keywords (nil keywords = match on tool name alone).
		if rule.ArgKeywords == nil {
			return rule.Category
		}
		allMatch := true
		for _, kw := range rule.ArgKeywords {
			if !strings.Contains(lowerArgs, strings.ToLower(kw)) {
				allMatch = false
				break
			}
		}
		if allMatch {
			return rule.Category
		}
	}

	return defaultCategory
}

// isP0 checks if a category is in the P0 list.
func (ct *CategoryTracker) isP0(category string) bool {
	for _, p0 := range p0Categories {
		if p0 == category {
			return true
		}
	}
	return false
}

// isP1 checks if a category is in the P1 list.
func (ct *CategoryTracker) isP1(category string) bool {
	for _, p1 := range p1Categories {
		if p1 == category {
			return true
		}
	}
	return false
}

// snapshotTimes returns a copy of category times with the active category's
// in-progress time included. Must be called with ct.mu held.
func (ct *CategoryTracker) snapshotTimes() map[string]time.Duration {
	snapshot := make(map[string]time.Duration, len(ct.categoryTime)+1)
	for k, v := range ct.categoryTime {
		snapshot[k] = v
	}

	// Add in-progress time for the active category.
	if ct.activeCategory != "" {
		if start, ok := ct.categoryLastStart[ct.activeCategory]; ok && !start.IsZero() {
			snapshot[ct.activeCategory] += time.Since(start)
		}
	}

	return snapshot
}

// formatDuration returns a human-readable duration string like "5m30s" or "12m".
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	mins := int(d.Minutes())
	secs := int(d.Seconds()) % 60
	if secs == 0 {
		return fmt.Sprintf("%dm", mins)
	}
	return fmt.Sprintf("%dm%ds", mins, secs)
}
