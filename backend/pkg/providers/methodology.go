package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// MethodologyCategory represents a single OWASP/PTES-aligned testing category.
type MethodologyCategory struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	OWASPRef      string  `json:"owasp_ref"`
	Priority      string  `json:"priority"` // P0, P1, P2, P3
	TimeBudgetPct float64 `json:"time_budget_pct"`
	Description   string  `json:"description"`
}

// CategoryStatus tracks the testing state for a single category.
type CategoryStatus struct {
	Status          string    `json:"status"` // not_started, in_progress, complete, skipped, blocked
	SubtasksTested  []int64   `json:"subtasks_tested,omitempty"`
	FindingCount    int       `json:"finding_count"`
	ToolCallCount   int       `json:"tool_call_count"`
	BlockReason     string    `json:"block_reason,omitempty"`
	LastUpdated     time.Time `json:"last_updated"`
	VulnsDiscovered []string  `json:"vulns_discovered,omitempty"`
}

// DefaultMethodologyCategories defines the 14 testing categories aligned with
// the existing generator.tmpl P0-P3 structure.
var DefaultMethodologyCategories = []MethodologyCategory{
	// P0 — Critical First (40% time budget)
	{ID: "auth_acquisition", Name: "Authentication Acquisition", OWASPRef: "API2:2023", Priority: "P0", TimeBudgetPct: 15, Description: "Login bypass, credential theft, registration abuse, password reset flaws"},
	{ID: "data_harvest", Name: "Data Harvest & Sensitive Data Exposure", OWASPRef: "API3:2023", Priority: "P0", TimeBudgetPct: 10, Description: "PII exposure, API key leakage, verbose error messages, debug endpoints"},
	{ID: "ssrf", Name: "Server-Side Request Forgery", OWASPRef: "API10:2023", Priority: "P0", TimeBudgetPct: 10, Description: "Internal service access, cloud metadata extraction, protocol smuggling"},
	{ID: "injection", Name: "Injection Attacks", OWASPRef: "API8:2023", Priority: "P0", TimeBudgetPct: 5, Description: "SQLi, NoSQLi, command injection, LDAP injection, template injection"},

	// P1 — High Value (30% time budget)
	{ID: "idor_bola", Name: "IDOR / Broken Object-Level Authorization", OWASPRef: "API1:2023", Priority: "P1", TimeBudgetPct: 8, Description: "Horizontal/vertical privilege escalation via ID manipulation"},
	{ID: "business_logic", Name: "Business Logic Flaws", OWASPRef: "API6:2023", Priority: "P1", TimeBudgetPct: 7, Description: "Amount tampering, workflow bypass, coupon abuse, negative quantity"},
	{ID: "race_conditions", Name: "Race Conditions", OWASPRef: "API6:2023", Priority: "P1", TimeBudgetPct: 5, Description: "Double-spend, TOCTOU, parallel processing flaws"},
	{ID: "account_takeover", Name: "Account Takeover", OWASPRef: "API2:2023", Priority: "P1", TimeBudgetPct: 5, Description: "Session hijacking, JWT manipulation, OAuth flaws, password reset chain"},
	{ID: "mass_assignment", Name: "Mass Assignment", OWASPRef: "API6:2023", Priority: "P1", TimeBudgetPct: 5, Description: "Adding admin fields to requests, modifying protected attributes"},

	// P2 — Standard Coverage (20% time budget)
	{ID: "api_attacks", Name: "API-Specific Attacks", OWASPRef: "API4:2023", Priority: "P2", TimeBudgetPct: 5, Description: "Rate limiting, GraphQL introspection, REST verb tampering, CORS"},
	{ID: "rce", Name: "Remote Code Execution", OWASPRef: "API8:2023", Priority: "P2", TimeBudgetPct: 5, Description: "File upload → shell, SSTI, deserialization, command injection to RCE"},
	{ID: "xss", Name: "Cross-Site Scripting", OWASPRef: "API8:2023", Priority: "P2", TimeBudgetPct: 5, Description: "Stored/reflected/DOM XSS, script injection via file upload"},
	{ID: "security_misconfig", Name: "Security Misconfiguration", OWASPRef: "API7:2023", Priority: "P2", TimeBudgetPct: 5, Description: "Default credentials, exposed .git/.env, debug endpoints, CORS wildcard"},

	// P3 — Advanced (10% time budget)
	{ID: "advanced", Name: "Advanced Techniques", OWASPRef: "Multiple", Priority: "P3", TimeBudgetPct: 10, Description: "HTTP smuggling, cache poisoning, cloud misconfig, AI/ML attacks"},
}

// VulnTypeToCategoryMapping maps [VULN_TYPE: xxx] tags to methodology categories.
// This bridges the existing FindingTracker's vuln type detection to coverage tracking.
var VulnTypeToCategoryMapping = map[string]string{
	// Auth Acquisition
	"auth_bypass":       "auth_acquisition",
	"broken_auth":       "auth_acquisition",
	"default_creds":     "auth_acquisition",
	"weak_password":     "auth_acquisition",
	"password_reset":    "auth_acquisition",
	"registration_flaw": "auth_acquisition",

	// Data Harvest
	"information_disclosure": "data_harvest",
	"pii_exposure":           "data_harvest",
	"api_key_leak":           "data_harvest",
	"debug_endpoint":         "data_harvest",
	"error_disclosure":       "data_harvest",

	// SSRF
	"ssrf":           "ssrf",
	"cloud_metadata": "ssrf",

	// Injection
	"sqli":              "injection",
	"nosql_injection":   "injection",
	"command_injection": "injection",
	"ldap_injection":    "injection",
	"ssti":              "injection",
	"xpath_injection":   "injection",
	"xxe":               "injection",

	// IDOR
	"idor":  "idor_bola",
	"bola":  "idor_bola",
	"bfla":  "idor_bola",
	"privesc": "idor_bola",

	// Business Logic
	"business_logic":   "business_logic",
	"amount_tampering": "business_logic",
	"workflow_bypass":  "business_logic",

	// Race Conditions
	"race_condition": "race_conditions",
	"toctou":         "race_conditions",
	"double_spend":   "race_conditions",

	// Account Takeover
	"session_hijacking": "account_takeover",
	"jwt_manipulation":  "account_takeover",
	"oauth_flaw":        "account_takeover",
	"account_takeover":  "account_takeover",
	"csrf":              "account_takeover",

	// Mass Assignment
	"mass_assignment": "mass_assignment",

	// API Attacks
	"rate_limit":          "api_attacks",
	"graphql_introspect":  "api_attacks",
	"cors_misconfiguration": "api_attacks",
	"missing_rate_limit":  "api_attacks",

	// RCE
	"rce":             "rce",
	"file_upload":     "rce",
	"deserialization": "rce",

	// XSS
	"xss":        "xss",
	"xss_stored": "xss",
	"xss_reflected": "xss",
	"xss_dom":    "xss",

	// Security Misconfig
	"security_misconfiguration": "security_misconfig",
	"open_redirect":             "security_misconfig",
	"path_traversal":            "security_misconfig",
	"vulnerable_component":      "security_misconfig",
	"directory_listing":         "security_misconfig",

	// Advanced
	"http_smuggling":  "advanced",
	"cache_poisoning": "advanced",
	"prototype_pollution": "advanced",
	"websocket_flaw":  "advanced",
}

// MethodologyCoverage tracks testing coverage across all methodology categories
// for a single flow. It is flow-scoped and goroutine-safe.
type MethodologyCoverage struct {
	mu         sync.RWMutex
	categories map[string]*CategoryStatus
	flowID     int64
	createdAt  time.Time
}

// NewMethodologyCoverage creates a new coverage tracker for a flow.
func NewMethodologyCoverage(flowID int64) *MethodologyCoverage {
	mc := &MethodologyCoverage{
		categories: make(map[string]*CategoryStatus, len(DefaultMethodologyCategories)),
		flowID:     flowID,
		createdAt:  time.Now(),
	}
	for _, cat := range DefaultMethodologyCategories {
		mc.categories[cat.ID] = &CategoryStatus{
			Status:      "not_started",
			LastUpdated: time.Now(),
		}
	}
	return mc
}

// MarkInProgress marks a category as being actively tested by a subtask.
func (mc *MethodologyCoverage) MarkInProgress(categoryID string, subtaskID int64) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	cs, ok := mc.categories[categoryID]
	if !ok {
		return
	}
	if cs.Status == "not_started" || cs.Status == "in_progress" {
		cs.Status = "in_progress"
		cs.LastUpdated = time.Now()
		// Track which subtasks tested this category (dedup).
		for _, id := range cs.SubtasksTested {
			if id == subtaskID {
				return
			}
		}
		cs.SubtasksTested = append(cs.SubtasksTested, subtaskID)
	}
}

// MarkComplete marks a category as fully tested.
func (mc *MethodologyCoverage) MarkComplete(categoryID string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if cs, ok := mc.categories[categoryID]; ok {
		cs.Status = "complete"
		cs.LastUpdated = time.Now()
	}
}

// MarkBlocked marks a category as blocked (e.g., WAF prevents testing).
func (mc *MethodologyCoverage) MarkBlocked(categoryID, reason string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if cs, ok := mc.categories[categoryID]; ok {
		cs.Status = "blocked"
		cs.BlockReason = reason
		cs.LastUpdated = time.Now()
	}
}

// MarkSkipped marks a category as intentionally skipped.
func (mc *MethodologyCoverage) MarkSkipped(categoryID, reason string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if cs, ok := mc.categories[categoryID]; ok {
		cs.Status = "skipped"
		cs.BlockReason = reason
		cs.LastUpdated = time.Now()
	}
}

// RecordFinding records that a vulnerability was found in a category.
func (mc *MethodologyCoverage) RecordFinding(vulnType string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	normalized := NormalizeVulnType(vulnType)
	catID, ok := VulnTypeToCategoryMapping[normalized]
	if !ok {
		return
	}

	cs, ok := mc.categories[catID]
	if !ok {
		return
	}

	cs.FindingCount++
	cs.VulnsDiscovered = append(cs.VulnsDiscovered, normalized)
	if cs.Status == "not_started" {
		cs.Status = "in_progress"
	}
	cs.LastUpdated = time.Now()
}

// RecordToolCall records a tool call contributing to a category.
func (mc *MethodologyCoverage) RecordToolCall(categoryID string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if cs, ok := mc.categories[categoryID]; ok {
		cs.ToolCallCount++
		if cs.Status == "not_started" {
			cs.Status = "in_progress"
		}
		cs.LastUpdated = time.Now()
	}
}

// GetCoverageScore returns the percentage of categories that have been started or completed.
func (mc *MethodologyCoverage) GetCoverageScore() float64 {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	if len(mc.categories) == 0 {
		return 0
	}

	tested := 0
	for _, cs := range mc.categories {
		if cs.Status != "not_started" {
			tested++
		}
	}
	return float64(tested) / float64(len(mc.categories)) * 100.0
}

// GetUncoveredP0 returns P0 category IDs that haven't been started.
func (mc *MethodologyCoverage) GetUncoveredP0() []string {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	var uncovered []string
	for _, cat := range DefaultMethodologyCategories {
		if cat.Priority != "P0" {
			continue
		}
		if cs, ok := mc.categories[cat.ID]; ok && cs.Status == "not_started" {
			uncovered = append(uncovered, cat.ID)
		}
	}
	return uncovered
}

// FormatCoverageForRefiner produces a detailed coverage analysis for the subtask refiner.
func (mc *MethodologyCoverage) FormatCoverageForRefiner() string {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	var sb strings.Builder
	sb.WriteString("## METHODOLOGY COVERAGE STATUS\n\n")
	sb.WriteString(fmt.Sprintf("Overall Coverage: %.0f%% (%d/%d categories started)\n\n",
		mc.getCoverageScoreLocked(), mc.getTestedCountLocked(), len(mc.categories)))

	// Group by priority.
	priorities := []string{"P0", "P1", "P2", "P3"}
	for _, prio := range priorities {
		sb.WriteString(fmt.Sprintf("### %s Categories\n", prio))
		for _, cat := range DefaultMethodologyCategories {
			if cat.Priority != prio {
				continue
			}
			cs := mc.categories[cat.ID]
			if cs == nil {
				continue
			}

			statusIcon := mc.statusIcon(cs.Status)
			sb.WriteString(fmt.Sprintf("- %s **%s** (%s): %s", statusIcon, cat.Name, cat.ID, cs.Status))
			if cs.FindingCount > 0 {
				sb.WriteString(fmt.Sprintf(" — %d findings", cs.FindingCount))
			}
			if cs.ToolCallCount > 0 {
				sb.WriteString(fmt.Sprintf(", %d tool calls", cs.ToolCallCount))
			}
			if cs.BlockReason != "" {
				sb.WriteString(fmt.Sprintf(" [BLOCKED: %s]", cs.BlockReason))
			}
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	// Directive section.
	uncoveredP0 := mc.getUncoveredByPriorityLocked("P0")
	uncoveredP1 := mc.getUncoveredByPriorityLocked("P1")

	if len(uncoveredP0) > 0 {
		sb.WriteString("### ⚠️ CRITICAL GAPS\n")
		sb.WriteString("The following P0 categories are UNCOVERED and MUST be addressed in the next subtask(s):\n")
		for _, catID := range uncoveredP0 {
			sb.WriteString(fmt.Sprintf("- **%s** — create a focused subtask for this category\n", catID))
		}
		sb.WriteString("\n")
	}

	if len(uncoveredP1) > 0 {
		sb.WriteString("### P1 Gaps (address after P0)\n")
		for _, catID := range uncoveredP1 {
			sb.WriteString(fmt.Sprintf("- %s\n", catID))
		}
		sb.WriteString("\n")
	}

	score := mc.getCoverageScoreLocked()
	if score < 80 {
		sb.WriteString(fmt.Sprintf("**Coverage target: 80%%. Current: %.0f%%. Add subtasks for uncovered categories before reporting.**\n", score))
	}

	return sb.String()
}

// FormatCoverageForPentester produces a compact status block for the pentester prompt.
func (mc *MethodologyCoverage) FormatCoverageForPentester() string {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	var sb strings.Builder
	sb.WriteString("<methodology_coverage>\n")
	sb.WriteString(fmt.Sprintf("Coverage: %.0f%%\n", mc.getCoverageScoreLocked()))

	for _, cat := range DefaultMethodologyCategories {
		cs := mc.categories[cat.ID]
		if cs == nil {
			continue
		}
		icon := mc.statusIcon(cs.Status)
		sb.WriteString(fmt.Sprintf("  %s %s [%s]: %s", icon, cat.ID, cat.Priority, cs.Status))
		if cs.FindingCount > 0 {
			sb.WriteString(fmt.Sprintf(" (%d findings)", cs.FindingCount))
		}
		sb.WriteString("\n")
	}
	sb.WriteString("</methodology_coverage>\n")
	return sb.String()
}

// FormatCoverageForGenerator produces coverage awareness context for the subtask generator.
func (mc *MethodologyCoverage) FormatCoverageForGenerator() string {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	score := mc.getCoverageScoreLocked()
	if score == 0 {
		return "" // No prior coverage data yet
	}

	var sb strings.Builder
	sb.WriteString("## PRIOR COVERAGE FROM PREVIOUS TASK\n")
	sb.WriteString(fmt.Sprintf("Coverage score: %.0f%%\n", score))
	sb.WriteString("Already tested:\n")

	for _, cat := range DefaultMethodologyCategories {
		cs := mc.categories[cat.ID]
		if cs == nil || cs.Status == "not_started" {
			continue
		}
		sb.WriteString(fmt.Sprintf("- %s: %s (%d findings)\n", cat.ID, cs.Status, cs.FindingCount))
	}

	uncovered := mc.getUncoveredByPriorityLocked("P0")
	uncovered = append(uncovered, mc.getUncoveredByPriorityLocked("P1")...)
	if len(uncovered) > 0 {
		sb.WriteString("\nUncovered categories to prioritize:\n")
		for _, catID := range uncovered {
			sb.WriteString(fmt.Sprintf("- %s\n", catID))
		}
	}

	return sb.String()
}

// ToJSON serializes the coverage state for DB persistence.
func (mc *MethodologyCoverage) ToJSON() (string, error) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	data := struct {
		FlowID     int64                      `json:"flow_id"`
		Categories map[string]*CategoryStatus `json:"categories"`
		CreatedAt  time.Time                  `json:"created_at"`
	}{
		FlowID:     mc.flowID,
		Categories: mc.categories,
		CreatedAt:  mc.createdAt,
	}

	b, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal methodology coverage: %w", err)
	}
	return string(b), nil
}

// ParseMethodologyCoverage restores coverage state from a JSON string.
func ParseMethodologyCoverage(flowID int64, data string) *MethodologyCoverage {
	if data == "" {
		return nil
	}

	var parsed struct {
		FlowID     int64                      `json:"flow_id"`
		Categories map[string]*CategoryStatus `json:"categories"`
		CreatedAt  time.Time                  `json:"created_at"`
	}

	if err := json.Unmarshal([]byte(data), &parsed); err != nil {
		return nil
	}

	mc := &MethodologyCoverage{
		categories: parsed.Categories,
		flowID:     flowID,
		createdAt:  parsed.CreatedAt,
	}

	// Ensure all default categories exist (in case new ones were added).
	for _, cat := range DefaultMethodologyCategories {
		if _, ok := mc.categories[cat.ID]; !ok {
			mc.categories[cat.ID] = &CategoryStatus{
				Status:      "not_started",
				LastUpdated: time.Now(),
			}
		}
	}

	return mc
}

// classifySubtaskCategories maps a subtask title/description to methodology categories
// using keyword matching.
func classifySubtaskCategories(title, description string) []string {
	combined := strings.ToLower(title + " " + description)
	var categories []string
	seen := make(map[string]bool)

	categoryKeywords := map[string][]string{
		"auth_acquisition":  {"auth", "login", "credential", "password", "registration", "signup", "sign up", "session", "token", "jwt", "oauth", "sso"},
		"data_harvest":      {"data", "sensitive", "pii", "leak", "exposure", "error", "debug", "verbose", "disclosure"},
		"ssrf":              {"ssrf", "server-side request", "metadata", "internal", "169.254"},
		"injection":         {"sqli", "sql injection", "nosql", "command injection", "ssti", "template injection", "inject", "xxe", "ldap"},
		"idor_bola":         {"idor", "bola", "bfla", "object reference", "privilege", "authorization", "access control", "horizontal", "vertical"},
		"business_logic":    {"business logic", "workflow", "amount", "tamper", "coupon", "discount", "payment", "price"},
		"race_conditions":   {"race condition", "race", "concurrent", "double spend", "toctou", "parallel"},
		"account_takeover":  {"account takeover", "ato", "session hijack", "password reset", "email change"},
		"mass_assignment":   {"mass assignment", "parameter pollution", "hidden field", "admin field"},
		"api_attacks":       {"api", "graphql", "rest", "rate limit", "cors", "verb tampering", "api abuse"},
		"rce":               {"rce", "remote code", "file upload", "web shell", "deserialization", "code execution"},
		"xss":               {"xss", "cross-site scripting", "script injection", "reflected", "stored xss", "dom xss"},
		"security_misconfig": {"misconfiguration", "misconfig", "default", ".git", ".env", "directory listing", "open redirect", "path traversal"},
		"advanced":          {"smuggling", "cache poisoning", "prototype pollution", "websocket", "cloud", "ai", "advanced"},
	}

	for catID, keywords := range categoryKeywords {
		for _, kw := range keywords {
			if strings.Contains(combined, kw) && !seen[catID] {
				categories = append(categories, catID)
				seen[catID] = true
				break
			}
		}
	}

	return categories
}

// NormalizeVulnType is the exported version of normalizeKey for cross-package usage.
func NormalizeVulnType(vulnType string) string {
	return normalizeKey(vulnType)
}

// ─── Internal helpers (called with lock held) ────────────────────────────────

func (mc *MethodologyCoverage) getCoverageScoreLocked() float64 {
	if len(mc.categories) == 0 {
		return 0
	}
	return float64(mc.getTestedCountLocked()) / float64(len(mc.categories)) * 100.0
}

func (mc *MethodologyCoverage) getTestedCountLocked() int {
	tested := 0
	for _, cs := range mc.categories {
		if cs.Status != "not_started" {
			tested++
		}
	}
	return tested
}

func (mc *MethodologyCoverage) getUncoveredByPriorityLocked(priority string) []string {
	var uncovered []string
	for _, cat := range DefaultMethodologyCategories {
		if cat.Priority != priority {
			continue
		}
		if cs, ok := mc.categories[cat.ID]; ok && cs.Status == "not_started" {
			uncovered = append(uncovered, cat.ID)
		}
	}
	return uncovered
}

func (mc *MethodologyCoverage) statusIcon(status string) string {
	switch status {
	case "complete":
		return "✅"
	case "in_progress":
		return "🔄"
	case "blocked":
		return "🚫"
	case "skipped":
		return "⏭️"
	default:
		return "❌"
	}
}

// ─── Tech Stack Profile ──────────────────────────────────────────────────────

// TechStackProfile describes the detected technology stack of the target.
type TechStackProfile struct {
	APIType     string   `json:"api_type"`     // rest, graphql, soap, grpc
	Framework   string   `json:"framework"`    // express, django, spring, rails, etc.
	Language    string   `json:"language"`      // javascript, python, java, go, php, etc.
	WAFType     string   `json:"waf_type"`     // cloudflare, aws_waf, modsecurity, etc.
	CloudProvider string `json:"cloud_provider"` // aws, azure, gcp, etc.
	Industry    string   `json:"industry"`     // fintech, crypto, ecommerce, healthcare, etc.
	Markers     []string `json:"markers"`      // Raw detection markers
}

// DetectTechStack analyzes execution context and tool results to build a tech stack profile.
func DetectTechStack(executionContext string) *TechStackProfile {
	lower := strings.ToLower(executionContext)
	profile := &TechStackProfile{}

	// API Type detection
	apiPatterns := map[string]*regexp.Regexp{
		"graphql": regexp.MustCompile(`(?i)graphql|/graphql|__schema|introspection`),
		"soap":    regexp.MustCompile(`(?i)wsdl|soap|xmlns:soap`),
		"grpc":    regexp.MustCompile(`(?i)grpc|protobuf|\.proto`),
		"rest":    regexp.MustCompile(`(?i)/api/v[0-9]|rest\s*api|json\s*api`),
	}
	for apiType, pattern := range apiPatterns {
		if pattern.MatchString(lower) {
			profile.APIType = apiType
			profile.Markers = append(profile.Markers, "api:"+apiType)
			break
		}
	}
	if profile.APIType == "" {
		profile.APIType = "rest"
	}

	// Framework detection
	frameworkPatterns := map[string]*regexp.Regexp{
		"express":    regexp.MustCompile(`(?i)x-powered-by:\s*express|express\.js|node\.js`),
		"django":     regexp.MustCompile(`(?i)django|csrfmiddlewaretoken|wsgi`),
		"spring":     regexp.MustCompile(`(?i)spring|spring-boot|x-application-context`),
		"rails":      regexp.MustCompile(`(?i)ruby on rails|x-powered-by:\s*phusion|_rails_`),
		"laravel":    regexp.MustCompile(`(?i)laravel|x-powered-by:\s*php.*laravel`),
		"flask":      regexp.MustCompile(`(?i)flask|werkzeug`),
		"fastapi":    regexp.MustCompile(`(?i)fastapi|starlette`),
		"aspnet":     regexp.MustCompile(`(?i)asp\.net|x-aspnet-version|x-powered-by:\s*asp`),
		"nextjs":     regexp.MustCompile(`(?i)next\.js|__next|_next/`),
	}
	for fw, pattern := range frameworkPatterns {
		if pattern.MatchString(lower) {
			profile.Framework = fw
			profile.Markers = append(profile.Markers, "framework:"+fw)
			break
		}
	}

	// Cloud provider detection
	cloudPatterns := map[string]*regexp.Regexp{
		"aws":   regexp.MustCompile(`(?i)amazonaws\.com|aws|x-amz-|cloudfront`),
		"azure": regexp.MustCompile(`(?i)azure|\.azurewebsites\.net|x-ms-`),
		"gcp":   regexp.MustCompile(`(?i)google cloud|\.googleapis\.com|gcp`),
	}
	for cloud, pattern := range cloudPatterns {
		if pattern.MatchString(lower) {
			profile.CloudProvider = cloud
			profile.Markers = append(profile.Markers, "cloud:"+cloud)
			break
		}
	}

	return profile
}

// AdjustPriorities returns category priority overrides based on tech stack.
// Returns a map of categoryID → new priority string.
func (ts *TechStackProfile) AdjustPriorities() map[string]string {
	adjustments := make(map[string]string)

	switch ts.APIType {
	case "graphql":
		adjustments["api_attacks"] = "P0" // GraphQL introspection is critical
		adjustments["injection"] = "P0"   // GraphQL variable injection
	}

	switch ts.Industry {
	case "fintech", "crypto":
		adjustments["race_conditions"] = "P0"  // Double-spend is critical
		adjustments["business_logic"] = "P0"   // Amount tampering
		adjustments["account_takeover"] = "P0" // Fund theft
	case "healthcare":
		adjustments["data_harvest"] = "P0" // PHI/PII is critical
		adjustments["idor_bola"] = "P0"    // Patient data access
	case "ecommerce":
		adjustments["business_logic"] = "P0" // Price/coupon manipulation
		adjustments["idor_bola"] = "P0"      // Order/payment data
	}

	if ts.WAFType != "" {
		adjustments["injection"] = "P1" // WAF makes injection harder, deprioritize slightly
	}

	return adjustments
}

// FormatTechStackForPrompt formats the tech stack profile for prompt injection.
func (ts *TechStackProfile) FormatTechStackForPrompt() string {
	if ts == nil || (ts.APIType == "rest" && ts.Framework == "" && ts.CloudProvider == "") {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("<tech_stack_profile>\n")
	if ts.APIType != "" {
		sb.WriteString(fmt.Sprintf("  API Type: %s\n", ts.APIType))
	}
	if ts.Framework != "" {
		sb.WriteString(fmt.Sprintf("  Framework: %s\n", ts.Framework))
	}
	if ts.CloudProvider != "" {
		sb.WriteString(fmt.Sprintf("  Cloud: %s\n", ts.CloudProvider))
	}
	if ts.WAFType != "" {
		sb.WriteString(fmt.Sprintf("  WAF: %s\n", ts.WAFType))
	}
	if ts.Industry != "" {
		sb.WriteString(fmt.Sprintf("  Industry: %s\n", ts.Industry))
	}

	adjustments := ts.AdjustPriorities()
	if len(adjustments) > 0 {
		sb.WriteString("  Priority adjustments:\n")
		for catID, newPrio := range adjustments {
			sb.WriteString(fmt.Sprintf("    %s → %s (due to tech stack)\n", catID, newPrio))
		}
	}
	sb.WriteString("</tech_stack_profile>\n")
	return sb.String()
}

// ─── Context propagation ─────────────────────────────────────────────────────

type methodologyCoverageKey struct{}

// WithMethodologyCoverage attaches a MethodologyCoverage to the context.
func WithMethodologyCoverage(ctx context.Context, mc *MethodologyCoverage) context.Context {
	return context.WithValue(ctx, methodologyCoverageKey{}, mc)
}

// GetMethodologyCoverage retrieves the MethodologyCoverage from context.
func GetMethodologyCoverage(ctx context.Context) *MethodologyCoverage {
	if mc, ok := ctx.Value(methodologyCoverageKey{}).(*MethodologyCoverage); ok {
		return mc
	}
	return nil
}
