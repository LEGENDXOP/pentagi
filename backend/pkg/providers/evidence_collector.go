package providers

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"pentagi/pkg/database"

	"github.com/sirupsen/logrus"
)

// EvidenceType classifies the kind of evidence collected.
type EvidenceType string

const (
	EvidenceTypeToolCall   EvidenceType = "tool_call"
	EvidenceTypeTermLog    EvidenceType = "terminal_log"
	EvidenceTypeScreenshot EvidenceType = "screenshot"
	EvidenceTypeHTTP       EvidenceType = "http_response"
	EvidenceTypeFile       EvidenceType = "file_artifact"
)

// Evidence represents a single piece of evidence from a penetration test.
type Evidence struct {
	ID           string       `json:"id"`
	FlowID       int64        `json:"flow_id"`
	SubtaskID    *int64       `json:"subtask_id,omitempty"`
	Type         EvidenceType `json:"type"`
	ToolName     string       `json:"tool_name"`
	Command      string       `json:"command,omitempty"`
	Content      string       `json:"content"`
	Timestamp    time.Time    `json:"timestamp"`
	ToolCallID   *int64       `json:"toolcall_id,omitempty"`
	ScreenshotID *int64       `json:"screenshot_id,omitempty"`
}

// ReportFinding represents a confirmed or suspected vulnerability finding
// with full evidence chain and compliance metadata. This extends the existing
// Finding type from dedup.go with richer reporting fields.
type ReportFinding struct {
	ID              string     `json:"id"`
	FlowID          int64      `json:"flow_id"`
	SubtaskID       *int64     `json:"subtask_id,omitempty"`
	VulnType        string     `json:"vuln_type"`
	Title           string     `json:"title"`
	Description     string     `json:"description"`
	Severity        string     `json:"severity"`
	Endpoint        string     `json:"endpoint,omitempty"`
	Evidence        []Evidence `json:"evidence,omitempty"`
	Fingerprint     string     `json:"fingerprint"`
	OWASPRef        string     `json:"owasp_ref,omitempty"`
	CWE             string     `json:"cwe,omitempty"`
	CVSSBase        float64    `json:"cvss_base,omitempty"`
	Remediation     string     `json:"remediation,omitempty"`
	Confirmed       bool       `json:"confirmed"`
	FalsePositive   bool       `json:"false_positive"`
	CreatedAt       time.Time  `json:"created_at"`
	RootCauseID     string     `json:"root_cause_id,omitempty"`
}

// EvidenceCollector hooks into executor.go to capture evidence from tool calls.
// It is flow-scoped and goroutine-safe.
type EvidenceCollector struct {
	mu        sync.Mutex
	flowID    int64
	evidence  []Evidence
	idCounter int
}

// NewEvidenceCollector creates a new evidence collector for a flow.
func NewEvidenceCollector(flowID int64) *EvidenceCollector {
	return &EvidenceCollector{
		flowID:   flowID,
		evidence: make([]Evidence, 0),
	}
}

// CollectFromToolCall extracts evidence from a tool call result.
// Only collects evidence from tools that are likely to produce findings.
func (ec *EvidenceCollector) CollectFromToolCall(
	toolName string,
	args string,
	result string,
	subtaskID *int64,
	toolCallID *int64,
) {
	if result == "" || !isEvidenceWorthy(toolName, result) {
		return
	}

	ec.mu.Lock()
	defer ec.mu.Unlock()

	ec.idCounter++
	ev := Evidence{
		ID:         fmt.Sprintf("EV-%04d", ec.idCounter),
		FlowID:     ec.flowID,
		SubtaskID:  subtaskID,
		Type:       classifyEvidenceType(toolName),
		ToolName:   toolName,
		Command:    truncateString(args, 2048),
		Content:    truncateString(result, 65536), // 64KB max
		Timestamp:  time.Now(),
		ToolCallID: toolCallID,
	}

	ec.evidence = append(ec.evidence, ev)
}

// GetEvidence returns all collected evidence.
func (ec *EvidenceCollector) GetEvidence() []Evidence {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	result := make([]Evidence, len(ec.evidence))
	copy(result, ec.evidence)
	return result
}

// GetEvidenceForVulnType returns evidence that may be relevant to a vulnerability type.
func (ec *EvidenceCollector) GetEvidenceForVulnType(vulnType string) []Evidence {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	var relevant []Evidence
	normalized := NormalizeVulnType(vulnType)
	for _, ev := range ec.evidence {
		if containsVulnIndicator(ev.Content, normalized) {
			relevant = append(relevant, ev)
		}
	}
	return relevant
}

// ─── Finding Registry ────────────────────────────────────────────────────────

// FindingRegistry manages finding deduplication and registration.
// It is flow-scoped and goroutine-safe.
type FindingRegistry struct {
	mu               sync.Mutex
	flowID           int64
	findings         []ReportFinding
	seenFingerprints map[string]bool
	idCounter        int
}

// NewFindingRegistry creates a new finding registry for a flow.
func NewFindingRegistry(flowID int64) *FindingRegistry {
	return &FindingRegistry{
		flowID:           flowID,
		findings:         make([]ReportFinding, 0),
		seenFingerprints: make(map[string]bool),
	}
}

// CheckAndRegister attempts to register a new finding. Returns true if the finding
// is new (not a duplicate), false if it's a duplicate.
// Fix ECHO-4: Adds semantic dedup — if a finding has the same normalized vuln_type
// and either (a) one has an empty endpoint while the other doesn't, or (b) they
// share the same hostname, the incoming finding is treated as a duplicate.
// When the new finding has a non-empty endpoint and the existing one is empty,
// the existing finding is upgraded with the new endpoint (more specific wins).
func (fr *FindingRegistry) CheckAndRegister(
	vulnType string,
	endpoint string,
	description string,
	severity string,
	subtaskID *int64,
	evidence []Evidence,
) (*ReportFinding, bool) {
	// Sanitize endpoint before any processing
	endpoint = sanitizeEndpoint(endpoint)

	fp := buildFingerprint(vulnType, endpoint)

	fr.mu.Lock()
	defer fr.mu.Unlock()

	if fr.seenFingerprints[fp] {
		return nil, false // Exact fingerprint duplicate
	}

	// Semantic dedup: same vuln_type with empty-vs-populated endpoint
	normalizedVT := NormalizeVulnType(vulnType)
	for i, existing := range fr.findings {
		if existing.VulnType != normalizedVT {
			continue
		}
		existingEP := normalizeEndpointForFingerprint(existing.Endpoint)
		newEP := normalizeEndpointForFingerprint(endpoint)

		// Case 1: One has empty endpoint, the other doesn't → same finding
		// Case 2: Same host after normalization → same finding
		isSemDupe := (existingEP == "" || newEP == "") ||
			extractHost(existingEP) == extractHost(newEP)

		if isSemDupe {
			// Keep the more specific version (the one WITH an endpoint)
			if existing.Endpoint == "" && endpoint != "" {
				fr.findings[i].Endpoint = endpoint
				fr.findings[i].Title = generateFindingTitle(normalizedVT, endpoint)
				logrus.WithFields(logrus.Fields{
					"vuln_type":    normalizedVT,
					"new_endpoint": endpoint,
				}).Debug("Semantic dedup: upgraded existing finding with specific endpoint")
			}
			fr.seenFingerprints[fp] = true
			return nil, false // Semantic duplicate
		}
	}

	fr.seenFingerprints[fp] = true

	fr.idCounter++
	normalized := NormalizeVulnType(vulnType)

	// Look up compliance data.
	var owaspRef, cwe string
	var cvssBase float64
	if cm := GetComplianceForVulnType(normalized); cm != nil {
		owaspRef = cm.OWASPTop10
		if len(cm.CWEIDs) > 0 {
			cwe = strings.Join(cm.CWEIDs, ", ")
		}
		cvssBase = cm.CVSSBase
	}

	// Get remediation text.
	remediation := FormatRemediation(normalized)

	finding := ReportFinding{
		ID:          fmt.Sprintf("F-%04d", fr.idCounter),
		FlowID:      fr.flowID,
		SubtaskID:   subtaskID,
		VulnType:    normalized,
		Title:       generateFindingTitle(normalized, endpoint),
		Description: description,
		Severity:    severity,
		Endpoint:    endpoint,
		Evidence:    evidence,
		Fingerprint: fp,
		OWASPRef:    owaspRef,
		CWE:         cwe,
		CVSSBase:    cvssBase,
		Remediation: remediation,
		CreatedAt:   time.Now(),
	}

	fr.findings = append(fr.findings, finding)
	return &finding, true
}

// GetFindings returns all registered findings.
func (fr *FindingRegistry) GetFindings() []ReportFinding {
	fr.mu.Lock()
	defer fr.mu.Unlock()

	result := make([]ReportFinding, len(fr.findings))
	copy(result, fr.findings)
	return result
}

// GetFindingsBySeverity returns findings grouped by severity.
func (fr *FindingRegistry) GetFindingsBySeverity() map[string][]ReportFinding {
	fr.mu.Lock()
	defer fr.mu.Unlock()

	grouped := make(map[string][]ReportFinding)
	for _, f := range fr.findings {
		if !f.FalsePositive {
			grouped[f.Severity] = append(grouped[f.Severity], f)
		}
	}
	return grouped
}

// PersistFindings writes all accumulated findings to the database.
// Uses best-effort semantics: logs errors but does not fail.
func (fr *FindingRegistry) PersistFindings(ctx context.Context, db database.Querier) {
	fr.mu.Lock()
	findings := make([]ReportFinding, len(fr.findings))
	copy(findings, fr.findings)
	fr.mu.Unlock()

	if len(findings) == 0 {
		return
	}

	for _, f := range findings {
		// Check if already persisted (dedup by fingerprint + flow_id).
		_, err := db.GetFindingByFingerprint(ctx, database.GetFindingByFingerprintParams{
			Fingerprint: f.Fingerprint,
			FlowID:      f.FlowID,
		})
		if err == nil {
			continue // Already exists.
		}

		var subtaskID sql.NullInt64
		if f.SubtaskID != nil {
			subtaskID = sql.NullInt64{Int64: *f.SubtaskID, Valid: true}
		}
		var rootCauseID sql.NullInt64

		_, err = db.CreateFinding(ctx, database.CreateFindingParams{
			FlowID:        f.FlowID,
			SubtaskID:     subtaskID,
			VulnType:      f.VulnType,
			Title:         f.Title,
			Description:   truncateString(f.Description, 8192),
			Severity:      f.Severity,
			Endpoint:      f.Endpoint,
			Fingerprint:   f.Fingerprint,
			OWASPRef:      f.OWASPRef,
			CWE:           f.CWE,
			CVSSBase:      f.CVSSBase,
			Remediation:   f.Remediation,
			Confirmed:     f.Confirmed,
			FalsePositive: f.FalsePositive,
			RootCauseID:   rootCauseID,
		})
		if err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"flow_id":     f.FlowID,
				"vuln_type":   f.VulnType,
				"fingerprint": f.Fingerprint,
			}).Warn("failed to persist finding to DB")
		}
	}
}

// GetFindingCount returns the total number of non-false-positive findings.
func (fr *FindingRegistry) GetFindingCount() int {
	fr.mu.Lock()
	defer fr.mu.Unlock()

	count := 0
	for _, f := range fr.findings {
		if !f.FalsePositive {
			count++
		}
	}
	return count
}

// ─── FINDINGS.md Sync (Fallback) ─────────────────────────────────────────────

// findingsMDBlockRegex matches structured finding blocks in FINDINGS.md.
// Supports the standard format:
//   [FINDING: F-NNN]
//   Title: <title>
//   [VULN_TYPE: <tag>]
//   Severity: Critical|High|Medium|Low|Info
//   Target: <endpoint>
//   Description: <text>
var findingsMDBlockRegex = regexp.MustCompile(
	`(?s)\[FINDING:\s*F-\d+\].*?(?:\[FINDING:|\z)`,
)
var findingsMDVulnTypeRegex = regexp.MustCompile(`\[VULN_TYPE:\s*(\w+)\]`)
var findingsMDSeverityRegex = regexp.MustCompile(`(?i)Severity:\s*(Critical|High|Medium|Low|Info)`)
var findingsMDTargetRegex = regexp.MustCompile(`(?i)Target:\s*(.+)`)
var findingsMDTitleRegex = regexp.MustCompile(`(?i)Title:\s*(.+)`)
var findingsMDDescRegex = regexp.MustCompile(`(?i)Description:\s*(.+)`)

// ParseAndSyncFindingsMD parses FINDINGS.md content and registers any findings
// not already present in the registry. This is a FALLBACK mechanism for flows
// where the agent wrote findings to FINDINGS.md but did not include [VULN_TYPE:]
// tags in individual tool responses.
//
// Returns the number of new findings registered.
func (fr *FindingRegistry) ParseAndSyncFindingsMD(content string, subtaskID *int64) int {
	if strings.TrimSpace(content) == "" {
		return 0
	}

	newCount := 0
	// Split content into finding blocks
	blocks := findingsMDBlockRegex.FindAllString(content, -1)

	// If no structured blocks found, try a simpler line-by-line approach
	// looking for VULN_TYPE tags anywhere in the file
	if len(blocks) == 0 {
		matches := findingsMDVulnTypeRegex.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) >= 2 {
				vulnType := match[1]
				severity := severityFromVulnType(vulnType)
				_, isNew := fr.CheckAndRegister(
					vulnType, "", truncateString(content, 4096), severity, subtaskID, nil,
				)
				if isNew {
					newCount++
				}
			}
		}
		return newCount
	}

	for _, block := range blocks {
		// Extract VULN_TYPE
		vtMatch := findingsMDVulnTypeRegex.FindStringSubmatch(block)
		if len(vtMatch) < 2 {
			continue // No vuln type = can't register
		}
		vulnType := vtMatch[1]

		// Use authoritative CVSS-based severity. Do NOT override with agent-written
		// severity from FINDINGS.md — agents tend to over-rate as CRITICAL.
		severity := severityFromVulnType(vulnType)
		// Agent's written severity is logged but not used (CVSS is authoritative).
		if sevMatch := findingsMDSeverityRegex.FindStringSubmatch(block); len(sevMatch) >= 2 {
			agentSev := strings.ToLower(sevMatch[1])
			if agentSev != severity {
				logrus.WithFields(logrus.Fields{
					"vuln_type":      vulnType,
					"agent_severity": agentSev,
					"cvss_severity":  severity,
				}).Debug("FINDINGS.md sync: agent severity differs from CVSS — using CVSS")
			}
		}

		// Extract endpoint — sanitize to strip template variables like ${port}${path}
		// and trailing backslashes that the LLM may inject (Fix ECHO-2).
		endpoint := ""
		if tgtMatch := findingsMDTargetRegex.FindStringSubmatch(block); len(tgtMatch) >= 2 {
			endpoint = sanitizeEndpoint(tgtMatch[1])
		}

		// Extract description
		description := truncateString(block, 4096)
		if descMatch := findingsMDDescRegex.FindStringSubmatch(block); len(descMatch) >= 2 {
			description = truncateString(descMatch[1], 4096)
		}

		// Extract title for logging
		title := ""
		if titleMatch := findingsMDTitleRegex.FindStringSubmatch(block); len(titleMatch) >= 2 {
			title = strings.TrimSpace(titleMatch[1])
		}

		_, isNew := fr.CheckAndRegister(
			vulnType, endpoint, description, severity, subtaskID, nil,
		)
		if isNew {
			newCount++
			logrus.WithFields(logrus.Fields{
				"vuln_type": vulnType,
				"severity":  severity,
				"endpoint":  endpoint,
				"title":     title,
			}).Info("FINDINGS.md sync: registered finding missed by primary extraction")
		}
	}

	return newCount
}

// ─── Report Generator ────────────────────────────────────────────────────────

// ReportFormat describes the output format for generated reports.
type ReportFormat string

const (
	ReportFormatMarkdown ReportFormat = "markdown"
	ReportFormatJSON     ReportFormat = "json"
)

// ReportData contains all aggregated data for report generation.
type ReportData struct {
	FlowID           int64              `json:"flow_id"`
	Title            string             `json:"title"`
	GeneratedAt      time.Time          `json:"generated_at"`
	TotalFindings    int                `json:"total_findings"`
	FindingsBySev    map[string]int     `json:"findings_by_severity"`
	CoverageScore    float64            `json:"coverage_score,omitempty"`
	Findings         []ReportFinding    `json:"findings"`
	ExecutiveSummary string             `json:"executive_summary,omitempty"`
}

// ReportGenerator produces structured reports from findings and evidence.
type ReportGenerator struct {
	flowID    int64
	title     string
	registry  *FindingRegistry
	collector *EvidenceCollector
	coverage  *MethodologyCoverage
}

// NewReportGenerator creates a new report generator.
func NewReportGenerator(
	flowID int64,
	title string,
	registry *FindingRegistry,
	collector *EvidenceCollector,
	coverage *MethodologyCoverage,
) *ReportGenerator {
	return &ReportGenerator{
		flowID:    flowID,
		title:     title,
		registry:  registry,
		collector: collector,
		coverage:  coverage,
	}
}

// GenerateMarkdownReport produces a Markdown-formatted penetration test report.
func (rg *ReportGenerator) GenerateMarkdownReport() string {
	data := rg.collectReportData()
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# Penetration Test Report: %s\n\n", rg.title))
	sb.WriteString(fmt.Sprintf("**Generated:** %s\n", data.GeneratedAt.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("**Flow ID:** %d\n\n", data.FlowID))

	// Executive Summary
	sb.WriteString("## Executive Summary\n\n")
	sb.WriteString(fmt.Sprintf("Total findings: **%d**\n\n", data.TotalFindings))

	sb.WriteString("| Severity | Count |\n|----------|-------|\n")
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		count := data.FindingsBySev[sev]
		if count > 0 {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", strings.ToUpper(sev), count))
		}
	}
	sb.WriteString("\n")

	if data.CoverageScore > 0 {
		sb.WriteString(fmt.Sprintf("**Methodology Coverage:** %.0f%%\n\n", data.CoverageScore))
	}

	// OWASP Summary
	owaspCounts := make(map[string]int)
	for _, f := range data.Findings {
		if f.OWASPRef != "" {
			owaspCounts[f.OWASPRef]++
		}
	}
	if len(owaspCounts) > 0 {
		sb.WriteString("## OWASP API Top 10 Coverage\n\n")
		sb.WriteString("| OWASP Category | Findings |\n|----------------|----------|\n")
		for cat, count := range owaspCounts {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", cat, count))
		}
		sb.WriteString("\n")
	}

	// Detailed Findings
	sb.WriteString("## Detailed Findings\n\n")
	for i, f := range data.Findings {
		if f.FalsePositive {
			continue
		}
		sb.WriteString(fmt.Sprintf("### %d. [%s] %s\n\n", i+1, strings.ToUpper(string(f.Severity)), f.Title))
		sb.WriteString(fmt.Sprintf("- **ID:** %s\n", f.ID))
		sb.WriteString(fmt.Sprintf("- **Type:** %s\n", f.VulnType))
		if f.Endpoint != "" {
			sb.WriteString(fmt.Sprintf("- **Endpoint:** `%s`\n", f.Endpoint))
		}
		if f.OWASPRef != "" {
			sb.WriteString(fmt.Sprintf("- **OWASP:** %s\n", f.OWASPRef))
		}
		if f.CWE != "" {
			sb.WriteString(fmt.Sprintf("- **CWE:** %s\n", f.CWE))
		}
		if f.CVSSBase > 0 {
			sb.WriteString(fmt.Sprintf("- **CVSS:** %.1f\n", f.CVSSBase))
		}
		sb.WriteString("\n")

		if f.Description != "" {
			sb.WriteString("**Description:**\n")
			sb.WriteString(f.Description + "\n\n")
		}

		// Evidence chain
		if len(f.Evidence) > 0 {
			sb.WriteString("**Evidence:**\n\n")
			for _, ev := range f.Evidence {
				sb.WriteString(fmt.Sprintf("- `%s` (%s) at %s\n",
					ev.ToolName, ev.Type, ev.Timestamp.Format("15:04:05")))
				if ev.Command != "" {
					sb.WriteString(fmt.Sprintf("  Command: `%s`\n", truncateString(ev.Command, 200)))
				}
				if ev.Content != "" {
					preview := truncateString(ev.Content, 500)
					sb.WriteString(fmt.Sprintf("  ```\n  %s\n  ```\n", preview))
				}
			}
			sb.WriteString("\n")
		}

		if f.Remediation != "" {
			sb.WriteString("**Remediation:**\n\n")
			sb.WriteString(f.Remediation + "\n\n")
		}

		sb.WriteString("---\n\n")
	}

	return sb.String()
}

// GenerateJSONReport produces a JSON-formatted report.
func (rg *ReportGenerator) GenerateJSONReport() (string, error) {
	data := rg.collectReportData()
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal report: %w", err)
	}
	return string(b), nil
}

func (rg *ReportGenerator) collectReportData() *ReportData {
	findings := rg.registry.GetFindings()
	findingsBySev := make(map[string]int)
	totalFindings := 0

	for _, f := range findings {
		if !f.FalsePositive {
			findingsBySev[f.Severity]++
			totalFindings++
		}
	}

	var coverageScore float64
	if rg.coverage != nil {
		coverageScore = rg.coverage.GetCoverageScore()
	}

	return &ReportData{
		FlowID:        rg.flowID,
		Title:         rg.title,
		GeneratedAt:   time.Now(),
		TotalFindings: totalFindings,
		FindingsBySev: findingsBySev,
		CoverageScore: coverageScore,
		Findings:      findings,
	}
}

// ─── Helper functions ────────────────────────────────────────────────────────

// isEvidenceWorthy determines if a tool call result should be collected as evidence.
func isEvidenceWorthy(toolName, result string) bool {
	// Always collect from offensive tools.
	offensiveTools := map[string]bool{
		"terminal":     true,
		"browser":      true,
		"pentester":    true,
		"hack_result":  true,
	}
	if offensiveTools[toolName] {
		// Only collect if the result contains something interesting.
		lower := strings.ToLower(result)
		interestingIndicators := []string{
			"vuln", "vulnerability", "injection", "xss", "sqli",
			"200 ok", "403", "401", "500",
			"admin", "root", "password", "token", "secret",
			"finding", "critical", "high", "exploit",
			"[vuln_type:", "access denied", "bypass",
		}
		for _, indicator := range interestingIndicators {
			if strings.Contains(lower, indicator) {
				return true
			}
		}
		// Collect terminal results that show HTTP responses.
		if strings.Contains(lower, "http/") || strings.Contains(lower, "status:") {
			return true
		}
		return false
	}
	return false
}

func classifyEvidenceType(toolName string) EvidenceType {
	switch toolName {
	case "terminal":
		return EvidenceTypeTermLog
	case "browser":
		return EvidenceTypeScreenshot
	default:
		return EvidenceTypeToolCall
	}
}

// sanitizeEndpoint strips shell-style template variables (${port}, $path, etc.),
// trailing backslashes, and other artifacts the LLM may inject into endpoints.
// This prevents raw template strings like "https://example.com:${port}${path}\"
// from entering the findings database.
func sanitizeEndpoint(endpoint string) string {
	ep := strings.TrimSpace(endpoint)
	if ep == "" {
		return ""
	}
	// Remove shell-style template variables: ${port}, ${path}, $port, $path
	ep = shellVarRegex.ReplaceAllString(ep, "")
	// Remove trailing backslashes (common LLM artifact)
	ep = strings.TrimRight(ep, "\\")
	// Remove trailing colons left after stripping :${port}
	ep = strings.TrimRight(ep, ":")
	// Clean up any double slashes in path (but preserve ://)
	for strings.Contains(ep, "///") {
		ep = strings.ReplaceAll(ep, "///", "//")
	}
	return strings.TrimSpace(ep)
}

// shellVarRegex matches shell-style template variables like ${port}, $path, ${HOST}
var shellVarRegex = regexp.MustCompile(`\$\{?\w+\}?`)

// extractHost extracts the hostname from a URL-like endpoint string.
// Returns the host portion (without scheme, port, or path).
// E.g., "https://backend.netbond.in:443/api" → "backend.netbond.in"
func extractHost(endpoint string) string {
	ep := strings.TrimSpace(endpoint)
	if ep == "" {
		return ""
	}
	// Strip scheme
	if idx := strings.Index(ep, "://"); idx != -1 {
		ep = ep[idx+3:]
	}
	// Strip path
	if idx := strings.IndexByte(ep, '/'); idx != -1 {
		ep = ep[:idx]
	}
	// Strip port
	if idx := strings.LastIndexByte(ep, ':'); idx != -1 {
		ep = ep[:idx]
	}
	return strings.ToLower(ep)
}

// normalizeEndpointForFingerprint applies additional normalization beyond
// sanitization for dedup fingerprinting: removes default ports, strips
// trailing slashes, and lowercases the hostname portion.
func normalizeEndpointForFingerprint(endpoint string) string {
	ep := sanitizeEndpoint(endpoint)
	if ep == "" {
		return ""
	}
	// Remove default ports :80 and :443
	ep = strings.Replace(ep, ":80/", "/", 1)
	ep = strings.Replace(ep, ":443/", "/", 1)
	ep = strings.TrimSuffix(ep, ":80")
	ep = strings.TrimSuffix(ep, ":443")
	// Strip trailing slashes for consistent matching
	ep = strings.TrimRight(ep, "/")
	// Lowercase the scheme+host portion (path stays case-sensitive)
	if idx := strings.Index(ep, "://"); idx != -1 {
		rest := ep[idx+3:]
		pathStart := strings.IndexByte(rest, '/')
		if pathStart != -1 {
			// scheme://HOST/path → lowercase scheme+host, keep path as-is
			ep = strings.ToLower(ep[:idx+3+pathStart]) + rest[pathStart:]
		} else {
			// No path — lowercase entire thing
			ep = strings.ToLower(ep)
		}
	}
	return ep
}

// buildFingerprint creates a dedup fingerprint from vuln type and endpoint.
// Fix ECHO-3: Normalizes the endpoint before fingerprinting so that
// equivalent endpoints (with/without default ports, trailing slashes,
// or case differences) produce the same fingerprint.
func buildFingerprint(vulnType, endpoint string) string {
	normalized := NormalizeVulnType(vulnType)
	generalizedEP := generalizeEndpoint(normalizeEndpointForFingerprint(endpoint))
	input := normalized + ":" + generalizedEP
	hash := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%x", hash[:8])
}

// generateFindingTitle creates a human-readable title for a finding.
func generateFindingTitle(vulnType, endpoint string) string {
	titleMap := map[string]string{
		"sqli":                       "SQL Injection",
		"xss":                        "Cross-Site Scripting (XSS)",
		"xss_stored":                 "Stored Cross-Site Scripting",
		"ssrf":                       "Server-Side Request Forgery (SSRF)",
		"idor":                       "Insecure Direct Object Reference (IDOR)",
		"auth_bypass":                "Authentication Bypass",
		"command_injection":          "OS Command Injection",
		"path_traversal":             "Path Traversal",
		"information_disclosure":     "Information Disclosure",
		"broken_auth":                "Broken Authentication",
		"security_misconfiguration":  "Security Misconfiguration",
		"csrf":                       "Cross-Site Request Forgery (CSRF)",
		"rce":                        "Remote Code Execution (RCE)",
		"race_condition":             "Race Condition",
		"business_logic":             "Business Logic Flaw",
		"mass_assignment":            "Mass Assignment",
		"jwt_manipulation":           "JWT Token Manipulation",
		"account_takeover":           "Account Takeover",
		"file_upload":                "Unrestricted File Upload",
		"ssti":                       "Server-Side Template Injection (SSTI)",
		"deserialization":            "Insecure Deserialization",
	}

	title := titleMap[vulnType]
	if title == "" {
		title = strings.ReplaceAll(vulnType, "_", " ")
		title = strings.Title(title) //nolint:staticcheck
	}

	if endpoint != "" {
		title += " on " + endpoint
	}

	return title
}

// containsVulnIndicator checks if content contains indicators of a specific vuln type.
func containsVulnIndicator(content, vulnType string) bool {
	lower := strings.ToLower(content)
	indicators := map[string][]string{
		"sqli":              {"sql", "union", "select", "inject", "'--"},
		"xss":               {"<script", "alert(", "onerror", "javascript:"},
		"ssrf":              {"169.254", "metadata", "localhost", "127.0.0.1"},
		"idor":              {"unauthorized", "other user", "different user"},
		"command_injection": {"whoami", "id=", "root:", "/etc/passwd"},
		"path_traversal":    {"../", "..\\", "/etc/", "passwd"},
	}

	if patterns, ok := indicators[vulnType]; ok {
		for _, p := range patterns {
			if strings.Contains(lower, p) {
				return true
			}
		}
	}

	// Generic check: does it contain the vuln type name?
	return strings.Contains(lower, strings.ReplaceAll(vulnType, "_", " "))
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "...[truncated]"
}

// severityFromVulnType determines severity using the authoritative CVSS scores
// from ComplianceMappings, keyed by normalized vulnerability type. This replaces
// the broken inferSeverityFromResponse which matched "critical" anywhere in text.
func severityFromVulnType(vulnType string) string {
	normalized := NormalizeVulnType(vulnType)
	if cm := GetComplianceForVulnType(normalized); cm != nil {
		switch {
		case cm.CVSSBase >= 9.0:
			return "critical"
		case cm.CVSSBase >= 7.0:
			return "high"
		case cm.CVSSBase >= 4.0:
			return "medium"
		case cm.CVSSBase >= 0.1:
			return "low"
		default:
			return "info"
		}
	}
	return "medium" // safe default for unmapped vuln types
}

// inferSeverityFromResponse was removed — it matched "critical" anywhere in
// response text (including prompt templates), causing all findings to be CRITICAL.
// Use severityFromVulnType() which uses authoritative CVSS scores instead.

// ─── Context propagation ─────────────────────────────────────────────────────

type evidenceCollectorKey struct{}
type findingRegistryKey struct{}

// WithEvidenceCollector attaches an EvidenceCollector to the context.
func WithEvidenceCollector(ctx context.Context, ec *EvidenceCollector) context.Context {
	return context.WithValue(ctx, evidenceCollectorKey{}, ec)
}

// GetEvidenceCollector retrieves the EvidenceCollector from context.
func GetEvidenceCollector(ctx context.Context) *EvidenceCollector {
	if ec, ok := ctx.Value(evidenceCollectorKey{}).(*EvidenceCollector); ok {
		return ec
	}
	return nil
}

// WithFindingRegistry attaches a FindingRegistry to the context.
func WithFindingRegistry(ctx context.Context, fr *FindingRegistry) context.Context {
	return context.WithValue(ctx, findingRegistryKey{}, fr)
}

// GetFindingRegistry retrieves the FindingRegistry from context.
func GetFindingRegistry(ctx context.Context) *FindingRegistry {
	if fr, ok := ctx.Value(findingRegistryKey{}).(*FindingRegistry); ok {
		return fr
	}
	return nil
}
