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

// PreloadFromDB seeds the FindingRegistry with findings already persisted in the
// database from prior subtasks. This ensures that cross-subtask duplicates are
// caught in-memory during the primary extraction path, not just at PersistFindings() time.
//
// SURGEON Fix #1: This is the primary fix for the duplicate findings issue.
// Without this, each subtask starts with an empty seenFingerprints map
// and only deduplicates against DB at the very end (defer PersistFindings).
func (fr *FindingRegistry) PreloadFromDB(existing []database.Finding) {
	fr.mu.Lock()
	defer fr.mu.Unlock()

	for _, f := range existing {
		// Register exact fingerprint
		fr.seenFingerprints[f.Fingerprint] = true

		// Also register the finding in the findings slice for semantic dedup
		fr.findings = append(fr.findings, ReportFinding{
			ID:          fmt.Sprintf("DB-%d", f.ID),
			FlowID:      f.FlowID,
			VulnType:    NormalizeVulnType(f.VulnType),
			Endpoint:    f.Endpoint,
			Fingerprint: f.Fingerprint,
			Severity:    f.Severity,
		})
	}

	logrus.WithField("preloaded_count", len(existing)).
		Debug("FindingRegistry: preloaded DB findings for cross-subtask dedup")
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
	// SURGEON Fix #4: Use validateEndpoint for defense-in-depth sanitization + validation
	endpoint = validateEndpoint(endpoint)

	fp := buildFingerprint(vulnType, endpoint)

	fr.mu.Lock()
	defer fr.mu.Unlock()

	if fr.seenFingerprints[fp] {
		return nil, false // Exact fingerprint duplicate
	}

	// FIX Issue-12 RC1: Semantic dedup based on generalized host+path, not just host.
	// Previously, any two findings of the same vuln_type on the same host were deduped,
	// even if they targeted completely different endpoints (e.g., /api/users vs /api/products).
	// Now we use generalizeEndpoint() which preserves path structure while normalizing IDs,
	// so /api/users/123 and /api/users/456 are still deduped (both become /api/users/{id})
	// but /api/users and /api/products are treated as distinct findings.
	normalizedVT := NormalizeVulnType(vulnType)
	for i, existing := range fr.findings {
		if existing.VulnType != normalizedVT {
			continue
		}
		existingEP := normalizeEndpointForFingerprint(existing.Endpoint)
		newEP := normalizeEndpointForFingerprint(endpoint)
		existingGenEP := generalizeEndpoint(existingEP)
		newGenEP := generalizeEndpoint(newEP)

		var isSemDupe bool
		if existingGenEP == "" && newGenEP == "" {
			// Both vague → true duplicate
			isSemDupe = true
		} else if existingGenEP == "" && newGenEP != "" {
			// Existing is vague, new has details → upgrade existing (mark as dupe, upgrade below)
			isSemDupe = true
		} else if existingGenEP != "" && newGenEP == "" {
			// New is vague, existing has details → skip the vague one
			isSemDupe = true
		} else {
			// Both have endpoints → compare generalized full endpoint (host+path)
			isSemDupe = existingGenEP == newGenEP
		}

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
// Fix AUDITOR-4: Added semantic dedup at DB level to prevent cross-subtask
// duplicates where the same vulnerability is found by different subtasks with
// slightly different endpoints (e.g., with URL vs without URL).
func (fr *FindingRegistry) PersistFindings(ctx context.Context, db database.Querier) {
	fr.mu.Lock()
	findings := make([]ReportFinding, len(fr.findings))
	copy(findings, fr.findings)
	fr.mu.Unlock()

	if len(findings) == 0 {
		return
	}

	// Load existing DB findings for this flow ONCE for semantic cross-subtask dedup.
	existingFindings, err := db.GetFlowFindings(ctx, fr.flowID)
	if err != nil {
		logrus.WithError(err).Warn("PersistFindings: failed to load existing findings for dedup (proceeding with fingerprint-only dedup)")
		existingFindings = nil
	}

	for _, f := range findings {
		// SURGEON Fix #1: Skip preloaded DB findings — they already exist in the database.
		if strings.HasPrefix(f.ID, "DB-") {
			continue
		}

		// Check 1: Exact fingerprint dedup.
		_, err := db.GetFindingByFingerprint(ctx, database.GetFindingByFingerprintParams{
			Fingerprint: f.Fingerprint,
			FlowID:      f.FlowID,
		})
		if err == nil {
			continue // Already exists (exact fingerprint match).
		}

		// Check 2: Semantic cross-subtask dedup — same vuln_type + same host.
		// This catches the Flow 25 bug where the same finding was stored twice:
		// once with a URL (from primary extraction) and once without (from
		// FINDINGS.md sync), producing different fingerprints but representing
		// the same vulnerability.
		if isSemanticDBDuplicate(f, existingFindings) {
			logrus.WithFields(logrus.Fields{
				"vuln_type":   f.VulnType,
				"endpoint":    f.Endpoint,
				"fingerprint": f.Fingerprint,
			}).Debug("PersistFindings: semantic dedup — skipping cross-subtask duplicate")
			continue
		}

		// SURGEON Fix #4: Final validation before DB insert — defense-in-depth
		f.Endpoint = validateEndpoint(f.Endpoint)

		var subtaskID sql.NullInt64
		if f.SubtaskID != nil {
			subtaskID = sql.NullInt64{Int64: *f.SubtaskID, Valid: true}
		}
		var rootCauseID sql.NullInt64

		// Fix AUDITOR-4: Auto-confirm findings with strong evidence patterns.
		confirmed := f.Confirmed || autoConfirmFromEvidence(f)

		newFinding, createErr := db.CreateFinding(ctx, database.CreateFindingParams{
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
			Confirmed:     confirmed,
			FalsePositive: f.FalsePositive,
			RootCauseID:   rootCauseID,
		})
		if createErr != nil {
			logrus.WithError(createErr).WithFields(logrus.Fields{
				"flow_id":     f.FlowID,
				"vuln_type":   f.VulnType,
				"fingerprint": f.Fingerprint,
			}).Warn("failed to persist finding to DB")
		} else {
			// Add to existing findings so subsequent findings in this batch
			// can also be deduped against it.
			existingFindings = append(existingFindings, database.Finding{
				ID:          newFinding.ID,
				FlowID:      f.FlowID,
				VulnType:    f.VulnType,
				Endpoint:    f.Endpoint,
				Fingerprint: f.Fingerprint,
			})
		}
	}
}

// isSemanticDBDuplicate checks whether a finding is a semantic duplicate of any
// existing DB finding. Two findings are semantic duplicates if they have the same
// normalized vuln_type AND either:
//   - one has an empty endpoint and the other doesn't (same finding, different detail level)
//   - both share the same hostname
//
// This mirrors the in-memory semantic dedup in CheckAndRegister but operates
// against the DB state, catching cross-subtask duplicates.
// isSemanticDBDuplicate checks whether a finding is a semantic duplicate of any
// existing DB finding. FIX Issue-12 RC1: Uses generalizeEndpoint() for host+path
// comparison instead of just extractHost(). This matches the in-memory dedup logic.
func isSemanticDBDuplicate(f ReportFinding, existing []database.Finding) bool {
	if len(existing) == 0 {
		return false
	}

	newVT := NormalizeVulnType(f.VulnType)
	newEP := normalizeEndpointForFingerprint(f.Endpoint)
	newGenEP := generalizeEndpoint(newEP)

	for _, ex := range existing {
		exVT := NormalizeVulnType(ex.VulnType)
		if exVT != newVT {
			continue
		}

		exEP := normalizeEndpointForFingerprint(ex.Endpoint)
		exGenEP := generalizeEndpoint(exEP)

		// Both vague → duplicate
		if exGenEP == "" && newGenEP == "" {
			return true
		}
		// Existing vague, new specific → NOT a duplicate. The new finding has
		// concrete endpoint details that the vague one lacks. Let it through so
		// the DB gets the more informative record.
		if exGenEP == "" && newGenEP != "" {
			continue
		}
		// New vague, existing specific → skip vague
		if exGenEP != "" && newGenEP == "" {
			return true
		}
		// Both have endpoints → compare generalized full endpoint
		if exGenEP == newGenEP {
			return true
		}
	}
	return false
}

// autoConfirmFromEvidence checks whether a finding's description/evidence contains
// strong indicators that the vulnerability was actually exploited (not just detected).
// This addresses the Flow 25 bug where 0% of findings were confirmed despite having
// clear PoC evidence (baseline 401 vs injected 500, data extraction, etc.).
func autoConfirmFromEvidence(f ReportFinding) bool {
	// Combine description and all evidence content for analysis
	var textToCheck string
	textToCheck = f.Description
	for _, ev := range f.Evidence {
		textToCheck += " " + ev.Content
	}

	lower := strings.ToLower(textToCheck)

	// Pattern 1: Error differential (baseline vs injected)
	errorDiffPatterns := []string{
		"baseline",
		"vs injected",
		"response differ",
		"status code changed",
		"different response",
		"error differ",
	}

	// Pattern 2: HTTP status differentials that indicate exploitation
	statusPatterns := []string{
		"401 to 200", "403 to 200", "401→200", "403→200",
		"returned 500", "returned 200", "got 500", "got 200",
		"status 500", "status 200",
		"500 internal server error",
	}

	// Pattern 3: Data extraction evidence
	dataPatterns := []string{
		"extracted", "dumped", "leaked", "disclosed",
		"password", "token", "secret", "credential",
		"successfully", "confirmed",
	}

	// Pattern 4: Active exploitation evidence
	exploitPatterns := []string{
		"poc", "proof of concept", "proof-of-concept",
		"exploit", "payload executed", "injection successful",
		"alert(1)", "alert(xss)", "<script",
		"union select", "' or 1=1", "' or '1'='1",
		"whoami", "uid=", "root:",
		"/etc/passwd",
		"oob callback", "interactsh", "out-of-band",
	}

	// Check each pattern group — require match from at least one strong group
	for _, p := range exploitPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}

	// Error differential + status pattern = confirmed
	hasErrorDiff := false
	for _, p := range errorDiffPatterns {
		if strings.Contains(lower, p) {
			hasErrorDiff = true
			break
		}
	}
	hasStatusChange := false
	for _, p := range statusPatterns {
		if strings.Contains(lower, p) {
			hasStatusChange = true
			break
		}
	}
	if hasErrorDiff && hasStatusChange {
		return true
	}

	// Data extraction + another indicator = confirmed
	dataMatches := 0
	for _, p := range dataPatterns {
		if strings.Contains(lower, p) {
			dataMatches++
		}
	}
	if dataMatches >= 2 {
		return true
	}

	// Agent explicitly says [CONFIRMED] in finding text
	if strings.Contains(lower, "[confirmed]") {
		return true
	}

	return false
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
// Supports two formats:
//   Format A (legacy): [FINDING: F-NNN] ... [FINDING: | EOF
//   Format B (actual agent output): ### [SEV] [CONFIDENCE] F-NNN: <title>
var findingsMDBlockRegex = regexp.MustCompile(
	`(?s)\[FINDING:\s*F-\d+\].*?(?:\[FINDING:|\z)`,
)

// findingsMDHeaderBlockRegex matches the format agents actually write per the
// pentester.tmpl template:
//   ### [CRITICAL] [CONFIRMED] F-001: Title here
//   [VULN_TYPE: sqli]
//   - **Target:** https://example.com/api
// FIX Issue-12 RC2: Made more flexible per VERDICT direction.
//   - Accepts ##, ###, #### heading levels (was: ### only)
//   - Accepts zero or more [bracketed] groups (was: 1-2)
//   - Accepts F-NNN or Finding-NNN numbering (not #NNN — too ambiguous per VERDICT)
var findingsMDHeaderBlockRegex = regexp.MustCompile(
	`(?m)^#{2,4}\s+(?:\[.+?\]\s+)*(?:F-\d+|Finding[- ]\d+)`,
)

// FIX Issue-12 RC2: Accept hyphens and spaces in VULN_TYPE tags.
// LLMs often write [VULN_TYPE: command-injection] or [VULN_TYPE: SQL Injection]
// instead of the canonical [VULN_TYPE: command_injection].
var findingsMDVulnTypeRegex = regexp.MustCompile(`\[VULN_TYPE:\s*([\w]+(?:[- ][\w]+)*)\]`)
var findingsMDSeverityRegex = regexp.MustCompile(`(?i)(?:Severity:\s*|###\s*\[)(Critical|High|Medium|Low|Info)`)
var findingsMDTargetRegex = regexp.MustCompile(`(?i)(?:Target:|\*\*Target:\*\*)\s*(.+)`)
var findingsMDTitleRegex = regexp.MustCompile(`(?i)(?:Title:\s*|F-\d+:\s*)(.+)`)
var findingsMDDescRegex = regexp.MustCompile(`(?i)(?:Description:|\*\*Impact:\*\*)\s*(.+)`)

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
	// Strategy 1: Try [FINDING: F-NNN] block format (legacy)
	blocks := findingsMDBlockRegex.FindAllString(content, -1)

	// Strategy 2: If no legacy blocks, try ### header format (actual agent output)
	// Agents write: ### [SEV] [CONFIDENCE] F-NNN: <title>
	if len(blocks) == 0 {
		blocks = splitByHeaderBlocks(content)
	}

	// Strategy 3: If still no blocks, scan for bare [VULN_TYPE:] tags anywhere
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

		// Fix AUDITOR-4: Use CVSS-based severity as primary, but fall back to
		// agent's written severity when the vuln type is not in ComplianceMappings.
		// This fixes the Flow 25 bug where agent classified as MEDIUM/LOW but DB
		// stored "info" — which happened because unmapped vuln types defaulted to
		// "medium" via severityFromVulnType, but in edge cases could produce "info".
		severity := severityFromVulnType(vulnType)
		if sevMatch := findingsMDSeverityRegex.FindStringSubmatch(block); len(sevMatch) >= 2 {
			agentSev := strings.ToLower(sevMatch[1])
			// If the vuln type is not in ComplianceMappings, prefer the agent's
			// severity — the agent has context about the specific finding.
			if GetComplianceForVulnType(vulnType) == nil && agentSev != "" {
				severity = agentSev
				logrus.WithFields(logrus.Fields{
					"vuln_type":      vulnType,
					"agent_severity": agentSev,
				}).Debug("FINDINGS.md sync: using agent severity for unmapped vuln type")
			} else if agentSev != severity {
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

// splitByHeaderBlocks splits FINDINGS.md content into blocks using the
// ### header format that agents actually produce per the pentester.tmpl template.
// Each block starts at a ### line containing F-NNN and ends before the next
// such header (or EOF). Only returns blocks that contain [VULN_TYPE: xxx].
func splitByHeaderBlocks(content string) []string {
	// Find all header positions
	locs := findingsMDHeaderBlockRegex.FindAllStringIndex(content, -1)
	if len(locs) == 0 {
		return nil
	}

	var blocks []string
	for i, loc := range locs {
		start := loc[0]
		end := len(content)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		block := content[start:end]

		// If block has explicit VULN_TYPE tag, include as-is
		if findingsMDVulnTypeRegex.MatchString(block) {
			blocks = append(blocks, block)
			continue
		}

		// FIX Issue-12 RC2: Try to infer VULN_TYPE from block content keywords.
		// Blocks without explicit tags are normally silently dropped, causing
		// finding loss. This fallback injects a synthetic tag when possible.
		if inferred := inferVulnTypeFromBlock(block); inferred != "" {
			block = block + "\n[VULN_TYPE: " + inferred + "]"
			blocks = append(blocks, block)
			logrus.WithFields(logrus.Fields{
				"inferred_type": inferred,
				"block_preview": truncateString(block, 200),
			}).Info("FINDINGS.md sync: inferred VULN_TYPE for block missing explicit tag")
		}
		// If inference fails, the block is still dropped (truly unrecoverable)
	}
	return blocks
}

// inferVulnTypeFromBlock tries to determine the vulnerability type from
// a finding block's content when the [VULN_TYPE:] tag is missing.
// Returns the canonical vuln type tag, or empty string if inference fails.
//
// FIX Issue-12 RC2: Per VERDICT, this is a last-resort fallback that only fires
// for blocks already matched by findingsMDHeaderBlockRegex (confirmed findings).
// Patterns are ordered most-specific first to avoid misclassification.
func inferVulnTypeFromBlock(block string) string {
	lower := strings.ToLower(block)

	// Check against known patterns, most specific first
	patterns := []struct {
		keywords   []string
		vulnType   string
		confidence string // HIGH or LOW_CONFIDENCE — per VERDICT requirement
	}{
		{[]string{"sql injection", "sqli", "union select", "' or "}, "sqli", "HIGH"},
		{[]string{"stored xss", "stored cross-site"}, "xss_stored", "HIGH"},
		{[]string{"reflected xss", "reflected cross-site"}, "xss_reflected", "HIGH"},
		{[]string{"dom xss", "dom-based xss", "dom based xss"}, "xss_dom", "HIGH"},
		{[]string{"cross-site scripting", "xss"}, "xss_reflected", "HIGH"},
		{[]string{"idor", "insecure direct object", "bola"}, "idor", "HIGH"},
		{[]string{"authentication bypass", "auth bypass"}, "auth_bypass", "HIGH"},
		{[]string{"privilege escalation", "privesc"}, "privilege_escalation", "HIGH"},
		{[]string{"path traversal", "directory traversal", "lfi", "local file inclusion"}, "path_traversal", "HIGH"},
		{[]string{"ssrf", "server-side request forgery"}, "ssrf", "HIGH"},
		{[]string{"csrf", "cross-site request forgery"}, "csrf", "HIGH"},
		{[]string{"command injection", "rce", "remote code execution", "os command"}, "command_injection", "HIGH"},
		{[]string{"ssti", "server-side template injection", "template injection"}, "ssti", "HIGH"},
		{[]string{"open redirect"}, "open_redirect", "HIGH"},
		{[]string{"xxe", "xml external entity"}, "xxe", "HIGH"},
		{[]string{"deserialization"}, "deserialization", "HIGH"},
		{[]string{"account takeover"}, "account_takeover", "HIGH"},
		{[]string{"jwt", "json web token"}, "jwt_manipulation", "HIGH"},
		{[]string{"file upload", "unrestricted upload"}, "file_upload", "HIGH"},
		{[]string{"mass assignment"}, "mass_assignment", "HIGH"},
		{[]string{"race condition"}, "race_condition", "HIGH"},
		// LOW_CONFIDENCE inferences — generic keywords per VERDICT requirement
		{[]string{"information disclosure", "info disclosure", "data leak"}, "information_disclosure", "LOW_CONFIDENCE"},
		{[]string{"sensitive data exposure", "data exposure"}, "sensitive_data_exposure", "LOW_CONFIDENCE"},
		{[]string{"security misconfiguration", "misconfiguration"}, "security_misconfiguration", "LOW_CONFIDENCE"},
		{[]string{"broken authentication", "broken auth"}, "broken_auth", "LOW_CONFIDENCE"},
		{[]string{"cors misconfiguration", "cors"}, "cors_misconfiguration", "LOW_CONFIDENCE"},
		{[]string{"missing rate limit", "rate limit"}, "missing_rate_limit", "LOW_CONFIDENCE"},
		{[]string{"business logic"}, "business_logic", "LOW_CONFIDENCE"},
		{[]string{"api abuse", "bfla", "broken function"}, "api_abuse", "LOW_CONFIDENCE"},
	}

	for _, p := range patterns {
		for _, kw := range p.keywords {
			if strings.Contains(lower, kw) {
				if p.confidence == "LOW_CONFIDENCE" {
					logrus.WithFields(logrus.Fields{
						"keyword":    kw,
						"vuln_type":  p.vulnType,
						"confidence": "LOW_CONFIDENCE",
					}).Warn("inferVulnTypeFromBlock: low-confidence inference — review recommended")
				}
				return p.vulnType
			}
		}
	}

	return ""
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

// sanitizeEndpoint strips shell-style template variables, trailing artifacts,
// credentials, markdown formatting, and multiline content from endpoint strings.
// Ensures the endpoint field contains ONLY a clean URL or path.
//
// SURGEON Fix #4: Enhanced sanitization to prevent credentials, API keys,
// and markdown artifacts from leaking into the findings database.
func sanitizeEndpoint(endpoint string) string {
	ep := strings.TrimSpace(endpoint)
	if ep == "" {
		return ""
	}

	// Step 0: Replace literal escaped newlines (\n, \r) with actual newlines
	// LLM agents often emit "\n" as a literal 2-char string rather than a real newline
	ep = strings.ReplaceAll(ep, "\\n", "\n")
	ep = strings.ReplaceAll(ep, "\\r", "\r")

	// Step 1: Remove markdown formatting artifacts
	ep = markdownCleanRegex.ReplaceAllString(ep, "")

	// Step 2: Take only the first line (prevent multiline content)
	if idx := strings.IndexByte(ep, '\n'); idx != -1 {
		ep = ep[:idx]
	}

	// Step 3: Extract the URL portion — stop at first space, parenthesis,
	// or credential-indicator after the URL.
	// If the string contains a URL, extract just the URL.
	if urlMatch := endpointURLExtractRegex.FindString(ep); urlMatch != "" {
		ep = urlMatch
	} else {
		// No URL found — might be a bare path like /api/users/123
		// Take content up to first space or parenthesis
		if idx := strings.IndexAny(ep, " \t("); idx != -1 {
			ep = ep[:idx]
		}
	}

	// Step 4: Remove shell-style template variables: ${port}, ${path}, $port, $path
	ep = shellVarRegex.ReplaceAllString(ep, "")

	// Step 5: Remove trailing backslashes (common LLM artifact)
	ep = strings.TrimRight(ep, "\\")

	// Step 6: Remove trailing colons left after stripping :${port}
	ep = strings.TrimRight(ep, ":")

	// Step 7: Clean up any triple+ slashes in path (but preserve ://)
	for strings.Contains(ep, "///") {
		ep = strings.ReplaceAll(ep, "///", "//")
	}

	// Step 8: Final credential scrub — if anything credential-like leaked through,
	// truncate at the credential boundary
	ep = credentialBoundaryRegex.ReplaceAllString(ep, "")

	// Step 9: Remove trailing punctuation that's not part of a URL
	ep = strings.TrimRight(ep, " \t,;|>")

	return strings.TrimSpace(ep)
}

// validateEndpoint enforces strict format rules on the endpoint field:
// - Must be a valid URL (with scheme) or a relative path starting with /
// - Must not contain embedded credentials, tokens, or markdown
// - Must not exceed 2048 characters
// - Must be single-line
//
// Returns the cleaned endpoint, or empty string if the input is irrecoverable.
//
// SURGEON Fix #4: Strict validation as a defense-in-depth layer.
func validateEndpoint(endpoint string) string {
	// First apply sanitization
	ep := sanitizeEndpoint(endpoint)
	if ep == "" {
		return ""
	}

	// Length check — URLs shouldn't be longer than 2048 chars
	if len(ep) > 2048 {
		ep = ep[:2048]
	}

	// Must be single-line
	if strings.ContainsAny(ep, "\n\r") {
		// Take first line only
		lines := strings.SplitN(ep, "\n", 2)
		ep = strings.TrimSpace(lines[0])
	}

	// Validate format: must be a URL or a path
	isURL := strings.HasPrefix(ep, "http://") || strings.HasPrefix(ep, "https://")
	isPath := strings.HasPrefix(ep, "/")
	isHostPort := hostPortRegex.MatchString(ep)

	if !isURL && !isPath && !isHostPort {
		// Not a recognizable endpoint format — try to extract a URL
		if urlMatch := endpointURLExtractRegex.FindString(ep); urlMatch != "" {
			return urlMatch
		}
		// Cannot salvage — return empty
		logrus.WithField("raw_endpoint", truncateString(ep, 200)).
			Warn("SURGEON-4: endpoint failed validation — discarding")
		return ""
	}

	// Credential detection — reject if obvious credentials are embedded
	if containsCredentialPattern(ep) {
		// Try to extract just the URL portion before the credential
		if urlMatch := endpointURLExtractRegex.FindString(ep); urlMatch != "" {
			return urlMatch
		}
		logrus.WithField("raw_endpoint", truncateString(ep, 200)).
			Warn("SURGEON-4: endpoint contains credentials — truncating to URL only")
		return ""
	}

	return ep
}

// containsCredentialPattern checks if a string contains obvious credential patterns.
func containsCredentialPattern(s string) bool {
	lower := strings.ToLower(s)
	credPatterns := []string{
		"password", "passwd", "pwd",
		"api_key", "apikey", "api-key",
		"secret", "token",
		"anon key", "anon_key",
		"bearer ", "authorization:",
	}
	for _, p := range credPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	// Check for JWT tokens (eyJ...)
	if strings.Contains(s, "eyJ") && len(s) > 50 {
		return true
	}
	return false
}

// markdownCleanRegex strips common markdown artifacts from endpoint strings.
var markdownCleanRegex = regexp.MustCompile(`(?:\*{1,2}|#{1,6}|` + "`" + `|~{2,3})`)

// endpointURLExtractRegex matches a URL (scheme + authority + optional path/query).
// Stops at whitespace, parentheses, or common credential delimiters.
var endpointURLExtractRegex = regexp.MustCompile(
	`https?://[^\s<>()"'` + "`" + `]+`,
)

// credentialBoundaryRegex matches patterns that indicate the start of credential
// data appended after a URL. Truncates everything from the match onward.
var credentialBoundaryRegex = regexp.MustCompile(
	`(?i)\s*(?:` +
		`\((?:anon|api|auth|bearer|token|key|secret|password|cred)` + // (Anon Key: ...
		`|(?:anon|api|auth|bearer|token|key|secret|password|cred)\s*[:=]` + // token: xxx, key=xxx
		`|eyJ[A-Za-z0-9_-]{10,}` + // JWT tokens (start with eyJ)
		`|[A-Za-z0-9+/]{40,}={0,2}` + // Long base64 strings (likely tokens)
		`).*$`,
)

// hostPortRegex matches host:port patterns like "api.example.com:8443"
var hostPortRegex = regexp.MustCompile(`^[a-zA-Z0-9][-a-zA-Z0-9.]*:\d{1,5}(?:/.*)?$`)

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
