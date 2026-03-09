package providers

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// Finding represents a single vulnerability finding from the pentesting agent.
type Finding struct {
	ID          string // Unique identifier, e.g., "F001"
	VulnType    string // Canonical vulnerability type from compliance.go (e.g., "sqli", "idor")
	Endpoint    string // URL path (e.g., "/api/users/123")
	Parameter   string // Affected parameter name (e.g., "id", "username")
	Method      string // HTTP method (e.g., "GET", "POST")
	Severity    string // CRITICAL, HIGH, MEDIUM, LOW
	Description string // Human-readable description of the finding
	Evidence    string // Proof / reproduction steps
	RootCauseID string // Assigned by the dedup engine after grouping
}

// RootCause represents a deduplicated group of findings sharing a common root cause.
type RootCause struct {
	ID       string    // Unique root cause identifier, e.g., "RC-001"
	VulnType string    // Canonical vulnerability type shared by all grouped findings
	Pattern  string    // Generalized endpoint pattern (e.g., "/api/users/{id}")
	Findings []Finding // All findings grouped under this root cause
	Severity string    // Highest severity among grouped findings
}

// DedupEngine detects duplicate vulnerability findings and groups them by root cause.
// It is safe for concurrent use.
type DedupEngine struct {
	mu         sync.RWMutex
	rootCauses []RootCause
	findingSeq int // monotonic counter for finding IDs
	rcSeq      int // monotonic counter for root cause IDs
}

// NewDedupEngine creates a new, empty deduplication engine.
func NewDedupEngine() *DedupEngine {
	return &DedupEngine{
		rootCauses: make([]RootCause, 0),
	}
}

// AddFinding processes a new finding, either grouping it with an existing root cause
// or creating a new one. Returns the assigned RootCauseID.
//
// Dedup strategy (conservative — false negatives preferred over false positives):
//  1. Normalize the VulnType via compliance.go alias resolution.
//  2. Different VulnTypes are NEVER grouped together.
//  3. Same VulnType + same generalized endpoint pattern → same root cause.
//  4. Same VulnType + same parameter name (non-empty) on any endpoint → same root cause.
//  5. Otherwise → new root cause.
func (d *DedupEngine) AddFinding(f Finding) string {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Assign a finding ID if not already set.
	d.findingSeq++
	if f.ID == "" {
		f.ID = fmt.Sprintf("F%03d", d.findingSeq)
	}

	// Normalize VulnType through the compliance alias system.
	normalized := normalizeKey(f.VulnType)
	f.VulnType = normalized

	endpointPattern := generalizeEndpoint(f.Endpoint)

	// Try to find a matching root cause.
	for i := range d.rootCauses {
		rc := &d.rootCauses[i]

		// Rule: different VulnTypes are NEVER grouped.
		if rc.VulnType != normalized {
			continue
		}

		matched := false

		// Strategy 1: Same VulnType + same generalized endpoint pattern.
		if endpointPattern != "" && rc.Pattern != "" && endpointPattern == rc.Pattern {
			matched = true
		}

		// Strategy 2: Same VulnType + same non-empty parameter name.
		if !matched && f.Parameter != "" {
			for _, existing := range rc.Findings {
				if strings.EqualFold(existing.Parameter, f.Parameter) {
					matched = true
					break
				}
			}
		}

		if matched {
			f.RootCauseID = rc.ID
			rc.Findings = append(rc.Findings, f)
			// Promote severity if the new finding is more severe.
			rc.Severity = highestSeverity(rc.Severity, f.Severity)
			// Widen the pattern if endpoints differ but are related.
			rc.Pattern = mergePatterns(rc.Pattern, endpointPattern)
			return rc.ID
		}
	}

	// No match — create a new root cause.
	d.rcSeq++
	rcID := fmt.Sprintf("RC-%03d", d.rcSeq)
	f.RootCauseID = rcID

	rc := RootCause{
		ID:       rcID,
		VulnType: normalized,
		Pattern:  endpointPattern,
		Findings: []Finding{f},
		Severity: f.Severity,
	}
	d.rootCauses = append(d.rootCauses, rc)
	return rcID
}

// GetRootCauses returns a copy of all root causes with their grouped findings.
func (d *DedupEngine) GetRootCauses() []RootCause {
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := make([]RootCause, len(d.rootCauses))
	for i, rc := range d.rootCauses {
		findings := make([]Finding, len(rc.Findings))
		copy(findings, rc.Findings)
		result[i] = RootCause{
			ID:       rc.ID,
			VulnType: rc.VulnType,
			Pattern:  rc.Pattern,
			Findings: findings,
			Severity: rc.Severity,
		}
	}
	return result
}

// GetUniqueCount returns the number of unique root causes (deduplicated vulnerability count).
func (d *DedupEngine) GetUniqueCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.rootCauses)
}

// GetDuplicateCount returns the total number of findings that were grouped as duplicates
// (total findings minus unique root causes).
func (d *DedupEngine) GetDuplicateCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()

	total := 0
	for _, rc := range d.rootCauses {
		total += len(rc.Findings)
	}
	return total - len(d.rootCauses)
}

// GetTotalFindings returns the total number of findings processed.
func (d *DedupEngine) GetTotalFindings() int {
	d.mu.RLock()
	defer d.mu.RUnlock()

	total := 0
	for _, rc := range d.rootCauses {
		total += len(rc.Findings)
	}
	return total
}

// Summary returns a human-readable dedup summary string.
func (d *DedupEngine) Summary() string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	total := 0
	for _, rc := range d.rootCauses {
		total += len(rc.Findings)
	}

	return fmt.Sprintf(
		"Dedup Summary: %d total findings → %d unique root causes (%d duplicates removed, %.0f%% reduction)",
		total,
		len(d.rootCauses),
		total-len(d.rootCauses),
		dedupReductionPct(total, len(d.rootCauses)),
	)
}

// ──────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────────────────────────────────────

// numericSegment matches path segments that are purely numeric (IDs).
var numericSegment = regexp.MustCompile(`^[0-9]+$`)

// uuidSegment matches UUID-shaped path segments.
var uuidSegment = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// hexIDSegment matches hex strings of 8+ characters that look like IDs (e.g., MongoDB ObjectIDs).
var hexIDSegment = regexp.MustCompile(`^[0-9a-fA-F]{8,}$`)

// generalizeEndpoint strips dynamic segments (numeric IDs, UUIDs, hex IDs) from URL paths
// and replaces them with {id} placeholders to create a pattern for grouping.
//
// Examples:
//
//	"/api/users/123"          → "/api/users/{id}"
//	"/api/users/123/posts/45" → "/api/users/{id}/posts/{id}"
//	"/api/items/abc-def-..."  → "/api/items/{id}"  (UUID)
func generalizeEndpoint(endpoint string) string {
	if endpoint == "" {
		return ""
	}

	// Strip query string and fragment for pattern matching.
	ep := endpoint
	if idx := strings.IndexByte(ep, '?'); idx != -1 {
		ep = ep[:idx]
	}
	if idx := strings.IndexByte(ep, '#'); idx != -1 {
		ep = ep[:idx]
	}

	parts := strings.Split(ep, "/")
	for i, part := range parts {
		if part == "" {
			continue
		}
		if numericSegment.MatchString(part) || uuidSegment.MatchString(part) || hexIDSegment.MatchString(part) {
			parts[i] = "{id}"
		}
	}
	return strings.Join(parts, "/")
}

// mergePatterns returns the more general of two patterns, or the common one if equal.
// For now we keep the existing pattern since both have already been generalized.
func mergePatterns(existing, incoming string) string {
	if existing == "" {
		return incoming
	}
	if incoming == "" {
		return existing
	}
	// If they match after generalization, keep as-is.
	if existing == incoming {
		return existing
	}
	// If one is a prefix of the other, keep the shorter (more general) one.
	if strings.HasPrefix(incoming, existing) {
		return existing
	}
	if strings.HasPrefix(existing, incoming) {
		return incoming
	}
	// Otherwise keep existing — conservative approach.
	return existing
}

// severityRank maps severity strings to numeric ranks for comparison.
var severityRank = map[string]int{
	"CRITICAL": 4,
	"HIGH":     3,
	"MEDIUM":   2,
	"LOW":      1,
	"INFO":     0,
}

// highestSeverity returns the more severe of two severity strings.
func highestSeverity(a, b string) string {
	ra := severityRank[strings.ToUpper(a)]
	rb := severityRank[strings.ToUpper(b)]
	if rb > ra {
		return strings.ToUpper(b)
	}
	return strings.ToUpper(a)
}

// dedupReductionPct calculates the percentage of findings removed by dedup.
func dedupReductionPct(total, unique int) float64 {
	if total == 0 {
		return 0
	}
	return float64(total-unique) / float64(total) * 100
}
