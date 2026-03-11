package providers

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

const defaultMaxNucleiScansPerDomain = 2

// nucleiTracker prevents redundant nuclei scans against the same domain.
// Thread-safe for concurrent use across agent goroutines.
type nucleiTracker struct {
	mu           sync.Mutex
	domains      map[string]int         // normalized domain → scan count
	scans        []nucleiScanRecord     // history for summary
	maxPerDomain int                    // default 2
}

// nucleiScanRecord logs a single nuclei scan for history/summary.
type nucleiScanRecord struct {
	Domain    string
	Tags      string
	Severity  string
	FindCount int
	Timestamp time.Time
}

// newNucleiTracker creates a tracker with the default per-domain limit.
func newNucleiTracker() *nucleiTracker {
	return &nucleiTracker{
		domains:      make(map[string]int),
		maxPerDomain: defaultMaxNucleiScansPerDomain,
	}
}

// Check returns (blocked, message) for a target domain. If the domain has
// already been scanned maxPerDomain times, it returns a blocking message
// with a summary of prior scans.
func (nt *nucleiTracker) Check(target string) (bool, string) {
	domain := normalizeDomain(target)
	if domain == "" {
		return false, ""
	}

	nt.mu.Lock()
	defer nt.mu.Unlock()

	count := nt.domains[domain]
	if count < nt.maxPerDomain {
		return false, ""
	}

	// Build summary of prior scans for this domain.
	var priorScans []string
	for _, s := range nt.scans {
		if s.Domain == domain {
			priorScans = append(priorScans, fmt.Sprintf(
				"  - %s: tags=%q severity=%q findings=%d",
				s.Timestamp.Format("15:04:05"), s.Tags, s.Severity, s.FindCount,
			))
		}
	}

	msg := fmt.Sprintf(
		"BLOCKED: Nuclei scan of '%s' denied — already scanned %d times (limit: %d).\n"+
			"Prior scans:\n%s\n"+
			"Use the findings you already have. Try a different target or a different tool.",
		domain, count, nt.maxPerDomain, strings.Join(priorScans, "\n"),
	)
	return true, msg
}

// Record logs a completed nuclei scan. Call after successful execution.
func (nt *nucleiTracker) Record(domain, tags, severity string, findCount int) {
	normalized := normalizeDomain(domain)
	if normalized == "" {
		return
	}

	nt.mu.Lock()
	defer nt.mu.Unlock()

	nt.domains[normalized]++
	nt.scans = append(nt.scans, nucleiScanRecord{
		Domain:    normalized,
		Tags:      tags,
		Severity:  severity,
		FindCount: findCount,
		Timestamp: time.Now(),
	})
}

// normalizeDomain extracts the hostname from a URL or host string and lowercases it.
// Examples:
//
//	"https://lapicart.com/path?q=1" → "lapicart.com"
//	"http://lapicart.com"           → "lapicart.com"
//	"lapicart.com:8080"             → "lapicart.com"
//	"192.168.1.100"                 → "192.168.1.100"
//	"lapicart.com"                  → "lapicart.com"
func normalizeDomain(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}

	// If it doesn't have a scheme, add one so url.Parse works correctly.
	parseTarget := target
	if !strings.Contains(parseTarget, "://") {
		parseTarget = "https://" + parseTarget
	}

	u, err := url.Parse(parseTarget)
	if err != nil {
		// Fallback: lowercase the raw input.
		return strings.ToLower(target)
	}

	host := u.Hostname() // strips port
	if host == "" {
		return strings.ToLower(target)
	}

	return strings.ToLower(host)
}

// extractNucleiTarget extracts the target from nuclei_scan tool call arguments.
func extractNucleiTarget(funcArgs string) string {
	var args map[string]interface{}
	if err := json.Unmarshal([]byte(funcArgs), &args); err != nil {
		return ""
	}
	if target, ok := args["target"].(string); ok {
		return target
	}
	return ""
}

// extractNucleiScanDetails extracts tags and severity from nuclei_scan arguments.
func extractNucleiScanDetails(funcArgs string) (tags, severity string) {
	var args map[string]interface{}
	if err := json.Unmarshal([]byte(funcArgs), &args); err != nil {
		return "", ""
	}
	if t, ok := args["tags"].(string); ok {
		tags = t
	}
	if s, ok := args["severity"].(string); ok {
		severity = s
	}
	return tags, severity
}

// extractNucleiTargetFromCmd extracts the target from a shell command containing "nuclei".
// It looks for -u or -target flags followed by a URL/host argument.
func extractNucleiTargetFromCmd(cmd string) string {
	fields := strings.Fields(cmd)
	for i, field := range fields {
		if (field == "-u" || field == "-target" || field == "--target") && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}
