package providers

import (
	"fmt"
	"regexp"
	"strings"

	"pentagi/pkg/database"
)

// CrossFlowInsight represents a sanitized finding from another flow that can
// be shared with the current flow's pentester agent to avoid redundant work
// and leverage successful techniques.
type CrossFlowInsight struct {
	FlowID     int64  `json:"flow_id"`
	TargetHint string `json:"target_hint"` // extracted from task input
	VulnType   string `json:"vuln_type"`   // detected from result (e.g., sqli, xss, idor)
	Technique  string `json:"technique"`   // what worked
	Summary    string `json:"summary"`     // brief description
}

// credentialPatterns matches common credential-like strings that should be
// redacted before sharing findings across flows.
var credentialPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|api[_-]?key|auth)\s*[:=]\s*\S+`),
	regexp.MustCompile(`(?i)(bearer|basic)\s+[A-Za-z0-9+/=_-]{8,}`),
	regexp.MustCompile(`[A-Za-z0-9+/]{32,}={0,2}`), // base64-like long strings (potential secrets)
}

// vulnTypePatterns maps VULN_TYPE tags (from the pentester template) to
// human-readable vulnerability categories.
var vulnTypePatterns = map[string]string{
	"sqli":                     "SQL Injection",
	"xss_stored":               "Stored XSS",
	"xss_reflected":            "Reflected XSS",
	"xss_dom":                  "DOM-based XSS",
	"idor":                     "Insecure Direct Object Reference",
	"auth_bypass":              "Authentication Bypass",
	"privilege_escalation":     "Privilege Escalation",
	"path_traversal":           "Path Traversal / LFI",
	"cors_misconfiguration":    "CORS Misconfiguration",
	"mass_assignment":          "Mass Assignment",
	"cryptographic_failure":    "Cryptographic Failure",
	"sensitive_data_exposure":  "Sensitive Data Exposure",
	"command_injection":        "Command Injection / RCE",
	"ssti":                     "Server-Side Template Injection",
	"business_logic":           "Business Logic Flaw",
	"missing_rate_limit":       "Missing Rate Limiting",
	"security_misconfiguration": "Security Misconfiguration",
	"file_upload":              "Unrestricted File Upload",
	"vulnerable_component":     "Vulnerable Component",
	"broken_auth":              "Broken Authentication",
	"ssrf":                     "Server-Side Request Forgery",
	"csrf":                     "Cross-Site Request Forgery",
	"information_disclosure":   "Information Disclosure",
	"api_abuse":                "API Access Control Failure",
	"xxe":                      "XML External Entity",
	"deserialization":          "Insecure Deserialization",
	"open_redirect":            "Open Redirect",
}

// vulnTypeRegex matches [VULN_TYPE: <tag>] markers in subtask results.
var vulnTypeRegex = regexp.MustCompile(`\[VULN_TYPE:\s*(\w+)\]`)

// ExtractCrossFlowInsights processes raw cross-flow finding rows from the
// database and produces sanitized insights suitable for prompt injection.
// It strips credentials and extracts vulnerability types and techniques.
func ExtractCrossFlowInsights(results []database.GetRecentCrossFlowFindingsRow) []CrossFlowInsight {
	insights := make([]CrossFlowInsight, 0, len(results))

	for _, r := range results {
		insight := CrossFlowInsight{
			FlowID:     r.FlowID,
			TargetHint: extractTargetHint(r.TaskInput),
			VulnType:   extractVulnType(r.Result),
			Technique:  extractTechnique(r.Result, r.Title),
			Summary:    sanitizeAndSummarize(r.Result, r.Title),
		}

		// Skip insights where we couldn't extract anything meaningful
		if insight.VulnType == "" && insight.Technique == "" {
			continue
		}

		insights = append(insights, insight)
	}

	return insights
}

// FormatInsightsForPrompt renders the cross-flow insights into a structured
// text block suitable for inclusion in the pentester system prompt.
func FormatInsightsForPrompt(insights []CrossFlowInsight) string {
	if len(insights) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Found %d relevant findings from other concurrent assessments:\n\n", len(insights)))

	for i, insight := range insights {
		sb.WriteString(fmt.Sprintf("### Finding %d (from Flow %d)\n", i+1, insight.FlowID))
		if insight.TargetHint != "" {
			sb.WriteString(fmt.Sprintf("- **Target context:** %s\n", insight.TargetHint))
		}
		if insight.VulnType != "" {
			sb.WriteString(fmt.Sprintf("- **Vulnerability type:** %s\n", insight.VulnType))
		}
		if insight.Technique != "" {
			sb.WriteString(fmt.Sprintf("- **Technique that worked:** %s\n", insight.Technique))
		}
		if insight.Summary != "" {
			sb.WriteString(fmt.Sprintf("- **Summary:** %s\n", insight.Summary))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("**Action:** Consider testing these same vulnerability patterns against your current target. Prioritize techniques that succeeded in other flows.\n")

	return sb.String()
}

// extractTargetHint pulls a brief target description from the task input,
// stripping any sensitive details. Returns at most 200 chars.
func extractTargetHint(taskInput string) string {
	// Redact potential credentials from the task input
	sanitized := redactCredentials(taskInput)

	// Truncate to a reasonable length
	if len(sanitized) > 200 {
		sanitized = sanitized[:200] + "..."
	}

	return strings.TrimSpace(sanitized)
}

// extractVulnType looks for [VULN_TYPE: xxx] tags in the result text.
// Falls back to keyword-based detection if no explicit tag is found.
func extractVulnType(result string) string {
	// First, try to find explicit VULN_TYPE tags
	matches := vulnTypeRegex.FindStringSubmatch(result)
	if len(matches) >= 2 {
		tag := strings.ToLower(strings.TrimSpace(matches[1]))
		if readable, ok := vulnTypePatterns[tag]; ok {
			return readable
		}
		return tag
	}

	// Fallback: keyword-based detection from the result text
	lowerResult := strings.ToLower(result)
	for tag, readable := range vulnTypePatterns {
		// Check for the tag itself or the readable name in the result
		if strings.Contains(lowerResult, strings.ToLower(tag)) ||
			strings.Contains(lowerResult, strings.ToLower(readable)) {
			return readable
		}
	}

	// Generic detection for common vulnerability keywords
	keywordMap := map[string]string{
		"sql injection":     "SQL Injection",
		"cross-site":        "Cross-Site Scripting",
		"default cred":      "Default Credentials",
		"default password":  "Default Credentials",
		"brute force":       "Brute Force Success",
		"directory listing": "Directory Listing",
		"open port":         "Open Port Discovery",
		"rce":               "Remote Code Execution",
		"remote code":       "Remote Code Execution",
		"buffer overflow":   "Buffer Overflow",
		"misconfigur":       "Misconfiguration",
	}

	for keyword, vulnType := range keywordMap {
		if strings.Contains(lowerResult, keyword) {
			return vulnType
		}
	}

	return "Security Finding"
}

// extractTechnique attempts to identify the specific technique or tool used
// from the result and title. Returns a brief description.
func extractTechnique(result, title string) string {
	combined := strings.ToLower(result + " " + title)

	// Look for tool names commonly used in pentesting
	toolPatterns := []struct {
		keyword string
		desc    string
	}{
		{"nmap", "Network scanning with nmap"},
		{"sqlmap", "Automated SQL injection with sqlmap"},
		{"hydra", "Credential brute-force with hydra"},
		{"metasploit", "Exploitation via Metasploit"},
		{"msfconsole", "Exploitation via Metasploit"},
		{"nikto", "Web vulnerability scanning with nikto"},
		{"gobuster", "Directory enumeration with gobuster"},
		{"dirb", "Directory enumeration with dirb"},
		{"wpscan", "WordPress scanning with wpscan"},
		{"nuclei", "Template-based scanning with nuclei"},
		{"ffuf", "Fuzzing with ffuf"},
		{"burp", "Burp Suite analysis"},
		{"crackmapexec", "Network protocol attacks with CrackMapExec"},
		{"impacket", "Windows/AD exploitation with Impacket"},
		{"bloodhound", "AD enumeration with BloodHound"},
		{"enum4linux", "SMB/NetBIOS enumeration"},
		{"searchsploit", "Exploit-DB search with searchsploit"},
	}

	for _, tp := range toolPatterns {
		if strings.Contains(combined, tp.keyword) {
			return tp.desc
		}
	}

	// Look for technique descriptions in the title
	if title != "" && len(title) < 150 {
		return "Approach: " + title
	}

	return ""
}

// sanitizeAndSummarize creates a brief, credential-free summary of the finding.
func sanitizeAndSummarize(result, title string) string {
	// Start with the title if available
	summary := title
	if summary == "" {
		// Extract the first meaningful line from the result
		lines := strings.Split(result, "\n")
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if len(trimmed) > 20 && !strings.HasPrefix(trimmed, "#") {
				summary = trimmed
				break
			}
		}
	}

	// Redact any credentials
	summary = redactCredentials(summary)

	// Truncate
	if len(summary) > 300 {
		summary = summary[:300] + "..."
	}

	return strings.TrimSpace(summary)
}

// redactCredentials removes credential-like patterns from text to prevent
// leaking sensitive information across flows.
func redactCredentials(text string) string {
	for _, pattern := range credentialPatterns {
		text = pattern.ReplaceAllString(text, "[REDACTED]")
	}
	return text
}
