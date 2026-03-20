package providers

import (
	"fmt"
	"strings"
	"sync"
)

// FindingTracker monitors tool call responses for vulnerability type markers and
// generates attack chain suggestions when HIGH or CRITICAL findings are detected.
// It is instantiated per-subtask inside performAgentChain and is goroutine-safe.
//
// Usage:
//
//	tracker := NewFindingTracker()
//	tracker.RecordFinding(toolResponse)       // after each tool call
//	if tracker.HasNewHighFindings() {
//	    msg := tracker.GetChainSuggestions()   // inject into agent chain
//	}
type FindingTracker struct {
	// discoveredVulns accumulates all vuln types detected this subtask (in order).
	discoveredVulns []string

	// injectedChainFor tracks vuln types for which chain suggestions have already
	// been injected, preventing duplicate injections.
	injectedChainFor map[string]bool

	// newHighFindings holds vuln types detected since the last call to
	// GetChainSuggestions (i.e., un-injected HIGH+ findings).
	newHighFindings []string

	// maxChainInjectionsPerSubtask caps the total number of chain suggestion
	// injections per subtask to prevent context bloat.
	maxChainInjectionsPerSubtask int

	// chainInjectionCount tracks how many times chain suggestions have been injected.
	chainInjectionCount int

	mu sync.Mutex
}

// ChainSuggestion holds formatted chain suggestions ready for prompt injection.
type ChainSuggestion struct {
	// TriggerVulns lists the vuln types that triggered this suggestion.
	TriggerVulns []string
	// FormattedMsg is the full message suitable for injection as a human-role message.
	FormattedMsg string
}

// NewFindingTracker creates a new FindingTracker with sensible defaults.
func NewFindingTracker() *FindingTracker {
	return &FindingTracker{
		discoveredVulns:              make([]string, 0),
		injectedChainFor:             make(map[string]bool),
		newHighFindings:              make([]string, 0),
		maxChainInjectionsPerSubtask: 3,
	}
}

// RecordFinding scans a tool response for [VULN_TYPE: xxx] markers and records
// any discovered HIGH or CRITICAL findings. Uses the vulnTypeRegex from cross_flow.go.
func (ft *FindingTracker) RecordFinding(response string) {
	if response == "" {
		return
	}

	matches := vulnTypeRegex.FindAllStringSubmatch(response, -1)
	if len(matches) == 0 {
		return
	}

	ft.mu.Lock()
	defer ft.mu.Unlock()

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		raw := match[1]
		normalized := normalizeKey(raw)

		// Record all discovered vulns for reporting.
		ft.discoveredVulns = append(ft.discoveredVulns, normalized)

		// Only track as "new high" if it's HIGH or CRITICAL and hasn't been injected yet.
		if ft.isHighOrCritical(normalized) && !ft.injectedChainFor[normalized] {
			ft.newHighFindings = append(ft.newHighFindings, normalized)
		}
	}
}

// HasNewHighFindings returns true if there are un-injected HIGH/CRITICAL findings
// and we haven't exceeded the per-subtask injection cap.
func (ft *FindingTracker) HasNewHighFindings() bool {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	return len(ft.newHighFindings) > 0 && ft.chainInjectionCount < ft.maxChainInjectionsPerSubtask
}

// GetChainSuggestions returns a ChainSuggestion for all pending new HIGH findings,
// marks them as injected, and resets the pending list.
// Returns nil if no suggestions are available.
func (ft *FindingTracker) GetChainSuggestions() *ChainSuggestion {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	if len(ft.newHighFindings) == 0 || ft.chainInjectionCount >= ft.maxChainInjectionsPerSubtask {
		return nil
	}

	// Deduplicate pending findings.
	unique := deduplicateStrings(ft.newHighFindings)

	// Generate chain suggestions using the existing FormatChainsForPrompt from chains.go.
	chainText := FormatChainsForPrompt(unique)
	if chainText == "" {
		// No chains available for these vuln types — still mark them as processed.
		for _, v := range unique {
			ft.injectedChainFor[v] = true
		}
		ft.newHighFindings = ft.newHighFindings[:0]
		return nil
	}

	// Build the injection message with clear system prefix.
	var sb strings.Builder
	sb.WriteString("[SYSTEM-AUTO: ATTACK CHAIN SUGGESTION]\n")
	sb.WriteString(fmt.Sprintf("Findings detected: %s\n\n", strings.Join(unique, ", ")))
	sb.WriteString(chainText)
	sb.WriteString("\nContinue escalation along these chains before moving to the next category. ")
	sb.WriteString("Focus on Priority 1 chains first — they have the highest success probability.")

	suggestion := &ChainSuggestion{
		TriggerVulns: unique,
		FormattedMsg: sb.String(),
	}

	// Mark all as injected and reset pending list.
	for _, v := range unique {
		ft.injectedChainFor[v] = true
	}
	ft.newHighFindings = ft.newHighFindings[:0]
	ft.chainInjectionCount++

	return suggestion
}

// GetDiscoveredVulns returns a copy of all vuln types discovered this subtask.
func (ft *FindingTracker) GetDiscoveredVulns() []string {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	result := make([]string, len(ft.discoveredVulns))
	copy(result, ft.discoveredVulns)
	return result
}

// HasDiscoveredVuln checks whether a specific vuln type has been detected this subtask.
func (ft *FindingTracker) HasDiscoveredVuln(vulnType string) bool {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	normalized := normalizeKey(vulnType)
	for _, v := range ft.discoveredVulns {
		if v == normalized {
			return true
		}
	}
	return false
}

// GetInjectionCount returns how many chain suggestion injections have been made.
func (ft *FindingTracker) GetInjectionCount() int {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	return ft.chainInjectionCount
}

// isHighOrCritical checks if a normalized vuln type is HIGH or CRITICAL severity
// based on ComplianceMappings CVSS scores (>= 7.0 = HIGH).
func (ft *FindingTracker) isHighOrCritical(normalizedVuln string) bool {
	cm := GetComplianceForVulnType(normalizedVuln)
	if cm == nil {
		// Unknown vuln type — treat conservatively as potentially high.
		return true
	}
	return cm.CVSSBase >= 7.0
}

// ─── Attack Chain Templates ─────────────────────────────────────────────────
// These encode the 10 most impactful attack chain patterns observed across real
// penetration test engagements. They complement the per-vuln chains in chains.go
// by providing higher-level multi-step escalation paths.

// AttackChainTemplate represents a full multi-step escalation path triggered by
// an initial finding. Unlike the per-vuln chains in chains.go (which suggest a
// SINGLE next step), these templates map the FULL escalation path from initial
// discovery to maximum impact.
type AttackChainTemplate struct {
	// Name is a human-readable label for the chain pattern.
	Name string
	// TriggerKeywords are substrings to match in tool output (case-insensitive)
	// that indicate this chain should be suggested.
	TriggerKeywords []string
	// Steps describes the ordered sequence of exploitation steps.
	Steps []string
	// MaxImpact describes the highest possible impact if the chain completes.
	MaxImpact string
}

// attackChainTemplates contains the 10 canonical chain templates derived from
// ADVICE_COMBINED.md analysis of real engagement patterns.
var attackChainTemplates = []AttackChainTemplate{
	{
		Name:            ".git Exposure → Credential Harvest → Full Compromise",
		TriggerKeywords: []string{".git", "git-dumper", ".git/HEAD", ".git/config", "git repository"},
		Steps: []string{
			"1. Dump full git repository using git-dumper",
			"2. Run trufflehog/gitleaks on commit history for leaked secrets",
			"3. Extract .env files, config files, and hardcoded credentials from all commits",
			"4. Test extracted credentials against login endpoints, APIs, and admin panels",
			"5. If JWT secret found: forge admin JWT → full account takeover",
			"6. If DB creds found: attempt direct DB access or SQLi with known schema",
		},
		MaxImpact: "Full compromise via leaked credentials (RCE/ATO)",
	},
	{
		Name:            "SSRF → Cloud Metadata → Infrastructure Takeover",
		TriggerKeywords: []string{"ssrf", "169.254.169.254", "metadata", "cloud metadata", "imds", "fd00:ec2"},
		Steps: []string{
			"1. Confirm SSRF via Interactsh OOB callback",
			"2. Fetch cloud metadata: http://169.254.169.254/latest/meta-data/iam/security-credentials/",
			"3. Try Azure IMDS: http://169.254.169.254/metadata/instance?api-version=2021-02-01",
			"4. Extract IAM temporary credentials (AccessKeyId, SecretAccessKey, Token)",
			"5. Use stolen IAM creds to enumerate cloud resources (S3, EC2, Lambda, secrets)",
			"6. Attempt lateral movement within cloud infrastructure",
		},
		MaxImpact: "Full cloud infrastructure compromise",
	},
	{
		Name:            "XSS → Cookie Theft → Session Hijack → Account Takeover",
		TriggerKeywords: []string{"xss", "stored xss", "reflected xss", "document.cookie", "alert(", "script>"},
		Steps: []string{
			"1. Confirm XSS executes in victim browser context",
			"2. Inject payload to exfiltrate document.cookie or localStorage tokens",
			"3. Use stolen session token to hijack authenticated session",
			"4. As hijacked user: perform privileged actions (password change, email change)",
			"5. If admin XSS: create new admin account or extract all user data",
			"6. Demonstrate full ATO with evidence of actions performed as victim",
		},
		MaxImpact: "Account Takeover (potentially admin-level)",
	},
	{
		Name:            "SQLi → Data Extraction → Credential Reuse → Lateral Movement",
		TriggerKeywords: []string{"sqli", "sql injection", "union select", "sqlmap", "blind sql", "error-based"},
		Steps: []string{
			"1. Confirm SQLi and identify database type and version",
			"2. Extract database schema (tables, columns, relationships)",
			"3. Dump credentials table: usernames, password hashes, API keys",
			"4. Crack password hashes or use extracted API keys for auth bypass",
			"5. Test credential reuse across other endpoints and services",
			"6. Attempt stacked queries for RCE: xp_cmdshell (MSSQL), LOAD_FILE (MySQL)",
		},
		MaxImpact: "Full database access + potential RCE via stacked queries",
	},
	{
		Name:            "GraphQL Introspection → Schema Exploitation → Data Exfiltration",
		TriggerKeywords: []string{"graphql", "introspection", "__schema", "__type", "graphql endpoint"},
		Steps: []string{
			"1. Run introspection query to dump full GraphQL schema",
			"2. Identify sensitive queries/mutations (user data, admin actions, payments)",
			"3. Test for IDOR via object ID manipulation in queries",
			"4. Test for SQLi/NoSQL injection in query arguments",
			"5. Use batch/alias queries for rate limit bypass and data enumeration",
			"6. Test mutations for unauthorized state changes (privilege escalation)",
		},
		MaxImpact: "Full data exfiltration + unauthorized state changes",
	},
	{
		Name:            "OAuth/SSO Misconfiguration → Token Theft → Account Takeover",
		TriggerKeywords: []string{"oauth", "redirect_uri", "authorization_code", "openid", "sso", "saml"},
		Steps: []string{
			"1. Map OAuth flow parameters (client_id, redirect_uri, response_type, scope)",
			"2. Test redirect_uri manipulation (open redirect → token theft)",
			"3. Test response_type downgrade (code → token for implicit flow leakage)",
			"4. Test scope escalation (request admin scope on user token)",
			"5. Chain with open redirect: steal authorization code via crafted redirect",
			"6. Exchange stolen code/token for full account access",
		},
		MaxImpact: "Account Takeover via stolen OAuth tokens",
	},
	{
		Name:            "Swagger/API Docs Exposure → Endpoint Discovery → Privilege Escalation",
		TriggerKeywords: []string{"swagger", "openapi", "api-docs", "api/docs", "redoc", "/v1/", "/v2/", "/v3/"},
		Steps: []string{
			"1. Download and parse full API specification",
			"2. Identify admin-only and internal endpoints from documentation",
			"3. Test each endpoint for broken function-level authorization (BFLA)",
			"4. Test IDOR on all object-referencing endpoints",
			"5. Look for deprecated/hidden endpoints (v1 vs v2 differences)",
			"6. Test mass assignment on all POST/PUT/PATCH endpoints",
		},
		MaxImpact: "Full API access with privilege escalation",
	},
	{
		Name:            "File Upload → Web Shell → Remote Code Execution",
		TriggerKeywords: []string{"file upload", "upload", "multipart", "file_upload", "unrestricted upload"},
		Steps: []string{
			"1. Test upload with various executable extensions (.php, .jsp, .aspx, .py)",
			"2. Bypass extension filters (double ext, null byte, content-type spoofing)",
			"3. Upload web shell and locate uploaded file URL",
			"4. Execute OS commands via web shell (whoami, id, env)",
			"5. Read environment variables and config files for further credentials",
			"6. Attempt privilege escalation via sudo/SUID/kernel exploits",
		},
		MaxImpact: "Remote Code Execution with potential root access",
	},
	{
		Name:            "IDOR → Horizontal Escalation → Sensitive Data Mass Extraction",
		TriggerKeywords: []string{"idor", "bola", "insecure direct object", "object reference", "user_id", "account_id"},
		Steps: []string{
			"1. Confirm IDOR by accessing another user's resource via ID manipulation",
			"2. Test vertical escalation: replace user ID with admin/superuser IDs",
			"3. Enumerate all CRUD operations (GET, POST, PUT, DELETE) with other user IDs",
			"4. Bulk-extract records by iterating through sequential/predictable IDs",
			"5. Chain with business actions: transfer funds, change ownership as other user",
			"6. Test across all API endpoints that accept user/object identifiers",
		},
		MaxImpact: "Mass data extraction + unauthorized actions as any user",
	},
	{
		Name:            "SSTI → Template Engine RCE → Server Compromise",
		TriggerKeywords: []string{"ssti", "template injection", "{{7*7}}", "${7*7}", "jinja2", "twig", "freemarker"},
		Steps: []string{
			"1. Confirm SSTI with math expression ({{7*7}} → 49)",
			"2. Identify template engine type and version",
			"3. Use engine-specific gadgets for RCE (Jinja2: __import__, Twig: system())",
			"4. Execute OS commands and read environment variables",
			"5. Extract application source code and configuration",
			"6. Pivot to internal network using server access",
		},
		MaxImpact: "Full server compromise via RCE",
	},
}

// CheckForChainOpportunity scans a tool result string for patterns that match
// known attack chain templates and returns the most relevant chain suggestion.
// Returns nil if no chain template matches.
//
// This function uses keyword matching (not regex) for performance — it runs
// on every tool call response and must complete in <1ms.
func CheckForChainOpportunity(toolResult string) *ChainSuggestion {
	if toolResult == "" {
		return nil
	}

	lower := strings.ToLower(toolResult)

	var bestMatch *AttackChainTemplate
	bestScore := 0

	for i := range attackChainTemplates {
		score := 0
		for _, kw := range attackChainTemplates[i].TriggerKeywords {
			if strings.Contains(lower, strings.ToLower(kw)) {
				score++
			}
		}
		if score > bestScore {
			bestScore = score
			bestMatch = &attackChainTemplates[i]
		}
	}

	// Require at least 1 keyword match.
	if bestMatch == nil || bestScore < 1 {
		return nil
	}

	// Format the chain template as a suggestion.
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[SYSTEM-AUTO: ATTACK CHAIN DETECTED — %s]\n\n", bestMatch.Name))
	sb.WriteString("Recommended escalation steps:\n")
	for _, step := range bestMatch.Steps {
		sb.WriteString(fmt.Sprintf("  %s\n", step))
	}
	sb.WriteString(fmt.Sprintf("\nMaximum potential impact: %s\n", bestMatch.MaxImpact))
	sb.WriteString("Follow this chain to maximize finding severity before moving to the next category.")

	return &ChainSuggestion{
		TriggerVulns: bestMatch.TriggerKeywords[:1], // use first keyword as representative
		FormattedMsg: sb.String(),
	}
}

// deduplicateStrings returns a new slice with duplicate strings removed,
// preserving order of first occurrence.
func deduplicateStrings(input []string) []string {
	seen := make(map[string]bool, len(input))
	result := make([]string, 0, len(input))
	for _, s := range input {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
