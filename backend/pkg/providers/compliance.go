package providers

import "strings"

// ComplianceMapping represents the mapping of a vulnerability type to compliance standards.
type ComplianceMapping struct {
	VulnType    string   // Normalized vulnerability type key (e.g., "sqli", "xss_stored")
	OWASPTop10  string   // OWASP Top 10 2021 category (e.g., "A03:2021-Injection")
	CWEIDs      []string // Associated CWE identifiers
	CVSSBase    float64  // Typical CVSS v3.1 base score
	Description string   // Brief human-readable description of the vulnerability category
}

// ComplianceMappings is the authoritative lookup table mapping normalized vulnerability
// type strings to their OWASP Top 10 2021 category, CWE IDs, and typical CVSS base scores.
var ComplianceMappings = map[string]ComplianceMapping{
	// ─── A01:2021 – Broken Access Control ───────────────────────────────
	"idor": {
		VulnType:    "idor",
		OWASPTop10:  "A01:2021-Broken Access Control",
		CWEIDs:      []string{"CWE-639", "CWE-284"},
		CVSSBase:    7.5,
		Description: "Insecure Direct Object Reference — accessing resources by manipulating identifiers without authorization checks",
	},
	"auth_bypass": {
		VulnType:    "auth_bypass",
		OWASPTop10:  "A01:2021-Broken Access Control",
		CWEIDs:      []string{"CWE-287", "CWE-863"},
		CVSSBase:    8.8,
		Description: "Authentication or authorization bypass allowing unauthorized access to protected functionality",
	},
	"privilege_escalation": {
		VulnType:    "privilege_escalation",
		OWASPTop10:  "A01:2021-Broken Access Control",
		CWEIDs:      []string{"CWE-269", "CWE-250"},
		CVSSBase:    8.8,
		Description: "Elevating privileges from a lower-privilege context to a higher one (horizontal or vertical)",
	},
	"path_traversal": {
		VulnType:    "path_traversal",
		OWASPTop10:  "A01:2021-Broken Access Control",
		CWEIDs:      []string{"CWE-22", "CWE-23"},
		CVSSBase:    7.5,
		Description: "Directory/path traversal allowing access to files outside the intended directory",
	},
	"cors_misconfiguration": {
		VulnType:    "cors_misconfiguration",
		OWASPTop10:  "A01:2021-Broken Access Control",
		CWEIDs:      []string{"CWE-942", "CWE-346"},
		CVSSBase:    5.3,
		Description: "Overly permissive Cross-Origin Resource Sharing policy allowing unauthorized cross-origin access",
	},
	"mass_assignment": {
		VulnType:    "mass_assignment",
		OWASPTop10:  "A01:2021-Broken Access Control",
		CWEIDs:      []string{"CWE-915"},
		CVSSBase:    6.5,
		Description: "Mass assignment / auto-binding allowing attackers to modify object properties they should not access",
	},

	// ─── A02:2021 – Cryptographic Failures ──────────────────────────────
	"cryptographic_failure": {
		VulnType:    "cryptographic_failure",
		OWASPTop10:  "A02:2021-Cryptographic Failures",
		CWEIDs:      []string{"CWE-327", "CWE-328", "CWE-330"},
		CVSSBase:    7.5,
		Description: "Use of weak, broken, or improperly implemented cryptographic algorithms or protocols",
	},
	"sensitive_data_exposure": {
		VulnType:    "sensitive_data_exposure",
		OWASPTop10:  "A02:2021-Cryptographic Failures",
		CWEIDs:      []string{"CWE-311", "CWE-312", "CWE-319"},
		CVSSBase:    6.5,
		Description: "Sensitive data transmitted or stored without adequate encryption (cleartext passwords, tokens, PII)",
	},

	// ─── A03:2021 – Injection ───────────────────────────────────────────
	"sqli": {
		VulnType:    "sqli",
		OWASPTop10:  "A03:2021-Injection",
		CWEIDs:      []string{"CWE-89"},
		CVSSBase:    9.8,
		Description: "SQL injection allowing execution of arbitrary SQL queries against backend databases",
	},
	"xss_stored": {
		VulnType:    "xss_stored",
		OWASPTop10:  "A03:2021-Injection",
		CWEIDs:      []string{"CWE-79"},
		CVSSBase:    6.1,
		Description: "Stored/persistent Cross-Site Scripting — malicious scripts saved and served to other users",
	},
	"xss_reflected": {
		VulnType:    "xss_reflected",
		OWASPTop10:  "A03:2021-Injection",
		CWEIDs:      []string{"CWE-79"},
		CVSSBase:    6.1,
		Description: "Reflected Cross-Site Scripting — malicious scripts reflected via URL parameters or form inputs",
	},
	"xss_dom": {
		VulnType:    "xss_dom",
		OWASPTop10:  "A03:2021-Injection",
		CWEIDs:      []string{"CWE-79"},
		CVSSBase:    6.1,
		Description: "DOM-based Cross-Site Scripting — client-side script manipulation via DOM environment",
	},
	"command_injection": {
		VulnType:    "command_injection",
		OWASPTop10:  "A03:2021-Injection",
		CWEIDs:      []string{"CWE-78", "CWE-77"},
		CVSSBase:    9.8,
		Description: "OS command injection allowing execution of arbitrary system commands on the host",
	},
	"ssti": {
		VulnType:    "ssti",
		OWASPTop10:  "A03:2021-Injection",
		CWEIDs:      []string{"CWE-1336", "CWE-94"},
		CVSSBase:    9.8,
		Description: "Server-Side Template Injection allowing code execution through template engine abuse",
	},
	"ldap_injection": {
		VulnType:    "ldap_injection",
		OWASPTop10:  "A03:2021-Injection",
		CWEIDs:      []string{"CWE-90"},
		CVSSBase:    8.6,
		Description: "LDAP injection allowing manipulation of LDAP queries for unauthorized data access",
	},
	"xpath_injection": {
		VulnType:    "xpath_injection",
		OWASPTop10:  "A03:2021-Injection",
		CWEIDs:      []string{"CWE-643"},
		CVSSBase:    8.6,
		Description: "XPath injection allowing manipulation of XML queries",
	},

	// ─── A04:2021 – Insecure Design ────────────────────────────────────
	"business_logic": {
		VulnType:    "business_logic",
		OWASPTop10:  "A04:2021-Insecure Design",
		CWEIDs:      []string{"CWE-840", "CWE-841"},
		CVSSBase:    6.5,
		Description: "Business logic flaws allowing abuse of intended application workflows",
	},
	"missing_rate_limit": {
		VulnType:    "missing_rate_limit",
		OWASPTop10:  "A04:2021-Insecure Design",
		CWEIDs:      []string{"CWE-770", "CWE-799"},
		CVSSBase:    5.3,
		Description: "Absence of rate limiting enabling brute-force, credential stuffing, or resource exhaustion",
	},

	// ─── A05:2021 – Security Misconfiguration ───────────────────────────
	"security_misconfiguration": {
		VulnType:    "security_misconfiguration",
		OWASPTop10:  "A05:2021-Security Misconfiguration",
		CWEIDs:      []string{"CWE-16", "CWE-1032"},
		CVSSBase:    5.3,
		Description: "Insecure default configuration, incomplete setup, open cloud storage, verbose error messages",
	},
	"file_upload": {
		VulnType:    "file_upload",
		OWASPTop10:  "A05:2021-Security Misconfiguration",
		CWEIDs:      []string{"CWE-434"},
		CVSSBase:    9.8,
		Description: "Unrestricted file upload allowing execution of malicious files on the server",
	},

	// ─── A06:2021 – Vulnerable and Outdated Components ──────────────────
	"vulnerable_component": {
		VulnType:    "vulnerable_component",
		OWASPTop10:  "A06:2021-Vulnerable and Outdated Components",
		CWEIDs:      []string{"CWE-1104"},
		CVSSBase:    7.5,
		Description: "Use of software components with known vulnerabilities (outdated libraries, frameworks, OS)",
	},

	// ─── A07:2021 – Identification and Authentication Failures ──────────
	"broken_auth": {
		VulnType:    "broken_auth",
		OWASPTop10:  "A07:2021-Identification and Authentication Failures",
		CWEIDs:      []string{"CWE-287", "CWE-384", "CWE-613"},
		CVSSBase:    7.5,
		Description: "Broken authentication mechanisms — weak passwords, session fixation, missing MFA",
	},
	"session_hijacking": {
		VulnType:    "session_hijacking",
		OWASPTop10:  "A07:2021-Identification and Authentication Failures",
		CWEIDs:      []string{"CWE-384", "CWE-614"},
		CVSSBase:    8.1,
		Description: "Session management flaws allowing session hijacking, fixation, or token theft",
	},

	// ─── A08:2021 – Software and Data Integrity Failures ────────────────
	"deserialization": {
		VulnType:    "deserialization",
		OWASPTop10:  "A08:2021-Software and Data Integrity Failures",
		CWEIDs:      []string{"CWE-502"},
		CVSSBase:    9.8,
		Description: "Insecure deserialization leading to remote code execution, injection, or privilege escalation",
	},

	// ─── A09:2021 – Security Logging and Monitoring Failures ────────────
	"insufficient_logging": {
		VulnType:    "insufficient_logging",
		OWASPTop10:  "A09:2021-Security Logging and Monitoring Failures",
		CWEIDs:      []string{"CWE-778", "CWE-223"},
		CVSSBase:    3.8,
		Description: "Insufficient logging, monitoring, or alerting that delays breach detection and response",
	},

	// ─── A10:2021 – Server-Side Request Forgery ─────────────────────────
	"ssrf": {
		VulnType:    "ssrf",
		OWASPTop10:  "A10:2021-Server-Side Request Forgery",
		CWEIDs:      []string{"CWE-918"},
		CVSSBase:    7.5,
		Description: "Server-Side Request Forgery allowing the server to make requests to unintended locations",
	},

	// ─── Cross-category / additional types ──────────────────────────────
	"csrf": {
		VulnType:    "csrf",
		OWASPTop10:  "A01:2021-Broken Access Control",
		CWEIDs:      []string{"CWE-352"},
		CVSSBase:    6.5,
		Description: "Cross-Site Request Forgery — tricking authenticated users into performing unintended actions",
	},
	"open_redirect": {
		VulnType:    "open_redirect",
		OWASPTop10:  "A01:2021-Broken Access Control",
		CWEIDs:      []string{"CWE-601"},
		CVSSBase:    4.7,
		Description: "Open redirect allowing attacker-controlled redirection to phishing or malicious sites",
	},
	"information_disclosure": {
		VulnType:    "information_disclosure",
		OWASPTop10:  "A05:2021-Security Misconfiguration",
		CWEIDs:      []string{"CWE-200", "CWE-209"},
		CVSSBase:    5.3,
		Description: "Unintended information leakage — stack traces, internal IPs, debug pages, directory listings",
	},
	"api_abuse": {
		VulnType:    "api_abuse",
		OWASPTop10:  "A01:2021-Broken Access Control",
		CWEIDs:      []string{"CWE-285", "CWE-284"},
		CVSSBase:    7.5,
		Description: "API-level access control failures — missing function-level authorization, BOLA, BFLA",
	},
	"xxe": {
		VulnType:    "xxe",
		OWASPTop10:  "A05:2021-Security Misconfiguration",
		CWEIDs:      []string{"CWE-611"},
		CVSSBase:    7.5,
		Description: "XML External Entity injection allowing file disclosure, SSRF, or denial of service",
	},
}

// knownAliases maps informal / alternate names to the canonical VulnType key.
var knownAliases = map[string]string{
	"sql_injection":              "sqli",
	"sql injection":              "sqli",
	"xss":                        "xss_reflected",
	"cross-site scripting":       "xss_reflected",
	"cross site scripting":       "xss_reflected",
	"stored xss":                 "xss_stored",
	"reflected xss":              "xss_reflected",
	"dom xss":                    "xss_dom",
	"dom-based xss":              "xss_dom",
	"rce":                        "command_injection",
	"remote code execution":      "command_injection",
	"os command injection":       "command_injection",
	"cmd injection":              "command_injection",
	"template injection":         "ssti",
	"server-side template injection": "ssti",
	"directory traversal":        "path_traversal",
	"lfi":                        "path_traversal",
	"local file inclusion":       "path_traversal",
	"rfi":                        "file_upload",
	"remote file inclusion":      "file_upload",
	"insecure deserialization":   "deserialization",
	"broken authentication":      "broken_auth",
	"authentication bypass":      "auth_bypass",
	"session fixation":           "session_hijacking",
	"priv esc":                   "privilege_escalation",
	"privesc":                    "privilege_escalation",
	"sensitive data":             "sensitive_data_exposure",
	"data exposure":              "sensitive_data_exposure",
	"crypto failure":             "cryptographic_failure",
	"weak crypto":                "cryptographic_failure",
	"misconfig":                  "security_misconfiguration",
	"misconfiguration":           "security_misconfiguration",
	"rate limit":                 "missing_rate_limit",
	"rate limiting":              "missing_rate_limit",
	"brute force":                "missing_rate_limit",
	"info disclosure":            "information_disclosure",
	"information leak":           "information_disclosure",
	"info leak":                  "information_disclosure",
	"redirect":                   "open_redirect",
	"xml external entity":        "xxe",
	"xml injection":              "xxe",
	"cors":                       "cors_misconfiguration",
	"bola":                       "api_abuse",
	"bfla":                       "api_abuse",
	"api":                        "api_abuse",
	"vulnerable dependency":      "vulnerable_component",
	"outdated component":         "vulnerable_component",
	"logging failure":            "insufficient_logging",
	"monitoring failure":         "insufficient_logging",
}

// normalizeKey lowercases and trims the input, then resolves aliases.
func normalizeKey(vulnType string) string {
	key := strings.TrimSpace(strings.ToLower(vulnType))
	// FIX Issue-12 RC2: Replace all common separators with underscore.
	// The widened vulnTypeRegex now captures hyphens and spaces in tags
	// (e.g., "command-injection" or "SQL Injection"), so we must normalize them.
	key = strings.ReplaceAll(key, "-", "_")
	key = strings.ReplaceAll(key, " ", "_")
	if alias, ok := knownAliases[key]; ok {
		return alias
	}
	// Also try the original (un-underscored) form against aliases.
	original := strings.TrimSpace(strings.ToLower(vulnType))
	if alias, ok := knownAliases[original]; ok {
		return alias
	}
	return key
}

// GetComplianceForVulnType returns the compliance mapping for a given vulnerability type.
// It performs case-insensitive lookup and resolves common aliases.
// Returns nil if no mapping is found.
func GetComplianceForVulnType(vulnType string) *ComplianceMapping {
	key := normalizeKey(vulnType)
	if m, ok := ComplianceMappings[key]; ok {
		return &m
	}
	return nil
}

// GetOWASPSummary takes a slice of vulnerability type strings (as tagged by the pentester)
// and returns a map of OWASP Top 10 2021 category → count of findings in that category.
// Unrecognized types are counted under "Unclassified".
func GetOWASPSummary(findings []string) map[string]int {
	summary := make(map[string]int)
	for _, f := range findings {
		m := GetComplianceForVulnType(f)
		if m != nil {
			summary[m.OWASPTop10]++
		} else {
			summary["Unclassified"]++
		}
	}
	return summary
}

// GetAllVulnTypes returns a sorted list of all canonical vulnerability type keys.
// Useful for presenting the standard list to agents.
func GetAllVulnTypes() []string {
	types := make([]string, 0, len(ComplianceMappings))
	for k := range ComplianceMappings {
		types = append(types, k)
	}
	// Sort for deterministic output.
	sortStrings(types)
	return types
}

// sortStrings is a simple insertion sort (avoids importing "sort" for a small slice).
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// CVSSSeverity returns the qualitative severity string for a CVSS v3.1 base score.
func CVSSSeverity(score float64) string {
	switch {
	case score == 0.0:
		return "None"
	case score <= 3.9:
		return "Low"
	case score <= 6.9:
		return "Medium"
	case score <= 8.9:
		return "High"
	default:
		return "Critical"
	}
}
