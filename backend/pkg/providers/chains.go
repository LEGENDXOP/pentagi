package providers

import (
	"fmt"
	"strings"
)

// ChainedAttack represents a follow-up attack that becomes viable after discovering
// a specific vulnerability type. Real pentesters chain findings — this codifies that reasoning.
type ChainedAttack struct {
	VulnType  string // canonical vuln type tag from compliance.go to test next
	Technique string // specific, actionable technique description
	Reason    string // why the trigger finding enables this attack
	Priority  int    // 1=immediate (high confidence), 2=should try, 3=if time permits
}

// AttackChain groups a trigger vulnerability type with its follow-up attacks.
type AttackChain struct {
	TriggerVulnType string
	NextAttacks     []ChainedAttack
}

// AttackChains maps a discovered vulnerability type to the follow-up attacks it enables.
// Each entry contains 3-5 chained attacks ordered by priority.
// These chains encode the reasoning a senior pentester uses when pivoting from one finding to the next.
var AttackChains = map[string][]ChainedAttack{

	// ─── idor ───────────────────────────────────────────────────────────
	"idor": {
		{VulnType: "privilege_escalation", Technique: "Replace user ID with admin/superuser ID in the same API endpoint and check for vertical access", Reason: "IDOR proves object-level auth is broken — role-level auth is likely broken too", Priority: 1},
		{VulnType: "information_disclosure", Technique: "Enumerate sequential/predictable IDs to bulk-extract all records from the endpoint", Reason: "If one record leaks via IDOR, the entire dataset is likely extractable", Priority: 1},
		{VulnType: "api_abuse", Technique: "Test the same ID manipulation on all CRUD operations (PUT, DELETE, PATCH) not just GET", Reason: "Read IDOR often extends to write/delete IDOR on the same resource", Priority: 1},
		{VulnType: "business_logic", Technique: "Chain IDOR with business actions — transfer funds, change ownership, approve requests as another user", Reason: "Object reference flaws combined with state-changing actions create critical business impact", Priority: 2},
		{VulnType: "sensitive_data_exposure", Technique: "Check if IDOR-accessible records contain PII, credentials, or tokens not visible in normal responses", Reason: "Admin or other-user records often contain fields stripped from the requester's own view", Priority: 2},
	},

	// ─── auth_bypass ────────────────────────────────────────────────────
	"auth_bypass": {
		{VulnType: "privilege_escalation", Technique: "Access admin panels, management endpoints, and role-restricted APIs using the bypass method", Reason: "If authentication is bypassable, admin-only functionality is directly reachable", Priority: 1},
		{VulnType: "api_abuse", Technique: "Replay the bypass across all discovered API endpoints to map unauthenticated attack surface", Reason: "Auth bypass on one endpoint usually means the same middleware flaw affects many endpoints", Priority: 1},
		{VulnType: "sensitive_data_exposure", Technique: "Access user data exports, backup endpoints, and configuration APIs without authentication", Reason: "Data-heavy endpoints behind auth are now fully exposed", Priority: 1},
		{VulnType: "information_disclosure", Technique: "Hit debug, health-check, and metrics endpoints (e.g., /actuator, /debug/pprof) that rely on auth", Reason: "Internal monitoring endpoints often exist but are hidden behind auth — bypass reveals them", Priority: 2},
		{VulnType: "business_logic", Technique: "Perform privileged business operations (approvals, deletions, config changes) without auth", Reason: "State-changing operations without authentication create maximum business impact", Priority: 2},
	},

	// ─── sqli ───────────────────────────────────────────────────────────
	"sqli": {
		{VulnType: "sensitive_data_exposure", Technique: "Use UNION SELECT or blind techniques to dump credentials table, API keys, and PII", Reason: "SQLi grants direct database read access — credentials and secrets are the first target", Priority: 1},
		{VulnType: "auth_bypass", Technique: "Extract password hashes and session tokens from the database, or use tautology bypass on login", Reason: "Database access means auth data is directly readable or bypassable", Priority: 1},
		{VulnType: "command_injection", Technique: "Attempt stacked queries with xp_cmdshell (MSSQL), LOAD_FILE/INTO OUTFILE (MySQL), or COPY (PostgreSQL)", Reason: "Some DBMS configs allow OS command execution from SQL context", Priority: 2},
		{VulnType: "information_disclosure", Technique: "Enumerate database schema, table names, user privileges, and DB version for further exploitation", Reason: "Schema knowledge reveals hidden tables, admin flags, and application architecture", Priority: 2},
		{VulnType: "privilege_escalation", Technique: "UPDATE user role/is_admin fields directly in the database via stacked queries or second-order SQLi", Reason: "Write access to the users table means self-promotion to admin", Priority: 2},
	},

	// ─── xss_stored ─────────────────────────────────────────────────────
	"xss_stored": {
		{VulnType: "session_hijacking", Technique: "Inject payload that exfiltrates document.cookie or localStorage tokens to attacker-controlled server", Reason: "Stored XSS executes in every victim's browser — session tokens are trivially stealable", Priority: 1},
		{VulnType: "privilege_escalation", Technique: "Craft XSS payload that triggers admin-only actions (create admin user, change permissions) when admin views the page", Reason: "If an admin triggers the stored XSS, the payload runs with admin privileges in their session", Priority: 1},
		{VulnType: "csrf", Technique: "Use XSS to bypass CSRF protections by reading CSRF tokens from the DOM and issuing forged requests", Reason: "XSS in same origin can read any anti-CSRF token, making CSRF protections useless", Priority: 2},
		{VulnType: "information_disclosure", Technique: "Inject keylogger or form-grabber script to capture credentials typed on the page", Reason: "Persistent script execution enables long-term credential harvesting from all page visitors", Priority: 2},
		{VulnType: "sensitive_data_exposure", Technique: "Exfiltrate page content, hidden form fields, and API responses visible to each victim's session", Reason: "Each user who triggers the XSS leaks their personal data visible on that page", Priority: 3},
	},

	// ─── ssrf ───────────────────────────────────────────────────────────
	"ssrf": {
		{VulnType: "information_disclosure", Technique: "Fetch cloud metadata endpoints (169.254.169.254, metadata.google.internal) for IAM credentials and tokens", Reason: "SSRF from cloud-hosted apps almost always leaks instance metadata with temporary credentials", Priority: 1},
		{VulnType: "sensitive_data_exposure", Technique: "Scan internal network services (Redis, Elasticsearch, Memcached on default ports) for unauthenticated data access", Reason: "Internal services typically lack auth — SSRF provides network-level access to reach them", Priority: 1},
		{VulnType: "api_abuse", Technique: "Proxy requests through SSRF to access internal APIs, admin panels, and microservices not exposed externally", Reason: "SSRF turns the server into a proxy, giving access to the entire internal network", Priority: 1},
		{VulnType: "path_traversal", Technique: "Use file:// protocol handler to read local files (/etc/passwd, application configs, .env files)", Reason: "Many SSRF implementations support file:// URIs enabling local file read", Priority: 2},
		{VulnType: "command_injection", Technique: "Target internal services with known RCE vulnerabilities (Redis SLAVEOF, Memcached injection, Gopher protocol attacks)", Reason: "Internal services reachable via SSRF often run unpatched and are exploitable for RCE", Priority: 3},
	},

	// ─── information_disclosure ─────────────────────────────────────────
	"information_disclosure": {
		{VulnType: "broken_auth", Technique: "Use leaked credentials, API keys, or tokens from error pages/debug output to authenticate as other users", Reason: "Disclosed credentials or tokens provide direct authentication bypass", Priority: 1},
		{VulnType: "sensitive_data_exposure", Technique: "Follow up on discovered internal IPs and service names to map internal architecture for further attacks", Reason: "Internal network details enable targeted attacks against specific services", Priority: 2},
		{VulnType: "sqli", Technique: "Use disclosed database type, version, and table names to craft precise injection payloads", Reason: "Database details from error messages eliminate blind SQLi guesswork", Priority: 2},
		{VulnType: "privilege_escalation", Technique: "Leverage disclosed user roles, permission structures, or admin endpoints to target privilege boundaries", Reason: "Knowledge of the authorization model reveals exactly where to attack for escalation", Priority: 2},
		{VulnType: "vulnerable_component", Technique: "Research CVEs for disclosed software versions (Server headers, X-Powered-By, stack traces with library versions)", Reason: "Exact version numbers from headers/errors map directly to known CVEs", Priority: 3},
	},

	// ─── security_misconfiguration ──────────────────────────────────────
	"security_misconfiguration": {
		{VulnType: "broken_auth", Technique: "Try default credentials on discovered admin panels, databases, and management interfaces", Reason: "Misconfigured deployments frequently retain default credentials", Priority: 1},
		{VulnType: "information_disclosure", Technique: "Access exposed debug endpoints (/debug, /actuator, /phpinfo, /.env, /server-status)", Reason: "Misconfigurations often leave debug/monitoring endpoints publicly accessible", Priority: 1},
		{VulnType: "path_traversal", Technique: "Test for directory listing and traverse from exposed directories to sensitive files", Reason: "Directory listing combined with traversal exposes the full filesystem", Priority: 2},
		{VulnType: "sensitive_data_exposure", Technique: "Check for exposed .git, .svn, .env, backup files, and source code archives", Reason: "Misconfigured servers often serve version control and config files", Priority: 2},
		{VulnType: "privilege_escalation", Technique: "Abuse misconfigured CORS, permissive CSP, or missing security headers to escalate access", Reason: "Missing security headers enable client-side attacks that lead to privilege escalation", Priority: 3},
	},

	// ─── file_upload ────────────────────────────────────────────────────
	"file_upload": {
		{VulnType: "command_injection", Technique: "Upload a web shell (PHP/JSP/ASPX) and execute OS commands through the uploaded file's URL", Reason: "Unrestricted upload + server-side execution = full RCE via web shell", Priority: 1},
		{VulnType: "xss_stored", Technique: "Upload an HTML/SVG file containing JavaScript — when served, it executes in the application's origin", Reason: "HTML/SVG uploads served from the same origin are equivalent to stored XSS", Priority: 1},
		{VulnType: "path_traversal", Technique: "Manipulate the filename parameter (../../etc/cron.d/shell) to write files outside the upload directory", Reason: "Upload handlers that don't sanitize filenames allow arbitrary file write via traversal", Priority: 2},
		{VulnType: "ssrf", Technique: "Upload a file with an embedded URL reference (XXE in DOCX/SVG, SSRF in image processing)", Reason: "File processing libraries (ImageMagick, LibreOffice) often fetch embedded URLs", Priority: 2},
		{VulnType: "deserialization", Technique: "Upload serialized object payloads disguised as legitimate file types to trigger insecure deserialization", Reason: "File processing pipelines may deserialize uploaded content unsafely", Priority: 3},
	},

	// ─── path_traversal ─────────────────────────────────────────────────
	"path_traversal": {
		{VulnType: "sensitive_data_exposure", Technique: "Read /etc/shadow, .env files, database configs, and application.yml for credentials and secrets", Reason: "Path traversal gives filesystem read access — config files contain credentials", Priority: 1},
		{VulnType: "information_disclosure", Technique: "Read application source code to discover hidden endpoints, hardcoded secrets, and business logic", Reason: "Source code access reveals the entire application architecture and all secret material", Priority: 1},
		{VulnType: "broken_auth", Technique: "Extract session secret keys, JWT signing keys, or OAuth client secrets from config files", Reason: "Cryptographic keys from config files allow forging valid sessions and tokens", Priority: 1},
		{VulnType: "command_injection", Technique: "If write-capable (via null byte or parameter pollution), overwrite cron jobs, SSH authorized_keys, or .bashrc", Reason: "Path traversal with write access enables arbitrary code execution through file overwrites", Priority: 2},
		{VulnType: "privilege_escalation", Technique: "Read /etc/passwd and SUID binary lists to identify local privilege escalation vectors", Reason: "System file access reveals user accounts and potential local privesc paths", Priority: 3},
	},

	// ─── command_injection ──────────────────────────────────────────────
	"command_injection": {
		{VulnType: "sensitive_data_exposure", Technique: "Read environment variables (env, printenv), config files, and database connection strings from the server", Reason: "OS access means full access to every secret on the filesystem and in memory", Priority: 1},
		{VulnType: "privilege_escalation", Technique: "Check sudo -l, SUID binaries, kernel version for local privesc; try sudo/SUID/kernel exploits", Reason: "Command injection as a web user is the starting point for root escalation", Priority: 1},
		{VulnType: "information_disclosure", Technique: "Map internal network with ifconfig/ip, arp -a, netstat, and /etc/hosts to discover adjacent targets", Reason: "Internal network reconnaissance reveals lateral movement targets", Priority: 2},
		{VulnType: "ssrf", Technique: "Use curl/wget from the compromised server to reach internal services, metadata APIs, and cloud resources", Reason: "Shell access is the ultimate SSRF — reach any network-accessible service", Priority: 2},
		{VulnType: "broken_auth", Technique: "Dump running processes (ps aux) and memory to extract credentials, tokens, and session data", Reason: "In-memory secrets (DB passwords, API keys) are accessible with OS-level access", Priority: 3},
	},

	// ─── broken_auth ────────────────────────────────────────────────────
	"broken_auth": {
		{VulnType: "privilege_escalation", Technique: "Use compromised low-privilege credentials to test for vertical escalation to admin/superuser roles", Reason: "Valid credentials are the prerequisite for testing authorization boundaries", Priority: 1},
		{VulnType: "session_hijacking", Technique: "Analyze session token generation for predictability — test sequential tokens, weak entropy, or reuse after logout", Reason: "Broken auth often correlates with weak session management", Priority: 1},
		{VulnType: "idor", Technique: "Authenticate as different users and compare API responses to find object-level authorization gaps", Reason: "Multiple valid sessions enable systematic horizontal access control testing", Priority: 2},
		{VulnType: "sensitive_data_exposure", Technique: "Access authenticated endpoints that expose user data, payment info, or internal reports", Reason: "Authentication grants access to data-rich areas of the application", Priority: 2},
		{VulnType: "api_abuse", Technique: "Test all API endpoints with the compromised credentials looking for missing function-level authorization", Reason: "Valid auth tokens allow testing every endpoint for broken function-level access control", Priority: 3},
	},

	// ─── csrf ───────────────────────────────────────────────────────────
	"csrf": {
		{VulnType: "privilege_escalation", Technique: "Craft CSRF payload that adds attacker-controlled account as admin or changes victim's role to elevated", Reason: "CSRF on role-management endpoints directly yields privilege escalation", Priority: 1},
		{VulnType: "business_logic", Technique: "Chain CSRF with state-changing operations — fund transfers, order placement, account settings changes", Reason: "CSRF on critical business functions creates maximum real-world impact", Priority: 1},
		{VulnType: "broken_auth", Technique: "Use CSRF to change the victim's password or email, then take over their account via password reset", Reason: "CSRF on account settings endpoints enables full account takeover", Priority: 2},
		{VulnType: "sensitive_data_exposure", Technique: "Trigger data export or report generation via CSRF and redirect output to attacker-controlled destination", Reason: "If export functionality lacks CSRF protection, data can be exfiltrated through the victim", Priority: 3},
	},

	// ─── missing_rate_limit (rate_limit_bypass) ─────────────────────────
	"missing_rate_limit": {
		{VulnType: "broken_auth", Technique: "Brute-force login credentials using common password lists (rockyou top 1000) against discovered usernames", Reason: "Missing rate limits make credential brute-force trivially feasible", Priority: 1},
		{VulnType: "sensitive_data_exposure", Technique: "Enumerate valid usernames, emails, or account IDs through rapid requests to registration/reset endpoints", Reason: "Rate-limit absence allows mass enumeration of user data", Priority: 1},
		{VulnType: "business_logic", Technique: "Abuse rate-unlimited actions for financial gain — coupon reuse, referral abuse, voting manipulation", Reason: "Business operations without rate limits can be repeated for cumulative impact", Priority: 2},
		{VulnType: "api_abuse", Technique: "Flood resource-intensive API endpoints to cause denial of service or resource exhaustion", Reason: "Unlimited API access enables both enumeration and availability attacks", Priority: 3},
	},

	// ─── open_redirect ──────────────────────────────────────────────────
	"open_redirect": {
		{VulnType: "sensitive_data_exposure", Technique: "Chain with OAuth flows — redirect authorization code or access token to attacker-controlled URL", Reason: "Open redirect in OAuth redirect_uri leaks authorization codes and tokens", Priority: 1},
		{VulnType: "session_hijacking", Technique: "Redirect authenticated users to attacker-controlled page that captures Referer header with session tokens", Reason: "Redirects can leak sensitive tokens via Referer when redirecting to attacker domain", Priority: 1},
		{VulnType: "xss_reflected", Technique: "Chain redirect with javascript: URI scheme or data: URI to achieve XSS where direct injection fails", Reason: "Some open redirect implementations allow javascript: protocol, converting redirect to XSS", Priority: 2},
		{VulnType: "information_disclosure", Technique: "Use the redirect as a trusted proxy to phish internal users or capture credentials via fake login page", Reason: "Trusted domain in URL bar makes phishing pages significantly more convincing", Priority: 3},
	},

	// ─── mass_assignment ────────────────────────────────────────────────
	"mass_assignment": {
		{VulnType: "privilege_escalation", Technique: "Add role=admin, is_superuser=true, or permissions[] fields to registration/update API requests", Reason: "Mass assignment on user objects directly enables self-promotion to admin", Priority: 1},
		{VulnType: "auth_bypass", Technique: "Set verified=true, email_confirmed=true, or mfa_enabled=false fields to bypass verification steps", Reason: "Overwriting verification flags bypasses intended authentication workflows", Priority: 1},
		{VulnType: "business_logic", Technique: "Modify price=0, discount=100, balance=999999, or subscription_tier=enterprise in API requests", Reason: "Mass assignment on financial/subscription objects creates direct business impact", Priority: 2},
		{VulnType: "sensitive_data_exposure", Technique: "Inject fields that cause the API to return additional data (include_details=true, verbose=1, fields=all)", Reason: "Some APIs use request parameters to control response verbosity — mass assignment can unlock hidden data", Priority: 3},
	},

	// ─── ssti ───────────────────────────────────────────────────────────
	"ssti": {
		{VulnType: "command_injection", Technique: "Escalate from template expression to OS command execution using engine-specific gadgets (Jinja2: __import__('os').popen(), Twig: system())", Reason: "SSTI almost always escalates to RCE through template engine internals", Priority: 1},
		{VulnType: "sensitive_data_exposure", Technique: "Read application configuration, environment variables, and secret keys through template context objects", Reason: "Template context typically contains application config with secrets", Priority: 1},
		{VulnType: "information_disclosure", Technique: "Enumerate template engine type and version, application framework, and internal class structure", Reason: "Template introspection reveals the full application stack for targeted exploitation", Priority: 2},
		{VulnType: "path_traversal", Technique: "Use template file inclusion directives to read arbitrary files from the server filesystem", Reason: "Many template engines support file inclusion that can be abused for arbitrary file read", Priority: 2},
	},

	// ─── deserialization ────────────────────────────────────────────────
	"deserialization": {
		{VulnType: "command_injection", Technique: "Use ysoserial (Java), pickle payloads (Python), or marshal chains (Ruby) to achieve RCE via deserialization gadgets", Reason: "Insecure deserialization is a direct path to arbitrary code execution in most languages", Priority: 1},
		{VulnType: "privilege_escalation", Technique: "Craft serialized user objects with elevated roles/permissions and submit them to bypass authorization", Reason: "If user state is stored in serialized form, forging admin user objects is trivial", Priority: 1},
		{VulnType: "ssrf", Technique: "Use deserialization gadget chains that trigger outbound HTTP requests (URLClassLoader, JNDI injection)", Reason: "Some gadget chains achieve SSRF as a stepping stone to RCE (Log4Shell-style)", Priority: 2},
		{VulnType: "sensitive_data_exposure", Technique: "Deserialize objects that trigger file reads or database queries to exfiltrate data via error messages or OOB channels", Reason: "Even without direct RCE, deserialization can trigger controlled data access operations", Priority: 3},
	},

	// ─── xxe ────────────────────────────────────────────────────────────
	"xxe": {
		{VulnType: "path_traversal", Technique: "Use external entity declarations to read /etc/passwd, config files, and source code via file:// protocol", Reason: "XXE is a direct arbitrary file read primitive through XML entity expansion", Priority: 1},
		{VulnType: "ssrf", Technique: "Use external entities with http:// to reach internal services, cloud metadata, and admin panels", Reason: "XXE server-side fetching is equivalent to SSRF through XML parser", Priority: 1},
		{VulnType: "sensitive_data_exposure", Technique: "Exfiltrate multi-line files using OOB (out-of-band) XXE with parameter entities and external DTD hosting", Reason: "OOB XXE bypasses output encoding limitations to extract binary/multiline data", Priority: 2},
		{VulnType: "command_injection", Technique: "On PHP with expect://, use expect://id to execute commands; on other stacks, chain with discovered LFI for RCE", Reason: "Some XML parser configurations support protocol handlers that enable code execution", Priority: 3},
	},

	// ─── cors_misconfiguration ──────────────────────────────────────────
	"cors_misconfiguration": {
		{VulnType: "sensitive_data_exposure", Technique: "Create attacker page that makes cross-origin requests to leak authenticated API responses (profile data, tokens)", Reason: "Permissive CORS with credentials allows attacker origin to read authenticated responses", Priority: 1},
		{VulnType: "csrf", Technique: "Use CORS to read CSRF tokens cross-origin, then craft forged state-changing requests", Reason: "CORS misconfiguration defeats anti-CSRF protections that rely on same-origin policy", Priority: 1},
		{VulnType: "session_hijacking", Technique: "Exfiltrate session tokens, JWTs, or auth cookies via cross-origin JavaScript requests", Reason: "If CORS allows credential-bearing requests from any origin, session theft is trivial", Priority: 2},
	},

	// ─── vulnerable_component ───────────────────────────────────────────
	"vulnerable_component": {
		{VulnType: "command_injection", Technique: "Search exploit-db and CVE databases for known RCE exploits matching the exact component version", Reason: "Known-vulnerable components often have public exploits with trivial exploitation", Priority: 1},
		{VulnType: "sqli", Technique: "Check if the vulnerable component has known injection vulnerabilities (e.g., older WordPress plugins, Drupal SQLi)", Reason: "Many component CVEs are injection-type vulnerabilities with published payloads", Priority: 2},
		{VulnType: "deserialization", Technique: "Test for known deserialization CVEs in the component (e.g., Apache Commons, Jackson, Fastjson)", Reason: "Serialization libraries are among the most common sources of critical component CVEs", Priority: 2},
		{VulnType: "sensitive_data_exposure", Technique: "Check if the vulnerability allows data extraction (e.g., Heartbleed, padding oracle, memory disclosure bugs)", Reason: "Some component vulns directly leak memory or stored data", Priority: 3},
	},

	// ─── session_hijacking ──────────────────────────────────────────────
	"session_hijacking": {
		{VulnType: "privilege_escalation", Technique: "Hijack admin/high-privilege user sessions by targeting their predictable or fixated session tokens", Reason: "Session hijacking directly inherits the victim's privilege level", Priority: 1},
		{VulnType: "idor", Technique: "Use the hijacked session to access other users' resources and test object-level authorization", Reason: "A hijacked session provides a different user context to test horizontal access controls", Priority: 2},
		{VulnType: "sensitive_data_exposure", Technique: "Access all data visible to the hijacked user — profile, payment methods, private messages, API keys", Reason: "Full session access means full data access within that user's scope", Priority: 2},
		{VulnType: "business_logic", Technique: "Perform irreversible actions (purchases, deletions, approvals) as the victim user", Reason: "Session hijacking enables any action the victim is authorized to perform", Priority: 3},
	},
}

// GetAttackChains returns the chained attacks enabled by discovering the given vulnerability type.
// It normalizes the input using the same alias resolution as compliance.go.
// Returns nil if no chains are defined for the given type.
func GetAttackChains(vulnType string) []ChainedAttack {
	key := normalizeKey(vulnType)
	if chains, ok := AttackChains[key]; ok {
		return chains
	}
	return nil
}

// FormatChainsForPrompt takes a list of discovered vulnerability types and produces a
// formatted string suitable for injection into agent prompts. It deduplicates suggested
// attacks, groups them by priority, and presents actionable next steps.
func FormatChainsForPrompt(findings []string) string {
	if len(findings) == 0 {
		return ""
	}

	// Deduplicate: track seen (vulnType + technique) combos
	type chainKey struct {
		vulnType  string
		technique string
	}
	seen := make(map[chainKey]bool)

	// Collect chains grouped by priority
	byPriority := map[int][]string{1: {}, 2: {}, 3: {}}

	for _, finding := range findings {
		chains := GetAttackChains(finding)
		if chains == nil {
			continue
		}
		normalizedFinding := normalizeKey(finding)
		for _, c := range chains {
			key := chainKey{vulnType: c.VulnType, technique: c.Technique}
			if seen[key] {
				continue
			}
			seen[key] = true

			// Get compliance info for the target vuln type
			severity := ""
			if cm := GetComplianceForVulnType(c.VulnType); cm != nil {
				severity = fmt.Sprintf(" [CVSS %.1f %s]", cm.CVSSBase, CVSSSeverity(cm.CVSSBase))
			}

			entry := fmt.Sprintf("  → [%s] %s%s\n    Technique: %s\n    Reason: %s (triggered by: %s)",
				c.VulnType, getVulnDescription(c.VulnType), severity, c.Technique, c.Reason, normalizedFinding)
			byPriority[c.Priority] = append(byPriority[c.Priority], entry)
		}
	}

	// Build output
	var sb strings.Builder
	sb.WriteString("## ATTACK CHAIN SUGGESTIONS\n")
	sb.WriteString("Based on your current findings, the following follow-up attacks are recommended:\n\n")

	priorityLabels := map[int]string{
		1: "🔴 PRIORITY 1 — Immediate (High Confidence)",
		2: "🟡 PRIORITY 2 — Should Try",
		3: "🟢 PRIORITY 3 — If Time Permits",
	}

	hasContent := false
	for _, p := range []int{1, 2, 3} {
		entries := byPriority[p]
		if len(entries) == 0 {
			continue
		}
		hasContent = true
		sb.WriteString(fmt.Sprintf("### %s\n", priorityLabels[p]))
		for _, entry := range entries {
			sb.WriteString(entry)
			sb.WriteString("\n\n")
		}
	}

	if !hasContent {
		return ""
	}

	sb.WriteString("Use these suggestions to prioritize your next subtasks. Focus on Priority 1 chains first.\n")
	return sb.String()
}

// GetAllChainTriggers returns a sorted list of all vulnerability types that have attack chains defined.
func GetAllChainTriggers() []string {
	triggers := make([]string, 0, len(AttackChains))
	for k := range AttackChains {
		triggers = append(triggers, k)
	}
	sortStrings(triggers)
	return triggers
}

// getVulnDescription returns a short description for a vuln type from ComplianceMappings.
func getVulnDescription(vulnType string) string {
	key := normalizeKey(vulnType)
	if m, ok := ComplianceMappings[key]; ok {
		return m.Description
	}
	return vulnType
}
