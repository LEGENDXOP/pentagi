# Phase 3 — Feature 3.2: Auto-Remediation Suggestions

## Summary

For each vulnerability finding in PentAGI reports, we now generate specific code-level fix suggestions with before/after examples in multiple languages. This transforms findings from "here's what's broken" to "here's how to fix it."

## Changes

### New File: `backend/pkg/providers/remediation.go`

**Purpose:** Provides a structured remediation database covering all 31 canonical vulnerability types defined in `compliance.go`.

**Types:**

```go
type Remediation struct {
    VulnType     string        // Canonical key (e.g., "sqli", "xss_stored")
    Title        string        // Human-readable title
    Description  string        // General fix approach
    CodeExamples []CodeExample // Language-specific fix patterns
    References   []string      // OWASP, CWE, and other links
}

type CodeExample struct {
    Language    string // "python", "node", "go", "php", "java"
    Framework   string // "django", "express", "gin", "laravel", "spring"
    BadCode     string // Vulnerable example
    FixedCode   string // Fixed example
    Explanation string // Why the fix works
}
```

**Coverage — All 31 Vuln Types:**

| # | Vuln Type | Languages Covered |
|---|-----------|-------------------|
| 1 | `idor` | Python (Django), Node (Express) |
| 2 | `auth_bypass` | Python (Django), Node (Express) |
| 3 | `privilege_escalation` | Python (Django), Go (Gin) |
| 4 | `path_traversal` | Python (Flask), Go (net/http) |
| 5 | `cors_misconfiguration` | Node (Express), Python (Django) |
| 6 | `mass_assignment` | Node (Express), PHP (Laravel) |
| 7 | `cryptographic_failure` | Python (stdlib), Node (crypto) |
| 8 | `sensitive_data_exposure` | Python (Django), Go (Gin) |
| 9 | `sqli` | Python (Flask), Node (Express), Go (database/sql) |
| 10 | `xss_stored` | Python (Django), Node (Express) |
| 11 | `xss_reflected` | Python (Flask), PHP (vanilla) |
| 12 | `xss_dom` | JS (browser), JS (browser + DOMPurify) |
| 13 | `command_injection` | Python (stdlib), Go (os/exec) |
| 14 | `ssti` | Python (Flask), Node (Express/Nunjucks) |
| 15 | `ldap_injection` | Python (ldap3), Java (Spring) |
| 16 | `xpath_injection` | Python (lxml), Java (javax.xml) |
| 17 | `business_logic` | Python (Django), Node (Express) |
| 18 | `missing_rate_limit` | Node (Express), Python (Django) |
| 19 | `security_misconfiguration` | Python (Django), Node (Express) |
| 20 | `file_upload` | Python (Flask), Node (Express) |
| 21 | `vulnerable_component` | Node (npm), Python (pip) |
| 22 | `broken_auth` | Python (Django), Node (Express) |
| 23 | `session_hijacking` | Python (Django), PHP (vanilla) |
| 24 | `deserialization` | Python (stdlib), Java (stdlib) |
| 25 | `insufficient_logging` | Python (Django/structlog), Node (Express/Winston) |
| 26 | `ssrf` | Python (Flask), Go (net/http) |
| 27 | `csrf` | Python (Django), Node (Express) |
| 28 | `open_redirect` | Python (Django), Node (Express) |
| 29 | `information_disclosure` | Python (Flask), Go (Gin) |
| 30 | `api_abuse` | Python (Django REST), Node (Express) |
| 31 | `xxe` | Python (lxml/defusedxml), Java (javax.xml) |

**API Functions:**
- `GetRemediation(vulnType string) *Remediation` — Returns remediation for a vuln type (uses same alias resolution as compliance module)
- `GetAllRemediations() []Remediation` — Returns all remediation entries
- `FormatRemediation(vulnType string) string` — Returns a formatted Markdown remediation block ready for report embedding

**Key Design Decisions:**
- Reuses `normalizeKey()` from `compliance.go` for consistent alias resolution — aliases like "sql_injection", "rce", "lfi" all resolve correctly
- Code examples are real, working patterns (not pseudocode), 5-15 lines each
- Each vuln type has at least 2 language/framework examples
- References link to OWASP Cheat Sheets, CWE definitions, and PortSwigger research
- File is self-contained — no new dependencies needed

### Modified File: `backend/pkg/templates/prompts/reporter.tmpl`

**What changed:** Added an "Auto-Remediation Suggestions" section between the Per-Finding Compliance Reference and Executive Compliance Posture sections.

**New instructions to the reporter agent:**
1. For EVERY finding (or deduplicated root cause), include a Remediation subsection
2. Provide general fix description + at least 2 code examples (before/after)
3. Tailor examples to the target's detected technology stack when possible
4. Include OWASP/CWE reference links
5. For process-oriented fixes (e.g., `vulnerable_component`, `insufficient_logging`), provide configuration/process guidance instead of code

**Template format example included showing the expected remediation output structure.**

## Integration Points

- The `GetRemediation()` function can be called from the report generation pipeline to auto-populate remediation sections
- The `FormatRemediation()` helper outputs ready-to-embed Markdown blocks
- The reporter template instructs the AI reporter agent to include remediation for every finding
- Alias resolution ensures findings tagged with informal names (e.g., "sql injection", "rce", "lfi") still get correct remediation

## Files Changed
- **NEW:** `backend/pkg/providers/remediation.go` (31 remediation entries, ~900 lines)
- **MODIFIED:** `backend/pkg/templates/prompts/reporter.tmpl` (added ~45 lines for remediation section)
