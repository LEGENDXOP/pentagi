# Phase 3 — Feature 3.3: Compliance Mapping Engine

**Date:** 2026-03-09
**Status:** Implemented

## Summary

Auto-maps every penetration testing finding to **OWASP Top 10 2021**, **CWE IDs**, and **CVSS v3.1 base scores** using a lookup-table engine. Integrates into both the pentester (discovery-time tagging) and reporter (compliance report generation) workflows.

---

## Files Changed

### 1. NEW: `backend/pkg/providers/compliance.go`

**Purpose:** Core compliance mapping engine — the lookup table and helper functions.

**Types:**
- `ComplianceMapping` — struct holding `VulnType`, `OWASPTop10`, `CWEIDs`, `CVSSBase`, `Description`

**Data:**
- `ComplianceMappings` — canonical map of **31 vulnerability types** to their compliance metadata:

  | Vuln Type | OWASP Category | CWE IDs | CVSS Base |
  |-----------|----------------|---------|-----------|
  | `idor` | A01:2021-Broken Access Control | CWE-639, CWE-284 | 7.5 |
  | `auth_bypass` | A01:2021-Broken Access Control | CWE-287, CWE-863 | 8.8 |
  | `privilege_escalation` | A01:2021-Broken Access Control | CWE-269, CWE-250 | 8.8 |
  | `path_traversal` | A01:2021-Broken Access Control | CWE-22, CWE-23 | 7.5 |
  | `cors_misconfiguration` | A01:2021-Broken Access Control | CWE-942, CWE-346 | 5.3 |
  | `mass_assignment` | A01:2021-Broken Access Control | CWE-915 | 6.5 |
  | `cryptographic_failure` | A02:2021-Cryptographic Failures | CWE-327, CWE-328, CWE-330 | 7.5 |
  | `sensitive_data_exposure` | A02:2021-Cryptographic Failures | CWE-311, CWE-312, CWE-319 | 6.5 |
  | `sqli` | A03:2021-Injection | CWE-89 | 9.8 |
  | `xss_stored` | A03:2021-Injection | CWE-79 | 6.1 |
  | `xss_reflected` | A03:2021-Injection | CWE-79 | 6.1 |
  | `xss_dom` | A03:2021-Injection | CWE-79 | 6.1 |
  | `command_injection` | A03:2021-Injection | CWE-78, CWE-77 | 9.8 |
  | `ssti` | A03:2021-Injection | CWE-1336, CWE-94 | 9.8 |
  | `ldap_injection` | A03:2021-Injection | CWE-90 | 8.6 |
  | `xpath_injection` | A03:2021-Injection | CWE-643 | 8.6 |
  | `business_logic` | A04:2021-Insecure Design | CWE-840, CWE-841 | 6.5 |
  | `missing_rate_limit` | A04:2021-Insecure Design | CWE-770, CWE-799 | 5.3 |
  | `security_misconfiguration` | A05:2021-Security Misconfiguration | CWE-16, CWE-1032 | 5.3 |
  | `file_upload` | A05:2021-Security Misconfiguration | CWE-434 | 9.8 |
  | `vulnerable_component` | A06:2021-Vulnerable and Outdated Components | CWE-1104 | 7.5 |
  | `broken_auth` | A07:2021-Identification and Authentication Failures | CWE-287, CWE-384, CWE-613 | 7.5 |
  | `session_hijacking` | A07:2021-Identification and Authentication Failures | CWE-384, CWE-614 | 8.1 |
  | `deserialization` | A08:2021-Software and Data Integrity Failures | CWE-502 | 9.8 |
  | `insufficient_logging` | A09:2021-Security Logging and Monitoring Failures | CWE-778, CWE-223 | 3.8 |
  | `ssrf` | A10:2021-Server-Side Request Forgery | CWE-918 | 7.5 |
  | `csrf` | A01:2021-Broken Access Control | CWE-352 | 6.5 |
  | `open_redirect` | A01:2021-Broken Access Control | CWE-601 | 4.7 |
  | `information_disclosure` | A05:2021-Security Misconfiguration | CWE-200, CWE-209 | 5.3 |
  | `api_abuse` | A01:2021-Broken Access Control | CWE-285, CWE-284 | 7.5 |
  | `xxe` | A05:2021-Security Misconfiguration | CWE-611 | 7.5 |

- `knownAliases` — map of **40+ aliases** (e.g., `"sql_injection"` → `"sqli"`, `"rce"` → `"command_injection"`, `"lfi"` → `"path_traversal"`) for fuzzy matching

**Functions:**
- `GetComplianceForVulnType(vulnType string) *ComplianceMapping` — case-insensitive lookup with alias resolution; returns nil if unrecognized
- `GetOWASPSummary(findings []string) map[string]int` — aggregates a slice of vuln type tags into OWASP category → count map; unrecognized types counted as `"Unclassified"`
- `GetAllVulnTypes() []string` — returns sorted list of all canonical vuln type keys
- `CVSSSeverity(score float64) string` — converts CVSS v3.1 base score to qualitative severity (None/Low/Medium/High/Critical)

**Design decisions:**
- No external dependencies — pure Go, no `sort` package import (uses inline insertion sort for the small slice)
- Aliases normalized via lowercasing + underscore normalization for maximum matching flexibility
- All OWASP categories A01–A10 covered; all CWE IDs are real, verified identifiers
- CVSS base scores represent typical/representative values, not worst-case

---

### 2. MODIFIED: `backend/pkg/templates/prompts/reporter.tmpl`

**Section added:** `## COMPLIANCE MAPPING — OWASP TOP 10 2021 / CWE / CVSS` (inserted after REPORT FORMULATION CRITERIA)

**What it adds to the reporter agent's instructions:**
1. **OWASP Top 10 2021 Breakdown Table** — the reporter must produce a summary table showing finding counts per OWASP category (only categories with ≥1 finding)
2. **Per-Finding Compliance Reference** — each individual finding must include `Vuln Type`, `OWASP`, `CWE`, and `CVSS Base` metadata in a structured format
3. **Executive Compliance Posture** — 2-3 sentence executive summary covering severity breakdown, most-affected OWASP categories, and overall risk assessment
4. **Standard Vulnerability Type Tags** — full canonical tag list for validation (reporter can correct pentester tags if needed)

---

### 3. MODIFIED: `backend/pkg/templates/prompts/pentester.tmpl`

**Section added:** `## VULNERABILITY CLASSIFICATION — COMPLIANCE TAGGING` (inserted before COMPLETION REQUIREMENTS)

**What it adds to the pentester agent's instructions:**
1. **Tagging protocol** — every discovered vulnerability MUST include a `[VULN_TYPE: <tag>]` marker using a canonical tag
2. **Standard tag table** — complete 31-entry table with tag names and descriptions for easy reference during assessment
3. **Completion requirement #6** — added: "Tag EVERY discovered vulnerability with a `[VULN_TYPE: <tag>]` marker from the standard list above"

---

## How It Works End-to-End

1. **During pentest:** The pentester agent discovers a vulnerability and tags it:
   ```
   Found SQL injection in the login form's username parameter.
   [VULN_TYPE: sqli]
   ```

2. **During reporting:** The reporter agent:
   - Collects all `[VULN_TYPE: ...]` tags from subtask results
   - Looks up each tag against the compliance mapping table
   - Generates the OWASP Top 10 breakdown table
   - Adds per-finding CWE/CVSS metadata
   - Writes executive compliance posture summary

3. **Programmatic use:** Backend code can call:
   ```go
   m := providers.GetComplianceForVulnType("sqli")
   // m.OWASPTop10 = "A03:2021-Injection"
   // m.CWEIDs = ["CWE-89"]
   // m.CVSSBase = 9.8
   
   summary := providers.GetOWASPSummary([]string{"sqli", "idor", "xss_stored", "sqli"})
   // summary = {"A03:2021-Injection": 3, "A01:2021-Broken Access Control": 1}
   ```

---

## OWASP Top 10 2021 Coverage

All 10 categories are mapped:

| Category | # Vuln Types Mapped |
|----------|-------------------|
| A01:2021-Broken Access Control | 8 (idor, auth_bypass, privilege_escalation, path_traversal, cors_misconfiguration, mass_assignment, csrf, open_redirect, api_abuse) |
| A02:2021-Cryptographic Failures | 2 (cryptographic_failure, sensitive_data_exposure) |
| A03:2021-Injection | 8 (sqli, xss_stored, xss_reflected, xss_dom, command_injection, ssti, ldap_injection, xpath_injection) |
| A04:2021-Insecure Design | 2 (business_logic, missing_rate_limit) |
| A05:2021-Security Misconfiguration | 4 (security_misconfiguration, file_upload, information_disclosure, xxe) |
| A06:2021-Vulnerable and Outdated Components | 1 (vulnerable_component) |
| A07:2021-Identification and Authentication Failures | 2 (broken_auth, session_hijacking) |
| A08:2021-Software and Data Integrity Failures | 1 (deserialization) |
| A09:2021-Security Logging and Monitoring Failures | 1 (insufficient_logging) |
| A10:2021-Server-Side Request Forgery | 1 (ssrf) |

---

## Testing Notes

- The `compliance.go` file is a pure data + function package with no external dependencies
- Can be unit tested by calling `GetComplianceForVulnType` with each key and alias
- `GetOWASPSummary` can be tested with mixed valid/invalid inputs to verify the "Unclassified" bucket
- Template changes are prompt-only (no Go template syntax changes) — they add instructions, not executable template logic
