# Phase 2, Upgrade 2.4 — Attack Chain Reasoning

## Summary
Implements automatic attack chain suggestions so the pentesting agent chains findings like a real pentester instead of treating each vulnerability in isolation. When a vulnerability is discovered, the system now suggests specific follow-up attacks with actionable techniques, prioritized by likelihood of success.

## Changes

### 1. NEW FILE: `backend/pkg/providers/chains.go`

**Purpose:** Codifies the reasoning a senior pentester uses when pivoting from one finding to the next.

**Types:**
- `ChainedAttack` — represents a single follow-up attack with `VulnType`, `Technique`, `Reason`, and `Priority` (1=immediate, 2=should try, 3=if time permits)
- `AttackChain` — groups a trigger vuln type with its follow-up attacks

**Data:**
- `AttackChains` map with **21 trigger vulnerability types**, each with 3-5 chained attacks
- **94 total chained attack entries** covering the full attack surface
- All vuln types reference canonical tags from `compliance.go`

**Trigger Types Covered (21):**

| # | Trigger | Chains To | Priority 1 Focus |
|---|---------|-----------|------------------|
| 1 | `idor` | privesc, info disclosure, api abuse, biz logic, data exposure | Vertical escalation + bulk extraction |
| 2 | `auth_bypass` | privesc, api abuse, data exposure, info disclosure, biz logic | Admin access + full API surface |
| 3 | `sqli` | data exposure, auth bypass, cmd injection, info disclosure, privesc | Credential dump + OS command exec |
| 4 | `xss_stored` | session hijack, privesc, csrf, info disclosure, data exposure | Session theft + admin takeover |
| 5 | `ssrf` | info disclosure, data exposure, api abuse, path traversal, cmd injection | Cloud metadata + internal services |
| 6 | `information_disclosure` | broken auth, data exposure, sqli, privesc, vuln component | Leaked credentials + CVE research |
| 7 | `security_misconfiguration` | broken auth, info disclosure, path traversal, data exposure, privesc | Default creds + debug endpoints |
| 8 | `file_upload` | cmd injection, xss stored, path traversal, ssrf, deserialization | Web shell RCE |
| 9 | `path_traversal` | data exposure, info disclosure, broken auth, cmd injection, privesc | Config file credentials |
| 10 | `command_injection` | data exposure, privesc, info disclosure, ssrf, broken auth | Env secrets + local privesc |
| 11 | `broken_auth` | privesc, session hijack, idor, data exposure, api abuse | Vertical escalation + session analysis |
| 12 | `csrf` | privesc, biz logic, broken auth, data exposure | Role modification + account takeover |
| 13 | `missing_rate_limit` | broken auth, data exposure, biz logic, api abuse | Credential brute-force |
| 14 | `open_redirect` | data exposure, session hijack, xss reflected, info disclosure | OAuth token theft |
| 15 | `mass_assignment` | privesc, auth bypass, biz logic, data exposure | Self-promote to admin |
| 16 | `ssti` | cmd injection, data exposure, info disclosure, path traversal | RCE via template engine |
| 17 | `deserialization` | cmd injection, privesc, ssrf, data exposure | Gadget chain RCE |
| 18 | `xxe` | path traversal, ssrf, data exposure, cmd injection | File read + internal SSRF |
| 19 | `cors_misconfiguration` | data exposure, csrf, session hijack | Cross-origin data theft |
| 20 | `vulnerable_component` | cmd injection, sqli, deserialization, data exposure | Known CVE exploitation |
| 21 | `session_hijacking` | privesc, idor, data exposure, biz logic | Inherit victim privileges |

**Functions:**
- `GetAttackChains(vulnType string) []ChainedAttack` — returns chains for a vuln type (alias-aware via `normalizeKey`)
- `FormatChainsForPrompt(findings []string) string` — formats all chain suggestions for prompt injection, deduplicating across findings and grouping by priority with CVSS severity annotations
- `GetAllChainTriggers() []string` — returns sorted list of all trigger types with defined chains

**Design Decisions:**
- Reuses `normalizeKey()` from `compliance.go` for alias resolution — "sql injection" resolves to "sqli" chains
- `FormatChainsForPrompt` deduplicates by (vulnType + technique) so overlapping chains from multiple findings don't repeat
- Severity annotations pulled from `ComplianceMappings` for context in prompt output
- Priority system (1/2/3) with visual emoji markers (🔴🟡🟢) in formatted output

### 2. MODIFIED: `backend/pkg/templates/prompts/pentester.tmpl`

**Added section:** `## ATTACK CHAIN REASONING` (inserted before COMPLETION REQUIREMENTS)

Contains:
- `<chain_protocol>` with rules for chain-based testing behavior
- 5 detailed chain examples showing real pivot reasoning
- `<available_chains>` listing all 21 trigger types the system supports
- Instruction to look for "ATTACK CHAIN SUGGESTIONS" in execution context

**Modified section:** `## COMPLETION REQUIREMENTS`
- Added requirement #8: "After each finding, check attack chains and pursue at least the Priority 1 follow-up attacks before moving on"

### 3. MODIFIED: `backend/pkg/templates/prompts/subtasks_refiner.tmpl`

**Added section:** `<attack_chain_reasoning>` (after deduplication guidance)

Contains:
- Instruction to scan completed subtask results for `[VULN_TYPE: ...]` tags
- Full chain reference for all 21 trigger types with specific follow-up actions
- Priority ordering rules: chain follow-ups before generic scanning
- Cascading chain logic: if a chain follow-up discovers a new vuln, add chains for that finding too
- Deduplication rule: don't add chain subtasks for already-tested follow-ups

## Integration Notes

### How It Works End-to-End:
1. Pentester agent discovers a vulnerability (e.g., SQLi) and tags it `[VULN_TYPE: sqli]`
2. `GetAttackChains("sqli")` returns 5 chained attacks with techniques and priorities
3. `FormatChainsForPrompt(["sqli"])` generates formatted suggestions for the execution context
4. Pentester prompt's chain reasoning section instructs the agent to follow Priority 1 chains immediately
5. Subtask refiner sees the finding in completed results and adds chain follow-up subtasks to the plan
6. If a chain follow-up discovers another vuln (e.g., command injection from stacked queries), the cycle repeats

### Not Changed (intentionally):
- `compliance.go` — untouched, chains reference its vuln types
- No new Go dependencies added
- No template variables added (chains are injected via execution context, not new `.ChainSuggestions` field)

### Future Integration Point:
The `FormatChainsForPrompt()` function is ready to be called wherever findings are collected and injected into `ExecutionContext` or `SubtaskContext`. The provider layer that builds the pentester prompt should call this function with the current findings list and append the result to the execution context string.
