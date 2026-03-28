# Phase 2 & 3 Implementation Plan

## Phase 1 Recap (DONE ✅)
42 bug fixes — loop prevention, security hardening, state management, template upgrades.
24 files changed, 704 insertions. All cross-checked clean.

---

## Phase 2: Architecture Upgrades (How the Agent THINKS)

### Upgrade 2.1: DB-Backed Execution State
**What:** Replace file-based STATE.json with DB-persisted execution state. The `Context` column already exists on `Subtask` but is completely unused.

**Why:** STATE.json gets lost on crash, is never backed up, agent can overwrite/corrupt it. DB state survives everything.

**Files to change:**
- `backend/pkg/database/models.go` — Already has `Context string` on Subtask ✅
- `backend/pkg/database/subtasks.sql.go` — Add `UpdateSubtaskContext` query
- `backend/sqlc/models/subtasks.sql` — Add SQL for UpdateSubtaskContext
- `backend/pkg/controller/subtask.go` — Add `SetContext(ctx, json)` and `GetContext(ctx)` methods
- `backend/pkg/providers/performer.go` — After each tool call, persist execution state to DB
- `backend/pkg/templates/prompts/pentester.tmpl` — Inject `{{.SubtaskContext}}` so agent sees its persisted state

**Implementation:**
1. Add SQL query: `UPDATE subtasks SET context = $2, updated_at = NOW() WHERE id = $1`
2. Add Go method `SetContext` on subtaskWorker
3. In `performAgentChain`, after tool call processing, serialize state (tool_call_count, current_phase, findings_count, attacks_done) and call `SetContext`
4. In template rendering, load subtask context and inject into system prompt
5. On crash recovery, agent resumes with full state from DB

**Effort:** M
**Dependencies:** None (Context column already exists)

---

### Upgrade 2.2: Execution Metrics Pipeline
**What:** Pass real-time execution metrics (tool call count, elapsed time, unique commands, error rate) into every template context.

**Why:** Phase 1 Fixer 5 added template blocks for `{{.ExecutionMetrics}}` but the backend never populates them. Without metrics, templates can't make informed decisions about loops or progress.

**Files to change:**
- `backend/pkg/providers/helpers.go` — Add `ExecutionMetrics` struct and collector
- `backend/pkg/providers/performer.go` — Track metrics in the for{} loop, pass to template rendering
- `backend/pkg/templates/prompts/` — Already have `{{if .ExecutionMetrics}}` blocks (Phase 1) ✅

**Implementation:**
1. Define `ExecutionMetrics` struct: `ToolCallCount int`, `ElapsedSeconds int`, `UniqueCommands int`, `ErrorCount int`, `LastToolName string`, `RepeatedCallCount int`
2. In `performAgentChain`, maintain metrics alongside toolCallCount (which already exists from Phase 1)
3. Pass metrics into template context map when rendering system prompts
4. Reflector and pentester templates already consume them (Phase 1)

**Effort:** S
**Dependencies:** None

---

### Upgrade 2.3: Smart Reflector — Real Loop Detection
**What:** Upgrade the reflector from a format enforcer to an actual cognitive checkpoint. It should analyze execution history and detect patterns, not just redirect format errors.

**Why:** Current reflector (`reflector.tmpl`) only fires when agent outputs text instead of tool calls. It has ZERO visibility into whether the agent is making progress. Phase 1 added template-level loop detection hints, but the reflector needs execution history injected.

**Files to change:**
- `backend/pkg/providers/performer.go` — When invoking reflector, include last N tool calls + results in context
- `backend/pkg/templates/prompts/reflector.tmpl` — Add execution history analysis section
- `backend/pkg/providers/helpers.go` — Add `getRecentToolHistory(n int)` helper

**Implementation:**
1. Track last 10 tool calls with names + truncated results in performer loop
2. When reflector is invoked, inject this history into its prompt
3. Reflector template analyzes: are tool calls diverse? Is there progress? Same commands repeating?
4. Reflector can now recommend: "STOP — you're looping" or "CHANGE APPROACH — try different tool"

**Effort:** M
**Dependencies:** Upgrade 2.2 (metrics)

---

### Upgrade 2.4: Attack Chain Reasoning
**What:** When a finding is discovered, automatically generate "next attack" suggestions based on what was found. Finding A → enables attacks B, C, D.

**Why:** Current agent treats each attack category independently. A real pentester chains findings — "I found IDOR on user profiles, now let me check if I can escalate to admin via the same pattern."

**Files to change:**
- `backend/pkg/templates/prompts/pentester.tmpl` — Add attack chain reasoning section
- `backend/pkg/templates/prompts/subtasks_refiner.tmpl` — Refiner should consider chains when generating next subtasks
- NEW: `backend/pkg/providers/chains.go` — Attack chain logic (mapping finding types → next attacks)

**Implementation:**
1. Define attack chain map: `IDOR → [privesc, data_exfil, mass_enum]`, `auth_bypass → [admin_access, api_abuse]`, etc.
2. After each finding, lookup chain map and inject "NEXT_ATTACKS" into pentester context
3. Refiner uses chains to prioritize subtasks — chain-derived attacks get higher priority
4. Template shows: "Based on F003 (IDOR on /api/users), try: admin panel access, bulk data export, privilege escalation"

**Effort:** M
**Dependencies:** Upgrade 2.1 (state tracking)

---

### Upgrade 2.5: Context Window Optimization
**What:** Intelligent context management — keep relevant findings and tool results, discard noise. Current summarizer drops middle content blindly.

**Why:** After 20+ tool calls, context window fills with irrelevant old results. Agent loses track of recent findings. Phase 1 improved summarizer sampling but the fundamental approach is still "truncate by size."

**Files to change:**
- `backend/pkg/providers/handlers.go` — Upgrade summarizer to relevance-based
- `backend/pkg/providers/helpers.go` — Add context relevance scoring
- `backend/pkg/providers/performer.go` — Track which context items are "hot" (recently referenced)

**Implementation:**
1. Tag each context item with last-referenced timestamp
2. Summarizer keeps: (a) all findings, (b) last 5 tool results, (c) current attack context, (d) errors
3. Summarizer drops: old successful commands that aren't referenced, verbose output from completed attacks
4. "Hot" items (referenced in last 3 tool calls) are never dropped

**Effort:** L
**Dependencies:** Upgrade 2.2 (metrics for tracking)

---

### Upgrade 2.6: Workspace File Injection for Generator
**What:** Make the subtask generator see what files already exist in /work/ before generating subtasks.

**Why:** Phase 1 Fixer 5 added `{{if .WorkspaceFiles}}` to generator template, but the backend code to populate `.WorkspaceFiles` doesn't exist yet. Generator is still blind.

**Files to change:**
- `backend/pkg/providers/performers.go` — Where generator is called, list /work/ files and inject
- `backend/pkg/tools/terminal.go` — Add `ListWorkspaceFiles()` helper
- Templates already have blocks ✅

**Implementation:**
1. Add `ListWorkspaceFiles(workdir string) []FileInfo` to terminal.go
2. Before calling generator template, execute `ListWorkspaceFiles` and add to template context
3. Generator sees existing STATE.json, FINDINGS.md, etc. and doesn't re-create them

**Effort:** S
**Dependencies:** None

---

## Phase 3: Unique Features (What the Tool Can DO)

### Feature 3.1: Vulnerability Deduplication Engine (inspired by Shannon)
**What:** Automatically detect when multiple "findings" are really the same vulnerability on different endpoints. Group them under one root cause.

**Why:** v6 retest had 151 findings but only ~15 real ones. Severity inflation destroys report credibility.

**Files to change:**
- NEW: `backend/pkg/providers/dedup.go` — Deduplication engine
- `backend/pkg/templates/prompts/pentester.tmpl` — Inject dedup context
- `backend/pkg/providers/performer.go` — Call dedup after each finding

**Implementation:**
1. `DedupEngine` struct with `AddFinding(finding)` and `GetUniqueFindings() []Finding`
2. Similarity check: same vuln type + same parameter + similar endpoint = duplicate
3. Each finding gets a `rootCauseID` — all dupes share same ID
4. Template shows: "Similar to F003 — same IDOR pattern. Grouping under ROOT-001"
5. Final report groups by root cause, not by individual endpoint

**Effort:** M
**Dependencies:** None

---

### Feature 3.2: Auto-Remediation Suggestions (inspired by Shannon)
**What:** For each finding, generate specific code-level fix suggestions with examples.

**Why:** A finding without a fix is only half useful. Developers need "here's what to change" not just "this is broken."

**Files to change:**
- `backend/pkg/templates/prompts/reporter.tmpl` — Add remediation section to report template
- NEW: `backend/pkg/providers/remediation.go` — Remediation knowledge base

**Implementation:**
1. Map vuln types to remediation templates: IDOR → "Add authorization check: `if (user.id !== resource.ownerId) return 403`"
2. Include language-specific examples (Python/Node/Go/PHP)
3. Reporter template generates remediation section per finding
4. Optional: generate PR-style diff for common frameworks

**Effort:** M
**Dependencies:** None

---

### Feature 3.3: Compliance Mapping (inspired by HexStrike)
**What:** Auto-map every finding to OWASP Top 10, CWE IDs, and CVSS scores.

**Why:** Professional reports need compliance references. Manual mapping is tedious.

**Files to change:**
- NEW: `backend/pkg/providers/compliance.go` — Compliance mapping engine
- `backend/pkg/templates/prompts/reporter.tmpl` — Include compliance info in report
- `backend/pkg/templates/prompts/pentester.tmpl` — Agent tags findings with CWE during discovery

**Implementation:**
1. Define mapping: vuln_type → {owasp_category, cwe_ids[], cvss_base}
2. e.g., IDOR → {A01:2021-Broken Access Control, [CWE-639, CWE-284], 7.5}
3. Agent includes CWE tag when reporting findings
4. Reporter auto-generates compliance table in final report
5. Summary section: "X findings map to OWASP A01, Y to A03..."

**Effort:** S
**Dependencies:** None

---

### Feature 3.4: Cost Tracking & Optimization (inspired by Shannon)
**What:** Track LLM token usage, API calls, and cost per finding. Show efficiency metrics.

**Why:** Running PentAGI costs real money. Users need to know: "This scan cost $X and found Y findings = $Z per finding."

**Files to change:**
- `backend/pkg/providers/pconfig/config.go` — Already has `CallUsage` with token tracking ✅ (Phase 1 fixed Merge)
- `backend/pkg/providers/performer.go` — Aggregate costs per subtask
- NEW: `backend/pkg/providers/cost.go` — Cost calculation (model → price/1K tokens)
- `backend/pkg/templates/prompts/reporter.tmpl` — Add cost summary to report

**Implementation:**
1. Price table: claude-opus=$15/M-in,$75/M-out, claude-sonnet=$3/M-in,$15/M-out, etc.
2. After each LLM call, calculate cost from CallUsage
3. Track per-subtask and per-flow total cost
4. Report footer: "Total cost: $X.XX | Findings: Y | Cost per finding: $Z.ZZ"
5. Include breakdown: recon=$A, attacks=$B, reporting=$C

**Effort:** S
**Dependencies:** None (CallUsage already works)

---

### Feature 3.5: Finding Evidence Snapshots (inspired by PentestGPT)
**What:** Automatically capture HTTP request/response pairs as evidence for each finding. Store as structured data, not just terminal logs.

**Why:** Current evidence is buried in terminal logs. A proper finding needs: exact request, exact response, reproduction steps.

**Files to change:**
- `backend/pkg/tools/terminal.go` — Intercept curl/httpx commands, parse req/res
- NEW: `backend/pkg/providers/evidence.go` — Evidence storage and formatting
- `backend/pkg/templates/prompts/pentester.tmpl` — Instruct agent to use structured evidence format

**Implementation:**
1. When terminal sees `curl` command, parse the flags into structured request
2. Capture response headers + body (first 4KB)
3. Store as Evidence struct: {finding_id, request, response, timestamp, reproduction_steps}
4. Reporter uses structured evidence for clean report formatting
5. Agent prompt instructs: "After confirming a finding, save evidence with: `curl -v ... 2>&1 | tee /work/evidence/F001.txt`"

**Effort:** L
**Dependencies:** Feature 3.1 (dedup — evidence links to root cause)

---

### Feature 3.6: Multi-Flow Finding Sharing (inspired by PentestAgent)
**What:** When multiple flows test different targets, share findings across flows so agents learn from each other.

**Why:** If Flow A finds that target uses default admin:admin, Flow B testing a similar target should check that first.

**Files to change:**
- `backend/pkg/controller/flow.go` — Add cross-flow finding query
- `backend/pkg/database/` — Add query: GetRecentFindingsAcrossFlows
- `backend/pkg/templates/prompts/pentester.tmpl` — Inject cross-flow insights

**Implementation:**
1. New DB query: `SELECT findings FROM subtasks WHERE flow_id != $1 AND created_at > $2 ORDER BY created_at DESC LIMIT 10`
2. At flow start, query recent findings from other flows
3. Inject into pentester template: "Other scans recently found: [OTP bypass, default creds, IDOR]. Check these patterns."
4. Agent prioritizes attacks that worked on similar targets

**Effort:** M
**Dependencies:** Upgrade 2.1 (DB-backed state)

---

### Feature 3.7: Progress Dashboard Data (inspired by HexStrike)
**What:** Expose real-time execution data via API endpoints for dashboard consumption.

**Why:** Currently no way to monitor a running flow except reading terminal logs. A dashboard needs structured data.

**Files to change:**
- `backend/pkg/server/` — Add API endpoints for flow progress
- `backend/pkg/controller/flow.go` — Add progress data methods
- `backend/pkg/providers/performer.go` — Emit progress events

**Implementation:**
1. New API: `GET /api/flows/{id}/progress` → returns {phase, tool_calls, findings_count, elapsed, attacks_done, attacks_remaining}
2. New API: `GET /api/flows/{id}/findings` → returns structured findings list
3. Performer emits progress events on each tool call completion
4. WebSocket support for real-time updates (optional, SSE as simpler alternative)

**Effort:** L
**Dependencies:** Upgrade 2.1 (state), Upgrade 2.2 (metrics)

---

## Implementation Order

### Wave 1 — Foundation (no dependencies, small effort)
1. **Upgrade 2.6** — Workspace file injection for generator (S)
2. **Upgrade 2.2** — Execution metrics pipeline (S)
3. **Feature 3.3** — Compliance mapping (S)
4. **Feature 3.4** — Cost tracking (S)

### Wave 2 — Core Upgrades (depends on Wave 1)
5. **Upgrade 2.1** — DB-backed execution state (M)
6. **Feature 3.1** — Vulnerability deduplication (M)
7. **Feature 3.2** — Auto-remediation suggestions (M)
8. **Upgrade 2.3** — Smart reflector with loop detection (M)

### Wave 3 — Advanced Features (depends on Wave 2)
9. **Upgrade 2.4** — Attack chain reasoning (M)
10. **Feature 3.6** — Multi-flow finding sharing (M)
11. **Upgrade 2.5** — Context window optimization (L)
12. **Feature 3.5** — Finding evidence snapshots (L)

### Wave 4 — Polish (depends on Wave 3)
13. **Feature 3.7** — Progress dashboard data (L)

---

## Risk Assessment

| Change | Risk | Mitigation |
|--------|------|------------|
| DB-backed state (2.1) | Medium — new DB writes on every tool call | Batch writes, async flush, don't block agent loop |
| Metrics pipeline (2.2) | Low — additive only | Nil-safe template blocks already exist |
| Smart reflector (2.3) | Medium — could incorrectly flag legitimate diverse tool usage as loops | Tunable thresholds, conservative initial values |
| Attack chains (2.4) | Low — advisory only, doesn't force agent | Agent can ignore suggestions |
| Context optimization (2.5) | High — wrong pruning loses important info | Keep all findings always, only prune tool outputs |
| Dedup engine (3.1) | Medium — false positives group different vulns | Require same vuln_type + high endpoint similarity |
| Compliance mapping (3.3) | Low — lookup table only | Static data, no side effects |
| Cost tracking (3.4) | Low — read-only metrics | No impact on execution |
| Multi-flow sharing (3.6) | Medium — stale findings could mislead | Only share confirmed findings, timestamp filter |
| Dashboard API (3.7) | Low — read-only endpoints | No impact on execution |

---

## Total Effort Estimate
- **Wave 1:** 4 items, all S → ~4 agent sessions
- **Wave 2:** 4 items, all M → ~8 agent sessions  
- **Wave 3:** 4 items, M+M+L+L → ~10 agent sessions
- **Wave 4:** 1 item, L → ~3 agent sessions
- **Total:** ~25 agent sessions across 4 waves
