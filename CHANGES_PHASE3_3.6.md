# Phase 3 — Feature 3.6: Multi-Flow Finding Sharing

## Summary

When multiple PentAGI flows run simultaneously against different targets, findings
from completed subtasks are now shared across flows. This allows agents to learn
from each other — if Flow A discovers that default credentials work on a service,
Flow B testing a similar target will see that intelligence and can prioritize
testing the same pattern.

## Problem

Each flow was completely isolated. Parallel assessments had no way to benefit from
each other's discoveries, leading to redundant reconnaissance and missed
opportunities to leverage proven techniques.

## Solution

A cross-flow intelligence pipeline that:

1. Queries recently finished subtask results from *other* flows (last 24 hours)
2. Filters for subtasks containing `FINDING` markers (from the pentester's
   vulnerability tagging protocol)
3. Extracts and sanitizes insights — vulnerability types, techniques, target hints
4. Injects the formatted intelligence into the pentester agent's system prompt
5. Redacts credentials and sensitive data before sharing

## Files Changed

### 1. `backend/sqlc/models/subtasks.sql`
**Added:** `GetRecentCrossFlowFindings` query
- Joins subtasks → tasks → flows to find cross-flow results
- Filters: `f.id != @current_flow_id`, `s.status = 'finished'`, `result LIKE '%FINDING%'`
- Only last 24 hours (`s.updated_at > NOW() - INTERVAL '24 hours'`)
- Respects soft-delete (`f.deleted_at IS NULL`)
- Limited to 10 results to control token usage

### 2. `backend/pkg/database/subtasks.sql.go`
**Added:** Hand-written Go method matching the sqlc pattern
- `GetRecentCrossFlowFindingsRow` struct with: ID, Title, Result, TaskID, TaskInput, FlowID
- `GetRecentCrossFlowFindings(ctx, currentFlowID)` method on `*Queries`
- Follows exact patterns from existing methods (QueryContext, row scanning, proper Close/Err)

### 3. `backend/pkg/database/querier.go`
**Added:** Interface method declaration
- `GetRecentCrossFlowFindings(ctx context.Context, currentFlowID int64) ([]GetRecentCrossFlowFindingsRow, error)`
- Inserted alphabetically near other `GetFlow*` methods

### 4. `backend/pkg/providers/cross_flow.go` (NEW)
**Created:** Cross-flow intelligence extraction and formatting
- `CrossFlowInsight` struct: FlowID, TargetHint, VulnType, Technique, Summary
- `ExtractCrossFlowInsights()`: Processes raw DB rows into sanitized insights
  - Extracts VULN_TYPE tags using the same `[VULN_TYPE: xxx]` protocol from pentester.tmpl
  - Falls back to keyword-based vulnerability detection
  - Identifies tools/techniques from result text (nmap, sqlmap, hydra, etc.)
  - Extracts target hints from task input (truncated to 200 chars)
  - Skips rows where no meaningful insight could be extracted
- `FormatInsightsForPrompt()`: Renders insights as structured markdown for prompt injection
- `redactCredentials()`: Strips password/token/API key patterns before sharing
  - Regex-based: matches `password:`, `bearer`, base64-like long strings
- Complete mapping of all VULN_TYPE tags from pentester.tmpl to human-readable names

### 5. `backend/pkg/providers/handlers.go`
**Modified:** `GetPentesterHandler` — pentester handler function
- Added cross-flow query call at the start of `pentesterHandler`
- Calls `fp.db.GetRecentCrossFlowFindings(ctx, fp.flowID)`
- On error: logs warning and continues without cross-flow data (non-fatal)
- On success: extracts insights and formats for prompt
- Passes `"CrossFlowInsights"` key into the pentester template context

### 6. `backend/pkg/templates/prompts/pentester.tmpl`
**Added:** Conditional cross-flow intelligence section
- Placed between `PERSISTED EXECUTION STATE` and `LOOP PREVENTION` sections
- Wrapped in `{{if .CrossFlowInsights}}` conditional
- Uses `<cross_flow_intelligence>` XML tags for structured prompt formatting
- Instructs the agent to prioritize testing patterns that succeeded in other flows

## Design Decisions

### Why filter by `FINDING` in result text?
The pentester template already requires agents to tag vulnerabilities with
`[VULN_TYPE: <tag>]` markers. The `FINDING` keyword appears naturally in
vulnerability reports. This avoids sharing routine reconnaissance output
(nmap scans, directory listings) that would add noise without actionable intel.

### Why 24-hour window?
Findings older than 24 hours are likely from different engagements or outdated
targets. The window keeps intelligence fresh and relevant to the current
assessment session.

### Why limit to 10 findings?
Each finding adds ~100-200 tokens to the system prompt. 10 findings ≈ 1-2K tokens,
which stays well within the token budget without impacting primary agent performance.

### Why redact credentials?
Even within the same PentAGI instance, credentials from one target should not
leak to flows targeting different systems. The redaction strips passwords, tokens,
API keys, and long base64 strings. Only vulnerability *patterns* and *techniques*
are shared.

### Why non-fatal on error?
Cross-flow intelligence is an enhancement, not a requirement. If the DB query fails
(e.g., during initial setup with no other flows), the pentester agent continues
normally without any cross-flow data.

## Security Considerations

- **Credential redaction:** Multiple regex patterns strip passwords, tokens, bearer
  tokens, and suspicious base64 strings before any cross-flow data enters a prompt
- **Soft-delete awareness:** Query respects `f.deleted_at IS NULL` — findings from
  deleted flows are never shared
- **Only finished subtasks:** In-progress subtasks are excluded to avoid sharing
  partial/incorrect information
- **Target hints truncated:** Task input excerpts are capped at 200 characters to
  limit information exposure
- **No raw result sharing:** Results are processed through extraction functions,
  never injected verbatim into prompts

## Testing Notes

To verify:
1. Start two flows targeting different targets
2. Let Flow A complete a subtask with a FINDING tag in the result
3. When Flow B's pentester agent runs, check the system prompt for the
   `<cross_flow_intelligence>` section
4. Verify credentials are redacted and vulnerability types are properly extracted
