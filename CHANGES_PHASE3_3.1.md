# Phase 3 — Feature 3.1: Vulnerability Deduplication Engine

**Date:** 2026-03-09
**Status:** Implemented

## Problem

PentAGI's v6 test produced 151 findings but only ~15 were real unique vulnerabilities. The agent reported identical vulnerabilities on different endpoints as separate criticals (e.g., "IDOR on /api/users/1" and "IDOR on /api/users/2" counted as two separate CRITICAL findings), causing massive severity inflation.

## Solution

A deduplication engine that groups findings by root cause, eliminating duplicate noise while preserving all evidence.

## Files Changed

### NEW: `backend/pkg/providers/dedup.go`

Core deduplication engine with the following types and API:

- **`Finding`** — Represents a single vulnerability finding (ID, VulnType, Endpoint, Parameter, Method, Severity, Description, Evidence, RootCauseID)
- **`RootCause`** — A deduplicated group of findings sharing one root cause (ID, VulnType, Pattern, Findings, Severity)
- **`DedupEngine`** — Thread-safe engine with mutex protection

**Public API:**
| Method | Description |
|---|---|
| `NewDedupEngine()` | Creates a new empty engine |
| `AddFinding(f Finding) string` | Processes a finding, groups it or creates new root cause, returns RootCauseID |
| `GetRootCauses() []RootCause` | Returns defensive copy of all root causes |
| `GetUniqueCount() int` | Number of unique root causes |
| `GetDuplicateCount() int` | Number of duplicate findings removed |
| `GetTotalFindings() int` | Total raw findings processed |
| `Summary() string` | Human-readable dedup summary |

**Dedup Strategy (conservative — false negatives > false positives):**

1. **VulnType normalization** — Uses `normalizeKey()` from compliance.go to resolve aliases (e.g., "sql_injection" → "sqli")
2. **Different VulnTypes are NEVER grouped** — Hard rule, no exceptions
3. **Same VulnType + same generalized endpoint pattern → same root cause**
   - Endpoint generalization: strips numeric IDs, UUIDs, hex ObjectIDs
   - `/api/users/123` → `/api/users/{id}`
   - `/api/items/550e8400-e29b-...` → `/api/items/{id}`
4. **Same VulnType + same parameter name → same root cause**
   - SQLi on `id` param at `/api/users` and `/api/orders` = same root cause
5. **Severity promotion** — Root cause severity = highest among grouped findings

### NEW: `backend/pkg/providers/dedup_test.go`

Comprehensive test suite (362 lines):

| Test | What it validates |
|---|---|
| `TestGeneralizeEndpoint` | Numeric IDs, UUIDs, hex IDs, query strings stripped correctly |
| `TestHighestSeverity` | Severity comparison/promotion logic |
| `TestDedupEngine_SameEndpointPattern` | IDOR on /api/users/1 and /2 → 1 root cause |
| `TestDedupEngine_SameParamDifferentEndpoint` | SQLi on same param across endpoints → 1 root cause |
| `TestDedupEngine_DifferentVulnTypesNeverGrouped` | IDOR + SQLi on same endpoint → 2 root causes |
| `TestDedupEngine_AliasNormalization` | "sql_injection" and "sqli" correctly grouped |
| `TestDedupEngine_TrulyDifferentFindings` | XSS on /search?q and /profile?bio → 2 root causes |
| `TestDedupEngine_EmptyEngine` | Zero-state behavior |
| `TestDedupEngine_Summary` | Human-readable summary string |
| `TestDedupEngine_ThreadSafety` | 100 concurrent goroutines → correct grouping |
| `TestDedupEngine_UUIDEndpoints` | UUID path segments generalized correctly |
| `TestDedupEngine_GetRootCausesReturnsCopy` | Defensive copy prevents mutation |
| `TestDedupEngine_FindingIDAutoAssignment` | Auto-generated IDs + custom ID preservation |
| `TestDedupEngine_MassiveScenario` | 50 findings → ≤9 root causes (simulates real-world) |

### MODIFIED: `backend/pkg/templates/prompts/pentester.tmpl`

Added `## VULNERABILITY DEDUPLICATION — AVOID DUPLICATE FINDINGS` section before the compliance tagging section. Instructs the pentester agent to:

1. Check if a similar finding already exists before reporting new ones
2. Generalize endpoint patterns (strip IDs/UUIDs) when comparing
3. Same vuln type + similar endpoint/same param = reference original finding
4. Use `[DUPLICATE of F00X]` format for duplicates instead of full findings
5. Goal: ~10-20 unique root causes, not 100+ inflated findings

### MODIFIED: `backend/pkg/templates/prompts/reporter.tmpl`

Added `### Deduplication — Group Findings by Root Cause` section with:

1. Root cause grouping format (`[ROOT CAUSE: RC-001]` blocks)
2. Dedup rules for report generation matching engine logic
3. Summary metrics: total raw findings, unique root causes, reduction %
4. Executive posture now references deduplicated counts, not raw counts

## Integration Notes

The `DedupEngine` is designed to be instantiated per-engagement and can be integrated at the report generation layer:

```go
engine := providers.NewDedupEngine()

// As findings come in from the pentester agent:
rcID := engine.AddFinding(providers.Finding{
    VulnType: "idor",
    Endpoint: "/api/users/1",
    Severity: "HIGH",
})

// At report time:
rootCauses := engine.GetRootCauses()
fmt.Println(engine.Summary())
// → "Dedup Summary: 151 total findings → 15 unique root causes (136 duplicates removed, 90% reduction)"
```

## Design Decisions

1. **Conservative dedup** — If uncertain, create a new root cause. False negatives (missing a dedup opportunity) are less harmful than false positives (incorrectly merging distinct vulnerabilities).
2. **Thread-safe** — All methods protected by `sync.RWMutex` since findings may arrive concurrently from parallel agent tasks.
3. **Reuses compliance.go's `normalizeKey()`** — Single source of truth for VulnType normalization and alias resolution.
4. **Defensive copies** — `GetRootCauses()` returns deep copies to prevent external mutation.
5. **Prompt-level + engine-level dedup** — Belt and suspenders approach: pentester prompt reduces duplicates at source; engine catches any that slip through.
