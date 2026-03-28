# Phase 3 — Feature 3.5: Finding Evidence Snapshots

## Overview

Automatically capture HTTP request/response pairs as structured evidence for each
penetration testing finding. Evidence is parsed transparently from `curl -v` and
HTTPie output without changing what the agent sees.

## Problem

- Evidence was buried in raw terminal logs — hard to extract for reports
- A proper pentest finding needs: exact request, exact response, reproduction steps
- Reporters had no structured access to evidence data

## Solution

### New File: `backend/pkg/providers/evidence.go`

Complete evidence capture system with:

#### Data Structures
- **`Evidence`** — Top-level evidence item with finding ID, type (http/terminal/file),
  timestamps, and reproduction steps
- **`HTTPRequest`** — Structured HTTP request: method, URL, headers, body
- **`HTTPResponse`** — Structured HTTP response: status code, headers, body (truncated to 4KB)
- **`EvidenceStore`** — Thread-safe in-memory store keyed by finding ID

#### EvidenceStore Methods
- `NewEvidenceStore()` — Creates empty store
- `Add(e Evidence)` — Adds evidence; auto-truncates bodies to 4KB; unassigned findings stored under `_unassigned`
- `GetForFinding(findingID)` — Returns all evidence for a specific finding
- `GetAll()` — Returns full snapshot of all evidence
- `FormatForReport()` — Human-readable report format with request/response/repro steps

#### HTTP Parsers
- **`ParseCurlVerbose(output)`** — Parses `curl -v` stderr output:
  - Extracts `> METHOD /path HTTP/1.1` request lines
  - Extracts `< HTTP/1.1 STATUS` response lines
  - Parses request/response headers from `> Header: Value` / `< Header: Value` lines
  - Skips SSL/TLS negotiation lines (`* SSL`, `* TLS`, `* ALPN`, etc.)
  - Reconstructs full URL from path + Host header + connected host
  - Detects HTTPS from SSL markers in output
  - Collects response body (everything after headers, excluding `*` verbose lines)

- **`ParseHTTPieOutput(output)`** — Parses HTTPie default output:
  - Detects `HTTP/1.1 STATUS` response status line
  - Parses response headers
  - Optionally parses request line/headers from `--print=Hh` output
  - Collects response body

- **`DetectAndParseHTTP(command, output)`** — Auto-detection dispatcher:
  - Checks if command is `curl` with `-v`/`--verbose` flag → uses `ParseCurlVerbose`
  - Checks if command starts with `http`/`https`/`httpie` → uses `ParseHTTPieOutput`
  - Returns nil for non-HTTP commands (transparent no-op)
  - Auto-generates reproduction steps from command

#### Helper Functions
- `truncateString(s, maxLen)` — Truncates with `[TRUNCATED: original size N bytes]` marker
- `isCurlVerbose(command)` — Detects curl with -v/-vvv/--verbose flags
- `isHTTPieCommand(command)` — Detects HTTPie invocations
- `isHTTPMethod(s)` — Validates HTTP method strings
- `buildReproSteps(command)` — Generates numbered reproduction steps from command
- `extractURL(command)` — Extracts URL from command arguments

### New File: `backend/pkg/providers/evidence_test.go`

Comprehensive test suite covering:
- EvidenceStore CRUD operations (Add, GetForFinding, GetAll)
- Unassigned evidence storage
- Body truncation on Add
- FormatForReport output (with data and empty)
- ParseCurlVerbose: basic HTTP, HTTPS with SSL lines, empty input, malformed input
- ParseHTTPieOutput: basic response, missing response
- DetectAndParseHTTP: curl verbose, curl without verbose, HTTPie, non-HTTP commands, empty output
- Helper functions: isCurlVerbose, isHTTPieCommand, truncateString, extractURL

### Modified: `backend/pkg/tools/terminal.go`

**Integration changes (transparent — no output modification):**

1. Added import: `pentagi/pkg/providers`
2. Added `evidenceStore *providers.EvidenceStore` field to `terminal` struct
3. Updated `NewTerminalTool()` to initialize evidence store automatically
4. Added `NewTerminalToolWithEvidence()` constructor for shared evidence stores
5. Added `GetEvidenceStore()` accessor for report generation
6. Added `captureEvidence(command, output)` private method:
   - Called after successful command execution (both sync and detach modes)
   - Calls `providers.DetectAndParseHTTP()` to attempt evidence extraction
   - Stores evidence if HTTP traffic detected
   - Logs at DEBUG level for observability
   - **Never modifies command output** — fully transparent to the agent
   - **Never returns errors** — evidence capture failure is silent

### Modified: `backend/pkg/templates/prompts/pentester.tmpl`

Added **Evidence Capture Protocol** section before Completion Requirements:
- Instructs agent to always use `curl -v` when confirming HTTP-based findings
- Provides curl command templates for GET and POST evidence capture
- Defines structured finding format with `[FINDING: <id>]` markers
- Explains automatic evidence capture (agent doesn't need to paste request/response)
- Added completion requirement #7: "Always use `curl -v` when confirming HTTP-based findings"

### Modified: `backend/pkg/templates/prompts/reporter.tmpl`

Added **Evidence Snapshots Per Finding** subsection in the Compliance Mapping section:
- Defines evidence format: Request → Response → Reproduction Steps
- Rules for including evidence in each finding
- Guidance on selecting most representative evidence when multiple exist
- Instructions for terminal-only evidence (non-HTTP findings)
- References `<execution_logs>` as the source for evidence data

## Design Decisions

1. **Transparent capture**: Evidence parsing happens after command execution completes.
   The agent's output is never modified. If parsing fails, it fails silently.

2. **4KB truncation**: All bodies (request, response, output) are capped at 4KB to
   prevent memory bloat from large responses (e.g., HTML pages, binary downloads).

3. **In-memory store**: Evidence is stored in-memory per-flow. This is intentional —
   evidence is transient and only needed during report generation. For persistence,
   the FormatForReport() output can be included in the final report.

4. **Unassigned evidence**: Evidence captured before a finding ID is known is stored
   under `_unassigned`. During reporting, these can be matched to findings.

5. **Regex-based parsing**: curl -v output follows a well-defined format (`>` for
   request, `<` for response, `*` for info). The parser is tolerant of missing
   sections and handles partial output gracefully.

## Files Changed

| File | Action | Lines Changed |
|------|--------|---------------|
| `backend/pkg/providers/evidence.go` | **NEW** | ~370 lines |
| `backend/pkg/providers/evidence_test.go` | **NEW** | ~330 lines |
| `backend/pkg/tools/terminal.go` | Modified | ~50 lines added |
| `backend/pkg/templates/prompts/pentester.tmpl` | Modified | ~45 lines added |
| `backend/pkg/templates/prompts/reporter.tmpl` | Modified | ~30 lines added |
