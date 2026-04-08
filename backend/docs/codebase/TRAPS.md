# Traps & Gotchas

## 1. DO NOT EDIT — Auto-Generated Files

| File | Generator | Edit Instead |
|------|-----------|--------------|
| pkg/graph/generated.go (36,540 lines) | gqlgen | pkg/graph/schema.graphqls |
| pkg/graph/model/models_gen.go (1,281 lines) | gqlgen | pkg/graph/schema.graphqls |
| pkg/database/*.sql.go (23 files, ~8,500 lines) | sqlc | sqlc/models/*.sql |
| pkg/database/querier.go | sqlc | sqlc/models/*.sql |
| pkg/database/db.go | sqlc | sqlc/models/*.sql |
| pkg/database/models.go | sqlc | migrations/sql/*.sql (for schema) |
| pkg/server/docs/docs.go (7,757 lines) | swag | API handler annotations |

## 2. Known Deadlock Patterns

- **NEVER call fw.Finish() from inside worker/watchdog goroutine** — flow worker tracks goroutines with wg (WaitGroup). Finish() calls wg.Wait(), which deadlocks if called from a goroutine tracked by the same wg. Use inline cleanup pattern instead (see checkAndFinishIfDone in flow.go).
- **FlowControlManager.CheckPoint blocks on pause** — if an agent goroutine holds a lock while paused, other goroutines waiting on that lock will also block.

## 3. Known Bug-Prone Areas

### clearCallArguments (helpers.go:576) ⚠️
Strips tool call arguments for repeat detection hashing. If you delete fields used for uniqueness (like `question` in AskAdvice), all calls of that type hash identically → repeatingDetector triggers after 3 calls → permanent blocking. Only strip fields that are truly non-unique.

### mergedContext (performer.go:150) ⚠️
Takes the MINIMUM of parent context deadline and nested timeout. If parent has less time than the nested timeout allows, the nested agent gets killed early with no warning. The timeout at performer.go:115 (getNestedTimeout) returns 45/25/15 min by depth, but mergedContext may reduce it further.

### repeatingDetector (helpers.go:43-61) ⚠️
Tracks call hashes over a sliding window. Aggressive thresholds can block legitimate repeated operations (e.g., reading different sections of a file with same tool). The `isReadOnlyCall` check (helpers.go:187) provides an escape hatch for reads.

### File read/write dedup thresholds
- FileReadCache (file_read_cache.go) — too aggressive = blocks legitimate re-reads after file modifications
- WriteDeduplicator (write_dedup.go) — blocks identical writes even if content changed between them
- ReadLoopDetector (read_loop_detector.go) — can trigger false positives on legitimate iterative analysis

### evidence_collector semantic dedup (evidence_collector.go:442)
`isSemanticDBDuplicate` checks for existing findings with same host. But same host with different paths/ports = different findings. The fingerprint builder (evidence_collector.go:1292) includes endpoint, but the semantic check may still over-deduplicate.

### Flow watchdog auto-resume (flow_watchdog.go)
Can auto-resume stalled flows up to `FLOW_WATCHDOG_MAX_RESUMES` times. If the root cause isn't transient, this just burns LLM tokens repeatedly.

## 4. Env Vars That Bypass Config Struct

These are read directly with os.Getenv, not through pkg/config/Config:

| Var | Location | Purpose |
|-----|----------|---------|
| SUBTASK_MAX_DURATION | performer.go:64 | Max subtask duration |
| MAX_TOOL_CALLS_PER_SUBTASK | performer.go:75 | Tool call limit per subtask |
| MAX_NESTING_DEPTH | performer.go:86 | Max nested agent depth |
| SUBTASK_MAX_RETRIES | task.go (env read) | Max subtask retry count |
| FLOW_WATCHDOG_ENABLED | flow_watchdog.go | Enable/disable watchdog |
| FLOW_WATCHDOG_INTERVAL | flow_watchdog.go | Watchdog check interval |
| FLOW_WATCHDOG_MAX_RESUMES | flow_watchdog.go | Max auto-resumes |
| READ_STREAK_WARN_THRESHOLD | performer.go:3331 | Read loop warning threshold |
| READ_STREAK_BLOCK_THRESHOLD | performer.go:3342 | Read loop block threshold |
| READ_STREAK_FORCE_THRESHOLD | performer.go:3353 | Read loop force-finish threshold |

## 5. Testing Gaps

| Package | Status |
|---------|--------|
| pkg/controller/ | Zero test files |
| pkg/providers/ | Has tester/ subpackage but limited coverage |
| pkg/masteragent/ | Zero test files |
| pkg/tools/ | Zero test files |
| pkg/graph/ | Zero test files |
| pkg/server/services/ | Zero test files |
| pkg/notifications/ | Has test files (notifier, publisher, telegram) |

## 6. Common Mistakes by AI Agents

1. **Editing generated.go** instead of schema.graphqls → changes get overwritten on next generate
2. **Editing *.sql.go** instead of sqlc/models/*.sql → changes get overwritten by sqlc generate
3. **Not running `go build`** after changes → syntax errors not caught
4. **Changing function signatures** without checking all callers (especially interfaces in provider.go, tools.go)
5. **Adding imports that create circular dependencies** — controller imports providers but NOT vice versa
6. **Modifying performer.go** without understanding the full call chain — 3565 lines, very interconnected
7. **Assuming tool names are strings** — use constants from registry.go (FinalyToolName, CoderToolName, etc.)
8. **Adding new DB queries** to .sql.go files instead of sqlc/models/*.sql
9. **Forgetting to update tool registration** in both registry.go AND tools.go when adding new tools
10. **Editing models.go** (database) directly — it's generated from migration SQL schemas

## 7. Import Dependency Rules

```
server → controller → providers → tools
                    → masteragent
                    → database
                    → docker
                    → templates
                    → config

providers CANNOT import controller (would be circular)
tools CANNOT import providers (would be circular)
masteragent CANNOT import controller directly (uses adapter interface)
```
