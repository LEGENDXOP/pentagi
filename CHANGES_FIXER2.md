# CHANGES_FIXER2.md — Applied Fixes to Detection System & Helpers

## Files Modified
1. `backend/pkg/providers/helpers.go`
2. `backend/pkg/providers/handlers.go`
3. `backend/pkg/providers/subtask_patch.go`
4. `backend/pkg/providers/performer.go` (minor: constructor update)

---

## Fix 2: Replace repeatingDetector with sliding-window + category-based detection
**File:** `backend/pkg/providers/helpers.go`

**Problem:** The old `repeatingDetector` only caught *consecutive identical* calls. If an agent alternated between two commands (A, B, A, B…), the detector never triggered because it reset its counter on any different call.

**Changes:**
- Added `const repeatingWindowSize = 10` — sliding window of last 10 calls
- Replaced struct: added `history` (sliding window) and `threshold` fields
- Added `newRepeatingDetector()` constructor that initializes threshold from `RepeatingToolCallThreshold`
- `detect()` now maintains a sliding window and counts frequency of each `(name, args)` pair — triggers when any pair appears ≥ threshold times within the window
- `clearCallArguments()` now produces canonical JSON via `json.Marshal()` instead of non-deterministic `fmt.Sprintf("%v")` — ensures identical arguments always produce the same string
- Removed unused `sort` import
- Updated `performer.go` to use `newRepeatingDetector()` instead of `&repeatingDetector{}`

---

## Fix 16: Fix getTasksInfo mutating DB-returned slice
**File:** `backend/pkg/providers/helpers.go`

**Problem:** `append(slice[:i], slice[i+1:]...)` modifies the underlying array of the DB-returned slice. If the database layer caches or reuses returned slices, this corrupts shared state.

**Changes:**
- Replaced in-place `append` removal with a new `otherTasks` slice built by iteration
- The original DB slice is never modified

---

## Fix 27: Fix nil subtask pointer in prepareExecutionContext
**File:** `backend/pkg/providers/helpers.go`

**Problem:** After sorting subtasks and searching for `subtaskID`, if the ID wasn't found, `subtasksInfo.Subtask` remained nil. The code proceeded to use it in template rendering without a nil check, risking nil pointer dereferences.

**Changes:**
- Added explicit nil check after the subtask search loop
- Returns a descriptive error `"subtask %d not found in task's subtask list"` instead of proceeding with nil

---

## Fix 23: Fix GetMemoristHandler variable shadowing and format string bugs
**File:** `backend/pkg/providers/handlers.go`

**Problem:** 
1. `taskID := action.TaskID.Int64()` shadowed the outer closure parameter `taskID *int64`
2. `subtaskID := action.SubtaskID.Int64()` shadowed the outer `subtaskID *int64`
3. Format string used `%d` with a pointer `taskID` (prints memory address, not value)
4. Grammar errors: "user no specified task"

**Changes:**
- Renamed inner variables to `requestedTaskID` and `requestedSubtaskID` to avoid shadowing
- Fixed the else branch for taskID: added nil check (`else if taskID != nil`) and dereference (`*taskID`)
- Added separate else branch when taskID is nil
- Fixed grammar: "user no specified" → "user did not specify"
- Applied same pattern to subtaskID handling

---

## Fix 24: Fix summarizer dropping middle content
**File:** `backend/pkg/providers/handlers.go`

**Problem:** When a tool result exceeded `2*msgSummarizerLimit`, the code kept the first and last N bytes and put `{TRUNCATED}` in the middle. For pentesting tools, the middle of a scan often contains the most critical findings.

**Changes:**
- Replaced simple head+tail truncation with a sampling strategy:
  - Always preserves head (first chunk) and tail (last chunk)
  - Takes 3 evenly-spaced samples from the middle section
  - Uses remaining budget for middle content
  - Labels sections clearly: `{SAMPLED_MIDDLE}` and `{...}` between samples

---

## Fix 29: Fix fixToolCallArgs validation
**File:** `backend/pkg/providers/handlers.go`

**Problem:** When the tool call fixer LLM produced invalid JSON, the result was returned as-is without validation. This could create an infinite fix-retry loop (fixer produces bad JSON → retry → fixer again → bad JSON again).

**Changes:**
- Added `json.Unmarshal` validation of the fixer's output before returning
- If the fixer produced invalid JSON, returns a descriptive error and ends the agent span with `"invalid_json"` status
- Prevents the infinite fix-retry loop

---

## Fix 41: Fix wrapError panic on nil
**File:** `backend/pkg/providers/handlers.go`

**Problem:** `wrapError` called `err.Error()` and `fmt.Errorf("%s: %w", msg, err)` without a nil check. If called with nil error, `err.Error()` panics and `%w` with nil produces garbled output.

**Changes:**
- Added nil check at the top of `wrapError`
- When `err == nil`: logs the message alone and returns `errors.New(msg)`
- When `err != nil`: original behavior with `WithError(err)` and `fmt.Errorf` wrapping
- Added `"errors"` import to handlers.go

---

## Fix 28: Fix reorder-after-remove in subtask_patch.go
**File:** `backend/pkg/providers/subtask_patch.go`

**Problem:** If a `reorder` operation referenced a subtask that was `remove`d in the same patch, `calculateInsertIndex` silently fell back to appending at the end. The reordered subtask ended up in the wrong position with no warning.

**Changes:**
- `calculateInsertIndex` now accepts a `removed map[int64]bool` parameter and returns `(int, error)`
- When `afterID` references a removed subtask, logs a warning and returns an error explaining the issue (still returns the fallback position for graceful degradation)
- When `afterID` is not found at all, logs a warning
- Both call sites (add + reorder) updated to handle the new `(int, error)` return — they log warnings but continue with the fallback position to avoid breaking the operation entirely
