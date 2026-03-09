# Phase 2 — Upgrade 2.6: Workspace File Injection for Subtask Generator

## Problem
The subtask generator (`subtasks_generator.tmpl`) was blind to existing files in the container workspace (`/work/`). When files like `STATE.json` or `FINDINGS.md` already existed from a previous run or completed subtask, the generator would re-create them because it had no visibility into what was already there.

The template already had `{{if .WorkspaceFiles}}` / `{{.Cwd}}` blocks ready — they just were never populated from the backend.

## Changes

### 1. `backend/pkg/tools/terminal.go` — New `FileInfo` struct and `ListWorkspaceFiles` function

Added at the end of the file:

- **`FileInfo`** struct with `Path string`, `Size int64`, `Modified string` fields (JSON-tagged)
- **`ListWorkspaceFiles(ctx, dockerClient, containerName, containerLID, workdir)`** standalone function that:
  - Executes `find <workdir> -maxdepth 2 -type f -printf '%s\t%TY-%Tm-%Td %TH:%TM\t%p\n'` inside the container
  - Limits output to 100 files via `head -100`
  - Uses a 10-second timeout
  - Parses the tab-delimited output into `[]FileInfo`
  - Returns `nil, nil` for an empty workspace (not an error)
  - Properly shell-escapes the workdir path

### 2. `backend/pkg/tools/tools.go` — Interface extension and implementation

- Added `ListWorkspaceFiles(ctx context.Context) ([]FileInfo, error)` to the `FlowToolsExecutor` interface
- Added implementation on `flowToolsExecutor` that delegates to the standalone `ListWorkspaceFiles` function using the executor's `docker` client, `flowID` (for container name), and `primaryLID`

### 3. `backend/pkg/providers/provider.go` — Generator context population

In `GenerateSubtasks()`:

- Added `"pentagi/pkg/docker"` import
- Before building `generatorContext`, calls `fp.executor.ListWorkspaceFiles(ctx)`
- On error: logs a warning and continues with `nil` (graceful degradation — generator still works, just without file visibility)
- On success: populates `generatorContext["user"]["WorkspaceFiles"]` with the file list
- Always sets `generatorContext["user"]["Cwd"]` to `docker.WorkFolderPathInContainer` (`"/work"`)

### 4. `backend/pkg/templates/templates.go` — Variable declarations

Added `"WorkspaceFiles"` and `"Cwd"` to `PromptVariables[PromptTypeSubtasksGenerator]` so the template validator recognizes them as authorized variables.

### 5. `backend/pkg/templates/validator/testdata.go` — Test data

Added `"WorkspaceFiles"` entry to `CreateDummyTemplateData()` with two sample `tools.FileInfo` entries, ensuring the template validator test can render the template with workspace state.

## Template Rendering Flow

```
GenerateSubtasks()
  │
  ├─ fp.executor.ListWorkspaceFiles(ctx)  ← NEW
  │   └─ executes `find /work -maxdepth 2 -type f -printf ...` in container
  │
  ├─ generatorContext["user"]["WorkspaceFiles"] = files  ← NEW
  ├─ generatorContext["user"]["Cwd"] = "/work"           ← NEW
  │
  ├─ fp.prompter.RenderTemplate(PromptTypeSubtasksGenerator, generatorContext["user"])
  │   └─ subtasks_generator.tmpl now renders <workspace_state> block with real data
  │
  └─ fp.performSubtasksGenerator(...)
```

## Design Decisions

1. **Standalone function, not method**: `ListWorkspaceFiles` is a package-level function (not a `terminal` method) because the subtask generator doesn't have a `terminal` instance — it's called from the provider layer via the executor.

2. **Graceful degradation**: If `ListWorkspaceFiles` fails (container not running yet, docker issue, etc.), the generator proceeds without workspace visibility. This is a non-critical enhancement.

3. **`find -printf` over `stat`**: Using `find -printf` gets path, size, and mtime in a single exec call with no additional parsing complexity. The `%TY-%Tm-%Td %TH:%TM` format gives a human-readable timestamp.

4. **100-file limit**: Prevents token bloat if the workspace has many files. `maxdepth 2` also keeps the listing shallow and relevant.

5. **Nil vs empty slice**: Returns `nil` (not `[]FileInfo{}`) for empty workspaces, which makes `{{if .WorkspaceFiles}}` in the template evaluate to false — so no empty `<workspace_state>` block is rendered.
