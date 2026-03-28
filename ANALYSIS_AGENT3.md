# Agent 3 — Tools & Terminal Analysis

## File: tools.go (1521 lines)

### Finding 1: No Rate Limiting on Any Tool Execution
- **Line(s):** entire file — all `Get*Executor` methods (lines 447-1520)
- **Severity:** HIGH
- **Description:** Every executor (Assistant, Primary, Installer, Coder, Pentester, Searcher, Generator, Refiner, Memorist, Enricher, Reporter) registers tool handlers with zero rate limiting. An LLM can call any tool (terminal, browser, search engines, etc.) as rapidly as it wants. This is confirmed by auditor context: "Tool calls have no rate limiting." This affects both external API tools (Google, Tavily, Perplexity — which have real cost implications) and internal tools (terminal, file — which can overload the Docker host).
- **Current Code:** All handler registration follows this pattern:
```go
handlers := map[string]ExecutorHandler{
    TerminalToolName: term.Handle,
    FileToolName:     term.Handle,
    // ... more tools
}
```
- **Proposed Fix:** Add a rate-limiting wrapper around ExecutorHandler:
```go
type RateLimitedHandler struct {
    handler  ExecutorHandler
    limiter  *rate.Limiter  // golang.org/x/time/rate
}

func NewRateLimitedHandler(handler ExecutorHandler, rps float64, burst int) ExecutorHandler {
    limiter := rate.NewLimiter(rate.Limit(rps), burst)
    return func(ctx context.Context, name string, args json.RawMessage) (string, error) {
        if err := limiter.Wait(ctx); err != nil {
            return "", fmt.Errorf("rate limit exceeded for tool %s: %w", name, err)
        }
        return handler(ctx, name, args)
    }
}
```
Apply different limits per tool category: external APIs (1-2 rps), terminal (5 rps), search (2 rps).

### Finding 2: Container Spawned with NET_RAW and Optional NET_ADMIN Capabilities
- **Line(s):** 393-401 (Prepare method)
- **Severity:** HIGH
- **Description:** The primary container is always given `NET_RAW` capability and optionally `NET_ADMIN` (if `DockerNetAdmin` config is true). `NET_RAW` allows raw socket operations (ARP spoofing, packet sniffing). `NET_ADMIN` allows full network configuration changes (routing table manipulation, interface configuration). While this is intentional for a pentesting tool, there's no per-flow or per-user granularity — every flow gets the same capabilities.
- **Current Code:**
```go
capAdd := []string{"NET_RAW"}
if fte.cfg.DockerNetAdmin {
    capAdd = append(capAdd, "NET_ADMIN")
}
```
- **Proposed Fix:** Make capabilities configurable per-flow, not globally. Add a flow-level `RequiredCapabilities` field that can be restricted by admin policy:
```go
capAdd := fte.getFlowCapabilities(fte.flowID)  // filtered by admin policy
```

### Finding 3: `context.Background()` Used Instead of Passed Context in Multiple Locations
- **Line(s):** 385, 502, 792, 992, 1272, 1340, 1407
- **Severity:** MEDIUM
- **Description:** Multiple `Get*Executor` methods call `fte.db.GetFlowPrimaryContainer(context.Background(), fte.flowID)` instead of using a passed-in context. This means:
  1. If the parent context is cancelled (e.g., user disconnects), the DB query continues unnecessarily.
  2. No timeout propagation from the caller.
  3. No tracing context propagation for observability.
- **Current Code:**
```go
container, err := fte.db.GetFlowPrimaryContainer(context.Background(), fte.flowID)
```
- **Proposed Fix:** Accept `ctx context.Context` in the executor factory methods, or store a context in the struct:
```go
func (fte *flowToolsExecutor) GetInstallerExecutor(ctx context.Context, cfg InstallerExecutorConfig) (ContextToolsExecutor, error) {
    container, err := fte.db.GetFlowPrimaryContainer(ctx, fte.flowID)
    // ...
}
```

### Finding 4: Container Entry Point is `tail -f /dev/null` — No Health Check
- **Line(s):** 405-407
- **Severity:** LOW
- **Description:** The primary container uses `tail -f /dev/null` as the entrypoint to keep it alive. There's no health check mechanism. If the container enters a degraded state (e.g., filesystem full, OOM but not killed), commands will still be attempted against it with potentially misleading errors.
- **Current Code:**
```go
&container.Config{
    Image:      fte.image,
    Entrypoint: []string{"tail", "-f", "/dev/null"},
},
```
- **Proposed Fix:** Add a Docker health check:
```go
&container.Config{
    Image:      fte.image,
    Entrypoint: []string{"tail", "-f", "/dev/null"},
    Healthcheck: &container.HealthConfig{
        Test:     []string{"CMD-SHELL", "echo ok"},
        Interval: 30 * time.Second,
        Timeout:  5 * time.Second,
        Retries:  3,
    },
},
```

### Finding 5: Release Only Deletes Primary Container — TODO Says "Delete All"
- **Line(s):** 424-433
- **Severity:** MEDIUM
- **Description:** The `Release` method has a TODO comment acknowledging it should delete all flow containers, but only deletes the primary one. If secondary containers were spawned (e.g., by pentester actions or custom executors), they become orphaned and will consume resources indefinitely.
- **Current Code:**
```go
func (fte *flowToolsExecutor) Release(ctx context.Context) error {
    if fte.store != nil {
        fte.store.Close()
    }

    // TODO: here better to get flow containers list and delete all of them
    if err := fte.docker.DeleteContainer(ctx, fte.primaryLID, fte.primaryID); err != nil {
        containerName := PrimaryTerminalName(fte.flowID)
        return fmt.Errorf("failed to delete container '%s': %w", containerName, err)
    }

    return nil
}
```
- **Proposed Fix:**
```go
func (fte *flowToolsExecutor) Release(ctx context.Context) error {
    if fte.store != nil {
        fte.store.Close()
    }

    containers, err := fte.db.GetFlowContainers(ctx, fte.flowID)
    if err != nil {
        logrus.WithError(err).Warn("failed to list flow containers for cleanup")
        // Fall through to at least delete primary
    }
    
    var errs []error
    for _, cnt := range containers {
        if err := fte.docker.DeleteContainer(ctx, cnt.LocalID.String, cnt.ID); err != nil {
            errs = append(errs, err)
        }
    }
    
    // Always attempt primary deletion even if listing failed
    if len(containers) == 0 {
        if err := fte.docker.DeleteContainer(ctx, fte.primaryLID, fte.primaryID); err != nil {
            errs = append(errs, err)
        }
    }
    
    return errors.Join(errs...)
}
```

### Finding 6: Massive Code Duplication in Executor Factory Methods
- **Line(s):** 497-1520 (all `Get*Executor` methods)
- **Severity:** MEDIUM
- **Description:** There are 12 executor factory methods that repeat nearly identical patterns: create terminal, create browser, check IsAvailable, append definitions, set handlers. Each search engine (Google, DuckDuckGo, Tavily, Traversaal, Perplexity, Searxng, Sploitus) is instantiated with the same boilerplate in `GetAssistantExecutor` and `GetSearcherExecutor`. This makes it very easy to miss adding a new tool to one executor while adding it to others, and makes bug fixes need to be applied N times.
- **Proposed Fix:** Extract common tool-creation logic into builder methods:
```go
func (fte *flowToolsExecutor) buildSearchTools(taskID, subtaskID *int64, summarizer SummarizeHandler) ([]llms.FunctionDefinition, map[string]ExecutorHandler) {
    defs := []llms.FunctionDefinition{}
    handlers := map[string]ExecutorHandler{}
    
    google := &google{flowID: fte.flowID, taskID: taskID, ...}
    if google.IsAvailable() {
        defs = append(defs, registryDefinitions[GoogleToolName])
        handlers[GoogleToolName] = google.Handle
    }
    // ... same for other search tools
    return defs, handlers
}
```

### Finding 7: AssistantExecutor Creates Terminal Without taskID/subtaskID
- **Line(s):** 501-515
- **Severity:** LOW
- **Description:** In `GetAssistantExecutor`, the terminal is created without `taskID` and `subtaskID` fields (they're zero-valued nil). This means terminal logs from assistant actions won't be properly associated with tasks, making it harder to audit/debug what the assistant did.
- **Current Code:**
```go
term := &terminal{
    flowID:       fte.flowID,
    containerID:  container.ID,
    containerLID: container.LocalID.String,
    dockerClient: fte.docker,
    tlp:          fte.tlp,
}
```
- **Proposed Fix:** Either explicitly set `taskID: nil, subtaskID: nil` to document intent, or require the assistant executor to also track task context when available.

### Finding 8: Store Close Not Idempotent — Potential Double-Close Race
- **Line(s):** 340-347 (SetEmbedder), 419-421 (Release)
- **Severity:** LOW
- **Description:** `SetEmbedder` closes the existing store before replacing it, and `Release` also closes the store. If `SetEmbedder` is called concurrently or if `Release` is called after `SetEmbedder`, the store could be double-closed. There's no mutex protecting `fte.store`.
- **Current Code:**
```go
func (fte *flowToolsExecutor) SetEmbedder(embedder embeddings.Embedder) {
    if fte.store != nil {
        fte.store.Close()
    }
    // ... create new store
}

func (fte *flowToolsExecutor) Release(ctx context.Context) error {
    if fte.store != nil {
        fte.store.Close()
    }
    // ...
}
```
- **Proposed Fix:** Add a sync.Mutex to protect store access, or use sync.Once for Release:
```go
type flowToolsExecutor struct {
    mu    sync.Mutex
    store *pgvector.Store
    // ...
}
```

---

## File: registry.go (427 lines)

### Finding 9: Terminal Tool Description Leaks Hard Timeout Limits to LLM
- **Line(s):** 157-160
- **Severity:** MEDIUM
- **Description:** The terminal tool description explicitly tells the LLM: "hard limit timeout 1200 seconds and optimum timeout 60 seconds." This leaks implementation details to the model and could encourage it to set long timeouts (up to 20 minutes). An adversarial prompt could instruct the model to "run this command with 1200 second timeout" knowing the system will accept it. The timeout limits should be enforced server-side, not advertised to the LLM.
- **Current Code:**
```go
TerminalToolName: {
    Name: TerminalToolName,
    Description: "Calls a terminal command in blocking mode with hard limit timeout 1200 seconds and " +
        "optimum timeout 60 seconds, only one command can be executed at a time",
    Parameters: reflector.Reflect(&TerminalAction{}),
},
```
- **Proposed Fix:** Remove timeout specifics from the description:
```go
TerminalToolName: {
    Name: TerminalToolName,
    Description: "Executes a terminal command in the working container. Commands run in blocking mode " +
        "with automatic timeout enforcement. Only one command can be executed at a time.",
    Parameters: reflector.Reflect(&TerminalAction{}),
},
```

### Finding 10: ToolType Classification Has Security Implications — AgentToolType Not Rate-Limited Differently
- **Line(s):** 56-77 (ToolType enum), 84-117 (toolsTypeMapping)
- **Severity:** HIGH
- **Description:** The `ToolType` classification system distinguishes between `EnvironmentToolType` (terminal, file), `SearchNetworkToolType` (Google, DuckDuckGo, etc.), `AgentToolType` (coder, pentester, maintenance, etc.), and others. However, this classification is ONLY used for display/logging purposes — it doesn't actually enforce different rate limits, cost limits, or security policies per type. `AgentToolType` tools (which spawn sub-agent LLM calls — expensive!) are treated identically to simple barrier tools. A single outer LLM call could trigger N inner agent calls, each of which can trigger their own tool calls recursively.
- **Current Code:**
```go
func GetToolType(name string) ToolType {
    if toolType, ok := toolsTypeMapping[name]; ok {
        return toolType
    }
    return NoneToolType
}
```
- **Proposed Fix:** Add enforcement to the executor's Execute method that checks tool type:
```go
func (ce *customExecutor) Execute(...) (string, error) {
    toolType := GetToolType(name)
    switch toolType {
    case AgentToolType:
        if err := ce.agentLimiter.Wait(ctx); err != nil {
            return "", fmt.Errorf("agent call rate limit exceeded")
        }
    case SearchNetworkToolType:
        if err := ce.searchLimiter.Wait(ctx); err != nil {
            return "", fmt.Errorf("search rate limit exceeded")
        }
    }
    // ... proceed with handler
}
```

### Finding 11: `allowedSummarizingToolsResult` and `allowedStoringInMemoryTools` Are Never Validated at Registration
- **Line(s):** 131-153
- **Severity:** LOW
- **Description:** Two allowlist slices control which tools' results can be summarized and which can be stored in memory. These are plain string slices with no compile-time or init-time validation that the names actually exist in the registry. If a tool name is typo'd or renamed, the allowlist silently becomes incorrect with no error.
- **Current Code:**
```go
var allowedSummarizingToolsResult = []string{
    TerminalToolName,
    BrowserToolName,
}

var allowedStoringInMemoryTools = []string{
    TerminalToolName,
    FileToolName,
    SearchToolName,
    // ...
}
```
- **Proposed Fix:** Add an `init()` function that validates all names exist in `registryDefinitions`:
```go
func init() {
    for _, name := range allowedSummarizingToolsResult {
        if _, ok := registryDefinitions[name]; !ok {
            panic(fmt.Sprintf("allowedSummarizingToolsResult references unknown tool: %s", name))
        }
    }
    for _, name := range allowedStoringInMemoryTools {
        if _, ok := registryDefinitions[name]; !ok {
            panic(fmt.Sprintf("allowedStoringInMemoryTools references unknown tool: %s", name))
        }
    }
}
```

### Finding 12: External Functions (User-Defined) Not Classified in ToolType System
- **Line(s):** 84-117 (toolsTypeMapping), cross-ref tools.go lines 29-56 (ExternalFunction)
- **Severity:** MEDIUM
- **Description:** The system supports user-defined external functions via the `Functions` struct (with URL-based callbacks). However, external functions are not represented in `toolsTypeMapping`. When `GetToolType()` is called on an external function name, it returns `NoneToolType`. This means external functions bypass any type-based security policies, logging categorization, and rate limiting that might be added in the future. External functions call arbitrary URLs provided by users — they should arguably have the strictest controls.
- **Proposed Fix:** Add a dedicated `ExternalToolType` and register external functions in the mapping at executor creation time:
```go
const (
    // ...
    ExternalToolType  // Add to ToolType enum
)

// When registering external functions:
for _, fn := range functions.Function {
    toolsTypeMapping[fn.Name] = ExternalToolType
}
```

### Finding 13: Tool Schema Reflection Uses Package-Level Reflector — Not Thread-Safe for Concurrent Modifications
- **Line(s):** 126-129
- **Severity:** LOW
- **Description:** The `reflector` is a package-level variable used for schema generation. While `jsonschema.Reflector` is likely safe for concurrent reads, this is a shared mutable struct. If any code modifies reflector settings concurrently (e.g., changing `DoNotReference`), it could cause data races.
- **Current Code:**
```go
var reflector = &jsonschema.Reflector{
    DoNotReference: true,
    ExpandedStruct: true,
}
```
- **Proposed Fix:** Since this is used only at init time with `registryDefinitions` (which are populated at package load), this is likely safe in practice. But for defensive coding, either make it a const-like pattern or document that it must not be modified after init.

### Finding 14: `getMessageType` Falls Through to `MsglogTypeThoughts` for Unknown Tools
- **Line(s):** 380-398
- **Severity:** LOW
- **Description:** The `getMessageType` function has a default case that returns `MsglogTypeThoughts` for any unrecognized tool name. This means if a new tool is added but the developer forgets to update this switch, its messages will be silently logged as "thoughts" — incorrect categorization that makes debugging and auditing harder.
- **Current Code:**
```go
func getMessageType(name string) database.MsglogType {
    switch name {
    // ... cases ...
    default:
        return database.MsglogTypeThoughts
    }
}
```
- **Proposed Fix:** Add a warning log for the default case, or use the tool type mapping:
```go
default:
    logrus.WithField("tool_name", name).Warn("unknown tool type for message logging, defaulting to thoughts")
    return database.MsglogTypeThoughts
```

---

## File: terminal.go (408 lines)

### Finding 15: No Command Blocklist/Allowlist — Any Command Can Be Executed
- **Line(s):** 127-132 (ExecCommand)
- **Severity:** CRITICAL
- **Description:** The terminal tool accepts any `command` string from the LLM and passes it directly to `sh -c command` with zero filtering. This is the confirmed known issue: "Terminal tool can run any command with no safeguards." An adversarial prompt could instruct the LLM to run `rm -rf /`, install backdoors, exfiltrate data via curl, or pivot to other containers/hosts. Even without adversarial prompts, LLM hallucinations can cause destructive commands.
- **Current Code:**
```go
cmd := []string{
    "sh",
    "-c",
    command,
}
```
- **Proposed Fix:** Add a command validation layer with configurable blocklist:
```go
var blockedCommands = []string{
    "rm -rf /", "mkfs", "dd if=/dev/zero",
    ":(){ :|:& };:", // fork bomb
    "curl.*|sh", "wget.*|sh", // pipe-to-shell
}

var blockedPatterns = []*regexp.Regexp{
    regexp.MustCompile(`(?i)(curl|wget).*\|\s*(ba)?sh`),
    regexp.MustCompile(`(?i)nc\s+-[el]`),  // reverse shells
    regexp.MustCompile(`(?i)/dev/(tcp|udp)/`), // bash reverse shells
}

func validateCommand(command string) error {
    for _, pattern := range blockedPatterns {
        if pattern.MatchString(command) {
            return fmt.Errorf("command blocked by security policy: matches pattern %s", pattern.String())
        }
    }
    return nil
}
```
Note: Container isolation provides some protection, but with `NET_RAW`/`NET_ADMIN` capabilities, network-based attacks are still possible from within.

### Finding 16: No Output Size Limit on Command Execution — Unbounded Memory Usage
- **Line(s):** 207-219 (getExecResult, io.Copy)
- **Severity:** HIGH
- **Description:** The `getExecResult` method uses `io.Copy(&dst, resp.Reader)` to read the entire command output into a `bytes.Buffer` with no size limit. If a command produces gigabytes of output (e.g., `cat /dev/urandom | xxd`, `find / -type f`, a verbose build), it will consume unbounded memory on the host. The only safeguard is the timeout, but a fast-producing command can generate enormous output before timeout.
- **Current Code:**
```go
dst := bytes.Buffer{}
errChan := make(chan error, 1)

go func() {
    _, copyErr := io.Copy(&dst, resp.Reader)
    errChan <- copyErr
}()
```
- **Proposed Fix:** Use `io.LimitReader` to cap output size:
```go
const maxOutputSize = 1 * 1024 * 1024 // 1 MB
dst := bytes.Buffer{}
errChan := make(chan error, 1)

go func() {
    limitedReader := io.LimitReader(resp.Reader, maxOutputSize+1)
    _, copyErr := io.Copy(&dst, limitedReader)
    errChan <- copyErr
}()

// After reading:
if dst.Len() > maxOutputSize {
    truncated := dst.String()[:maxOutputSize]
    return truncated + "\n\n[OUTPUT TRUNCATED: exceeded 1MB limit]", nil
}
```

### Finding 17: Timeout Value Controlled by LLM with Insufficient Validation
- **Line(s):** 93-94 (Handle method), 160-162 (ExecCommand)
- **Severity:** HIGH
- **Description:** The LLM provides the `Timeout` field in `TerminalAction`. The only validation is `if timeout <= 0 || timeout > 20*time.Minute` which clamps to the default 5-minute timeout. However, the JSON schema description advertises "minimum 10; maximum 1200; default 60" but this isn't enforced at the struct level — only the 20-minute hard cap is. This means the LLM can set a 1-second timeout (causing premature kills) or a 1200-second (20 min) timeout tying up resources. The `defaultExtraExecTimeout` (5 seconds) is also added on top, so the actual timeout is `action.Timeout + 5` seconds.
- **Current Code:**
```go
timeout := time.Duration(action.Timeout)*time.Second + defaultExtraExecTimeout
// ... later in ExecCommand:
if timeout <= 0 || timeout > 20*time.Minute {
    timeout = defaultExecCommandTimeout
}
```
- **Proposed Fix:** Enforce both min and max:
```go
const (
    minExecTimeout = 10 * time.Second
    maxExecTimeout = 5 * time.Minute  // reduce from 20 min
)

func clampTimeout(requested time.Duration) time.Duration {
    if requested < minExecTimeout {
        return minExecTimeout
    }
    if requested > maxExecTimeout {
        return maxExecTimeout
    }
    return requested
}
```

### Finding 18: Error Swallowing in `wrapCommandResult` — Errors Returned as Success
- **Line(s):** 63-77
- **Severity:** HIGH
- **Description:** The `wrapCommandResult` method takes errors from command execution and **converts them to successful return values**: it returns `(fmt.Sprintf("terminal tool '%s' handled with error: %v", name, err), nil)`. This means the caller (executor) never sees the error, considers the tool call successful, and feeds the error message as a "result" to the LLM. While this prevents the agent loop from crashing, it means:
  1. Error metrics/tracking won't count these as failures
  2. The DB will record this as a successful tool call
  3. The LLM might misinterpret the error message as valid output
- **Current Code:**
```go
func (t *terminal) wrapCommandResult(ctx context.Context, args json.RawMessage, name, result string, err error) (string, error) {
    if err != nil {
        // ... logging ...
        return fmt.Sprintf("terminal tool '%s' handled with error: %v", name, err), nil
    }
    return result, nil
}
```
- **Proposed Fix:** Return a structured error response that the executor can distinguish:
```go
type ToolErrorResult struct {
    IsError bool   `json:"is_error"`
    Tool    string `json:"tool"`
    Message string `json:"message"`
    Output  string `json:"output,omitempty"`
}

func (t *terminal) wrapCommandResult(...) (string, error) {
    if err != nil {
        // Still return nil error to not crash agent loop,
        // but use a structured format the executor can detect
        errResult := ToolErrorResult{
            IsError: true,
            Tool:    name,
            Message: err.Error(),
            Output:  result[:min(len(result), 1000)],
        }
        data, _ := json.Marshal(errResult)
        return string(data), nil  
    }
    return result, nil
}
```

### Finding 19: ReadFile Has 100MB Limit But No Protection Against Reading Binary Files
- **Line(s):** 306-308
- **Severity:** MEDIUM
- **Description:** `ReadFile` allows reading files up to 100MB (`maxReadFileSize = 100 * 1024 * 1024`). This is enormous for a file that will be sent as text to an LLM. A 100MB text file would be hundreds of thousands of tokens. Furthermore, there's no check for binary files — reading a compiled binary, an image, or a compressed archive would produce garbage text that wastes LLM context. The entire file content is read into memory in one shot (`make([]byte, tarHeader.Size)`), so a 100MB allocation happens on every large file read.
- **Current Code:**
```go
const maxReadFileSize int64 = 100 * 1024 * 1024 // 100 MB limit
if tarHeader.Size > maxReadFileSize {
    return "", fmt.Errorf("file '%s' size %d exceeds maximum allowed size %d", tarHeader.Name, tarHeader.Size, maxReadFileSize)
}
```
- **Proposed Fix:** 
  1. Reduce the limit drastically (e.g., 256KB for text destined for LLM context)
  2. Add binary file detection:
```go
const maxReadFileSize int64 = 256 * 1024 // 256 KB for LLM consumption

// After reading first 512 bytes, check for binary content:
if isBinary(fileContent[:min(len(fileContent), 512)]) {
    return fmt.Sprintf("file '%s' appears to be binary (%d bytes), cannot display as text", tarHeader.Name, tarHeader.Size), nil
}
```

### Finding 20: ReadFile Reads Entire Directory Recursively Without Limits
- **Line(s):** 269-330 (ReadFile with tar iteration)
- **Severity:** MEDIUM
- **Description:** If `path` points to a directory, `CopyFromContainer` returns a tar archive of the entire directory tree. The code iterates through ALL files in the tar with no limit on the number of files or total accumulated size. A directory with thousands of files could produce massive output. While individual files are capped at 100MB, the accumulated `buffer` has no cap.
- **Current Code:**
```go
var buffer strings.Builder
tarReader := tar.NewReader(reader)
for {
    tarHeader, err := tarReader.Next()
    if err == io.EOF {
        break
    }
    // ... reads and appends every file
    buffer.Write(fileContent)
}
```
- **Proposed Fix:** Add limits:
```go
const maxTotalReadSize = 512 * 1024  // 512 KB total
const maxFilesRead = 50

filesRead := 0
for {
    tarHeader, err := tarReader.Next()
    if err == io.EOF {
        break
    }
    filesRead++
    if filesRead > maxFilesRead {
        buffer.WriteString(fmt.Sprintf("\n[TRUNCATED: read %d files, skipping rest]\n", maxFilesRead))
        break
    }
    // ... read file
    if buffer.Len() > maxTotalReadSize {
        buffer.WriteString("\n[TRUNCATED: total output exceeded 512KB]\n")
        break
    }
}
```

### Finding 21: WriteFile Has Path Traversal Potential
- **Line(s):** 338-390 (WriteFile)
- **Severity:** HIGH
- **Description:** The `WriteFile` method uses `filepath.Dir(path)` and `filepath.Base(path)` to construct the tar archive, then copies it to the container. While the container provides some isolation, the path is entirely LLM-controlled. The LLM could write to sensitive paths like `/etc/passwd`, `/etc/shadow`, `/root/.ssh/authorized_keys`, or `/usr/bin/` to install executables. Combined with `NET_RAW`/`NET_ADMIN` capabilities, writing a malicious script and then executing it via terminal could enable container escape or lateral movement.
- **Current Code:**
```go
func (t *terminal) WriteFile(ctx context.Context, flowID int64, content string, path string) (string, error) {
    // ... no path validation ...
    dir := filepath.Dir(path)
    err = t.dockerClient.CopyToContainer(ctx, containerName, dir, archive, container.CopyToContainerOptions{
        AllowOverwriteDirWithFile: true,
    })
```
- **Proposed Fix:** Restrict write paths to the work directory:
```go
func (t *terminal) WriteFile(ctx context.Context, flowID int64, content string, path string) (string, error) {
    // Ensure path is within work directory
    cleanPath := filepath.Clean(path)
    if !strings.HasPrefix(cleanPath, docker.WorkFolderPathInContainer) {
        return "", fmt.Errorf("write path must be within %s, got: %s", docker.WorkFolderPathInContainer, path)
    }
    // ... rest of method
}
```

### Finding 22: Detach Mode Has Invisible Background Execution with No Tracking
- **Line(s):** 175-193 (detach handling in ExecCommand)
- **Severity:** MEDIUM
- **Description:** When `detach=true`, the command is started in a goroutine and if it doesn't complete within 500ms (`defaultQuickCheckTimeout`), the function returns "Command started in background" with no way to:
  1. Check its status later
  2. Get its output when it completes
  3. Kill it if needed
  4. Know if it failed
  The goroutine continues running but its result channel is never read. This is a goroutine leak — the channel and result are GC'd but the Docker exec continues running up to the full timeout.
- **Current Code:**
```go
if detach {
    resultChan := make(chan execResult, 1)
    go func() {
        output, err := t.getExecResult(ctx, createResp.ID, timeout)
        resultChan <- execResult{output: output, err: err}
    }()

    select {
    case result := <-resultChan:
        // ...
    case <-time.After(defaultQuickCheckTimeout):
        return fmt.Sprintf("Command started in background with timeout %s (still running)", timeout), nil
    }
}
```
- **Proposed Fix:** Track background executions and provide a way to query/kill them:
```go
type backgroundExec struct {
    id        string
    command   string
    startTime time.Time
    resultCh  chan execResult
    cancel    context.CancelFunc
}

// Store in terminal struct and provide methods:
func (t *terminal) ListBackgroundExecs() []backgroundExec { ... }
func (t *terminal) KillBackgroundExec(id string) error { ... }
```

### Finding 23: Timeout Error Leaks Partial Output in Error Message
- **Line(s):** 228-231
- **Severity:** MEDIUM
- **Description:** When a command times out, the partial output is embedded in the error message: `fmt.Errorf("timeout value is too low...: %s", result)`. This error message gets returned through `wrapCommandResult` which converts it to a string result for the LLM. The partial output could be arbitrarily large (no size limit on `dst.String()` — see Finding 16) and could contain sensitive information from the container.
- **Current Code:**
```go
case <-ctx.Done():
    resp.Close()
    <-errChan
    result := fmt.Sprintf("temporary output: %s", dst.String())
    return "", fmt.Errorf("timeout value is too low, use greater value if you need so: %w: %s", ctx.Err(), result)
```
- **Proposed Fix:** Limit the partial output size:
```go
case <-ctx.Done():
    resp.Close()
    <-errChan
    partial := dst.String()
    if len(partial) > 4096 {
        partial = partial[:4096] + "\n[partial output truncated]"
    }
    return "", fmt.Errorf("command timed out after %v: partial output: %s", timeout, partial)
```

### Finding 24: Summarization Only Applied to Terminal and Browser — Other Tools Can Return Huge Results
- **Line(s):** Cross-file: registry.go line 131-133, executor.go line 319-320
- **Severity:** MEDIUM
- **Description:** The summarization mechanism (`allowedSummarizingToolsResult`) only covers `TerminalToolName` and `BrowserToolName`. Other tools that can return large results — like file reads (100MB!), Google/DuckDuckGo/Tavily/Perplexity search results, Sploitus — are NOT summarized even when they exceed `DefaultResultSizeLimit` (16KB). This means those large results go directly to the LLM context, potentially exceeding token limits or causing degraded performance.
- **Current Code:**
```go
var allowedSummarizingToolsResult = []string{
    TerminalToolName,
    BrowserToolName,
}
// ...
allowSummarize := slices.Contains(allowedSummarizingToolsResult, name)
if ce.summarizer != nil && allowSummarize && len(result) > DefaultResultSizeLimit {
```
- **Proposed Fix:** Either add all content-producing tools to the summarization list, or add a hard truncation fallback for non-summarized tools:
```go
// After summarization attempt:
if len(result) > MaxHardResultLimit {
    result = result[:MaxHardResultLimit] + "\n\n[RESULT TRUNCATED: exceeded maximum size]"
}
```

### Finding 25: `ExecCommand` Uses `Tty: true` — Allows Terminal Escape Sequences
- **Line(s):** 165-170
- **Severity:** LOW
- **Description:** The exec is created with `Tty: true`, which means commands can output ANSI escape sequences, terminal control codes, and potentially terminal injection attacks. While the output is logged and fed to the LLM as text, TTY escape sequences could:
  1. Corrupt log display
  2. Confuse output parsing
  3. In rare cases, exploit terminal emulator vulnerabilities in the frontend
- **Current Code:**
```go
createResp, err := t.dockerClient.ContainerExecCreate(ctx, containerName, container.ExecOptions{
    Cmd:          cmd,
    AttachStdout: true,
    AttachStderr: true,
    WorkingDir:   cwd,
    Tty:          true,
})
```
- **Proposed Fix:** Strip ANSI escape sequences from output before logging/returning, or use `Tty: false` for non-interactive commands:
```go
import "regexp"
var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func stripANSI(s string) string {
    return ansiRegex.ReplaceAllString(s, "")
}
```

---

## Cross-Cutting Concerns

### Finding 26: No Concurrent Execution Guard Despite "Only One Command at a Time" Claim
- **Line(s):** registry.go line 158, terminal.go entire Handle method
- **Severity:** HIGH
- **Description:** The terminal tool description says "only one command can be executed at a time," but there's NO mutex, semaphore, or any concurrency control in the `terminal` struct or `Handle` method. If the LLM issues multiple tool calls in parallel (which langchain supports), multiple commands will execute simultaneously in the same container, potentially interfering with each other (e.g., concurrent writes to the same file, conflicting package installations).
- **Proposed Fix:** Add a mutex to the terminal struct:
```go
type terminal struct {
    mu           sync.Mutex
    flowID       int64
    // ...
}

func (t *terminal) ExecCommand(...) (string, error) {
    t.mu.Lock()
    defer t.mu.Unlock()
    // ...
}
```

### Finding 27: No Audit Trail for Security-Sensitive Operations
- **Line(s):** terminal.go entire file
- **Severity:** MEDIUM
- **Description:** While terminal commands are logged via `tlp.PutMsg`, there's no structured security audit log. Command execution in a pentesting tool is security-critical. The logs mix with regular output logs and there's no separate security audit trail capturing: who initiated the command, which LLM model, what the original user prompt was, what network access was used.
- **Proposed Fix:** Add structured security audit events:
```go
func (t *terminal) auditLog(ctx context.Context, action, command, result string, err error) {
    logrus.WithContext(ctx).WithFields(logrus.Fields{
        "audit":     true,
        "flow_id":   t.flowID,
        "action":    action,
        "command":   command,
        "result":    result[:min(len(result), 256)],
        "error":     err,
        "timestamp": time.Now().UTC(),
    }).Info("security audit")
}
```

---

## Summary Statistics

| Severity | Count |
|----------|-------|
| CRITICAL | 2     |
| HIGH     | 6     |
| MEDIUM   | 9     |
| LOW      | 5     |
| **Total**| **22**|

## Top 5 Priority Fixes

1. **[CRITICAL] Finding 15:** Add command blocklist/validation for terminal execution
2. **[CRITICAL] Finding 1:** Add rate limiting to all tool execution
3. **[HIGH] Finding 16:** Add output size limits to prevent memory exhaustion
4. **[HIGH] Finding 21:** Add path validation to WriteFile to prevent writing to sensitive locations
5. **[HIGH] Finding 26:** Add concurrency guard to enforce "one command at a time" promise
