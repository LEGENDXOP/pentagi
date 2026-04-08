# Package Map — Function & File Index

## pkg/controller (5,900 lines, 25 files)

### Core Files
FILE flows.go (550) — Top-level flow controller, CRUD, Master Agent init
FILE flow.go (1068) — Flow worker lifecycle, Docker setup, auto-completion
FILE task.go (667) — Task worker, subtask iteration with retry/backoff
FILE subtask.go (444) — Subtask worker, agent chain execution
FILE subtasks.go (277) — Subtask controller, plan generation/refinement
FILE assistant.go (583) — Assistant worker lifecycle
FILE flow_control.go (287) — Pause/resume/steer/abort flow control
FILE flow_watchdog.go (307) — Stall detection, zombie recovery
FILE flow_control_adapter.go (39) — Adapter for masteragent interface
FILE context.go (61) — Shared FlowContext/TaskContext/SubtaskContext structs

### Log Workers (pattern: Xlog.go = per-flow worker, Xlogs.go = controller)
FILE msglog.go (248) + msglogs.go (69) — Message logs
FILE alog.go (82) + alogs.go (72) — Agent logs
FILE aslog.go (418) + aslogs.go (85) — Assistant logs (with streaming batcher)
FILE slog.go (86) + slogs.go (72) — Search logs
FILE termlog.go (101) + termlogs.go (82) — Terminal logs
FILE vslog.go (94) + vslogs.go (72) — Vector store logs
FILE screenshot.go (63) + screenshots.go (69) — Screenshots

### Key Functions
FUNC NewFlowController → flows.go:79 — Creates top-level controller
FUNC CreateFlow → flows.go:187 — Creates new flow with provider/docker
FUNC LoadFlows → flows.go:142 — Loads existing flows on startup
FUNC ResumeFlow → flows.go:370 — Resumes paused flow
FUNC NewFlowWorker → flow.go:114 — Creates flow worker with containers
FUNC LoadFlowWorker → flow.go:300 — Loads flow from DB
FUNC checkAndFinishIfDone → flow.go (unexported) — Auto-completion logic
FUNC NewTaskWorker → task.go:50 — Creates task with subtask generation
FUNC (tw).Run → task.go:354 — Main task loop: iterate subtasks with retry
FUNC NewSubtaskWorker → subtask.go:49 — Creates subtask
FUNC (sw).Run → subtask.go:332 — Runs agent chain for subtask
FUNC NewFlowControlManager → flow_control.go:72 — Creates pause/steer manager
FUNC (fcm).CheckPoint → flow_control.go (interface) — Called from agent loops

### Imports This Package: server/services, graph
### This Package Imports: providers, tools, database, config, docker, masteragent, notifications

---

## pkg/providers (28,500 lines, ~50 files)

### Core Files
FILE performer.go (3565) — Core agent execution loop, tool dispatch, circuit breaker
FILE provider.go (1270) — FlowProvider interface, subtask generation/refinement
FILE providers.go (1046) — ProviderController, provider CRUD, LLM client setup
FILE handlers.go (1222) — Agent handler factories (coder, pentester, searcher, etc.)
FILE performers.go (993) — Agent chain runners (performCoder, performPentester, etc.)
FILE helpers.go (1935) — Repeat detection, chain management, execution context ⚠️
FILE evidence_collector.go (1428) — Finding registry, evidence collection, report gen
FILE assistant.go (405) — AssistantProvider for chat-mode agents

### Analysis & Detection Files
FILE read_loop_detector.go (838) — Detects agents stuck in read loops
FILE file_read_cache.go (574) — Caches file reads, prevents re-reads
FILE terminal_cache.go (359) — Caches terminal output
FILE write_dedup.go (264) — Deduplicates write operations
FILE tool_circuit_breaker.go (76) — Circuit breaker for failing tools
FILE completed_work_tracker.go (1245) — Tracks completed work, prevents re-runs
FILE blocker_tracker.go (480) — Tracks blockers during execution

### Security/Attack Files
FILE attack_budget.go (470) — Per-vector attempt budgets
FILE attack_budget_integration.go (186) — Budget integration with tool calls
FILE methodology.go (731) — OWASP methodology coverage tracking
FILE category_tracker.go (496) — P0/P1 category coverage
FILE finding_tracker.go (417) — Finding tracking with chain suggestions
FILE waf_detector.go (460) — WAF detection from tool output
FILE chains.go (311) — Attack chain definitions
FILE exploit_pipeline.go (441) — Exploit development state machine
FILE exploit_templates.go (82) — Python exploit template selection
FILE dedup.go (293) — Finding deduplication engine
FILE compliance.go (391) — OWASP/CVSS compliance mapping
FILE remediation.go (1671) — Remediation recommendations
FILE industry_detector.go (356) — Industry-specific playbook detection
FILE cross_flow.go (262) — Cross-flow insight extraction

### Execution Management Files
FILE context_manager.go (637) — Priority-based context management
FILE execution_state.go (441) — Persistent execution state with async writer
FILE subtask_timebox.go (621) — Per-subtask time limits
FILE subtask_patch.go (279) — Subtask plan modification validation
FILE dag_scheduler.go (295) — DAG-based subtask scheduling
FILE parallel_executor.go (201) — Parallel subtask execution
FILE budget.go (113) — Execution time budget
FILE cost.go (296) — LLM cost tracking

### Key Functions
FUNC performAgentChain → performer.go:205 — Main agent loop (LLM call → tool → check)
FUNC execToolCall → performer.go:2278 — Dispatches tool calls to handlers
FUNC callWithRetries → performer.go:2555 — LLM call with retry logic
FUNC performReflector → performer.go:2720 — Self-reflection on stuck agents
FUNC clearCallArguments → helpers.go:576 ⚠️ — Strips args for repeat detection
FUNC (rd).detect → helpers.go:61 ⚠️ — Repeat call detection
FUNC NewEvidenceCollector → evidence_collector.go:78 — Creates evidence collector
FUNC (fr).CheckAndRegister → evidence_collector.go:200 — Finding dedup + register
FUNC (fr).ParseAndSyncFindingsMD → evidence_collector.go:627 — Sync FINDINGS.md to DB
FUNC NewFlowProvider → providers.go:319 — Creates provider for a flow
FUNC GetAskAdviceHandler → handlers.go:199 — Advice agent handler
FUNC GetCoderHandler → handlers.go:356 — Coder agent handler
FUNC GetPentesterHandler → handlers.go:715 — Pentester agent handler
FUNC performCoder → performers.go:411 — Runs coder agent chain
FUNC performPentester → performers.go:647 — Runs pentester agent chain

### Subdirectories
anthropic/ bedrock/ custom/ gemini/ ollama/ openai/ — LLM provider implementations
pconfig/ (903 lines) — Provider configuration
provider/ (1188 lines) — Base provider implementation
embeddings/ (498 lines) — Embedding providers

---

## pkg/tools (15,500 lines, 29 files)

### Core Files
FILE tools.go (1711) — Tool/FlowToolsExecutor interfaces, executor configs, wiring
FILE executor.go (727) — Tool dispatch with rate limiting, size limits, interceptors
FILE registry.go (614) — Tool name constants, type mapping, schema definitions
FILE args.go (382) — Tool argument structs

### Tool Implementations
FILE terminal.go (865) — Shell execution in Docker containers
FILE browser.go (454) — Headless browser (simple HTTP)
FILE browser_playwright.go (567) — Playwright browser automation
FILE duckduckgo.go (563) — DuckDuckGo search
FILE google.go (152) — Google Custom Search
FILE tavily.go (312) — Tavily search
FILE perplexity.go (420) — Perplexity AI search
FILE searxng.go (314) — SearXNG meta-search
FILE sploitus.go (384) — Sploitus exploit search
FILE traversaal.go (163) — Traversaal search
FILE nuclei.go (793) — Nuclei vulnerability scanner
FILE graphiti_search.go (903) — Knowledge graph search
FILE interactsh.go (806) — Out-of-band interaction testing
FILE interactsh_monitor.go (204) — Background interaction polling
FILE memory.go (238) — Vector store memory search
FILE code.go (286) — Code vector store search/store
FILE guide.go (280) — Guide vector store search/store
FILE search.go (269) — Generic vector store search
FILE attack_path.go (661) — Attack graph analysis
FILE race_condition.go (583) — Race condition testing
FILE auth_store.go (674) — Authentication state management
FILE auth_flows.go (328) — Authentication flow execution
FILE memory_search_limiter.go (326) — Limits consecutive memory searches
FILE context.go (35) — Agent context helpers

### Key Functions
FUNC NewFlowToolsExecutor → tools.go:309 — Creates all tools for a flow
FUNC GetToolType → registry.go:96 — Returns tool type classification
FUNC GetRegistryDefinitions → registry.go:591 — All tool schemas for LLM
FUNC NewTerminalTool → terminal.go:71 — Creates terminal tool
FUNC NewBrowserPlaywrightTool → browser_playwright.go:53 — Creates Playwright tool
FUNC NewNucleiTool → nuclei.go:48 — Creates Nuclei scanner tool
FUNC NewDuckDuckGoTool → duckduckgo.go:81 — Creates DDG search tool
FUNC BuildAttackGraph → attack_path.go:342 — Builds attack path graph
FUNC NewAuthStoreTool → auth_store.go:195 — Creates auth management tool

### Interfaces
Tool interface → tools.go:61 — IsAvailable() + Handle(ctx, name, args)
FlowToolsExecutor interface → tools.go:278 — Full tool executor for a flow
ContextToolsExecutor interface → tools.go:159 — Per-context tool executor

---

## pkg/masteragent (1,118 lines, 5 files)

FILE agent.go (644) — Agent struct, RunCycle logic, LLM-based flow analysis
FILE supervisor.go (176) — Manages agent lifecycle per flow
FILE state.go (195) — Cycle state tracking (health, progress, cooldowns)
FILE instructions.go (85) — System prompt building
FILE config.go (18) — MasterAgentConfig struct

### Key Functions
FUNC NewAgent → agent.go:44 — Creates master agent for a flow
FUNC (a).RunCycle → agent.go:85 — Single supervisor analysis cycle
FUNC NewSupervisor → supervisor.go:35 — Creates supervisor manager
FUNC StartForFlow → supervisor.go:57 — Starts agent for a flow
FUNC StopForFlow → supervisor.go:84 — Stops agent for a flow

### Key Interface
FlowControlAdapter → agent.go:22 — GetControlStatus, Steer, Pause, Resume, Abort

---

## pkg/database (10,600 lines, 28 files)

FILE models.go (1112) — sqlc-gen: all enums + model structs
FILE querier.go (272) — sqlc-gen: Querier interface (all DB methods)
FILE db.go (31) — sqlc-gen: DBTX interface, New(), Queries struct
FILE database.go (137) — Hand-written: null helpers, SanitizeUTF8, NewGorm
FILE toolcalls_zombie.go (49) — Hand-written: FailRunningToolcallsBySubtask/Flow
FILE api_token_with_secret.go (6) — Hand-written: APITokenWithSecret struct
FILE *.sql.go (23 files) — sqlc-gen: one per entity

---

## pkg/config (297 lines)

FUNC NewConfig → config.go:239 — Loads Config struct from environment
TYPE Config → config.go:15 — All application settings

---

## pkg/templates (1,083 lines)

FUNC GetDefaultPrompts → templates.go:455 — Returns all default prompt templates
FUNC NewFlowPrompter → templates.go:566 — Creates flow-scoped prompter
FUNC RenderPrompt → templates.go:659 — Renders a prompt template
TYPE Prompter interface → templates.go:556 — RenderTemplate + DumpTemplates
