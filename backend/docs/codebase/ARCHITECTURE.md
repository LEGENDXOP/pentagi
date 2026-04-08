# Architecture — Data Flows & Critical Paths

## 1. Flow Lifecycle

```
CreateFlow (flows.go:187)
  → NewFlowWorker (flow.go:114)
    → SpawnContainer (docker/client.go:154)
    → NewFlowProvider (providers.go:319)
    → NewFlowToolsExecutor (tools.go:309)
    → StartForFlow [master agent] (supervisor.go:57)
    → worker goroutine started
      → PutInput (flow.go:612)
        → NewTaskWorker (task.go:50)
          → GenerateSubtasks (provider.go:380)
          → task.Run (task.go:354)
            → subtaskCtrl.Pop → NewSubtaskWorker (subtask.go:49)
            → subtask.Run (subtask.go:332)
              → PerformAgentChain (provider.go:794)
                → performAgentChain (performer.go:205)
            → RefineSubtasks between subtasks (provider.go:491)
          → GetTaskResult (provider.go:619)
      → checkAndFinishIfDone (flow.go, inline)
  → StopFlow/FinishFlow → cleanup containers + stop master agent
```

## 2. Agent Execution Loop (performAgentChain)

```
performAgentChain (performer.go:205)
  loop:
    1. callWithRetries (performer.go:2555) → LLM API call
    2. Parse response for tool calls
    3. For each tool call:
       a. FlowControl checkpoint (pause/steer/abort check)
       b. execToolCall (performer.go:2278)
          → Pre-checks: circuit breaker (performer.go:2430)
          → Pre-checks: write dedup, read cache, repeat detection
          → executor.Execute (executor.go) → specific tool handler
          → Post: record to graphiti, update evidence, track budget
       c. Handle nested agents (coder/pentester/searcher):
          → performCoder (performers.go:411)
          → performPentester (performers.go:647)
          → performSearcher (performers.go:755)
          Each creates nested context with reduced timeout
    4. Check termination: Done tool, max iterations, timeout, budget
    5. Optional: performReflector (performer.go:2720) on stall
  end loop
```

## 3. Tool Execution Path

```
Agent outputs tool call
  → execToolCall (performer.go:2278)
    → ToolCircuitBreaker.Check (tool_circuit_breaker.go:38)
    → repeatingDetector.detect (helpers.go:61) ⚠️
    → FileReadCache.CheckFileRead (file_read_cache.go:293)
    → WriteDeduplicator.CheckWrite (write_dedup.go:60)
    → ReadLoopDetector.Check (read_loop_detector.go:198)
    → MemorySearchLimiter.CheckAndRecord (memory_search_limiter.go:150)
    → executor handler (tool-specific)
    → ToolCircuitBreaker.RecordSuccess/Failure
    → AttackBudgetManager.RecordAttempt (attack_budget.go:241)
    → BlockerTracker.AnalyzeToolOutput (blocker_tracker.go:180)
    → WAFDetector.AnalyzeToolResult (waf_detector.go:206)
    → CompletedWorkTracker.RecordExecution (completed_work_tracker.go:185)
    → Return result to LLM
```

## 4. Finding Registration Path

```
Agent discovers vulnerability
  → Two paths:

  Path A: Inline evidence collection
    → EvidenceCollector.CollectFromToolCall (evidence_collector.go:87)
    → isEvidenceWorthy (evidence_collector.go:1024)
    → classifyEvidenceType (evidence_collector.go:1056)
    → EvidenceStore.Add (evidence/evidence.go:69)

  Path B: FINDINGS.md sync
    → extractWrittenFindingsContent (performer.go:3489)
    → FindingRegistry.ParseAndSyncFindingsMD (evidence_collector.go:627)
    → splitByHeaderBlocks (evidence_collector.go:733)
    → inferVulnTypeFromBlock (evidence_collector.go:778)
    → For each finding:
      → buildFingerprint (evidence_collector.go:1292)
      → isSemanticDBDuplicate (evidence_collector.go:442)
      → CheckAndRegister (evidence_collector.go:200)
      → PersistFindings (evidence_collector.go:336) → DB insert
```

## 5. Master Agent Cycle

```
Supervisor.StartForFlow (supervisor.go:57)
  → goroutine: loop with configurable interval
    → Agent.RunCycle (agent.go:85)
      → Gather flow state (tasks, subtasks, findings, messages)
      → Build system prompt (instructions.go)
      → LLM analysis → LLMDecision (state.go:29)
      → Execute decision:
        Action NONE → log, continue
        Action STEER → FlowControlAdapter.Steer (inject guidance)
        Action PAUSE → FlowControlAdapter.Pause
        Action ABORT → FlowControlAdapter.Abort
      → CycleState.RecordHealth/Progress (state.go)
    → sleep interval
  → StopForFlow (supervisor.go:84) terminates goroutine
```

## 6. Timeout Hierarchy

```
Flow timeout (global, from config)
  └─ Task timeout (subtask iteration budget)
     └─ Subtask timeout:
        Option A: SubtaskTimebox (subtask_timebox.go:231)
          → ClassifySubtask (subtask_timebox.go:162) → category-specific limit
        Option B: getSubtaskMaxDuration (performer.go:64) → env SUBTASK_MAX_DURATION
     └─ Nested agent timeout (performer.go:115 getNestedTimeout):
        Depth 0: 45 min
        Depth 1: 25 min
        Depth 2: 15 min
        Uses mergedContext (performer.go:150) → takes MINIMUM of parent and nested ⚠️
     └─ Tool timeout (per-tool, in executor)
        Default: 120s for terminal commands
```

## 7. Key Interfaces → Implementations

| Interface | File:Line | Implementor |
|-----------|-----------|-------------|
| FlowController | controller/flows.go:29 | flowController (flows.go) |
| FlowWorker | controller/flow.go:31 | flowWorker (flow.go) |
| TaskWorker | controller/task.go:25 | taskWorker (task.go) |
| SubtaskWorker | controller/subtask.go:20 | subtaskWorker (subtask.go) |
| FlowProvider | providers/provider.go:79 | flowProvider (provider.go) |
| AssistantProvider | providers/assistant.go:26 | assistantProvider (assistant.go) |
| ProviderController | providers/providers.go:43 | providerController (providers.go) |
| FlowToolsExecutor | tools/tools.go:278 | (built in tools.go:309) |
| Tool | tools/tools.go:61 | terminal, browser, duckduckgo, nuclei, etc. |
| FlowControlManager | controller/flow_control.go:36 | flowControlManager (flow_control.go) |
| FlowControlAdapter | masteragent/agent.go:22 | flowControlMasterAgentAdapter (controller) |
| Querier | database/querier.go:12 | Queries (database/db.go:23) |
| DockerClient | docker/client.go:55 | dockerClient (client.go) |
| Prompter | templates/templates.go:556 | flowPrompter (templates.go) |
| SubscriptionsController | graph/subscriptions/controller.go:18 | (controller.go:119) |

## 8. Database Layer

```
SQL source:     sqlc/models/*.sql (22 query files)
Migrations:     migrations/sql/ (23 files, 20241026 → 20260402)
Generated Go:   pkg/database/*.sql.go (auto-generated by sqlc)
Config:         sqlc/sqlc.yml
Querier:        pkg/database/querier.go (interface with all DB methods)
Hand-written:   pkg/database/database.go (helpers), toolcalls_zombie.go

Workflow: Edit sqlc/models/*.sql → run `sqlc generate` → pkg/database/ updated
```

## 9. GraphQL Layer

```
Schema:         pkg/graph/schema.graphqls
Config:         gqlgen/gqlgen.yml
Generated:      pkg/graph/generated.go (36K lines), pkg/graph/model/models_gen.go
Resolvers:      pkg/graph/schema.resolvers.go (hand-written, 2264 lines)
Subscriptions:  pkg/graph/subscriptions/ (controller, publisher, subscriber)

Workflow: Edit schema.graphqls → run `gqlgen generate` → update resolvers
```
