# Agent 5 — Templates & Configuration Analysis

---

## File: pentester.tmpl (316 lines)

### Finding 1: "ALWAYS search Graphiti FIRST" — Compulsive Loop Trigger
- **Line(s):** 10 (inside `<memory_protocol>` / `<graphiti_search>` tag)
- **Severity:** CRITICAL
- **Description:** When `{{.GraphitiEnabled}}` is true, the template injects `<graphiti_search>ALWAYS search Graphiti FIRST to check execution history and avoid redundant work</graphiti_search>`. The word "ALWAYS" combined with "FIRST" creates a compulsive obligation — the LLM interprets this as a mandatory pre-step for EVERY action, causing a search loop where every tool call is preceded by a Graphiti search, which returns results that trigger more searches.
- **Current Text:**
  ```
  {{- if .GraphitiEnabled}}
  <graphiti_search>ALWAYS search Graphiti FIRST to check execution history and avoid redundant work</graphiti_search>
  {{- end}}
  ```
- **Proposed Fix:**
  ```
  {{- if .GraphitiEnabled}}
  <graphiti_search>Search Graphiti at the START of a new subtask to check execution history. Do NOT search Graphiti before every individual command — only when beginning a new objective or when you suspect prior work exists for the current target.</graphiti_search>
  {{- end}}
  ```

### Finding 2: Reinforced "ALWAYS search" in Graphiti Protocol Section
- **Line(s):** 31-38 (`<when_to_search>` section)
- **Severity:** CRITICAL
- **Description:** The `<when_to_search>` block doubles down on the compulsive search pattern with "ALWAYS search Graphiti BEFORE attempting any significant action" followed by 5 bullet points covering virtually every possible action. This means *every* reconnaissance, exploitation, error handling, planning, and discovery action must be preceded by a Graphiti search. Combined with Finding 1, this creates a guaranteed loop: action → search → action → search.
- **Current Text:**
  ```
  <when_to_search>
  ALWAYS search Graphiti BEFORE attempting any significant action:
  - Before running reconnaissance tools → Check what was already discovered
  - Before exploitation attempts → Find similar successful exploits
  - When encountering errors → See how similar errors were resolved
  - When planning attacks → Review successful attack chains
  - After discovering entities → Understand their relationships
  </when_to_search>
  ```
- **Proposed Fix:**
  ```
  <when_to_search>
  Search Graphiti at these KEY decision points (NOT before every command):
  - At the START of a new subtask → Check what was already discovered about the target
  - When STUCK or encountering repeated errors → See how similar errors were resolved
  - When pivoting to a new attack vector → Review if this path was already explored
  DO NOT search Graphiti:
  - Before every individual command execution
  - When you already have the information you need in the current context
  - More than 3 times total per subtask unless genuinely needed
  </when_to_search>
  ```

### Finding 3: No Anti-Loop / Max-Iteration Guard
- **Line(s):** Entire file (absent)
- **Severity:** HIGH
- **Description:** The template has NO instruction to detect or break out of repetitive loops. There is a `<repetition>Maximum 3 attempts of identical tool calls</repetition>` (line ~113), but this only covers *identical* tool calls — not semantically equivalent ones (e.g., same nmap scan with slightly different flags). There's no broader "if you've been working on this subtask for more than N commands, summarize what you've tried and move on" instruction.
- **Current Text:** (absent — only the narrow repetition rule exists)
  ```
  <repetition>Maximum 3 attempts of identical tool calls</repetition>
  ```
- **Proposed Fix:** Add a new section after `<terminal_protocol>`:
  ```
  ## LOOP PREVENTION
  <anti_loop_protocol>
  - Track the number of commands executed in this subtask. After 15 commands without meaningful progress, STOP and report what you've tried.
  - If you find yourself searching Graphiti more than 3 times for the same subtask, STOP searching and work with what you have.
  - If the same tool fails 3 times (even with different flags), switch to a completely different tool or approach.
  - "Meaningful progress" means: new information discovered, new access gained, or a confirmed dead-end that eliminates an approach.
  - If no progress after pivoting twice, report the subtask as blocked with a detailed explanation.
  </anti_loop_protocol>
  ```

### Finding 4: Graphiti Search Types Documentation is Overwhelming
- **Line(s):** 40-87 (`<search_type_selection>`)
- **Severity:** MEDIUM
- **Description:** Six search types with detailed examples consume ~50 lines of the prompt. This is excessive in-context documentation that burns tokens and increases the chance of the LLM trying to use all search types systematically (another form of loop). The `entity_relationships` and `entity_by_label` types have important constraints ("can only be used after discovering an entity") that could be enforced programmatically instead of relying on prompt instructions.
- **Proposed Fix:** Condense to a brief table. Move the detailed examples to a guide/reference that the agent can look up if needed, rather than embedding in every prompt invocation.

### Finding 5: No Filesystem State Awareness
- **Line(s):** Entire file (absent)
- **Severity:** HIGH
- **Description:** The pentester template never instructs the agent to check the filesystem for existing results, scripts, or outputs from prior subtasks. The `<execution_context>` provides task metadata but not file-level state. This means the pentester may re-run scans whose output already exists in the working directory.
- **Proposed Fix:** Add to `<execution_context_usage>`:
  ```
  - Before starting work, check the working directory ({{.Cwd}}) for existing files, scan results, and scripts from prior subtasks
  - Reuse existing data files rather than re-running time-consuming scans
  ```

### Finding 6: Context Variables Inventory
- **Line(s):** Throughout
- **Severity:** INFO
- **Description:** For cross-reference purposes, the available template variables in pentester.tmpl are:
  - `{{.GraphitiEnabled}}` — boolean, gates Graphiti sections
  - `{{.GraphitiSearchToolName}}` — tool name for Graphiti search
  - `{{.SearchGuideToolName}}`, `{{.StoreGuideToolName}}` — guide memory tools
  - `{{.DockerImage}}`, `{{.Cwd}}`, `{{.ContainerPorts}}` — container info
  - `{{.IsDefaultDockerImage}}` — boolean for Kali image check
  - `{{.SummarizationToolName}}`, `{{.SummarizedContentPrefix}}` — summarization
  - `{{.SearchToolName}}`, `{{.CoderToolName}}`, `{{.AdviceToolName}}`, `{{.MemoristToolName}}`, `{{.MaintenanceToolName}}` — team tools
  - `{{.HackResultToolName}}` — final report delivery
  - `{{.CurrentTime}}`, `{{.ExecutionContext}}`, `{{.Lang}}` — runtime context
  - `{{.ToolPlaceholder}}` — tool definitions injection point

---

## File: primary_agent.tmpl (211 lines)

### Finding 7: No Anti-Loop Guard in Orchestrator
- **Line(s):** Entire file (absent)
- **Severity:** HIGH
- **Description:** The primary agent (orchestrator) has no instruction to detect when it or its delegates are stuck in loops. It says "LIMIT repeated attempts to 3 maximum for any approach" (line ~159) and "If an approach fails after 3 attempts, pivot" (line ~135), but these are vague and don't define what constitutes an "approach" vs a "tool call." There's no instruction to monitor overall subtask duration or count of delegations.
- **Proposed Fix:** Add a dedicated loop detection section:
  ```
  ## PROGRESS MONITORING
  <progress_tracking>
  - Track total tool calls and delegations for the current subtask
  - After 10 total tool calls/delegations without new findings, reassess the approach entirely
  - If a specialist returns results that are identical or near-identical to previous results, do NOT re-delegate the same task
  - Report the subtask as blocked if 3 different approaches all fail
  </progress_tracking>
  ```

### Finding 8: Memory Protocol is Better Than pentester.tmpl's — Inconsistency
- **Line(s):** 28-34 (`<memory_protocol>`)
- **Severity:** MEDIUM
- **Description:** The primary_agent.tmpl has a much more balanced memory protocol: "Use {{.MemoristToolName}} ONLY when information in the current context is insufficient." This is the CORRECT approach. But pentester.tmpl says "ALWAYS search Graphiti FIRST" — a direct contradiction in philosophy. When the primary agent delegates to the pentester, the pentester ignores this balanced approach and compulsively searches.
- **Proposed Fix:** Align pentester.tmpl's memory protocol with primary_agent.tmpl's balanced approach (see Finding 1 fix).

### Finding 9: No Explicit Subtask Completion Criteria
- **Line(s):** 150-167 (Execution Management / Completion Requirements)
- **Severity:** MEDIUM
- **Description:** The template says "Provide COMPREHENSIVE results" and "Include critical information" but doesn't define what *done* looks like for different types of subtasks. This ambiguity can cause the agent to over-work or under-work subtasks. The completion section focuses on *format* (use the tool, communicate in language X) but not *substance* (when to stop working).
- **Proposed Fix:** Add explicit completion criteria:
  ```
  <completion_criteria>
  A subtask is COMPLETE when ANY of these conditions is met:
  - The specific objective described in the subtask is achieved
  - You have conclusive evidence the objective is not achievable (with explanation)
  - You have gathered all available information for this subtask's scope
  Do NOT continue working after the objective is met — report immediately.
  </completion_criteria>
  ```

### Finding 10: Missing `{{.GraphitiEnabled}}` Guard
- **Line(s):** Entire file
- **Severity:** LOW
- **Description:** Unlike pentester.tmpl, the primary_agent.tmpl has no Graphiti-related sections at all. If Graphiti is enabled system-wide, the orchestrator has no awareness of the knowledge graph, even though its delegates (pentester) are heavily guided by it. This creates an information asymmetry — the orchestrator can't reason about what the pentester found in Graphiti.
- **Proposed Fix:** Consider adding a lightweight Graphiti awareness section (not the full search protocol, just awareness that delegates have access to it).

---

## File: subtasks_generator.tmpl (41 lines — context data only)

**Note:** This file contains ONLY the XML context template that provides data to the generator. The actual system prompt is in `generator.tmpl` (183 lines). Analysis covers both.

### Finding 11: Generator Has NO Access to Filesystem State
- **Line(s):** subtasks_generator.tmpl (entire file) + generator.tmpl (entire file)
- **Severity:** CRITICAL
- **Description:** The subtask generator receives:
  - `{{.Task.Input}}` — the user's request
  - `{{.Tasks}}` — previous tasks (id, input, status, result)
  - `{{.Subtasks}}` — previous subtasks (task_id, id, title, description, status, result)
  
  It does NOT receive:
  - Current filesystem state (what files exist in the working directory)
  - Current container state (what tools are installed, what's running)
  - Any Graphiti/knowledge graph context
  - Network scan results or other artifacts from prior executions
  
  This means the initial plan is created BLIND to existing work artifacts. If a previous task already produced scan results in `/tmp/nmap_results.txt`, the generator has no way to know this and will create subtasks to re-run those scans.
- **Current Text:** (subtasks_generator.tmpl provides only task/subtask metadata)
- **Proposed Fix:** Add a filesystem summary context variable:
  ```
  {{if .WorkspaceFiles}}
  <workspace_state>
    <working_directory>{{.Cwd}}</working_directory>
    {{range .WorkspaceFiles}}
    <file>
      <path>{{.Path}}</path>
      <size>{{.Size}}</size>
      <modified>{{.Modified}}</modified>
    </file>
    {{end}}
  </workspace_state>
  {{end}}
  ```
  This requires backend changes to populate `.WorkspaceFiles` by listing the working directory before calling the generator.

### Finding 12: Generator Creates Plan Without Seeing Execution Logs
- **Line(s):** subtasks_generator.tmpl (entire file)
- **Severity:** HIGH
- **Description:** While `subtasks_refiner.tmpl` has `{{.ExecutionState}}` and `{{.ExecutionLogs}}` variables, the generator has neither. On a task retry or re-plan after failure, the generator only sees the high-level `status` and `result` of previous subtasks — not the detailed execution logs that explain *why* they failed. This leads to plans that repeat the same failing approaches.
- **Proposed Fix:** Add execution log context to the generator template:
  ```
  {{if .ExecutionLogs}}
  <recent_execution_logs>
  {{.ExecutionLogs}}
  </recent_execution_logs>
  {{end}}
  ```

### Finding 13: Duplicate "TASK PLANNING STRATEGIES" Section in generator.tmpl
- **Line(s):** generator.tmpl lines ~95-107 AND lines ~109-140
- **Severity:** MEDIUM
- **Description:** `generator.tmpl` contains TWO sections both titled `## TASK PLANNING STRATEGIES`. The first describes a 4-phase flow (Research → Selection → Execution), the second describes a slightly different 4-phase flow with more detail. The second one partially overlaps and partially contradicts the first (e.g., the first has "Special Case: Penetration Testing" while the second doesn't). This confuses the LLM about which strategy to follow.
- **Current Text:**
  ```
  ## TASK PLANNING STRATEGIES
  1. **Research and Exploration → Selection → Execution Flow**
  ...
  2. **Special Case: Penetration Testing**
  ...
  
  ## TASK PLANNING STRATEGIES  ← DUPLICATE HEADING
  1. **Research and Exploration Phase**
  ...
  ```
- **Proposed Fix:** Merge the two sections into one coherent strategy section. Keep the penetration testing special case from the first, and the more detailed phase descriptions from the second.

### Finding 14: Strategic Task Distribution Percentages Are Rigid
- **Line(s):** generator.tmpl lines ~62-68 (`Strategic Task Distribution`)
- **Severity:** LOW
- **Description:** The template prescribes a rigid distribution: "~10% setup, ~30% experimentation, ~30% evaluation, ~30% execution." For a pentest engagement, this means only ~10% for recon, which contradicts pentesting best practices where recon should be 30-50%. The distribution should be task-type-dependent or at least presented as a guideline, not a mandate.
- **Proposed Fix:** Change to "These are suggested distributions — adjust based on the specific task type" and add a pentest-specific variant.

---

## File: subtasks_refiner.tmpl (70 lines — context data only)

**Note:** The actual refinement system prompt is in `refiner.tmpl` (225 lines). This file only provides context data.

### Finding 15: Refiner Has Filesystem State — But Generator Doesn't (Asymmetry)
- **Line(s):** subtasks_refiner.tmpl lines 56-60
- **Severity:** HIGH
- **Description:** The refiner template includes `{{.ExecutionState}}` and `{{.ExecutionLogs}}`, giving it awareness of what actually happened during execution. But the generator (subtasks_generator.tmpl) has NO equivalent. This asymmetry means:
  1. The initial plan (generator) is created blind → creates redundant subtasks
  2. The refiner then has to clean up the generator's mess → but may not fully correct it
  
  This is the ROOT CAUSE of the reported issue "subtasks_generator creates initial plan WITHOUT seeing current workspace files."
- **Proposed Fix:** See Finding 11 — add workspace state to the generator template.

### Finding 16: Refiner Receives Completed Subtask Results But May Not Use Them Effectively
- **Line(s):** subtasks_refiner.tmpl lines 29-42 (`<completed_subtasks>`)
- **Severity:** MEDIUM
- **Description:** The refiner receives completed subtask results, but there's no explicit instruction in the context template to COMPARE completed results against planned subtasks to identify redundancy. The `<planned_subtasks>` section (lines 44-55) shows remaining work but doesn't flag which planned subtasks might already be partially or fully satisfied by completed results. This is why the refiner regenerates completed work — it sees results but doesn't have guidance on deduplication.
- **Proposed Fix:** Add a deduplication instruction in the context data:
  ```
  <refinement_guidance>
  IMPORTANT: Before modifying the plan, check each planned subtask against completed subtask results.
  If a planned subtask's objective is ALREADY ACHIEVED by completed subtask results, REMOVE it.
  Do NOT create new subtasks for work that is already done.
  </refinement_guidance>
  ```

---

## File: reflector.tmpl (109 lines)

### Finding 17: reflector.tmpl is NOT a "Reflector" — It's a Tool Call Format Enforcer
- **Line(s):** Entire file
- **Severity:** INFO (but IMPORTANT for understanding the system)
- **Description:** Despite its filename, `reflector.tmpl` is actually a "Tool Call Workflow Enforcer" that acts as a proxy for the user. When an agent produces unstructured text instead of a tool call, this template creates a "user" response that redirects the agent to use proper structured tool calls. It does NOT reflect on progress, detect loops, or evaluate work quality.
  
  This means **there is NO actual reflection/loop-detection mechanism in the template system**. The reported issue "no anti-loop instructions in any template" is confirmed — there is literally no template designed to detect or break loops.

### Finding 18: Reflector Has No Loop Detection Capability
- **Line(s):** Entire file (absent functionality)
- **Severity:** CRITICAL
- **Description:** The system needs a genuine reflection mechanism that:
  1. Detects when the agent is repeating actions
  2. Counts total tool calls per subtask and triggers a review after N calls
  3. Compares current actions against recent history to identify loops
  4. Can force a subtask to be marked as "blocked" or "failed" instead of continuing forever
  
  Currently, the only "reflector" is a format enforcer that just tells the agent to use tool calls. There is ZERO loop detection.
- **Proposed Fix:** Either repurpose reflector.tmpl or create a new `loop_detector.tmpl` that:
  ```
  # PROGRESS EVALUATOR
  
  You are reviewing the agent's recent actions to determine if meaningful progress is being made.
  
  ## RECENT ACTIONS
  {{.RecentActions}}
  
  ## EVALUATION CRITERIA
  1. Has the agent produced NEW information in the last 5 actions?
  2. Are the last 3 actions semantically different from each other?
  3. Has the agent been searching the same knowledge base repeatedly?
  4. Is the agent making progress toward the subtask objective?
  
  ## DECISION
  - CONTINUE: If meaningful progress is being made
  - REDIRECT: If the agent is stuck, suggest a different approach
  - STOP: If the agent is in a clear loop, recommend marking the subtask as blocked
  ```

### Finding 19: Barrier Tools Reference is Valuable but Under-documented
- **Line(s):** 42-52 (`<barrier_tools>`)
- **Severity:** LOW
- **Description:** The reflector receives `{{.BarrierTools}}` — the set of tools the agent was SUPPOSED to use. This is a good mechanism for enforcing tool usage. However, the template could be more explicit about matching the agent's attempted text output to the correct barrier tool.

---

## File: full_execution_context.tmpl (91 lines)

### Finding 20: Execution Context Lacks Command History / Tool Call Count
- **Line(s):** Entire file
- **Severity:** HIGH
- **Description:** The execution context template provides:
  - `{{.Task.Input}}` — global task
  - `{{.Tasks}}` — previous tasks (id, title, input, status, result)
  - `{{.CompletedSubtasks}}` — completed subtasks (id, title, description, status, result)
  - `{{.Subtask}}` — current subtask (id, title, description)
  - `{{.PlannedSubtasks}}` — remaining subtasks (id, title, description)
  
  It does NOT provide:
  - Number of tool calls executed so far in the current subtask
  - List of recent commands/actions
  - Time elapsed since subtask started
  - Any loop indicators
  
  Without this information, no template can implement loop detection even if they wanted to.
- **Proposed Fix:** Add execution metrics:
  ```
  {{if .ExecutionMetrics}}
  <execution_metrics>
    <tool_calls_count>{{.ExecutionMetrics.ToolCallCount}}</tool_calls_count>
    <elapsed_seconds>{{.ExecutionMetrics.ElapsedSeconds}}</elapsed_seconds>
    <unique_commands>{{.ExecutionMetrics.UniqueCommands}}</unique_commands>
  </execution_metrics>
  {{end}}
  ```

### Finding 21: No "Current Subtask Results So Far" Field
- **Line(s):** Lines 60-68 (`<current_subtask>`)
- **Severity:** MEDIUM
- **Description:** The current subtask section only shows `id`, `title`, and `description` — but NOT any partial results or intermediate findings. If the agent's context is summarized/truncated, it loses track of what it already found in the current subtask. There's no "results so far" field to anchor the agent's progress.
- **Proposed Fix:** Add intermediate results to the current subtask:
  ```
  {{if .Subtask}}
  <current_subtask>
  <id>{{.Subtask.ID}}</id>
  <title>{{.Subtask.Title}}</title>
  <description>{{.Subtask.Description}}</description>
  {{if .Subtask.IntermediateResults}}
  <results_so_far>{{.Subtask.IntermediateResults}}</results_so_far>
  {{end}}
  </current_subtask>
  {{end}}
  ```

---

## File: reporter.tmpl (102 lines)

### Finding 22: Reporter Template is Well-Structured — Minor Improvements
- **Line(s):** Entire file
- **Severity:** LOW
- **Description:** The reporter template is one of the better-designed templates. It has clear evaluation methodology, independent judgment criteria, and explicit output requirements. The main issue is that it relies on the same XML context (completed subtasks, execution logs) but doesn't explicitly instruct the reporter to CHECK for loop patterns. A reporter that identifies "the agent ran nmap 15 times" would be valuable feedback.
- **Proposed Fix:** Add to evaluation methodology:
  ```
  4. **Efficiency Assessment**
     - Note if the execution shows signs of repetitive or looping behavior
     - Flag if excessive tool calls were made relative to the task complexity
     - Report any wasted effort that could be avoided in future similar tasks
  ```

### Finding 23: Reporter Has Character Limit But No Structured Sections
- **Line(s):** Lines 7-8 (`no more than {{.N}} characters`)
- **Severity:** LOW
- **Description:** The report is limited to `{{.N}}` characters but has no structured format (e.g., sections for "Findings," "Vulnerabilities," "Recommendations"). For penetration testing, a structured report is critical. The template only says "Start with SUCCESS/FAILURE" and "concise summary" — this may produce a wall of text without clear structure.
- **Proposed Fix:** Add optional structured format guidance:
  ```
  ## REPORT STRUCTURE (suggested):
  1. **Status:** SUCCESS/FAILURE
  2. **Summary:** 1-2 sentence overview
  3. **Key Findings:** Bullet points of critical discoveries
  4. **Gaps/Blockers:** What wasn't completed and why
  5. **Recommendations:** Next steps if applicable
  ```

---

## File: assistant.tmpl (236 lines)

### Finding 24: assistant.tmpl Has Contradictory Memory Protocol vs primary_agent.tmpl
- **Line(s):** Lines 66-72 (`<memory_protocol>`)
- **Severity:** HIGH
- **Description:** The assistant template says "ALWAYS attempt to retrieve relevant information from memory FIRST using {{.MemoristToolName}}." This is the SAME compulsive pattern as pentester.tmpl's "ALWAYS search Graphiti FIRST." However, the primary_agent.tmpl correctly says "Use {{.MemoristToolName}} ONLY when information in the current context is insufficient."
  
  Three templates, three different memory philosophies:
  - **pentester.tmpl:** "ALWAYS search Graphiti FIRST" (compulsive)
  - **assistant.tmpl:** "ALWAYS attempt to retrieve from memory FIRST" (compulsive)
  - **primary_agent.tmpl:** "ONLY when context is insufficient" (balanced — CORRECT)
  
  This inconsistency means that depending on which agent handles a task, memory search behavior varies wildly.
- **Current Text:**
  ```
  <memory_protocol>
  - ALWAYS attempt to retrieve relevant information from memory FIRST using {{.MemoristToolName}}
  - Only store valuable, novel, and reusable knowledge that would benefit future tasks
  - Use specific, semantic search queries with relevant keywords for effective retrieval
  - Leverage previously stored solutions to similar problems before attempting new approaches
  </memory_protocol>
  ```
- **Proposed Fix:** Align with primary_agent.tmpl's balanced approach:
  ```
  <memory_protocol>
  - Use {{.MemoristToolName}} ONLY when information in the current context is insufficient
  - If the current conversation and execution context contain all necessary information, a memory search is NOT required
  - Only store valuable, novel, and reusable knowledge that would benefit future tasks
  - Use specific, semantic search queries with relevant keywords for effective retrieval
  </memory_protocol>
  ```

### Finding 25: assistant.tmpl Lists Specific Search Engine Tool Names
- **Line(s):** Lines 128-130 (`<available_tools>`)
- **Severity:** MEDIUM
- **Description:** The assistant template hard-codes specific search engine tool names: `{{.GoogleToolName}}`, `{{.DuckDuckGoToolName}}`, `{{.TavilyToolName}}`, `{{.TraversaalToolName}}`, `{{.PerplexityToolName}}`. If any of these services are disabled or unavailable, the LLM may still try to use them. More importantly, no other template lists these tool names — the pentester and primary_agent only reference a generic `{{.SearchToolName}}`. This inconsistency means the assistant might use search tools that other agents don't even know about.
- **Current Text:**
  ```
  - Web search: Use available online search engines like {{.GoogleToolName}}, {{.DuckDuckGoToolName}}, {{.TavilyToolName}}, {{.TraversaalToolName}}, {{.PerplexityToolName}}
  ```
- **Proposed Fix:** Either guard these with conditionals or use a generic `{{.SearchToolName}}` reference:
  ```
  - Web search: Use {{.SearchToolName}} to search the internet for information
  ```

### Finding 26: assistant.tmpl Has No Graphiti Integration
- **Line(s):** Entire file
- **Severity:** LOW
- **Description:** Like primary_agent.tmpl, the assistant has no `{{.GraphitiEnabled}}` conditional. Since the assistant is used for interactive sessions, this means interactive users don't benefit from the knowledge graph even when it's enabled. This is a design choice but worth noting — Graphiti data is only accessible through the pentester agent path.

---

## File: refiner.tmpl (225 lines — actual system prompt for subtask refinement)

### Finding 27: Refiner Has Good Failure Analysis But No Deduplication Check
- **Line(s):** Lines 88-109 (`REFINEMENT RULES` → `Failed Subtask Handling`)
- **Severity:** HIGH
- **Description:** The refiner has an excellent failure analysis framework (categorizing failures as Technical/Environmental/Conceptual/External). However, it has NO explicit instruction to check if a planned subtask's objective was ALREADY achieved by completed subtask results. The refiner focuses on failed subtask handling but never checks: "Hey, this planned subtask says 'scan ports' but subtask #3 already completed a port scan successfully — remove it."
  
  This is the ROOT CAUSE of the reported issue "subtasks_refiner regenerates completed work." The refiner sees the completed subtask results, sees the planned subtasks, but is never told to match them against each other for deduplication.
- **Proposed Fix:** Add a new refinement rule:
  ```
  6. **Completed Work Deduplication**
     - Before modifying the plan, compare each planned subtask against ALL completed subtask results
     - If a planned subtask's objective is FULLY or SUBSTANTIALLY achieved by completed results, REMOVE it
     - If a planned subtask is PARTIALLY covered, MODIFY it to only cover the remaining gap
     - Never create new subtasks that duplicate work already successfully completed
     - When in doubt, check the completed subtask's `<result>` field for evidence of completion
  ```

### Finding 28: Refiner Also Has Duplicate Task Distribution Percentages
- **Line(s):** Lines 159-165 (`Progressive Convergence Planning`)
- **Severity:** LOW
- **Description:** The refiner copies the same rigid "~10% setup, ~30% experimentation, ~30% evaluation, ~30% execution" distribution from generator.tmpl. For a REFINER that runs mid-execution, these percentages are meaningless — by the time the refiner runs, setup may be 100% done and the split should be different. The refiner should focus on "what's the fastest path to completion from here" not "maintain the original distribution."
- **Proposed Fix:** Replace with:
  ```
  - Focus on the shortest path from current state to task completion
  - Eliminate exploratory subtasks if a clear solution path has been identified
  - Consolidate remaining work into the minimum number of subtasks
  ```

### Finding 29: Delta Operations Format is Good — But "reorder" May Confuse LLMs
- **Line(s):** Lines 183-210 (`OUTPUT FORMAT: DELTA OPERATIONS`)
- **Severity:** LOW
- **Description:** The delta-based patch operations (`add`, `remove`, `modify`, `reorder`) are a well-designed mechanism for efficient plan modification. However, `reorder` using `after_id` with null/0 semantics can confuse some LLMs that struggle with null vs 0 distinction. The examples are helpful but could be more explicit about edge cases.

### Finding 30: Refiner Has No Max-Iterations Guard
- **Line(s):** Entire file (absent)
- **Severity:** HIGH
- **Description:** The refiner runs after each subtask completion, potentially infinitely. If every refinement adds new subtasks that replace removed ones, the execution loop never terminates. There's no instruction like "if you've refined the plan more than N times for the same task, signal completion."
- **Proposed Fix:** Add:
  ```
  ## TERMINATION AWARENESS
  - If the plan has been refined more than 5 times and progress is minimal, signal task completion by removing all remaining subtasks and explaining the stall
  - Track that this is refinement iteration {{.RefinementIteration}} of maximum {{.MaxRefinements}}
  ```
  This requires the backend to pass `.RefinementIteration` and `.MaxRefinements` to the template.

---

## File: config.go (878 lines)

### Finding 31: No Execution Limits in Config
- **Line(s):** Lines 191-230 (`AgentConfig` struct)
- **Severity:** HIGH
- **Description:** The `AgentConfig` struct contains LLM generation parameters (temperature, max_tokens, top_k, etc.) but NO execution control parameters such as:
  - `max_tool_calls` — maximum tool calls per subtask
  - `subtask_timeout` — time limit per subtask
  - `max_refinements` — maximum plan refinement iterations
  - `max_retries` — maximum retry count per approach
  - `command_timeout` — default command execution timeout
  
  These limits exist only as soft guidance in prompt text ("Maximum 3 attempts," "Hard limit: 20 minutes") rather than as enforceable configuration. Without configurable hard limits, the system relies entirely on the LLM's self-discipline, which is unreliable.
- **Current Text:** (AgentConfig fields)
  ```go
  type AgentConfig struct {
      Model             string          `json:"model,omitempty" yaml:"model,omitempty"`
      MaxTokens         int             `json:"max_tokens,omitempty" yaml:"max_tokens,omitempty"`
      Temperature       float64         `json:"temperature,omitempty" yaml:"temperature,omitempty"`
      // ... (all LLM generation params)
  }
  ```
- **Proposed Fix:** Add execution control fields:
  ```go
  type AgentConfig struct {
      // ... existing LLM params ...
      
      // Execution limits
      MaxToolCalls     int           `json:"max_tool_calls,omitempty" yaml:"max_tool_calls,omitempty"`
      SubtaskTimeout   time.Duration `json:"subtask_timeout,omitempty" yaml:"subtask_timeout,omitempty"`
      MaxRefinements   int           `json:"max_refinements,omitempty" yaml:"max_refinements,omitempty"`
      CommandTimeout   time.Duration `json:"command_timeout,omitempty" yaml:"command_timeout,omitempty"`
  }
  ```
  These should be enforced at the Go level (middleware/wrapper around agent execution) rather than relying on prompt-level instructions.

### Finding 32: No Per-Agent Graphiti Configuration
- **Line(s):** Lines 234-259 (`ProviderConfig` struct)
- **Severity:** MEDIUM
- **Description:** Graphiti is enabled/disabled system-wide (via `{{.GraphitiEnabled}}` in templates). But the config has no per-agent Graphiti toggle. You might want Graphiti enabled for the pentester but not for the assistant, or vice versa. Currently the only control is in the templates themselves via the `{{if .GraphitiEnabled}}` conditional.
- **Proposed Fix:** Add `GraphitiEnabled bool` to `AgentConfig` or create a separate `GraphitiConfig` in `ProviderConfig`.

### Finding 33: Reasoning Config Has Max 32K Token Cap
- **Line(s):** Lines 488-495 (in `BuildOptions()`)
- **Severity:** LOW
- **Description:** The reasoning token limit is hard-coded: `ac.Reasoning.MaxTokens > 0 && ac.Reasoning.MaxTokens <= 32000`. For models like Claude 3.5/4 Opus that support extended thinking with higher token budgets, this may be unnecessarily restrictive.
- **Current Text:**
  ```go
  if ac.Reasoning.MaxTokens > 0 && ac.Reasoning.MaxTokens <= 32000 {
      options = append(options, llms.WithReasoning(llms.ReasoningNone, ac.Reasoning.MaxTokens))
  }
  ```
- **Proposed Fix:** Make the cap configurable or increase to 128000 for models that support it. At minimum, log a warning when the cap is hit.

### Finding 34: `CallUsage.Merge` Uses Last-Write-Wins Instead of Accumulation
- **Line(s):** Lines 82-99 (`Merge` method)
- **Severity:** MEDIUM
- **Description:** The `Merge` method replaces values with `other` if they're > 0, rather than accumulating them. For tracking total token usage across multiple calls in a subtask, this means only the LAST call's token count is recorded. If the intent is to track cumulative usage, this is a bug.
- **Current Text:**
  ```go
  func (c *CallUsage) Merge(other CallUsage) {
      if other.Input > 0 {
          c.Input = other.Input  // overwrites, doesn't accumulate
      }
      // ...
  }
  ```
- **Proposed Fix:** If cumulative tracking is intended:
  ```go
  func (c *CallUsage) Merge(other CallUsage) {
      c.Input += other.Input
      c.Output += other.Output
      c.CacheRead += other.CacheRead
      c.CacheWrite += other.CacheWrite
      c.CostInput += other.CostInput
      c.CostOutput += other.CostOutput
  }
  ```
  If last-write-wins is intentional (because the API returns cumulative totals per conversation), add a comment explaining why.

### Finding 35: Legacy Config Handling Has Subtle Assistant Fallback Bug
- **Line(s):** Lines 388-414 (`handleLegacyConfig`)
- **Severity:** LOW
- **Description:** The legacy config handler always falls back `Assistant = PrimaryAgent` if `Assistant` is nil, even in the non-legacy code path. This means it's impossible to have a `PrimaryAgent` config WITHOUT it also applying to the `Assistant`. If someone intentionally wants different configs for primary_agent and assistant (e.g., the assistant should use default settings), they must explicitly set an empty `assistant: {}` config to avoid the fallback.
- **Current Text:**
  ```go
  if config.PrimaryAgent != nil {
      if config.Assistant == nil {
          config.Assistant = config.PrimaryAgent
      }
      return
  }
  ```
- **Proposed Fix:** Document this behavior or add a sentinel value for "use defaults, not PrimaryAgent."

---

## Cross-Template Issues

### Finding 36: Summarization Awareness Protocol is Duplicated Verbatim in 6+ Templates
- **Line(s):** pentester.tmpl, primary_agent.tmpl, reporter.tmpl, assistant.tmpl, refiner.tmpl, generator.tmpl
- **Severity:** MEDIUM
- **Description:** The `<summarized_content_handling>` section is copy-pasted identically across at least 6 templates, consuming ~30 lines each time. Any change to the summarization protocol requires updating ALL templates. This violates DRY and introduces risk of templates drifting out of sync.
- **Proposed Fix:** Extract into a shared partial template (Go templates support `{{template "name" .}}` and `{{define "name"}}...{{end}}`):
  ```
  {{template "summarized_content_handling" .}}
  ```
  Define once in a `_shared.tmpl` or `partials/summarization.tmpl` file.

### Finding 37: Three Different Memory Philosophies Across Agent Templates
- **Line(s):** (Cross-template)
- **Severity:** CRITICAL
- **Description:** As documented in Findings 1, 8, and 24:
  - **pentester.tmpl:** "ALWAYS search Graphiti FIRST" → compulsive, loop-inducing
  - **assistant.tmpl:** "ALWAYS attempt to retrieve from memory FIRST" → compulsive
  - **primary_agent.tmpl:** "ONLY when context is insufficient" → balanced, correct
  
  The system needs ONE consistent memory philosophy. The primary_agent.tmpl's approach is correct. All other templates should be aligned.
- **Proposed Fix:** Standardize all templates to use:
  ```
  Use memory/Graphiti ONLY when the current context is insufficient. If the conversation history and execution context contain the needed information, do NOT search memory.
  ```

### Finding 38: No Template Passes Execution Metrics (Tool Call Count, Elapsed Time)
- **Line(s):** (Cross-template — all templates + full_execution_context.tmpl)
- **Severity:** CRITICAL
- **Description:** None of the templates receive information about:
  - How many tool calls have been made in the current subtask
  - How long the current subtask has been running
  - How many times the refiner has been called for this task
  - How many Graphiti searches have been performed
  
  Without these metrics, NO template can implement loop detection, even with perfect prompt engineering. The data simply isn't available. This is the FUNDAMENTAL infrastructure gap that enables all loop bugs.
- **Proposed Fix:** The backend must:
  1. Track tool call counts per subtask execution
  2. Track elapsed time per subtask
  3. Track refinement iteration count
  4. Pass these as template variables (e.g., `{{.ToolCallCount}}`, `{{.ElapsedSeconds}}`, `{{.RefinementIteration}}`)
  5. Optionally enforce hard limits at the Go level, independent of prompts

### Finding 39: Execution Context Template Doesn't Show Which Subtasks Were SKIPPED or BLOCKED
- **Line(s):** full_execution_context.tmpl (entire file)
- **Severity:** MEDIUM
- **Description:** The execution context shows subtasks as `completed` or `planned`. But if a subtask was skipped (redundant), blocked (dependencies failed), or cancelled (by the refiner), there's no status to indicate this. The agent and refiner can only see binary completed/planned, losing information about WHY subtasks were removed from the plan.
- **Proposed Fix:** Ensure the `status` field in subtask data includes values like `skipped`, `blocked`, `cancelled` in addition to `completed` and `planned`.

### Finding 40: generator.tmpl and refiner.tmpl Both Reference `{{.SearchToolName}}` — But For Different Purposes
- **Line(s):** generator.tmpl `STRATEGIC SEARCH USAGE` section, refiner.tmpl `STRATEGIC SEARCH USAGE` section
- **Severity:** LOW
- **Description:** Both the generator and refiner have `{{.SearchToolName}}` access for research during planning. This is appropriate — planners should be able to research before planning. However, the conditions for using search are different between the two templates (generator: "when task contains unknown technical requirements"; refiner: "when previous subtask results revealed new technical requirements"). The distinction is correct but the naming is confusing — both just say "SearchToolName."

---

## Summary of Critical Findings

| # | Severity | Template | Issue |
|---|----------|----------|-------|
| 1 | CRITICAL | pentester.tmpl | "ALWAYS search Graphiti FIRST" causes compulsive search loops |
| 2 | CRITICAL | pentester.tmpl | "ALWAYS search before ANY significant action" reinforces loops |
| 11 | CRITICAL | subtasks_generator.tmpl | Generator has NO filesystem state awareness |
| 18 | CRITICAL | reflector.tmpl | No actual loop detection mechanism exists in the system |
| 37 | CRITICAL | Cross-template | Three contradictory memory search philosophies |
| 38 | CRITICAL | Cross-template | No execution metrics (tool call count, elapsed time) passed to ANY template |
| 3 | HIGH | pentester.tmpl | No anti-loop / max-iteration guard |
| 5 | HIGH | pentester.tmpl | No filesystem state awareness |
| 7 | HIGH | primary_agent.tmpl | No loop detection in orchestrator |
| 12 | HIGH | subtasks_generator.tmpl | Generator can't see execution logs |
| 15 | HIGH | subtasks_refiner.tmpl | Generator/refiner filesystem state asymmetry |
| 20 | HIGH | full_execution_context.tmpl | No tool call count or elapsed time in context |
| 24 | HIGH | assistant.tmpl | Compulsive "ALWAYS search memory FIRST" |
| 27 | HIGH | refiner.tmpl | No deduplication check against completed work |
| 30 | HIGH | refiner.tmpl | No max-iterations guard for refinement loop |
| 31 | HIGH | config.go | No execution limits configurable (max_tool_calls, timeouts) |

