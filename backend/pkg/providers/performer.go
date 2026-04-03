package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"pentagi/pkg/cast"
	"pentagi/pkg/csum"
	"pentagi/pkg/database"
	"pentagi/pkg/graphiti"
	obs "pentagi/pkg/observability"
	"pentagi/pkg/observability/langfuse"
	"pentagi/pkg/providers/pconfig"
	"pentagi/pkg/templates"
	"pentagi/pkg/tools"

	"github.com/sirupsen/logrus"
	"github.com/vxcontrol/langchaingo/llms"
	"github.com/vxcontrol/langchaingo/llms/reasoning"
	"github.com/vxcontrol/langchaingo/llms/streaming"
)

const (
	maxRetriesToCallSimpleChain = 3
	maxRetriesToCallAgentChain  = 3
	maxRetriesToCallFunction    = 3
	maxReflectorCallsPerChain   = 3
	delayBetweenRetries         = 5 * time.Second
	defaultMaxToolCallsPerSubtask = 100              // hard cap per subtask (configurable via MAX_TOOL_CALLS_PER_SUBTASK)
	defaultSubtaskDuration      = 60 * time.Minute   // default hard time limit per subtask
	defaultMaxNestingDepth      = 4                   // primary_agent(0) → pentester(1) → coder(2) → installer(3) all allowed
	nestedTimeoutDepth1         = 45 * time.Minute    // timeout for depth-1 nested agents
	nestedTimeoutDepth2         = 30 * time.Minute    // timeout for depth-2 nested agents
	nestedTimeoutDepth3         = 20 * time.Minute    // timeout for depth-3 nested agents

	// toolCallLimitWarningBuffer is how many calls before the limit we inject
	// a "wrap up" warning into the chain, giving the agent a chance to save findings.
	toolCallLimitWarningBuffer  = 10

	// autoDoneWarningThreshold is the number of post-delegation tool calls
	// without calling done before we inject a warning.
	autoDoneWarningThreshold    = 5
	// autoDoneForceThreshold is the number of ADDITIONAL calls after the
	// warning before we force-finish the subtask.
	autoDoneForceThreshold      = 3
)

// getSubtaskMaxDuration returns the subtask timeout, configurable via
// SUBTASK_MAX_DURATION env var (value in minutes). Defaults to 60 min.
func getSubtaskMaxDuration() time.Duration {
	if v := os.Getenv("SUBTASK_MAX_DURATION"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Minute
		}
	}
	return defaultSubtaskDuration
}

// getMaxToolCallsPerSubtask returns the maximum tool calls per subtask,
// configurable via MAX_TOOL_CALLS_PER_SUBTASK env var. Defaults to 100.
func getMaxToolCallsPerSubtask() int {
	if v := os.Getenv("MAX_TOOL_CALLS_PER_SUBTASK"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return defaultMaxToolCallsPerSubtask
}

// getMaxNestingDepth returns the maximum allowed agent delegation depth,
// configurable via MAX_NESTING_DEPTH env var. Defaults to 4.
func getMaxNestingDepth() int {
	if v := os.Getenv("MAX_NESTING_DEPTH"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return defaultMaxNestingDepth
}

// nestingDepthKey is a context key for tracking agent delegation depth.
type nestingDepthKey struct{}

// getNestingDepth extracts the current nesting depth from context. Returns 0 if unset.
func getNestingDepth(ctx context.Context) int {
	if v, ok := ctx.Value(nestingDepthKey{}).(int); ok {
		return v
	}
	return 0
}

// withIncrementedDepth returns a new context with the nesting depth incremented by 1.
func withIncrementedDepth(ctx context.Context) context.Context {
	return context.WithValue(ctx, nestingDepthKey{}, getNestingDepth(ctx)+1)
}

// getNestedTimeout returns the appropriate timeout for a given nesting depth.
// Nested agents get their own FRESH timeout to prevent parent deadline starvation.
// Each level gets a generous timeout (minimum 10 minutes) to allow real work.
// Env vars NESTED_TIMEOUT_DEPTH1/2/3 (in minutes) override the compiled defaults.
func getNestedTimeout(depth int) time.Duration {
	switch {
	case depth <= 0:
		return getSubtaskMaxDuration()
	case depth == 1:
		if v := os.Getenv("NESTED_TIMEOUT_DEPTH1"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				return time.Duration(n) * time.Minute
			}
		}
		return nestedTimeoutDepth1
	case depth == 2:
		if v := os.Getenv("NESTED_TIMEOUT_DEPTH2"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				return time.Duration(n) * time.Minute
			}
		}
		return nestedTimeoutDepth2
	case depth == 3:
		if v := os.Getenv("NESTED_TIMEOUT_DEPTH3"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				return time.Duration(n) * time.Minute
			}
		}
		return nestedTimeoutDepth3
	default:
		// Even deeper nesting still gets minimum 10 minutes
		return 10 * time.Minute
	}
}

// mergedContext creates a context that inherits values from valueCtx but
// cancels when EITHER the parent cancel context OR the timeout expires.
// This ensures abort signals from the user still propagate to nested agents
// while giving them a fresh deadline.
type mergedContext struct {
	context.Context // carries values + deadline from timeout context
	parentCancel    context.Context
	done            chan struct{}
	doneOnce        sync.Once
}

func newMergedContext(timeoutCtx context.Context, parentCancel context.Context) *mergedContext {
	mc := &mergedContext{
		Context:      timeoutCtx,
		parentCancel: parentCancel,
		done:         make(chan struct{}),
	}
	// Single goroutine merges both done channels; created once at construction.
	go func() {
		select {
		case <-mc.Context.Done():
		case <-mc.parentCancel.Done():
		}
		mc.doneOnce.Do(func() { close(mc.done) })
	}()
	return mc
}

func (mc *mergedContext) Done() <-chan struct{} {
	return mc.done
}

func (mc *mergedContext) Err() error {
	if err := mc.Context.Err(); err != nil {
		return err
	}
	return mc.parentCancel.Err()
}

// newNestedContext creates a fresh timeout context for nested agent chains
// that still respects parent cancellation (e.g., user abort).
func newNestedContext(parentCtx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	// Detach from parent's deadline but keep all context values
	freshCtx := context.WithoutCancel(parentCtx)
	timeoutCtx, cancel := context.WithTimeout(freshCtx, timeout)

	// Wrap so that parent cancellation also cancels us
	merged := newMergedContext(timeoutCtx, parentCtx)
	return merged, cancel
}

type callResult struct {
	streamID  int64
	funcCalls []llms.ToolCall
	info      map[string]any
	thinking  *reasoning.ContentReasoning
	content   string
}

func (fp *flowProvider) performAgentChain(
	ctx context.Context,
	optAgentType pconfig.ProviderOptionsType,
	chainID int64,
	taskID, subtaskID *int64,
	chain []llms.MessageContent,
	executor tools.ContextToolsExecutor,
	summarizer csum.Summarizer,
) error {
	ctx, span := obs.Observer.NewSpan(ctx, obs.SpanKindInternal, "providers.flowProvider.performAgentChain")
	defer span.End()

	var (
		wantToStop           bool
		detector             = newRepeatingDetector()
		nTracker             = newNucleiTracker()
		summarizerHandler    = fp.GetSummarizeResultHandler(taskID, subtaskID)
		toolCallCount        int
		summarizerFailures   int
		metrics              = &ExecutionMetrics{}
		metricsStartTime     = time.Now()
		toolHistory          = NewToolHistory(defaultToolHistorySize)
		execState            = NewExecutionState()
		ctxManager           = NewContextManager(defaultMaxContextTokens)

		// Sprint 2 module instances — wired into the loop below.
		industryDetected         bool
		halfwayAlertSent         bool
		findingTracker           = NewFindingTracker()
		categoryTracker          = NewCategoryTracker(int(getSubtaskMaxDuration().Minutes()))

		// Sprint 3: Advanced modules — WAF detection, exploit triggers, evidence collection.
		wafDetector       = NewWAFDetector()
		exploitState      = NewExploitDevelopmentState(fp.flowID)
		evidenceCollector = NewEvidenceCollector(fp.flowID)
		findingRegistry   = NewFindingRegistry(fp.flowID)

		// Intra-subtask terminal dedup: caches idempotent terminal command outputs
		// (token reads, schema introspection, jq on stored files) to prevent the
		// agent from re-executing identical commands 15-20x per subtask. The cache
		// is scoped to this single performAgentChain invocation — new subtask = new cache.
		terminalCache = NewTerminalOutputCache()

		// Known data tracker: scans terminal outputs for JWT tokens, GraphQL endpoints,
		// credentials, etc. and injects them into the system prompt so the LLM always
		// has access to previously extracted data — even after chain summarization
		// strips the literal values from tool results.
		knownData = newKnownDataTracker()

		// v5 fixes: amnesia prevention + semantic dedup + subtask time-boxing
		completedWork = NewCompletedWorkTracker()
		loopDetector  = NewDefaultReadLoopDetector()
		fileReadCache = NewFileReadCache()

		// v7: Bootstrap dedup — tracks whether initial setup commands have
		// already been executed. After the first sequence of mkdir/which/install
		// commands, subsequent bootstrap attempts get synthetic responses.
		bootstrapCompleted = false
		bootstrapCallCount = 0

		// Fix 13: Auto-done safety net — tracks calls since the last
		// delegation tool returned results. If the primary agent keeps
		// working without calling done, we inject warnings then force-finish.
		callsSinceLastDelegation    = 0
		delegationResultReceived    = false
		autoDoneWarningInjected     = false

		// Hard loop breaker: counts consecutive read-only tool calls.
		// Resets on any write/execute/offensive/barrier tool call.
		consecutiveReadStreak    = 0
		readStreakWarnThreshold  = getReadStreakWarnThreshold()  // default: 5
		readStreakBlockThreshold = getReadStreakBlockThreshold() // default: 8
		readStreakForceThreshold = getReadStreakForceThreshold() // default: 15
	)

	// Silence unused variable warnings for guard booleans (set inside loop).
	_ = industryDetected
	_ = halfwayAlertSent

	// Silence Sprint 3 variables until their wiring points.
	_ = wafDetector
	_ = exploitState
	_ = evidenceCollector

	// Async state writer — batches DB writes so the agent loop isn't blocked.
	stateWriter := NewAsyncStateWriter(fp.db)
	defer stateWriter.Close()

	// Persist findings to DB on subtask completion (best-effort).
	// Also sync FINDINGS.md as a fallback for flows where the agent wrote
	// findings to the file but did not include [VULN_TYPE:] tags in tool responses.
	defer func() {
		if findingRegistry == nil {
			return
		}

		// M6 FALLBACK: Try to read FINDINGS.md from the container and sync
		// any findings that were missed by the primary extraction path.
		func() {
			syncCtx := context.WithoutCancel(ctx)
			syncCtx, syncCancel := context.WithTimeout(syncCtx, 10*time.Second)
			defer syncCancel()

			readArgs, _ := json.Marshal(map[string]interface{}{
				"input":   "cat /work/FINDINGS.md 2>/dev/null || echo ''",
				"timeout": 5,
			})
			mdContent, err := executor.Execute(syncCtx, 0, "", "terminal", "", readArgs)
			if err != nil {
				logrus.WithError(err).Debug("FINDINGS.md sync: failed to read file (non-fatal)")
				return
			}
			if strings.TrimSpace(mdContent) == "" {
				return
			}
			newCount := findingRegistry.ParseAndSyncFindingsMD(mdContent, subtaskID)
			if newCount > 0 {
				logrus.WithField("new_findings", newCount).
					Info("FINDINGS.md sync: registered findings missed by primary extraction")
			}
		}()

		if findingRegistry.GetFindingCount() > 0 {
			persistCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			findingRegistry.PersistFindings(persistCtx, fp.db)
		}
	}()

	// v6: Write throttles — must be created before state restore so we can
	// fast-forward them for resumed subtasks.
	stateThrottle := NewStateWriteThrottle()
	resumeThrottle := NewResumeWriteThrottle()

	fields := logrus.Fields{
		"provider":     fp.Type(),
		"agent":        optAgentType,
		"flow_id":      fp.flowID,
		"msg_chain_id": chainID,
	}
	if taskID != nil {
		fields["task_id"] = *taskID
	}
	if subtaskID != nil {
		fields["subtask_id"] = *subtaskID
	}

	logger := logrus.WithContext(ctx).WithFields(fields)

	// --- Post-chain restore for tracked state files ---
	// When the agent chain finishes (success or failure), check if any tracked
	// state files were truncated to 0 bytes while a .bak exists with content.
	// This catches the case where `cat > FILE << 'EOF'` truncated the file but
	// the write was killed by context deadline before content was written.
	defer func() {
		restoreCmd := buildRestoreCheckCommand()
		restoreArgs, _ := json.Marshal(map[string]interface{}{
			"input":   restoreCmd,
			"timeout": 5,
		})
		// Use a detached context since the original may be expired (that's the
		// whole reason we need this restore — the context deadline killed the write).
		restoreCtx := context.WithoutCancel(ctx)
		restoreCtx, restoreCancel := context.WithTimeout(restoreCtx, 10*time.Second)
		defer restoreCancel()
		result, restoreErr := executor.Execute(restoreCtx, 0, "", "terminal", "", restoreArgs)
		if restoreErr != nil {
			logger.WithError(restoreErr).Debug("post-chain state file restore check failed (non-fatal)")
		} else if strings.Contains(result, "restored:") {
			logger.WithField("restore_result", result).Warn("auto-restored truncated state files from backup")
		}
	}()

	// Track execution time for duration calculation
	lastUpdateTime := time.Now()
	rollLastUpdateTime := func() float64 {
		durationDelta := time.Since(lastUpdateTime).Seconds()
		lastUpdateTime = time.Now()
		return durationDelta
	}

	executionContext, err := fp.getExecutionContext(ctx, taskID, subtaskID)
	if err != nil {
		logger.WithError(err).Error("failed to get execution context")
		return fmt.Errorf("failed to get execution context: %w", err)
	}

	// Sprint 2 wiring: Detect target industry from execution context and inject playbook.
	industryProfile := DetectIndustry(executionContext)
	if industryProfile.Type != "generic" && !industryDetected {
		industryDetected = true
		if playbook := FormatPlaybookForPrompt(industryProfile); playbook != "" {
			// Inject industry-specific playbook into system prompt.
			if len(chain) > 0 && chain[0].Role == llms.ChatMessageTypeSystem {
				if text, ok := chain[0].Parts[0].(llms.TextContent); ok {
					chain[0].Parts[0] = llms.TextContent{Text: text.Text + "\n\n" + playbook}
				}
			}
			logger.WithField("industry", industryProfile.Type).
				WithField("markers", industryProfile.Markers).
				Info("detected target industry from execution context, injected playbook")
		}
	}

	// Load persisted execution state from DB for resume (if any).
	if subtaskID != nil {
		if dbSubtask, err := fp.db.GetSubtask(ctx, *subtaskID); err == nil && dbSubtask.Context != "" {
			if loaded := ParseExecutionState(dbSubtask.Context); loaded != nil {
				execState = loaded
				// Restore metrics from persisted state so the agent resumes
				// with accurate counters instead of zero.
				toolCallCount = loaded.ToolCallCount
				metrics.ToolCallCount = loaded.ToolCallCount
				metrics.ErrorCount = loaded.ErrorCount
				for _, cmd := range loaded.AttacksDone {
					metrics.AddCommand(cmd)
				}
				metrics.LastToolName = loaded.CurrentAttack
				logger.WithFields(logrus.Fields{
					"resumed_tool_calls": loaded.ToolCallCount,
					"resumed_phase":      loaded.Phase,
					"resumed_errors":     loaded.ErrorCount,
				}).Info("resumed execution state from DB")

				// v5: Restore completed work items from persisted state
				if len(loaded.CompletedTasks) > 0 {
					completedWork.RestoreFromState(loaded.CompletedTasks)
					logger.WithField("restored_completed_tasks", len(loaded.CompletedTasks)).
						Info("restored completed work items from persisted state")
				}

				// v6/V2: Restore tracked operations from persisted state
				if loaded.TrackedOperations != nil {
					var ops []TrackedOperationJSON
					if err := json.Unmarshal(loaded.TrackedOperations, &ops); err == nil && len(ops) > 0 {
						completedWork.RestoreOperationsFromState(ops)
						logger.WithField("restored_operations", len(ops)).
							Info("restored tracked operations from persisted state (V2)")
					}
				}

				// v5: Restore loop detector alert count from persisted state
				// so escalation level (info → warning → critical) continues
				// from where it left off instead of resetting.
				if loaded.LoopAlertCount > 0 && loopDetector != nil {
					loopDetector.RestoreAlertCount(loaded.LoopAlertCount)
					logger.WithField("restored_loop_alerts", loaded.LoopAlertCount).
						Info("restored loop detector alert count from persisted state")
				}

				// v6: Fast-forward write throttles so resumed agents don't
				// immediately trigger a write on the very first tool call batch.
				stateThrottle.MarkWritten(loaded.ToolCallCount)
				resumeThrottle.MarkWritten(loaded.ToolCallCount)

				// v7: If resuming with >5 tool calls, bootstrap is definitely done
				if loaded.ToolCallCount > 5 {
					bootstrapCompleted = true
				}
			}
		}
	}

	groupID := fmt.Sprintf("flow-%d", fp.flowID)
	toolTypeMapping := tools.GetToolTypeMapping()

	// Retrieve the attack budget manager from context (if attached by the flow).
	attackBudget := GetAttackBudget(ctx)

	// Track nesting depth: increment for this level of delegation.
	depth := getNestingDepth(ctx)
	ctx = withIncrementedDepth(ctx)

	// Hard time limit per subtask to prevent infinite execution.
	// For nested agents (depth > 0), use a FRESH timeout detached from the parent's
	// deadline to prevent the shared-deadline starvation problem where each nesting
	// level eats into a single 45-minute budget.
	// Determine the effective timeout for this chain invocation.
	// For top-level (depth==0), start with the generic subtask timeout,
	// then potentially tighten it if timebox classifies the subtask shorter.
	effectiveTimeout := getSubtaskMaxDuration()

	// v5: Per-subtask-type time-boxing — classify the subtask and use a
	// category-specific budget (recon=30min, exploit=25min, generic=20min).
	var timebox *SubtaskTimebox
	if depth == 0 && ShouldUseTimebox() {
		if meta := GetSubtaskMeta(ctx); meta != nil {
			timebox = NewSubtaskTimebox(meta.Title, meta.Description)
			logger.WithFields(logrus.Fields{
				"timebox_category":     timebox.Category.String(),
				"timebox_max_duration": timebox.MaxDuration.String(),
			}).Info("created subtask timebox")

			// Use the tighter of generic timeout vs timebox budget.
			if timebox.MaxDuration < effectiveTimeout {
				effectiveTimeout = timebox.MaxDuration
			}
		}
	}

	var timeoutCancel context.CancelFunc
	if depth == 0 {
		// Top-level: create a fully fresh context detached from any inherited
		// deadline or cancellation. Critical for resumed flows where the parent
		// context is already expired. User abort handled at flow control level.
		freshCtx := context.WithoutCancel(ctx)
		ctx, timeoutCancel = context.WithTimeout(freshCtx, effectiveTimeout)
	} else {
		// Nested: fresh timeout that still respects parent cancellation
		nestedTimeout := getNestedTimeout(depth)
		ctx, timeoutCancel = newNestedContext(ctx, nestedTimeout)
	}
	defer timeoutCancel()

	timeWarningInjected := false

	// FIX: Create a per-chain delegation block tracker so that handlers can
	// count consecutive blocked delegation attempts and escalate responses.
	ctx = withDelegationTracker(ctx, newDelegationBlockTracker())

	// Attach finding registry to context so tool handlers can register findings.
	if findingRegistry != nil {
		ctx = WithFindingRegistry(ctx, findingRegistry)
	}

	// FIX: Inject resume context into the message chain so the LLM knows
	// what has already been done. Without this, chain summarization strips
	// execution history and the agent restarts from scratch.
	if execState != nil && execState.ToolCallCount > 0 {
		resumeMsg := execState.BuildResumeInjectionMessage()
		chain = append(chain, llms.MessageContent{
			Role: llms.ChatMessageTypeHuman,
			Parts: []llms.ContentPart{
				llms.TextContent{Text: resumeMsg},
			},
		})
		logger.WithField("tool_call_count", execState.ToolCallCount).
			Info("injected resume context into chain from persisted execution state")
	}

	// Sibling context injection: query completed sibling subtasks and inject
	// their CompletedTasks into the chain so the new agent knows what was
	// already done. This prevents redundant work across subtasks.
	if subtaskID != nil && taskID != nil {
		siblings, sibErr := fp.db.GetTaskSubtasks(ctx, *taskID)
		if sibErr == nil {
			var sibCtx strings.Builder
			for _, sib := range siblings {
				if sib.ID == *subtaskID || sib.Status != database.SubtaskStatusFinished {
					continue
				}
				if sib.Context == "" {
					continue
				}
				if loaded := ParseExecutionState(sib.Context); loaded != nil && len(loaded.CompletedTasks) > 0 {
					sibCtx.WriteString(fmt.Sprintf("\n### Already done by '%s':\n", sib.Title))
					for _, ct := range loaded.CompletedTasks {
						sibCtx.WriteString(fmt.Sprintf("- ✅ %s", ct.Description))
						if ct.OutputFile != "" {
							sibCtx.WriteString(fmt.Sprintf(" (results in %s)", ct.OutputFile))
						}
						sibCtx.WriteString("\n")
					}
				}
			}
			if sibCtx.Len() > 0 {
				chain = append(chain, llms.MessageContent{
					Role: llms.ChatMessageTypeHuman,
					Parts: []llms.ContentPart{
						llms.TextContent{Text: "[WORK ALREADY COMPLETED BY SIBLING SUBTASKS \u2014 DO NOT REPEAT]\n" + sibCtx.String() +
							"\nDo NOT re-run any of the above. Start with NEW work only."},
					},
				})
				logger.WithField("sibling_count", len(siblings)).
					Info("injected sibling subtask context")
			}
		}
	}

	for {
		if err := ctx.Err(); err != nil {
			// v5: If timebox is active and this is a deadline expiry (not user cancel),
			// perform graceful force-finish instead of returning a hard error.
			if timebox != nil && errors.Is(err, context.DeadlineExceeded) {
				// M7: Use enhanced force-finish that collects all available data
				// (findings, tool outputs, file paths) so nothing is lost.
				partialResult := timebox.BuildForceFinishResultFull(&ForceFinishContext{
					ToolCallCount:   toolCallCount,
					ExecState:       execState,
					Chain:           chain,
					ToolHistory:     toolHistory,
					FindingRegistry: findingRegistry,
					CompletedWork:   completedWork,
				})

				// Save partial results to DB so findings aren't lost.
				if subtaskID != nil {
					bgCtx, bgCancel := context.WithTimeout(context.Background(), 10*time.Second)
					if _, dbErr := fp.db.UpdateSubtaskResult(bgCtx, database.UpdateSubtaskResultParams{
						Result: partialResult,
						ID:     *subtaskID,
					}); dbErr != nil {
						logger.WithError(dbErr).Error("failed to save timebox force-finish result")
					}
					bgCancel()
				}

				logger.WithFields(logrus.Fields{
					"timebox_category": timebox.Category.String(),
					"timebox_elapsed":  timebox.Elapsed().Round(time.Second).String(),
					"tool_call_count":  toolCallCount,
				}).Warn("subtask time-boxed: force-finishing with partial results")

				// Return nil (success) so controller treats it as Finished
				// and advances to the next subtask.
				return nil
			}

			logger.WithError(err).Warn("context cancelled/timed out in agent chain loop")
			return fmt.Errorf("agent chain loop terminated: %w", err)
		}

		// Flow control checkpoint: pause/steer/abort
		if fp.flowControl != nil {
			steerMsg, fcErr := fp.flowControl(ctx, fp.flowID)
			if fcErr != nil {
				logger.WithError(fcErr).Warn("flow control: checkpoint returned error (abort or context cancel)")
				return fmt.Errorf("flow control checkpoint: %w", fcErr)
			}
			if steerMsg != "" {
				// Inject operator override as a system message into the chain
				overrideContent := fmt.Sprintf("[OPERATOR OVERRIDE] %s", steerMsg)
				chain = append(chain, llms.MessageContent{
					Role: llms.ChatMessageTypeHuman,
					Parts: []llms.ContentPart{
						llms.TextContent{Text: overrideContent},
					},
				})
				logger.WithField("steer_message", steerMsg).Info("flow control: operator steer message injected into chain")
			}
		}

		// Attack budget auto-pivot: check if the current attack vector's budget is exhausted.
		// If so, inject a pivot prompt directing the agent to switch vectors.
		if attackBudget != nil && metrics.LastToolName != "" {
			pivotAction := CheckAndBuildPivot(ctx, attackBudget, fp.prompter, metrics.LastToolName)
			if pivotAction != nil && pivotAction.ShouldPivot {
				logger.WithFields(logrus.Fields{
					"pivot_phase":  pivotAction.Phase,
					"pivot_vector": pivotAction.Vector,
					"pivot_reason": pivotAction.Reason,
				}).Info("attack budget exhausted, injecting pivot instruction")

				chain = append(chain, llms.MessageContent{
					Role: llms.ChatMessageTypeHuman,
					Parts: []llms.ContentPart{
						llms.TextContent{Text: pivotAction.PivotMessage},
					},
				})
				if err := fp.updateMsgChain(ctx, chainID, chain, rollLastUpdateTime()); err != nil {
					logger.WithError(err).Error("failed to update msg chain after pivot injection")
					return err
				}
			}
		}

		// Refresh system prompt with current execution metrics and time remaining.
		if metrics.ToolCallCount > 0 && len(chain) > 0 {
			if chain[0].Role == llms.ChatMessageTypeSystem && len(chain[0].Parts) > 0 {
				if text, ok := chain[0].Parts[0].(llms.TextContent); ok {
					// Compute time remaining from global execution budget so the
					// LLM sees the overall flow time left, not the per-subtask
					// deadline which can be misleadingly short after long recon.
					timeRemainingMinutes := -1 // -1 = omit from prompt
					if budget := GetBudget(ctx); budget != nil {
						remaining := budget.TimeRemaining()
						timeRemainingMinutes = int(remaining.Minutes())
					} else if deadline, ok := ctx.Deadline(); ok {
						// Fallback: no global budget in context, use subtask deadline.
						remaining := time.Until(deadline)
						if remaining > 0 {
							timeRemainingMinutes = int(remaining.Minutes())
						} else {
							timeRemainingMinutes = 0
						}
					}
					updated := injectMetricsIntoSystemPrompt(text.Text, metrics.Snapshot(metricsStartTime), timeRemainingMinutes)

					// Inject known extracted data into system prompt so the LLM
					// always has access to JWT tokens, GraphQL endpoints, etc.
					// even after chain summarization strips the literal values.
					if knownDataBlock := knownData.FormatForInjection(); knownDataBlock != "" {
						updated = injectKnownDataBlock(updated, knownDataBlock)
					}

					chain[0].Parts[0] = llms.TextContent{Text: updated}
				}
			}
		}

		// Context-aware pruning: before each LLM call, check if context
		// manager tracks enough items to warrant pruning old tool results.
		// This applies content-aware intelligence on top of the existing
		// chain summarizer — findings are always preserved, noise is dropped.
		if ctxManager.GetItemCount() > recentToolWindowSize {
			ctxManager.ReclassifyByAge()
			stats := ctxManager.Stats()
			if stats.OverBudget {
				prunedItems := ctxManager.Prune()
				logger.WithField("context_stats", stats.FormatStats()).
					WithField("pruned_items", len(prunedItems)).
					Debug("context manager pruned items before LLM call")
			}
		}

		// Safety net: validate chain integrity before sending to the LLM.
		// If orphaned tool_use blocks exist (from a previous interrupted execution),
		// insert synthetic tool_result blocks to prevent Anthropic 400 errors.
		if repairedChain, repairCount := validateAndRepairChain(chain); repairCount > 0 {
			chain = repairedChain
			logger.WithField("repaired_tool_results", repairCount).
				Warn("repaired orphaned tool_use blocks in message chain before LLM call")
			if err := fp.updateMsgChain(ctx, chainID, chain, rollLastUpdateTime()); err != nil {
				logger.WithError(err).Error("failed to update msg chain after repair")
				return err
			}
		}

		// v5: Per-subtask-type timebox warning injection (fires EARLIER than generic).
		if timebox != nil {
			if warningMsg := timebox.CheckWarning(); warningMsg != "" {
				chain = append(chain, llms.MessageContent{
					Role: llms.ChatMessageTypeHuman,
					Parts: []llms.ContentPart{
						llms.TextContent{Text: warningMsg},
					},
				})
				if err := fp.updateMsgChain(ctx, chainID, chain, rollLastUpdateTime()); err != nil {
					logger.WithError(err).Error("failed to update msg chain after timebox warning")
				}
				logger.WithFields(logrus.Fields{
					"timebox_category":  timebox.Category.String(),
					"timebox_remaining": timebox.Remaining().Round(time.Second).String(),
				}).Warn("injected timebox warning into agent chain")
			}
		}

		// Proactive time-based delegation warning: inject explicit human-role message
		// when time is running low. Uses boolean flag to prevent re-injection after
		// chain summarization (reviewer recommendation: don't scan chain content).
		if !timeWarningInjected && metrics.ToolCallCount > 0 {
			var remaining time.Duration
			var hasDL bool
			if b := GetBudget(ctx); b != nil {
				remaining = b.TimeRemaining()
				hasDL = remaining > 0
			} else if deadline, ok := ctx.Deadline(); ok {
				remaining = time.Until(deadline)
				hasDL = true
			}
			if hasDL {
				if remaining > 0 && remaining < 20*time.Minute {
					timeWarningInjected = true
					remainingMin := int(remaining.Minutes())
					var warningMsg string
					if remainingMin < 10 {
						warningMsg = fmt.Sprintf(
							"[TIME WARNING — CRITICAL: %d minutes remaining]\n"+
								"⛔ DO NOT delegate to coder, installer, or maintenance — delegation is BLOCKED.\n"+
								"Write any remaining files DIRECTLY using terminal heredoc or file tool.\n"+
								"Call the result/report tool NOW to save your work.",
							remainingMin,
						)
					} else {
						warningMsg = fmt.Sprintf(
							"[TIME WARNING: %d minutes remaining]\n"+
								"⚠ Do NOT delegate to coder, installer, or maintenance — there is not enough time.\n"+
								"If you need to write files (reports, findings), use terminal heredoc directly:\n"+
								"  cat > /work/REPORT.md << 'EOF'\n"+
								"  [content]\n"+
								"  EOF\n"+
								"Focus on saving your findings and completing the report.",
							remainingMin,
						)
					}
					chain = append(chain, llms.MessageContent{
						Role: llms.ChatMessageTypeHuman,
						Parts: []llms.ContentPart{
							llms.TextContent{Text: warningMsg},
						},
					})
					if err := fp.updateMsgChain(ctx, chainID, chain, rollLastUpdateTime()); err != nil {
						logger.WithError(err).Error("failed to update msg chain after time warning")
					}
					logger.WithFields(logrus.Fields{
						"remaining_minutes": remainingMin,
						"tool_call_count":   metrics.ToolCallCount,
					}).Warn("injected proactive time warning into agent chain")
				}
			}
		}

		// Sprint 2 wiring: P0 coverage gate — fire at 50% of global budget.
		if !halfwayAlertSent && metrics.ToolCallCount > 0 {
			var p0Remaining time.Duration
			var p0HasDL bool
			if b := GetBudget(ctx); b != nil {
				p0Remaining = b.TimeRemaining()
				p0HasDL = p0Remaining > 0
			} else if deadline, ok := ctx.Deadline(); ok {
				p0Remaining = time.Until(deadline)
				p0HasDL = true
			}
			if p0HasDL {
				elapsed := time.Since(metricsStartTime)
				totalBudget := p0Remaining + elapsed
				if alert := categoryTracker.CheckP0Coverage(elapsed, totalBudget); alert != nil {
					halfwayAlertSent = true
					chain = append(chain, llms.MessageContent{
						Role: llms.ChatMessageTypeHuman,
						Parts: []llms.ContentPart{
							llms.TextContent{Text: alert.FormattedMsg},
						},
					})
					if err := fp.updateMsgChain(ctx, chainID, chain, rollLastUpdateTime()); err != nil {
						logger.WithError(err).Error("failed to update msg chain after P0 coverage alert")
					}
					logger.WithFields(logrus.Fields{
						"missing_p0": alert.MissingP0,
						"tested_p0":  alert.TestedP0,
						"elapsed_pct": alert.ElapsedPercent,
					}).Info("injected P0 coverage alert at 50% time mark")
				}
			}
		}

		result, err := fp.callWithRetries(ctx, chain, optAgentType, executor)
		if err != nil {
			// Fix 12: Check if this is a context.DeadlineExceeded — if so,
			// save partial results and return the error so the controller
			// treats it as a deadline expiry (no retry, mark finished).
			if errors.Is(err, context.DeadlineExceeded) && subtaskID != nil {
				partialResult := fmt.Sprintf(
					"[DEADLINE EXPIRED during LLM call — subtask time budget exhausted]\n"+
						"Tool calls completed: %d\nPhase: %s\n",
					toolCallCount, execState.Phase,
				)
				bgCtx, bgCancel := context.WithTimeout(context.Background(), 10*time.Second)
				if _, dbErr := fp.db.UpdateSubtaskResult(bgCtx, database.UpdateSubtaskResultParams{
					Result: partialResult,
					ID:     *subtaskID,
				}); dbErr != nil {
					logger.WithError(dbErr).Error("failed to save partial results on deadline expiry (mid-LLM)")
				}
				bgCancel()
				logger.WithField("tool_call_count", toolCallCount).
					Warn("subtask deadline expired during LLM call: returning with partial results")
			}
			logger.WithError(err).Error("failed to call agent chain")
			return err
		}

		if err := fp.updateMsgChainUsage(ctx, chainID, optAgentType, result.info, rollLastUpdateTime()); err != nil {
			logger.WithError(err).Error("failed to update msg chain usage")
			return err
		}

		if len(result.funcCalls) == 0 {
			if optAgentType == pconfig.OptionsTypeAssistant {
				fp.storeAgentResponseToGraphiti(ctx, groupID, optAgentType, result, taskID, subtaskID, chainID)
				return fp.processAssistantResult(ctx, logger, chainID, chain, result, summarizer, summarizerHandler, rollLastUpdateTime())
			} else {
				// Build AI message with reasoning for reflector (universal pattern)
				reflectorMsg := llms.MessageContent{Role: llms.ChatMessageTypeAI}
				if result.content != "" || !result.thinking.IsEmpty() {
					reflectorMsg.Parts = append(reflectorMsg.Parts, llms.TextPartWithReasoning(result.content, result.thinking))
				}
				result, err = fp.performReflector(
					ctx, optAgentType, chainID, taskID, subtaskID,
					append(chain, reflectorMsg),
					fp.getLastHumanMessage(chain), result.content, executionContext, executor, 1,
					metrics.Snapshot(metricsStartTime), toolHistory)
				if err != nil {
					fields := make(logrus.Fields)
					if result != nil {
						fields["content"] = result.content[:min(1000, len(result.content))]
						if !result.thinking.IsEmpty() {
							fields["thinking"] = result.thinking.Content[:min(1000, len(result.thinking.Content))]
						}
						fields["execution"] = executionContext[:min(1000, len(executionContext))]
					}
					logger.WithError(err).WithFields(fields).Error("failed to perform reflector")
					return err
				}
				// Filter out reflector suggestions that are just state-file reads
				if result != nil && len(result.funcCalls) > 0 {
					result.funcCalls = filterReflectorSuggestions(result.funcCalls)
				}
			}
		}

		fp.storeAgentResponseToGraphiti(ctx, groupID, optAgentType, result, taskID, subtaskID, chainID)

		msg := llms.MessageContent{Role: llms.ChatMessageTypeAI}
		// Universal pattern: preserve content with or without reasoning (works for all providers thanks to deduplication)
		if result.content != "" || !result.thinking.IsEmpty() {
			msg.Parts = append(msg.Parts, llms.TextPartWithReasoning(result.content, result.thinking))
		}
		for _, toolCall := range result.funcCalls {
			msg.Parts = append(msg.Parts, toolCall)
		}
		chain = append(chain, msg)

		if err := fp.updateMsgChain(ctx, chainID, chain, rollLastUpdateTime()); err != nil {
			logger.WithError(err).Error("failed to update msg chain")
			return err
		}

		for idx, toolCall := range result.funcCalls {
			if toolCall.FunctionCall == nil {
				continue
			}

			funcName := toolCall.FunctionCall.Name
			metrics.AddCommand(funcName)
			metrics.LastToolName = funcName

			// v5/v6: Pre-execution checks — completed work re-run + file read cache + loop block.
			var v5Intercepted bool
			var v5Response string
			var v5Warning string

			// ── Hard Loop Breaker: consecutive read-only streak enforcement ──
			if !v5Intercepted && consecutiveReadStreak >= readStreakBlockThreshold {
				if isReadOnlyToolCall(funcName, toolCall.FunctionCall.Arguments) {
					v5Intercepted = true
					v5Response = fmt.Sprintf(
						"🛑 READ STREAK HARD BLOCK: You have executed %d consecutive read-only "+
							"commands with ZERO write or execute operations between them. "+
							"This read has been REFUSED.\n\n"+
							"YOUR ONLY ALLOWED ACTIONS:\n"+
							"1. Execute an offensive tool (curl, nmap, nuclei_scan, browser_navigate)\n"+
							"2. Write findings using terminal heredoc (cat > /work/FINDINGS.md << 'EOF')\n"+
							"3. Call the result/report tool to complete this subtask\n\n"+
							"The next read-only command will also be refused. After %d more refused reads, "+
							"this subtask will be FORCE-COMPLETED with partial results.",
						consecutiveReadStreak,
						readStreakForceThreshold-consecutiveReadStreak,
					)
					logger.WithField("consecutive_read_streak", consecutiveReadStreak).
						Warn("hard loop breaker: refused read-only tool call due to streak")
					consecutiveReadStreak++ // Keep incrementing even on blocks
				}
			}

			// v6: Loop detector per-file block — reject reads of files that participated
			// in detected cycles. New files that were never in a cycle pass through.
			if !v5Intercepted && loopDetector != nil && loopDetector.ShouldBlock() {
				if funcName == "terminal" {
					var termArgs map[string]interface{}
					if err := json.Unmarshal(json.RawMessage(toolCall.FunctionCall.Arguments), &termArgs); err == nil {
						if input, ok := termArgs["input"].(string); ok {
							if readPath, isRead := fileReadCache.extractReadPath(input); isRead {
								if loopDetector.ShouldBlockFile(readPath) {
									v5Intercepted = true
									v5Response = "🛑 LOOP DETECTOR BLOCK: Read of this file is blocked — " +
										"it was part of a detected read cycle. " +
										"Execute an offensive action, write your findings, or call the result tool."
									logger.WithField("blocked_file", readPath).Warn("loop detector blocked cycled file read")
								}
							}
						}
					}
				} else if funcName == "file" {
					var fileArgs map[string]interface{}
					if err := json.Unmarshal(json.RawMessage(toolCall.FunctionCall.Arguments), &fileArgs); err == nil {
						if action, ok := fileArgs["action"].(string); ok && action == "read_file" {
							filePath, _ := fileArgs["path"].(string)
							if loopDetector.ShouldBlockFile(filePath) {
								v5Intercepted = true
								v5Response = "🛑 LOOP DETECTOR BLOCK: Read of this file is blocked — " +
									"it was part of a detected read cycle. " +
									"Execute an offensive action, write your findings, or call the result tool."
								logger.WithField("blocked_file", filePath).Warn("loop detector blocked cycled file read")
							}
						}
					}
				}
			}

			// v6/V2: CheckReRun now returns warnings (isReRun=false, msg!="") AND blocks (isReRun=true).
			if !v5Intercepted && completedWork != nil && toolCall.FunctionCall != nil {
				if isReRun, msg := completedWork.CheckReRun(funcName, toolCall.FunctionCall.Arguments); isReRun {
					// Hard block — don't execute
					logger.WithField("rerun_msg", msg).Warn("completed work tracker V2 blocked re-run")
					v5Intercepted = true
					v5Response = msg
				} else if msg != "" {
					// Warning — execute but prepend warning to result
					logger.WithField("rerun_warning", msg).Info("completed work tracker V2 issued duplicate warning")
					v5Warning = msg
				}
			}

			// v6: Use InterceptTerminalRead for escalating interception.
			// Only intercepts after the configured threshold (default: 3 reads).
			if !v5Intercepted && fileReadCache != nil && funcName == "terminal" {
				var termArgs map[string]interface{}
				if err := json.Unmarshal(json.RawMessage(toolCall.FunctionCall.Arguments), &termArgs); err == nil {
					if input, ok := termArgs["input"].(string); ok {
						if cached, hit := fileReadCache.InterceptTerminalRead(input); hit {
							logger.WithField("file_cache_hit", true).
								Info("v6 terminal read cache interception")
							v5Intercepted = true
							v5Response = cached
						}
					}
				}
			}

			// v7: Bootstrap dedup — intercept redundant setup commands after
			// bootstrap is complete. The LLM ignores prompt instructions to not
			// re-run bootstrap, so we intercept at the code level.
			if !v5Intercepted && funcName == "terminal" {
				var termArgs map[string]interface{}
				if err := json.Unmarshal(json.RawMessage(toolCall.FunctionCall.Arguments), &termArgs); err == nil {
					if input, ok := termArgs["input"].(string); ok {
						if isBootstrapCommand(input) {
							if bootstrapCompleted {
								v5Intercepted = true
								v5Response = "\u2705 Bootstrap already completed. All tools are installed and directories exist. " +
									"Proceed directly to your next offensive action."
								logger.WithField("blocked_bootstrap", input).
									Info("v7 bootstrap dedup intercepted redundant setup command")
							} else {
								bootstrapCallCount++
								if bootstrapCallCount >= 3 {
									bootstrapCompleted = true
								}
							}
						}
					}
				}
			}

			// v14: Memorist circuit breaker — block memorist calls after 2+ failures.
			// This operates at the CALLING AGENT level, preventing the LLM from
			// invoking memorist when the service is known to be down.
			var memoristIntercepted bool
			var memoristResponse string
			if funcName == tools.MemoristToolName && fp.memoristCB != nil {
				if fp.memoristCB.shouldBlock() {
					memoristIntercepted = true
					memoristResponse = memoristBreakerMessage
					logger.WithField("memorist_breaker", "blocked").
						Warn("v14: memorist call blocked by flow-level circuit breaker")
				}
			}

			var response string
			var err error
			if v5Intercepted {
				response = v5Response
			} else if memoristIntercepted {
				response = memoristResponse
			} else {
				response, err = fp.execToolCall(ctx, chainID, idx, result, detector, executor, nTracker, terminalCache, knownData)
			}

			// v14: Track memorist unavailability at the flow level.
			if funcName == tools.MemoristToolName && fp.memoristCB != nil && !memoristIntercepted && !v5Intercepted {
				if err == nil && isUnavailableResponse(response) {
					fp.memoristCB.recordFailure()
					logger.WithField("memorist_breaker", "failure_recorded").
						Warn("v14: memorist returned unavailable — recording failure in flow breaker")
				} else if err == nil {
					fp.memoristCB.recordSuccess()
				}
			}

			// v6/V2: Prepend duplicate warning to response if CheckReRun issued one.
			if v5Warning != "" && !v5Intercepted {
				response = v5Warning + "\n\n" + response
			}

			// v5: Store file read results in semantic cache after successful execution.
			if !v5Intercepted && err == nil && fileReadCache != nil && funcName == "terminal" {
				var termArgs map[string]interface{}
				if jsonErr := json.Unmarshal(json.RawMessage(toolCall.FunctionCall.Arguments), &termArgs); jsonErr == nil {
					if input, ok := termArgs["input"].(string); ok {
						fileReadCache.StoreFileRead(input, response)
					}
				}
			}

			// Track repeated tool calls detected by the repeating detector
			isRepeating := strings.HasPrefix(response, "tool call '") && strings.HasSuffix(response, "' is repeating, please try another tool")
			if isRepeating {
				metrics.RepeatedCalls++
			}

			isError := err != nil || isRepeating

			// Record in tool history for loop analysis
			toolHistory.Add(ToolHistoryEntry{
				Name:      funcName,
				Arguments: toolCall.FunctionCall.Arguments,
				Result:    response,
				IsError:   isError,
				Timestamp: time.Now(),
			})

			// Record attempt in attack budget tracker for auto-pivot decisions.
			if attackBudget != nil && toolTypeMapping[funcName] != tools.AgentToolType {
				phase := ClassifyToolPhase(funcName)
				vector := ClassifyToolVector(funcName)
				success := IsToolCallSuccess(response, isRepeating)
				attackBudget.RecordAttempt(phase, vector, success)
			}

			if toolTypeMapping[funcName] != tools.AgentToolType {
				fp.storeToolExecutionToGraphiti(
					ctx, groupID, optAgentType, toolCall, response, err, executor, taskID, subtaskID, chainID,
				)
			}

			if err != nil {
				// Fix 12: Check if tool execution failed due to deadline expiry.
				// Save partial results and let the error propagate so the controller
				// handles it as a deadline expiry (no retry, mark finished).
				if errors.Is(err, context.DeadlineExceeded) && subtaskID != nil {
					partialResult := fmt.Sprintf(
						"[DEADLINE EXPIRED during tool execution — subtask time budget exhausted]\n"+
							"Tool calls completed: %d\nLast tool: %s\nPhase: %s\n",
						toolCallCount+idx+1, funcName, execState.Phase,
					)
					bgCtx, bgCancel := context.WithTimeout(context.Background(), 10*time.Second)
					if _, dbErr := fp.db.UpdateSubtaskResult(bgCtx, database.UpdateSubtaskResultParams{
						Result: partialResult,
						ID:     *subtaskID,
					}); dbErr != nil {
						logger.WithError(dbErr).Error("failed to save partial results on deadline expiry (mid-tool)")
					}
					bgCancel()
					logger.WithFields(logrus.Fields{
						"tool_call_count": toolCallCount + idx + 1,
						"func_name":       funcName,
					}).Warn("subtask deadline expired during tool execution: returning with partial results")
				}

				metrics.ErrorCount++
				logger.WithError(err).WithFields(logrus.Fields{
					"func_name": funcName,
					"func_args": toolCall.FunctionCall.Arguments,
				}).Error("failed to exec tool call")

				// CRITICAL: Before returning, insert synthetic tool_result for the
				// current failed tool call AND all remaining tool calls in the batch.
				// Without this, the chain in DB would have orphaned tool_use blocks
				// that cause Anthropic 400 errors on resume/retry.
				errMsg := fmt.Sprintf("Error: tool execution failed: %s", err.Error())
				chain = append(chain, llms.MessageContent{
					Role: llms.ChatMessageTypeTool,
					Parts: []llms.ContentPart{
						llms.ToolCallResponse{
							ToolCallID: toolCall.ID,
							Name:       funcName,
							Content:    errMsg,
						},
					},
				})
				// Add synthetic results for remaining tool calls in this batch
				for remainIdx := idx + 1; remainIdx < len(result.funcCalls); remainIdx++ {
					remainTC := result.funcCalls[remainIdx]
					if remainTC.FunctionCall == nil {
						continue
					}
					chain = append(chain, llms.MessageContent{
						Role: llms.ChatMessageTypeTool,
						Parts: []llms.ContentPart{
							llms.ToolCallResponse{
								ToolCallID: remainTC.ID,
								Name:       remainTC.FunctionCall.Name,
								Content:    "Error: tool execution was interrupted. Result unavailable.",
							},
						},
					})
				}
				// Best-effort save of the repaired chain to DB.
				// Use a fresh context since the original may be cancelled.
				saveCtx := context.WithoutCancel(ctx)
				if updateErr := fp.updateMsgChain(saveCtx, chainID, chain, rollLastUpdateTime()); updateErr != nil {
					logger.WithError(updateErr).Error("failed to save repaired chain after tool execution error")
				}

				return err
			}

			chain = append(chain, llms.MessageContent{
				Role: llms.ChatMessageTypeTool,
				Parts: []llms.ContentPart{
					llms.ToolCallResponse{
						ToolCallID: toolCall.ID,
						Name:       funcName,
						Content:    response,
					},
				},
			})
			if err := fp.updateMsgChain(ctx, chainID, chain, rollLastUpdateTime()); err != nil {
				logger.WithError(err).Error("failed to update msg chain")
				return err
			}

			// Track tool result in context manager for intelligent pruning.
			// The context manager classifies the result by content keywords
			// and tracks it for priority-based pruning decisions.
			ctxManager.Add(response, funcName)

			// If the tool call arguments reference content from previous results,
			// mark those results as referenced (bumps their priority).
			if toolCall.FunctionCall != nil {
				ctxManager.MarkReferenced(toolCall.FunctionCall.Arguments)
			}

			// Sprint 2 wiring: Record finding for attack chain detection.
			findingTracker.RecordFinding(response)
			if findingTracker.HasNewHighFindings() {
				if suggestion := findingTracker.GetChainSuggestions(); suggestion != nil {
					chain = append(chain, llms.MessageContent{
						Role: llms.ChatMessageTypeHuman,
						Parts: []llms.ContentPart{
							llms.TextContent{Text: suggestion.FormattedMsg},
						},
					})
					if err := fp.updateMsgChain(ctx, chainID, chain, rollLastUpdateTime()); err != nil {
						logger.WithError(err).Error("failed to update msg chain after chain suggestion")
					}
					logger.WithField("trigger_vulns", suggestion.TriggerVulns).
						Info("injected attack chain suggestion into agent chain")
				}
			}

			// Also check standalone chain opportunity from raw tool output keywords.
			if chainOpp := CheckForChainOpportunity(response); chainOpp != nil && findingTracker.GetInjectionCount() < 3 {
				chain = append(chain, llms.MessageContent{
					Role: llms.ChatMessageTypeHuman,
					Parts: []llms.ContentPart{
						llms.TextContent{Text: chainOpp.FormattedMsg},
					},
				})
				if err := fp.updateMsgChain(ctx, chainID, chain, rollLastUpdateTime()); err != nil {
					logger.WithError(err).Error("failed to update msg chain after chain opportunity")
				}
				logger.WithField("chain_name", chainOpp.TriggerVulns).
					Info("injected chain opportunity from tool output keywords")
			}

			// Sprint 2 wiring: Record tool call for category tracking and P0 coverage.
			categoryTracker.RecordToolCall(funcName, toolCall.FunctionCall.Arguments)

			// Sprint 3: WAF detection — analyze tool results for WAF indicators.
			if wafDetector != nil && toolCall.FunctionCall != nil {
				wafDetector.AnalyzeToolResult(funcName, toolCall.FunctionCall.Arguments, response)
				if wafCtx := wafDetector.FormatWAFContextForPrompt(); wafCtx != "" {
					// Inject WAF context as system message (not human) so it persists.
					if len(chain) > 0 && chain[0].Role == llms.ChatMessageTypeSystem {
						if text, ok := chain[0].Parts[0].(llms.TextContent); ok {
							if !strings.Contains(text.Text, "<waf_detection>") {
								chain[0].Parts[0] = llms.TextContent{Text: text.Text + "\n\n" + wafCtx}
								logger.Info("injected WAF detection context into system prompt")
							}
						}
					}
				}
			}

			// Sprint 3: Evidence collection — capture interesting tool results.
			if evidenceCollector != nil && toolCall.FunctionCall != nil {
				evidenceCollector.CollectFromToolCall(funcName, toolCall.FunctionCall.Arguments, response, subtaskID, nil)
			}

			// Sprint 3: Finding registration — extract [VULN_TYPE: xxx] from tool responses.
			if findingRegistry != nil && response != "" {
				matches := vulnTypeRegex.FindAllStringSubmatch(response, -1)
				for _, match := range matches {
					if len(match) >= 2 {
						vulnType := match[1]
						endpoint := ""
						if toolCall.FunctionCall != nil {
							endpoint = extractEndpointFromToolCall(funcName, toolCall.FunctionCall.Arguments)
						}
						severity := severityFromVulnType(vulnType)
						findingRegistry.CheckAndRegister(vulnType, endpoint, truncateString(response, 4096), severity, subtaskID, nil)
					}
				}
			}

			// Sprint 3: Exploit trigger — track failures for custom exploit development.
			if exploitState != nil && toolCall.FunctionCall != nil && isToolCallFailure(response) {
				if trigger := exploitState.RecordToolFailure(funcName, toolCall.FunctionCall.Arguments, response); trigger != nil {
					triggerMsg := FormatExploitTriggerForSystem(trigger)
					chain = append(chain, llms.MessageContent{
						Role: llms.ChatMessageTypeHuman,
						Parts: []llms.ContentPart{
							llms.TextContent{Text: triggerMsg},
						},
					})
					logger.WithField("endpoint", trigger.Endpoint).
						Info("exploit development triggered for failing endpoint")
				}
			}

			// Sprint 3: Methodology coverage — update from vuln type tags.
			if mc := GetMethodologyCoverage(ctx); mc != nil {
				matches := vulnTypeRegex.FindAllStringSubmatch(response, -1)
				for _, match := range matches {
					if len(match) >= 2 {
						mc.RecordFinding(match[1])
					}
				}
				// Classify tool call by category and record.
				for _, catID := range classifySubtaskCategories(funcName, toolCall.FunctionCall.Arguments) {
					mc.RecordToolCall(catID)
				}
			}

			// v5: Record execution in completed work tracker and loop detector.
			if completedWork != nil {
				completedWork.RecordExecution(funcName, toolCall.FunctionCall.Arguments, response, false)
			}
			if loopDetector != nil {
				loopDetector.Record(funcName, toolCall.FunctionCall.Arguments)
			}
			// v5: Record file writes to invalidate semantic read cache.
			if fileReadCache != nil && funcName == "terminal" {
				var termWriteArgs map[string]interface{}
				if jsonErr := json.Unmarshal(json.RawMessage(toolCall.FunctionCall.Arguments), &termWriteArgs); jsonErr == nil {
					if writeInput, ok := termWriteArgs["input"].(string); ok {
						fileReadCache.RecordFileWrite(writeInput)
					}
				}
			}

			// ── Hard Loop Breaker: update consecutive read streak ──
			if isReadOnlyToolCall(funcName, toolCall.FunctionCall.Arguments) {
				consecutiveReadStreak++
				if consecutiveReadStreak == readStreakWarnThreshold {
					warnMsg := fmt.Sprintf(
						"⚠️ [READ STREAK WARNING: %d consecutive read-only operations]\n"+
							"You have made %d consecutive read-only commands (ls, cat, head, grep, find, etc.) "+
							"without executing any write or offensive action.\n\n"+
							"If you continue reading without acting, your read commands will be BLOCKED "+
							"after %d consecutive reads, and the subtask will be FORCE-COMPLETED after %d.\n\n"+
							"TAKE ACTION NOW: execute an offensive tool, write your findings, or complete the subtask.",
						consecutiveReadStreak, consecutiveReadStreak,
						readStreakBlockThreshold, readStreakForceThreshold,
					)
					chain = append(chain, llms.MessageContent{
						Role: llms.ChatMessageTypeHuman,
						Parts: []llms.ContentPart{
							llms.TextContent{Text: warnMsg},
						},
					})
					logger.WithField("consecutive_read_streak", consecutiveReadStreak).
						Warn("hard loop breaker: injected read streak warning")
				}
			} else {
				// Any non-read tool call resets the streak
				if consecutiveReadStreak > 0 {
					logger.WithFields(logrus.Fields{
						"consecutive_read_streak_broken": consecutiveReadStreak,
						"breaking_tool":                  funcName,
					}).Debug("hard loop breaker: read streak broken by non-read tool call")
				}
				consecutiveReadStreak = 0
			}

			if executor.IsBarrierFunction(funcName) {
				wantToStop = true
			}

			// Fix 13: Track delegation results for auto-done enforcement.
			// When the primary agent (depth 0) receives a result from a
			// delegation tool (pentester, coder, maintenance, etc.),
			// start counting subsequent non-done calls.
			if depth == 0 && toolTypeMapping[funcName] == tools.AgentToolType {
				delegationResultReceived = true
				callsSinceLastDelegation = 0
				logger.WithField("delegation_tool", funcName).
					Debug("fix13: delegation result received, resetting auto-done counter")
			} else if depth == 0 && delegationResultReceived && !executor.IsBarrierFunction(funcName) {
				callsSinceLastDelegation++
			}
		}

		// ── Hard Loop Breaker: force-complete if streak reaches force threshold ──
		if consecutiveReadStreak >= readStreakForceThreshold {
			logger.WithFields(logrus.Fields{
				"consecutive_read_streak": consecutiveReadStreak,
				"tool_call_count":         toolCallCount + len(result.funcCalls),
			}).Error("hard loop breaker: FORCE-COMPLETING subtask due to extreme read streak")

			if subtaskID != nil {
				partialResult := fmt.Sprintf(
					"[FORCE-COMPLETED: Subtask terminated after %d consecutive read-only operations]\n"+
						"The agent executed %d read-only commands in a row without taking any "+
						"write or offensive action. This indicates an unproductive analysis loop.\n\n"+
						"Total tool calls: %d\n",
					consecutiveReadStreak, consecutiveReadStreak,
					toolCallCount+len(result.funcCalls),
				)
				// Collect recent tool results as evidence
				partialResult += "\nLast 5 read operations:\n"
				toolResultCount := 0
				for i := len(chain) - 1; i >= 0 && toolResultCount < 5; i-- {
					if chain[i].Role == llms.ChatMessageTypeTool {
						for _, part := range chain[i].Parts {
							if resp, ok := part.(llms.ToolCallResponse); ok {
								snippet := resp.Content
								if len(snippet) > 200 {
									snippet = snippet[:200] + "..."
								}
								partialResult += fmt.Sprintf("- %s: %s\n", resp.Name, snippet)
								toolResultCount++
							}
						}
					}
				}
				bgCtx, bgCancel := context.WithTimeout(context.Background(), 10*time.Second)
				if _, dbErr := fp.db.UpdateSubtaskResult(bgCtx, database.UpdateSubtaskResultParams{
					Result: partialResult,
					ID:     *subtaskID,
				}); dbErr != nil {
					logger.WithError(dbErr).Error("hard loop breaker: failed to save partial results")
				}
				bgCancel()
			}

			return fmt.Errorf("hard loop breaker: subtask force-completed after %d consecutive read-only operations", consecutiveReadStreak)
		}

		toolCallCount += len(result.funcCalls)
		metrics.ToolCallCount = toolCallCount

		// v5/v6: Read loop detection — check for cyclic read patterns after each batch.
		if loopDetector != nil {
			if alert := loopDetector.Check(); alert != nil {
				chain = append(chain, llms.MessageContent{
					Role: llms.ChatMessageTypeHuman,
					Parts: []llms.ContentPart{
						llms.TextContent{Text: alert.Message},
					},
				})
				if err := fp.updateMsgChain(ctx, chainID, chain, rollLastUpdateTime()); err != nil {
					logger.WithError(err).Error("failed to update msg chain after loop alert")
				}
				// v6: If the alert signals a hard block, log it prominently
				if alert.IsBlock {
					logger.WithField("total_alerts", alert.TotalAlerts).
						Error("loop detector engaged HARD BLOCK mode — all reads will be rejected")
				}
				logger.WithFields(logrus.Fields{
					"cycle_length": alert.CycleLength,
					"repeat_count": alert.RepeatCount,
					"total_alerts": alert.TotalAlerts,
					"is_block":     alert.IsBlock,
				}).Warn("injected loop detection alert into agent chain")
			}
		}

		// Fix 13: Auto-done safety net — inject escalating warnings when the
		// primary agent keeps working after receiving delegation results without
		// calling done. Force-finish if warnings are ignored.
		if depth == 0 && delegationResultReceived && !wantToStop {
			if callsSinceLastDelegation >= autoDoneWarningThreshold && !autoDoneWarningInjected {
				autoDoneWarningInjected = true
				warningMsg := fmt.Sprintf(
					"[⚠️ AUTO-DONE WARNING — You have made %d tool calls since receiving specialist results without calling \"%s\"]\n"+
						"Your specialist has already returned complete results. You MUST call \"%s\" NOW to finish this subtask.\n"+
						"Do NOT re-read files, re-verify, or re-delegate. Synthesize the results you have and call \"%s\" immediately.\n"+
						"If you do not call \"%s\" within %d more tool calls, the subtask will be FORCE-FINISHED with partial results.",
					callsSinceLastDelegation, tools.FinalyToolName,
					tools.FinalyToolName, tools.FinalyToolName, tools.FinalyToolName,
					autoDoneForceThreshold,
				)
				chain = append(chain, llms.MessageContent{
					Role: llms.ChatMessageTypeHuman,
					Parts: []llms.ContentPart{
						llms.TextContent{Text: warningMsg},
					},
				})
				if err := fp.updateMsgChain(ctx, chainID, chain, rollLastUpdateTime()); err != nil {
					logger.WithError(err).Error("failed to update msg chain after auto-done warning")
				}
				logger.WithFields(logrus.Fields{
					"calls_since_delegation": callsSinceLastDelegation,
					"tool_call_count":        toolCallCount,
				}).Warn("fix13: injected auto-done warning — agent not calling done after delegation results")
			}

			if autoDoneWarningInjected && callsSinceLastDelegation >= autoDoneWarningThreshold+autoDoneForceThreshold {
				logger.WithFields(logrus.Fields{
					"calls_since_delegation": callsSinceLastDelegation,
					"tool_call_count":        toolCallCount,
				}).Error("fix13: force-finishing subtask — agent ignored auto-done warning")

				// Force-finish: save partial results and exit the loop.
				if subtaskID != nil {
					partialResult := fmt.Sprintf(
						"[AUTO-DONE: Subtask force-finished after %d tool calls without calling done]\n"+
							"The agent received complete results from delegated specialists but failed to call the done tool.\n",
						toolCallCount,
					)
					// Collect recent tool results as evidence of work done
					partialResult += "\nRecent tool results (last 5):\n"
					toolResultCount := 0
					for i := len(chain) - 1; i >= 0 && toolResultCount < 5; i-- {
						if chain[i].Role == llms.ChatMessageTypeTool {
							for _, part := range chain[i].Parts {
								if resp, ok := part.(llms.ToolCallResponse); ok {
									snippet := resp.Content
									if len(snippet) > 300 {
										snippet = snippet[:300] + "..."
									}
									partialResult += fmt.Sprintf("- %s: %s\n", resp.Name, snippet)
									toolResultCount++
								}
							}
						}
					}
					if _, err := fp.db.UpdateSubtaskResult(ctx, database.UpdateSubtaskResultParams{
						Result: partialResult,
						ID:     *subtaskID,
					}); err != nil {
						logger.WithError(err).Error("fix13: failed to save partial results on auto-done force-finish")
					}
				}

				return fmt.Errorf("fix13: subtask force-finished — agent did not call done after %d calls post-delegation", callsSinceLastDelegation)
			}
		}

		// Persist execution state to DB asynchronously after each tool call batch.
		if subtaskID != nil {
			phase := "executing"
			if wantToStop {
				phase = "finishing"
			}

			// v6: Force immediate writes on phase transitions and barrier hits.
			prevPhase := execState.Phase
			execState.Update(metrics, phase)
			if prevPhase != phase {
				stateThrottle.ForceNext()
				resumeThrottle.ForceNext()
			}
			if wantToStop {
				stateThrottle.ForceNext()
				resumeThrottle.ForceNext()
			}

			// v5: Sync completed work and loop detector state before serialization.
			execState.UpdateCompletedTasks(completedWork)
			execState.UpdateLoopAlertCount(loopDetector)

			// v6/V2: Also persist tracked operations
			if opsJSON := completedWork.OperationsToJSON(); len(opsJSON) > 0 {
				if rawOps, err := json.Marshal(opsJSON); err == nil {
					execState.TrackedOperations = rawOps
				}
			}

			// v6: Generate resume context based on resume throttle schedule (was every 10,
			// now every 30 calls or 3 min).
			if resumeThrottle.ShouldWrite(toolCallCount) {
				resumeContent := buildResumeContent(toolHistory, metrics)
				if resumeContent != "" {
					execState.ResumeContext = resumeContent
					logger.WithField("tool_call_count", toolCallCount).
						Debug("persisted resume context to execution state")
				}
			}

			if stateJSON, err := execState.ToJSON(); err == nil {
				// Async DB write — always happens (coalesced by AsyncStateWriter).
				stateWriter.Write(*subtaskID, stateJSON)

				// v7: Batch STATE.json and RESUME.md writes into a single terminal call
				// when both throttles fire simultaneously. Saves 1 tool call per co-fire.
				wantWriteState := toolCallCount > 0 && stateThrottle.ShouldWrite(toolCallCount)
				wantWriteResume := toolCallCount > 0 && resumeThrottle.ShouldWrite(toolCallCount) && execState.ResumeContext != ""

				if wantWriteState && wantWriteResume {
					// Both fire — combine into a single terminal command
					combinedCmd := fmt.Sprintf(
						"cat > /work/STATE.json << 'STATE_EOF'\n%s\nSTATE_EOF\ncat > /work/RESUME.md << 'RESUME_EOF'\n%s\nRESUME_EOF",
						stateJSON, execState.ResumeContext,
					)
					writeArgs, _ := json.Marshal(map[string]interface{}{
						"input":   combinedCmd,
						"timeout": 8,
					})
					if _, writeErr := executor.Execute(ctx, 0, "", "terminal", "", writeArgs); writeErr != nil {
						logger.WithError(writeErr).Debug("failed to batch-write STATE.json + RESUME.md (non-fatal)")
					} else {
						stateThrottle.MarkWritten(toolCallCount)
						resumeThrottle.MarkWritten(toolCallCount)
					}
					if loopDetector != nil {
						loopDetector.RecordSystemWrite("STATE.json")
						loopDetector.RecordSystemWrite("RESUME.md")
					}
					if fileReadCache != nil {
						fileReadCache.RecordSystemFileWrite("STATE.json")
						fileReadCache.RecordSystemFileWrite("RESUME.md")
					}
				} else if wantWriteState {
					writeStateArgs, _ := json.Marshal(map[string]interface{}{
						"input":   fmt.Sprintf("cat > /work/STATE.json << 'STATE_EOF'\n%s\nSTATE_EOF", stateJSON),
						"timeout": 5,
					})
					if _, writeErr := executor.Execute(ctx, 0, "", "terminal", "", writeStateArgs); writeErr != nil {
						logger.WithError(writeErr).Debug("failed to update container STATE.json (non-fatal)")
					} else {
						stateThrottle.MarkWritten(toolCallCount)
					}
					if loopDetector != nil {
						loopDetector.RecordSystemWrite("STATE.json")
					}
					if fileReadCache != nil {
						fileReadCache.RecordSystemFileWrite("STATE.json")
					}
				} else if wantWriteResume {
					writeResumeArgs, _ := json.Marshal(map[string]interface{}{
						"input":   fmt.Sprintf("cat > /work/RESUME.md << 'RESUME_EOF'\n%s\nRESUME_EOF", execState.ResumeContext),
						"timeout": 5,
					})
					if _, writeErr := executor.Execute(ctx, 0, "", "terminal", "", writeResumeArgs); writeErr != nil {
						logger.WithError(writeErr).Debug("failed to write RESUME.md to container (non-fatal)")
					} else {
						resumeThrottle.MarkWritten(toolCallCount)
					}
					if loopDetector != nil {
						loopDetector.RecordSystemWrite("RESUME.md")
					}
					if fileReadCache != nil {
						fileReadCache.RecordSystemFileWrite("RESUME.md")
					}
				}
			}
		}

		maxToolCalls := getMaxToolCallsPerSubtask()

		// Inject approaching-limit warning to give the agent time for graceful completion
		if toolCallCount >= maxToolCalls-toolCallLimitWarningBuffer && toolCallCount < maxToolCalls {
			warningMsg := fmt.Sprintf(
				"[URGENT — APPROACHING TOOL CALL LIMIT: %d/%d calls used, only %d remaining]\n"+
					"You are about to reach the maximum tool call limit. "+
					"Please IMMEDIATELY save your findings using the result/report tool. "+
					"Summarize all discoveries, evidence, and recommendations NOW before the limit is reached.",
				toolCallCount, maxToolCalls, maxToolCalls-toolCallCount,
			)
			chain = append(chain, llms.MessageContent{
				Role: llms.ChatMessageTypeHuman,
				Parts: []llms.ContentPart{
					llms.TextContent{Text: warningMsg},
				},
			})
			if err := fp.updateMsgChain(ctx, chainID, chain, rollLastUpdateTime()); err != nil {
				logger.WithError(err).Error("failed to update msg chain after limit warning")
			}
			logger.WithFields(logrus.Fields{
				"tool_call_count": toolCallCount,
				"max_tool_calls":  maxToolCalls,
				"remaining":       maxToolCalls - toolCallCount,
			}).Warn("approaching tool call limit, injected warning to agent")
		}

		if toolCallCount >= maxToolCalls {
			logger.WithField("tool_call_count", toolCallCount).
				Warn("reached max tool calls per subtask, forcing stop")

			// Save partial results before failing so findings are not lost.
			if subtaskID != nil {
				partialResult := fmt.Sprintf("[PARTIAL — tool call limit reached at %d/%d calls]\n", toolCallCount, maxToolCalls)
				if execState != nil {
					partialResult += fmt.Sprintf("Phase: %s\nAttacks done: %v\nError count: %d\n",
						execState.Phase, execState.AttacksDone, execState.ErrorCount)
				}
				// Collect last few tool results from chain as evidence of work done
				partialResult += "\nTool call summary (last 10):\n"
				toolResultCount := 0
				for i := len(chain) - 1; i >= 0 && toolResultCount < 10; i-- {
					if chain[i].Role == llms.ChatMessageTypeTool {
						for _, part := range chain[i].Parts {
							if resp, ok := part.(llms.ToolCallResponse); ok {
								snippet := resp.Content
								if len(snippet) > 200 {
									snippet = snippet[:200] + "..."
								}
								partialResult += fmt.Sprintf("- %s: %s\n", resp.Name, snippet)
								toolResultCount++
							}
						}
					}
				}
				if _, err := fp.db.UpdateSubtaskResult(ctx, database.UpdateSubtaskResultParams{
					Result: partialResult,
					ID:     *subtaskID,
				}); err != nil {
					logger.WithError(err).Error("failed to save partial results on tool call limit")
				}
			}

			return fmt.Errorf("subtask tool call limit reached (%d calls)", toolCallCount)
		}

		// Check global budget across entire delegation tree
		if budget := GetBudget(ctx); budget != nil {
			if err := budget.Consume(len(result.funcCalls)); err != nil {
				logger.WithError(err).Warn("global execution budget exceeded")
				return err
			}
		}

		if wantToStop {
			return nil
		}

		// Proactive reflector: check if tool history signals a behavioral loop
		if shouldTrigger, reason := toolHistory.ShouldTriggerProactiveReflector(toolCallCount); shouldTrigger {
			// Mark the reflector as fired to start the cooldown period.
			// This prevents the reflector storm where the same condition
			// fires the reflector on every consecutive tool call.
			toolHistory.MarkReflectorFired()

			logger.WithFields(logrus.Fields{
				"trigger_reason":  reason,
				"tool_call_count": toolCallCount,
				"pattern_score":   toolHistory.GetPatternScore(),
				"error_rate_5":    toolHistory.GetErrorRate(5),
			}).Info("proactive reflector triggered")

			// Build a synthetic "status report" content for the reflector
			proactiveContent := fmt.Sprintf(
				"[PROACTIVE LOOP CHECK — triggered by: %s]\n\n"+
					"The agent has been executing tool calls. Review the execution history below "+
					"and determine if the agent should CONTINUE, CHANGE_APPROACH, or STOP.\n\n%s",
				reason, toolHistory.FormatForPrompt())

			proactiveMsg := llms.MessageContent{Role: llms.ChatMessageTypeAI}
			proactiveMsg.Parts = append(proactiveMsg.Parts, llms.TextContent{Text: proactiveContent})

			proactiveResult, proactiveErr := fp.performReflector(
				ctx, optAgentType, chainID, taskID, subtaskID,
				append(chain, proactiveMsg),
				fp.getLastHumanMessage(chain), proactiveContent, executionContext, executor, 1,
				metrics.Snapshot(metricsStartTime), toolHistory)
			if proactiveErr != nil {
				// Proactive reflector failure is non-fatal; log and continue
				logger.WithError(proactiveErr).Warn("proactive reflector failed, continuing execution")
			} else if proactiveResult != nil && len(proactiveResult.funcCalls) > 0 {
				// Filter out read-only state file checks from reflector suggestions.
				// The reflector often suggests "check STATE.json" or "review FINDINGS.md"
				// which causes the agent to enter an infinite read loop.
				filtered := filterReflectorSuggestions(proactiveResult.funcCalls)
				if len(filtered) > 0 {
					proactiveResult.funcCalls = filtered
					// Reflector provided a corrective tool call — inject it as the next result
					result = proactiveResult
					// Re-process the corrective tool calls by continuing the loop
					// The next iteration will pick up result.funcCalls from the reflector
					logger.Info("proactive reflector provided corrective tool calls")
				} else {
					logger.Info("proactive reflector suggestions were all state-reads, skipping injection")
				}
			}
		}

		if summarizer != nil {
			// it returns the same chain state if error occurs
			chain, err = summarizer.SummarizeChain(ctx, summarizerHandler, chain, fp.tcIDTemplate)
			if err != nil {
				summarizerFailures++
				// log swallowed error
				_, observation := obs.Observer.NewObservation(ctx)
				observation.Event(
					langfuse.WithEventName("chain summarization error swallowed"),
					langfuse.WithEventInput(chain),
					langfuse.WithEventStatus(err.Error()),
					langfuse.WithEventLevel(langfuse.ObservationLevelWarning),
					langfuse.WithEventMetadata(langfuse.Metadata{
						"tc_id_template":      fp.tcIDTemplate,
						"msg_chain_id":        chainID,
						"error":               err.Error(),
						"consecutive_failures": summarizerFailures,
					}),
				)
				logger.WithError(err).WithField("consecutive_failures", summarizerFailures).
					Warn("failed to summarize chain")
				if summarizerFailures >= 3 {
					return fmt.Errorf("chain summarization repeatedly failed (%d times): %w", summarizerFailures, err)
				}
			} else {
				summarizerFailures = 0 // reset on success
				if err := fp.updateMsgChain(ctx, chainID, chain, rollLastUpdateTime()); err != nil {
					logger.WithError(err).Error("failed to update msg chain")
					return err
				}
			}
		}
	}
}

func (fp *flowProvider) execToolCall(
	ctx context.Context,
	chainID int64,
	toolCallIDx int,
	result *callResult,
	detector *repeatingDetector,
	executor tools.ContextToolsExecutor,
	nTracker *nucleiTracker,
	terminalCache *TerminalOutputCache,
	knownData *knownDataTracker,
) (string, error) {
	var (
		streamID int64
		thinking string
	)

	// use streamID and thinking only for first tool call to minimize content
	if toolCallIDx == 0 {
		streamID = result.streamID
		if !result.thinking.IsEmpty() {
			thinking = result.thinking.Content
		}
	}

	toolCall := result.funcCalls[toolCallIDx]
	if toolCall.FunctionCall == nil {
		return "", fmt.Errorf("tool call at index %d has nil FunctionCall", toolCallIDx)
	}
	funcName := toolCall.FunctionCall.Name
	funcArgs := json.RawMessage(toolCall.FunctionCall.Arguments)

	logger := logrus.WithContext(ctx).WithFields(logrus.Fields{
		"agent":        fp.Type(),
		"flow_id":      fp.flowID,
		"func_name":    funcName,
		"func_args":    string(funcArgs)[:min(1000, len(funcArgs))],
		"tool_call_id": toolCall.ID,
		"msg_chain_id": chainID,
	})

	// --- Read-Only Soft Cap: check BEFORE repeat detection ---
	// The existing isReadOnlyCall() exemption in detect() remains untouched.
	// This is an ADDITIONAL guard that caps how many times the same file can
	// be read in a single subtask, preventing infinite STATE.json/HANDOFF.md loops.
	var readCapWarning string
	if toolCall.FunctionCall != nil {
		blocked, readCapMsg := detector.checkReadCap(*toolCall.FunctionCall)
		if blocked {
			logger.WithField("read_cap_msg", readCapMsg).Warn("read-only soft cap blocked tool call")
			return readCapMsg, nil
		}
		// If warning (not blocked), store it to prepend to the response after execution.
		readCapWarning = readCapMsg
	}

	// --- Nuclei Dedup: block redundant nuclei scans ---
	if nTracker != nil && toolCall.FunctionCall != nil {
		var nucleiTarget string

		if funcName == "nuclei_scan" {
			nucleiTarget = extractNucleiTarget(string(funcArgs))
		} else if funcName == "terminal" {
			var termArgs map[string]interface{}
			if err := json.Unmarshal(funcArgs, &termArgs); err == nil {
				if input, ok := termArgs["input"].(string); ok && strings.Contains(input, "nuclei") {
					nucleiTarget = extractNucleiTargetFromCmd(input)
				}
			}
		}

		if nucleiTarget != "" {
			if blocked, msg := nTracker.Check(nucleiTarget); blocked {
				logger.WithField("nuclei_target", nucleiTarget).Warn("nuclei dedup blocked scan")
				return msg, nil
			}
		}
	}

	// --- Browser Automation Install Blocker ---
	// Prevent the agent from installing playwright, puppeteer, chromium, etc.
	// These are unnecessary because browser tools (browser_navigate, browser_click, etc.)
	// are already available as built-in agent tools backed by Playwright.
	if funcName == "terminal" {
		var termArgs map[string]interface{}
		if err := json.Unmarshal(funcArgs, &termArgs); err == nil {
			if input, ok := termArgs["input"].(string); ok && isBrowserAutomationInstall(input) {
				logger.WithField("blocked_cmd", input).Warn("blocked browser automation package install attempt")
				return blockedBrowserInstallMessage, nil
			}
		}
	}

	// --- Terminal Output Cache: return cached result for idempotent commands ---
	// Check BEFORE repeat detection and execution. If the command was already
	// executed in this subtask and its output is cached, return the cached
	// result immediately. This is the primary mechanism for preventing the
	// 15-20x JWT token re-extraction and 4x GraphQL schema re-introspection.
	if funcName == "terminal" && terminalCache != nil {
		var termArgs map[string]interface{}
		if err := json.Unmarshal(funcArgs, &termArgs); err == nil {
			if input, ok := termArgs["input"].(string); ok {
				if cached, hit := terminalCache.Check(input); hit {
					logger.WithField("cache_hit", true).
						Info("terminal command cache hit — returning cached output")
					return cached, nil
				}
			}
		}
	}

	if detector.detect(toolCall) {
		response := fmt.Sprintf("tool call '%s' is repeating, please try another tool", funcName)

		_, observation := obs.Observer.NewObservation(ctx)
		observation.Event(
			langfuse.WithEventName("repeating tool call detected"),
			langfuse.WithEventInput(funcArgs),
			langfuse.WithEventMetadata(map[string]any{
				"tool_call_id": toolCall.ID,
				"tool_name":    funcName,
				"msg_chain_id": chainID,
			}),
			langfuse.WithEventStatus("failed"),
			langfuse.WithEventLevel(langfuse.ObservationLevelError),
			langfuse.WithEventOutput(response),
		)
		logger.Warn("failed to exec function: tool call is repeating")

		return response, nil
	}

	// --- Pre-write backup for tracked state files ---
	// When a terminal or file tool call writes to FINDINGS.md, STATE.json, or HANDOFF.md,
	// back up the file BEFORE execution. This protects against `cat > FILE << 'EOF'`
	// truncating the file to 0 bytes when the context deadline kills the write mid-stream.
	if trackedFile := isTrackedFileWrite(funcName, funcArgs); trackedFile != "" {
		backupCmd := buildBackupCommand(trackedFile)
		backupArgs, _ := json.Marshal(map[string]interface{}{
			"input":   backupCmd,
			"timeout": 5,
		})
		// Execute backup with a short timeout; failures are silently ignored.
		_, backupErr := executor.Execute(ctx, 0, "", "terminal", "", backupArgs)
		if backupErr != nil {
			logger.WithError(backupErr).WithField("tracked_file", trackedFile).
				Debug("pre-write backup failed (non-fatal, continuing with original command)")
		} else {
			logger.WithField("tracked_file", trackedFile).Debug("pre-write backup created")
		}
	}

	var (
		err      error
		response string
	)

	for idx := 0; idx <= maxRetriesToCallFunction; idx++ {
		if idx == maxRetriesToCallFunction {
			err = fmt.Errorf("reached max retries to call function: %w", err)
			logger.WithError(err).Error("failed to exec function")
			return "", fmt.Errorf("failed to exec function '%s': %w", funcName, err)
		}

		response, err = executor.Execute(ctx, streamID, toolCall.ID, funcName, thinking, funcArgs)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return "", err
			}

			// Short-circuit: if context deadline is >80% expired, skip the fix attempt
			// (which would make another LLM call that will also likely timeout)
			if deadline, ok := ctx.Deadline(); ok {
				remaining := time.Until(deadline)
				if remaining < getSubtaskMaxDuration()/5 {
					logger.WithError(err).Warn("skipping fixToolCallArgs: context nearly expired")
					return "", fmt.Errorf("tool execution failed (timeout imminent): %w", err)
				}
			}

			logger.WithError(err).Warn("failed to exec function")

			funcExecErr := err
			funcSchema, err := executor.GetToolSchema(funcName)
			if err != nil {
				logger.WithError(err).Error("failed to get tool schema")
				return "", fmt.Errorf("failed to get tool schema: %w", err)
			}

			funcArgs, err = fp.fixToolCallArgs(ctx, funcName, funcArgs, funcSchema, funcExecErr)
			if err != nil {
				logger.WithError(err).Error("failed to fix tool call args")
				return "", fmt.Errorf("failed to fix tool call args: %w", err)
			}
		} else {
			break
		}
	}

	// --- Post-execution: cache terminal output and extract known data ---
	// Store the terminal command output in the cache for future dedup, and
	// scan it for recognizable data patterns (JWT tokens, GraphQL endpoints)
	// to inject into the system prompt.
	if funcName == "terminal" && terminalCache != nil {
		var termArgs map[string]interface{}
		if err := json.Unmarshal(funcArgs, &termArgs); err == nil {
			if input, ok := termArgs["input"].(string); ok {
				// Cache the output for identical future commands.
				terminalCache.Store(input, response)

				// Extract known data patterns (tokens, endpoints, schemas)
				// for system prompt injection.
				if knownData != nil {
					knownData.Extract(input, response)
				}
			}
		}
	}

	// --- Post-execution: record nuclei scan results for dedup ---
	if nTracker != nil && toolCall.FunctionCall != nil {
		if funcName == "nuclei_scan" {
			target := extractNucleiTarget(string(funcArgs))
			tags, severity := extractNucleiScanDetails(string(funcArgs))
			// Count findings: crude heuristic based on response lines containing "[" (nuclei output format).
			findCount := 0
			for _, line := range strings.Split(response, "\n") {
				if strings.Contains(line, "[") && strings.Contains(line, "]") {
					findCount++
				}
			}
			nTracker.Record(target, tags, severity, findCount)
		} else if funcName == "terminal" {
			var termArgs map[string]interface{}
			if err := json.Unmarshal(funcArgs, &termArgs); err == nil {
				if input, ok := termArgs["input"].(string); ok && strings.Contains(input, "nuclei") {
					target := extractNucleiTargetFromCmd(input)
					if target != "" {
						nTracker.Record(target, "", "", 0)
					}
				}
			}
		}
	}

	// --- Prepend read cap warning if present ---
	if readCapWarning != "" {
		response = readCapWarning + "\n\n" + response
	}

	return response, nil
}

func (fp *flowProvider) callWithRetries(
	ctx context.Context,
	chain []llms.MessageContent,
	optAgentType pconfig.ProviderOptionsType,
	executor tools.ContextToolsExecutor,
) (*callResult, error) {
	var (
		err     error
		errs    []error
		msgType = database.MsglogTypeAnswer
		resp    *llms.ContentResponse
		result  callResult
	)

	ticker := time.NewTicker(delayBetweenRetries)
	defer ticker.Stop()

	fillResult := func(resp *llms.ContentResponse) error {
		var stopReason string
		var parts []string

		if resp == nil || len(resp.Choices) == 0 {
			return fmt.Errorf("no choices in response")
		}

		for _, choice := range resp.Choices {
			if stopReason == "" {
				stopReason = choice.StopReason
			}

			if choice.GenerationInfo != nil {
				result.info = choice.GenerationInfo
			}

			// Extract reasoning for logging/analytics (provider-aware)
			if result.thinking.IsEmpty() {
				if !choice.Reasoning.IsEmpty() {
					result.thinking = choice.Reasoning
				} else if len(choice.ToolCalls) > 0 && !choice.ToolCalls[0].Reasoning.IsEmpty() {
					// Gemini puts reasoning in first tool call when tools are used
					result.thinking = choice.ToolCalls[0].Reasoning
				}
			}

			if strings.TrimSpace(choice.Content) != "" {
				parts = append(parts, choice.Content)
			}

			for _, toolCall := range choice.ToolCalls {
				if toolCall.FunctionCall == nil {
					continue
				}
				result.funcCalls = append(result.funcCalls, toolCall)
			}
		}

		result.content = strings.Join(parts, "\n")
		if strings.Trim(result.content, "' \"\n\r\t") == "" && len(result.funcCalls) == 0 {
			return fmt.Errorf("no content and tool calls in response: stop reason '%s'", stopReason)
		}

		return nil
	}

	for idx := 0; idx <= maxRetriesToCallAgentChain; idx++ {
		if idx == maxRetriesToCallAgentChain {
			msg := fmt.Sprintf("failed to call agent chain: max retries reached, %d", idx)
			return nil, fmt.Errorf(msg+": %w", errors.Join(errs...))
		}

		var streamCb streaming.Callback
		if fp.streamCb != nil {
			// Close abandoned stream from previous retry attempt
			if result.streamID != 0 {
				_ = fp.streamCb(ctx, &StreamMessageChunk{
					Type:     StreamMessageChunkTypeFlush,
					MsgType:  msgType,
					StreamID: result.streamID,
				})
			}
			result.streamID = fp.callCounter.Add(1)
			// Reset result state for retry to avoid accumulating stale data
			result.funcCalls = nil
			result.content = ""
			result.info = nil
			result.thinking = nil
			streamCb = func(ctx context.Context, chunk streaming.Chunk) error {
				switch chunk.Type {
				case streaming.ChunkTypeReasoning:
					if chunk.Reasoning.IsEmpty() {
						return nil
					}
					return fp.streamCb(ctx, &StreamMessageChunk{
						Type:     StreamMessageChunkTypeThinking,
						MsgType:  msgType,
						Thinking: chunk.Reasoning,
						StreamID: result.streamID,
					})
				case streaming.ChunkTypeText:
					return fp.streamCb(ctx, &StreamMessageChunk{
						Type:     StreamMessageChunkTypeContent,
						MsgType:  msgType,
						Content:  chunk.Content,
						StreamID: result.streamID,
					})
				case streaming.ChunkTypeToolCall:
					// skip tool call chunks (we don't need them for now)
				case streaming.ChunkTypeDone:
					return fp.streamCb(ctx, &StreamMessageChunk{
						Type:     StreamMessageChunkTypeFlush,
						MsgType:  msgType,
						StreamID: result.streamID,
					})
				}
				return nil
			}
		}

		resp, err = fp.CallWithTools(ctx, optAgentType, chain, executor.Tools(), streamCb)
		if err == nil {
			err = fillResult(resp)
		}
		if err == nil {
			break
		} else {
			errs = append(errs, err)
		}

		// Exponential backoff: 5s → 15s → 45s with ±20% jitter
		backoff := delayBetweenRetries
		for i := 0; i < idx; i++ {
			backoff *= 3
		}
		jitter := time.Duration(rand.Int63n(int64(backoff) / 5)) //nolint:gosec
		if rand.Intn(2) == 0 {                                   //nolint:gosec
			backoff += jitter
		} else {
			backoff -= jitter
		}
		ticker.Reset(backoff)
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return nil, fmt.Errorf("context canceled while waiting for retry: %w", ctx.Err())
		}
	}

	if fp.streamCb != nil && result.streamID != 0 {
		fp.streamCb(ctx, &StreamMessageChunk{
			Type:     StreamMessageChunkTypeUpdate,
			MsgType:  msgType,
			Content:  result.content,
			Thinking: result.thinking,
			StreamID: result.streamID,
		})
		// don't update stream by ID if we got content separately from tool calls
		// because we stored thinking and content into standalone messages
		if len(result.funcCalls) > 0 && result.content != "" {
			result.streamID = 0
		}
	}

	return &result, nil
}

func (fp *flowProvider) performReflector(
	ctx context.Context,
	optOriginType pconfig.ProviderOptionsType,
	chainID int64,
	taskID, subtaskID *int64,
	chain []llms.MessageContent,
	humanMessage, content, executionContext string,
	executor tools.ContextToolsExecutor,
	iteration int,
	metrics ExecutionMetrics,
	toolHistory *ToolHistory,
) (*callResult, error) {
	ctx, span := obs.Observer.NewSpan(ctx, obs.SpanKindInternal, "providers.flowProvider.performReflector")
	defer span.End()

	var (
		optAgentType = pconfig.OptionsTypeReflector
		msgChainType = database.MsgchainTypeReflector
	)

	fields := logrus.Fields{
		"provider":     fp.Type(),
		"agent":        optAgentType,
		"origin":       optOriginType,
		"flow_id":      fp.flowID,
		"msg_chain_id": chainID,
		"iteration":    iteration,
	}
	if taskID != nil {
		fields["task_id"] = *taskID
	}
	if subtaskID != nil {
		fields["subtask_id"] = *subtaskID
	}

	logger := logrus.WithContext(ctx).WithFields(fields)

	if iteration > maxReflectorCallsPerChain {
		msg := "reflector called too many times"
		_, observation := obs.Observer.NewObservation(ctx)
		observation.Event(
			langfuse.WithEventName("reflector limit calls reached"),
			langfuse.WithEventInput(content),
			langfuse.WithEventStatus("failed"),
			langfuse.WithEventLevel(langfuse.ObservationLevelError),
			langfuse.WithEventOutput(msg),
		)
		logger.WithField("content", content[:min(1000, len(content))]).Warn(msg)
		return nil, errors.New(msg)
	}

	logger.WithField("content", content[:min(1000, len(content))]).Warn("got message instead of tool call")

	reflectorContext := map[string]map[string]any{
		"user": {
			"Message":          content,
			"BarrierToolNames": executor.GetBarrierToolNames(),
		},
		"system": {
			"BarrierTools":      executor.GetBarrierTools(),
			"CurrentTime":       getCurrentTime(),
			"ExecutionContext":   executionContext,
			"ExecutionMetrics":  &metrics,
		},
	}

	if humanMessage != "" {
		reflectorContext["system"]["Request"] = humanMessage
	}

	// Inject tool history summary when available
	if toolHistory != nil && toolHistory.Len() > 0 {
		reflectorContext["system"]["ToolHistorySummary"] = toolHistory.FormatForPrompt()

		// Pre-compute loop detection signals for template
		patternScore := toolHistory.GetPatternScore()
		errorRate := toolHistory.GetErrorRate(5)
		mostFreqName, mostFreqCount := toolHistory.GetMostFrequentInLast(repeatingWindowSize)
		reflectorContext["system"]["LoopDetection"] = map[string]any{
			"PatternScore":        fmt.Sprintf("%.2f", patternScore),
			"ErrorRate":           fmt.Sprintf("%.0f%%", errorRate*100),
			"MostFrequentTool":    mostFreqName,
			"MostFrequentCount":   mostFreqCount,
			"IsLoopLikely":        patternScore > 0.7 || errorRate > 0.5 || mostFreqCount > 3,
		}
	}

	ctx, observation := obs.Observer.NewObservation(ctx)
	reflectorAgent := observation.Agent(
		langfuse.WithAgentName("reflector"),
		langfuse.WithAgentInput(content),
		langfuse.WithAgentMetadata(langfuse.Metadata{
			"user_context":   reflectorContext["user"],
			"system_context": reflectorContext["system"],
		}),
	)
	ctx, observation = reflectorAgent.Observation(ctx)

	reflectorEvaluator := observation.Evaluator(
		langfuse.WithEvaluatorName("render reflector agent prompts"),
		langfuse.WithEvaluatorInput(reflectorContext),
		langfuse.WithEvaluatorMetadata(langfuse.Metadata{
			"user_context":   reflectorContext["user"],
			"system_context": reflectorContext["system"],
			"lang":           fp.language,
		}),
	)

	userReflectorTmpl, err := fp.prompter.RenderTemplate(templates.PromptTypeQuestionReflector, reflectorContext["user"])
	if err != nil {
		msg := "failed to get user reflector template"
		return nil, wrapErrorEndEvaluatorSpan(ctx, reflectorEvaluator, msg, err)
	}

	systemReflectorTmpl, err := fp.prompter.RenderTemplate(templates.PromptTypeReflector, reflectorContext["system"])
	if err != nil {
		msg := "failed to get system reflector template"
		return nil, wrapErrorEndEvaluatorSpan(ctx, reflectorEvaluator, msg, err)
	}

	reflectorEvaluator.End(
		langfuse.WithEvaluatorOutput(map[string]any{
			"user_template":   userReflectorTmpl,
			"system_template": systemReflectorTmpl,
		}),
		langfuse.WithEvaluatorStatus("success"),
		langfuse.WithEvaluatorLevel(langfuse.ObservationLevelDebug),
	)

	advice, err := fp.performSimpleChain(ctx, taskID, subtaskID, optAgentType,
		msgChainType, systemReflectorTmpl, userReflectorTmpl)
	if err != nil {
		advice = ToolPlaceholder
	}

	opts := []langfuse.AgentOption{
		langfuse.WithAgentStatus("failed"),
		langfuse.WithAgentOutput(advice),
		langfuse.WithAgentLevel(langfuse.ObservationLevelWarning),
	}
	defer func() {
		reflectorAgent.End(opts...)
	}()

	chain = append(chain, llms.TextParts(llms.ChatMessageTypeHuman, advice))
	result, err := fp.callWithRetries(ctx, chain, optOriginType, executor)
	if err != nil {
		logger.WithError(err).Error("failed to call agent chain by reflector")
		opts = append(opts,
			langfuse.WithAgentStatus(err.Error()),
			langfuse.WithAgentLevel(langfuse.ObservationLevelError),
		)
		return nil, err
	}

	// don't update duration delta for reflector because it's already included in the performAgentChain
	if err := fp.updateMsgChainUsage(ctx, chainID, optAgentType, result.info, 0); err != nil {
		logger.WithError(err).Error("failed to update msg chain usage")
		opts = append(opts,
			langfuse.WithAgentStatus(err.Error()),
			langfuse.WithAgentLevel(langfuse.ObservationLevelError),
		)
		return nil, err
	}

	// preserve reasoning in reflector response using universal pattern
	reflectorMsg := llms.MessageContent{Role: llms.ChatMessageTypeAI}
	if result.content != "" || !result.thinking.IsEmpty() {
		reflectorMsg.Parts = append(reflectorMsg.Parts, llms.TextPartWithReasoning(result.content, result.thinking))
	}
	chain = append(chain, reflectorMsg)
	if len(result.funcCalls) == 0 {
		return fp.performReflector(ctx, optOriginType, chainID, taskID, subtaskID, chain,
			humanMessage, result.content, executionContext, executor, iteration+1, metrics, toolHistory)
	}

	opts = append(opts, langfuse.WithAgentStatus("success"))
	return result, nil
}

func (fp *flowProvider) getLastHumanMessage(chain []llms.MessageContent) string {
	ast, err := cast.NewChainAST(chain, true)
	if err != nil {
		return ""
	}

	slices.Reverse(ast.Sections)
	for _, section := range ast.Sections {
		if section.Header.HumanMessage != nil {
			var hparts []string
			for _, part := range section.Header.HumanMessage.Parts {
				if text, ok := part.(llms.TextContent); ok {
					hparts = append(hparts, text.Text)
				}
			}
			return strings.Join(hparts, "\n")
		}
	}

	return ""
}

func (fp *flowProvider) processAssistantResult(
	ctx context.Context,
	logger *logrus.Entry,
	chainID int64,
	chain []llms.MessageContent,
	result *callResult,
	summarizer csum.Summarizer,
	summarizerHandler tools.SummarizeHandler,
	durationDelta float64,
) error {
	var err error

	processAssistantResultStartTime := time.Now()

	if fp.streamCb != nil {
		if result.streamID == 0 {
			result.streamID = fp.callCounter.Add(1)
		}
		err := fp.streamCb(ctx, &StreamMessageChunk{
			Type:     StreamMessageChunkTypeUpdate,
			MsgType:  database.MsglogTypeAnswer,
			Content:  result.content,
			Thinking: result.thinking,
			StreamID: result.streamID,
		})
		if err != nil {
			return fmt.Errorf("failed to stream assistant result: %w", err)
		}
	}

	if summarizer != nil {
		// it returns the same chain state if error occurs
		chain, err = summarizer.SummarizeChain(ctx, summarizerHandler, chain, fp.tcIDTemplate)
		if err != nil {
			// log swallowed error
			_, observation := obs.Observer.NewObservation(ctx)
			observation.Event(
				langfuse.WithEventName("chain summarization error swallowed"),
				langfuse.WithEventInput(chain),
				langfuse.WithEventStatus(err.Error()),
				langfuse.WithEventLevel(langfuse.ObservationLevelWarning),
				langfuse.WithEventMetadata(langfuse.Metadata{
					"tc_id_template": fp.tcIDTemplate,
					"msg_chain_id":   chainID,
					"error":          err.Error(),
				}),
			)
			logger.WithError(err).Warn("failed to summarize chain")
		}
	}

	// Preserve reasoning for assistant responses using universal pattern
	msg := llms.MessageContent{Role: llms.ChatMessageTypeAI}
	if result.content != "" || !result.thinking.IsEmpty() {
		msg.Parts = append(msg.Parts, llms.TextPartWithReasoning(result.content, result.thinking))
	}
	chain = append(chain, msg)
	durationDelta += time.Since(processAssistantResultStartTime).Seconds()
	if err := fp.updateMsgChain(ctx, chainID, chain, durationDelta); err != nil {
		return fmt.Errorf("failed to update msg chain: %w", err)
	}

	return nil
}

func (fp *flowProvider) updateMsgChain(
	ctx context.Context,
	chainID int64,
	chain []llms.MessageContent,
	durationDelta float64,
) error {
	chainBlob, err := json.Marshal(chain)
	if err != nil {
		return fmt.Errorf("failed to marshal msg chain: %w", err)
	}

	_, err = fp.db.UpdateMsgChain(ctx, database.UpdateMsgChainParams{
		Chain:           chainBlob,
		DurationSeconds: durationDelta,
		ID:              chainID,
	})
	if err != nil {
		return fmt.Errorf("failed to update msg chain in DB: %w", err)
	}

	return nil
}

func (fp *flowProvider) updateMsgChainUsage(
	ctx context.Context,
	chainID int64,
	optAgentType pconfig.ProviderOptionsType,
	info map[string]any,
	durationDelta float64,
) error {
	usage := fp.GetUsage(info)
	if usage.IsZero() {
		return nil
	}

	price := fp.GetPriceInfo(optAgentType)
	if price != nil {
		usage.UpdateCost(price)
	}

	// Feed usage to the in-memory CostTracker if one is attached to the context.
	if ct := GetCostTracker(ctx); ct != nil {
		ct.AddUsage(string(optAgentType), usage)
	}

	_, err := fp.db.UpdateMsgChainUsage(ctx, database.UpdateMsgChainUsageParams{
		UsageIn:         usage.Input,
		UsageOut:        usage.Output,
		UsageCacheIn:    usage.CacheRead,
		UsageCacheOut:   usage.CacheWrite,
		UsageCostIn:     usage.CostInput,
		UsageCostOut:    usage.CostOutput,
		DurationSeconds: durationDelta,
		ID:              chainID,
	})
	if err != nil {
		return fmt.Errorf("failed to update msg chain usage in DB: %w", err)
	}

	return nil
}

// storeToGraphiti stores messages to Graphiti with timeout
func (fp *flowProvider) storeToGraphiti(
	ctx context.Context,
	observation langfuse.Observation,
	groupID string,
	messages []graphiti.Message,
) error {
	if fp.graphitiClient == nil || !fp.graphitiClient.IsEnabled() {
		return nil
	}

	storeCtx, cancel := context.WithTimeout(ctx, fp.graphitiClient.GetTimeout())
	defer cancel()

	err := fp.graphitiClient.AddMessages(storeCtx, graphiti.AddMessagesRequest{
		GroupID:  groupID,
		Messages: messages,
		Observation: &graphiti.Observation{
			ID:      observation.ID(),
			TraceID: observation.TraceID(),
			Time:    time.Now().UTC(),
		},
	})
	if err != nil {
		logrus.WithError(err).
			WithField("group_id", groupID).
			Warn("failed to store messages to graphiti")
	}

	return err
}

// storeAgentResponseToGraphiti stores agent response to Graphiti
func (fp *flowProvider) storeAgentResponseToGraphiti(
	ctx context.Context,
	groupID string,
	agentType pconfig.ProviderOptionsType,
	result *callResult,
	taskID, subtaskID *int64,
	chainID int64,
) {
	if fp.graphitiClient == nil || !fp.graphitiClient.IsEnabled() {
		return
	}

	if result.content == "" {
		return
	}

	tmpl, err := templates.ReadGraphitiTemplate("agent_response.tmpl")
	if err != nil {
		logrus.WithError(err).Warn("failed to read agent response template for graphiti")
		return
	}

	content, err := templates.RenderPrompt("agent_response", tmpl, map[string]any{
		"AgentType": string(agentType),
		"Response":  result.content,
		"TaskID":    taskID,
		"SubtaskID": subtaskID,
	})
	if err != nil {
		logrus.WithError(err).Warn("failed to render agent response template for graphiti")
		return
	}

	parts := []string{fmt.Sprintf("PentAGI %s agent execution in flow %d", agentType, fp.flowID)}
	if taskID != nil {
		parts = append(parts, fmt.Sprintf("task %d", *taskID))
	}
	if subtaskID != nil {
		parts = append(parts, fmt.Sprintf("subtask %d", *subtaskID))
	}
	sourceDescription := strings.Join(parts, ", ")

	messages := []graphiti.Message{
		{
			Content:           content,
			Author:            fmt.Sprintf("%s Agent", string(agentType)),
			Timestamp:         time.Now(),
			Name:              "agent_response",
			SourceDescription: sourceDescription,
		},
	}
	logrus.WithField("messages", messages).Debug("storing agent response to graphiti")

	ctx, observation := obs.Observer.NewObservation(ctx)
	storeEvaluator := observation.Evaluator(
		langfuse.WithEvaluatorName("store messages to graphiti"),
		langfuse.WithEvaluatorInput(messages),
		langfuse.WithEvaluatorMetadata(langfuse.Metadata{
			"group_id":     groupID,
			"agent_type":   agentType,
			"task_id":      taskID,
			"subtask_id":   subtaskID,
			"msg_chain_id": chainID,
		}),
	)

	ctx, observation = storeEvaluator.Observation(ctx)
	if err := fp.storeToGraphiti(ctx, observation, groupID, messages); err != nil {
		storeEvaluator.End(
			langfuse.WithEvaluatorStatus(err.Error()),
			langfuse.WithEvaluatorLevel(langfuse.ObservationLevelError),
		)
		return
	}

	storeEvaluator.End(
		langfuse.WithEvaluatorStatus("success"),
	)
}

// storeToolExecutionToGraphiti stores tool execution to Graphiti
func (fp *flowProvider) storeToolExecutionToGraphiti(
	ctx context.Context,
	groupID string,
	agentType pconfig.ProviderOptionsType,
	toolCall llms.ToolCall,
	response string,
	execErr error,
	executor tools.ContextToolsExecutor,
	taskID, subtaskID *int64,
	chainID int64,
) {
	if fp.graphitiClient == nil || !fp.graphitiClient.IsEnabled() {
		return
	}

	if toolCall.FunctionCall == nil {
		return
	}

	funcName := toolCall.FunctionCall.Name
	funcArgs := toolCall.FunctionCall.Arguments

	registryDefs := tools.GetRegistryDefinitions()
	toolDef, ok := registryDefs[funcName]
	description := ""
	if ok {
		description = toolDef.Description
	}

	isBarrier := executor.IsBarrierFunction(funcName)

	status := "success"
	if execErr != nil {
		status = "failure"
		response = fmt.Sprintf("Error: %s", execErr.Error())
	}

	toolExecTmpl, err := templates.ReadGraphitiTemplate("tool_execution.tmpl")
	if err != nil {
		logrus.WithError(err).Warn("failed to read tool execution template for graphiti")
		return
	}

	toolExecContent, err := templates.RenderPrompt("tool_execution", toolExecTmpl, map[string]any{
		"ToolName":    funcName,
		"Description": description,
		"IsBarrier":   isBarrier,
		"Arguments":   funcArgs,
		"AgentType":   string(agentType),
		"Status":      status,
		"Result":      response,
		"TaskID":      taskID,
		"SubtaskID":   subtaskID,
	})
	if err != nil {
		logrus.WithError(err).Warn("failed to render tool execution template for graphiti")
		return
	}

	parts := []string{fmt.Sprintf("PentAGI tool execution in flow %d", fp.flowID)}
	if taskID != nil {
		parts = append(parts, fmt.Sprintf("task %d", *taskID))
	}
	if subtaskID != nil {
		parts = append(parts, fmt.Sprintf("subtask %d", *subtaskID))
	}
	sourceDescription := strings.Join(parts, ", ")

	messages := []graphiti.Message{
		{
			Content:           toolExecContent,
			Author:            fmt.Sprintf("%s Agent", string(agentType)),
			Timestamp:         time.Now(),
			Name:              fmt.Sprintf("tool_execution_%s", funcName),
			SourceDescription: sourceDescription,
		},
	}

	ctx, observation := obs.Observer.NewObservation(ctx)
	storeEvaluator := observation.Evaluator(
		langfuse.WithEvaluatorName("store tool execution to graphiti"),
		langfuse.WithEvaluatorInput(messages),
		langfuse.WithEvaluatorMetadata(langfuse.Metadata{
			"group_id":     groupID,
			"agent_type":   agentType,
			"tool_name":    funcName,
			"tool_args":    funcArgs,
			"task_id":      taskID,
			"subtask_id":   subtaskID,
			"msg_chain_id": chainID,
		}),
	)

	ctx, observation = storeEvaluator.Observation(ctx)
	if err := fp.storeToGraphiti(ctx, observation, groupID, messages); err != nil {
		storeEvaluator.End(
			langfuse.WithEvaluatorStatus(err.Error()),
			langfuse.WithEvaluatorLevel(langfuse.ObservationLevelError),
		)
		return
	}

	storeEvaluator.End(
		langfuse.WithEvaluatorStatus("success"),
	)
}

// isBootstrapCommand returns true if the command is a typical bootstrap/setup
// command that only needs to run once. Conservative: only matches patterns
// that are definitively setup-only (not general-purpose use of the same commands).
func isBootstrapCommand(command string) bool {
	cmd := strings.TrimSpace(command)

	// Exact patterns for common bootstrap commands
	bootstrapPatterns := []string{
		"mkdir -p /work/evidence",
		"mkdir -p /work/results",
		"mkdir -p /work/reports",
		"which jq",
		"which nuclei",
		"which curl",
		"which nmap",
		"which jq nuclei curl",
		"which jq curl nuclei",
		"which nmap nuclei jq curl",
	}

	for _, pattern := range bootstrapPatterns {
		if cmd == pattern || strings.HasPrefix(cmd, pattern+" ") {
			return true
		}
	}

	// Compound which commands: "which <tool1> <tool2> ..." with known tool names
	if strings.HasPrefix(cmd, "which ") && !strings.Contains(cmd, "/") {
		parts := strings.Fields(cmd)
		if len(parts) >= 2 && len(parts) <= 8 {
			allTools := true
			knownTools := map[string]bool{
				"jq": true, "nuclei": true, "curl": true, "nmap": true,
				"wget": true, "python3": true, "pip": true, "git": true,
				"subfinder": true, "httpx": true, "ffuf": true, "sqlmap": true,
				"nikto": true, "dirb": true, "gobuster": true, "wfuzz": true,
			}
			for _, part := range parts[1:] {
				if !knownTools[part] {
					allTools = false
					break
				}
			}
			if allTools {
				return true
			}
		}
	}

	// Simple mkdir for work subdirectories (no compound commands)
	if strings.HasPrefix(cmd, "mkdir -p /work/") && !strings.Contains(cmd, "&&") {
		return true
	}

	return false
}

// ─── Hard Loop Breaker: helper functions ─────────────────────────────────────────

// getReadStreakWarnThreshold returns the consecutive read-only streak count
// at which a warning is injected. Configurable via READ_STREAK_WARN env var.
func getReadStreakWarnThreshold() int {
	if v := os.Getenv("READ_STREAK_WARN"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 3 {
			return n
		}
	}
	return 5
}

// getReadStreakBlockThreshold returns the consecutive read-only streak count
// at which individual read calls are REFUSED. Configurable via READ_STREAK_BLOCK env var.
func getReadStreakBlockThreshold() int {
	if v := os.Getenv("READ_STREAK_BLOCK"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 4 {
			return n
		}
	}
	return 8
}

// getReadStreakForceThreshold returns the consecutive read-only streak count
// at which the subtask is FORCE-COMPLETED. Configurable via READ_STREAK_FORCE env var.
func getReadStreakForceThreshold() int {
	if v := os.Getenv("READ_STREAK_FORCE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 6 {
			return n
		}
	}
	return 15
}

// isReadOnlyToolCall returns true if the tool call is a read-only operation
// that should count toward the consecutive read streak. Uses the existing
// classification functions from helpers.go.
func isReadOnlyToolCall(funcName string, funcArgs string) bool {
	switch funcName {
	case "search", "search_code", "search_guide", "memorist", "graphiti_search":
		return true
	case "file":
		return strings.Contains(funcArgs, `"read_file"`)
	case "terminal":
		if isTerminalWriteCommand(funcArgs) {
			return false
		}
		var termArgs map[string]interface{}
		if err := json.Unmarshal([]byte(funcArgs), &termArgs); err != nil {
			return false
		}
		input, ok := termArgs["input"].(string)
		if !ok || input == "" {
			return false
		}
		primaryCmd := extractPrimaryCommand(input)
		if isOffensiveCommand(primaryCmd) {
			return false
		}
		return isReadCommand(primaryCmd)
	default:
		return false
	}
}
