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
	nestedTimeoutDepth1         = 25 * time.Minute    // timeout for depth-1 nested agents
	nestedTimeoutDepth2         = 20 * time.Minute    // timeout for depth-2 nested agents
	nestedTimeoutDepth3         = 15 * time.Minute    // timeout for depth-3 nested agents

	// toolCallLimitWarningBuffer is how many calls before the limit we inject
	// a "wrap up" warning into the chain, giving the agent a chance to save findings.
	toolCallLimitWarningBuffer  = 10
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
func getNestedTimeout(depth int) time.Duration {
	switch {
	case depth <= 0:
		return getSubtaskMaxDuration()
	case depth == 1:
		return nestedTimeoutDepth1
	case depth == 2:
		return nestedTimeoutDepth2
	case depth == 3:
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
}

func (mc *mergedContext) Done() <-chan struct{} {
	// We need a merged done channel. Use a goroutine to select on both.
	// This is created lazily and cached — but for simplicity we use a goroutine approach.
	// In practice, the timeout context's Done() is sufficient because we also
	// check parentCancel in the Err() method.
	done := make(chan struct{})
	go func() {
		select {
		case <-mc.Context.Done():
			close(done)
		case <-mc.parentCancel.Done():
			close(done)
		}
	}()
	return done
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
	merged := &mergedContext{
		Context:      timeoutCtx,
		parentCancel: parentCtx,
	}
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

		// Sprint 3: Integration placeholders for Sprint 2 modules.
		// These will be wired once finding_tracker.go, industry_detector.go,
		// and category_tracker.go are created by the Sprint 2 agent.
		chainSuggestionsInjected int // cap chain suggestions to avoid context bloat
		industryDetected         bool
		halfwayAlertSent         bool
	)

	// Silence unused variable warnings — these guard future Sprint 2 integration.
	_ = chainSuggestionsInjected
	_ = industryDetected
	_ = halfwayAlertSent

	// Async state writer — batches DB writes so the agent loop isn't blocked.
	stateWriter := NewAsyncStateWriter(fp.db)
	defer stateWriter.Close()

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

	// TODO(sprint2): Wire IndustryDetector.DetectIndustry(executionContext) here.
	// Once industry_detector.go is available:
	//   industryProfile := DetectIndustry(executionContext)
	//   if industryProfile.Type != "generic" && !industryDetected {
	//       industryDetected = true
	//       // Inject industry-specific playbook into system prompt
	//       if len(chain) > 0 && chain[0].Role == llms.ChatMessageTypeSystem {
	//           if text, ok := chain[0].Parts[0].(llms.TextContent); ok {
	//               updated := injectIndustryIntoSystemPrompt(text.Text, industryProfile)
	//               chain[0].Parts[0] = llms.TextContent{Text: updated}
	//           }
	//       }
	//       logger.WithField("industry", industryProfile.Type).Info("detected target industry from execution context")
	//   }

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
	var timeoutCancel context.CancelFunc
	if depth == 0 {
		// Top-level: standard timeout inheriting parent context
		ctx, timeoutCancel = context.WithTimeout(ctx, getSubtaskMaxDuration())
	} else {
		// Nested: fresh timeout that still respects parent cancellation
		nestedTimeout := getNestedTimeout(depth)
		ctx, timeoutCancel = newNestedContext(ctx, nestedTimeout)
	}
	defer timeoutCancel()

	timeWarningInjected := false

	for {
		if err := ctx.Err(); err != nil {
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
					// Compute time remaining from context deadline.
					timeRemainingMinutes := -1 // -1 = omit from prompt
					if deadline, ok := ctx.Deadline(); ok {
						remaining := time.Until(deadline)
						if remaining > 0 {
							timeRemainingMinutes = int(remaining.Minutes())
						} else {
							timeRemainingMinutes = 0
						}
					}
					updated := injectMetricsIntoSystemPrompt(text.Text, metrics.Snapshot(metricsStartTime), timeRemainingMinutes)
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

		// Proactive time-based delegation warning: inject explicit human-role message
		// when time is running low. Uses boolean flag to prevent re-injection after
		// chain summarization (reviewer recommendation: don't scan chain content).
		if !timeWarningInjected && metrics.ToolCallCount > 0 {
			if deadline, hasDL := ctx.Deadline(); hasDL {
				remaining := time.Until(deadline)
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

		// TODO(sprint2): Wire CategoryTracker.CheckHalfwayAlert() here (50% time mark P0 coverage).
		// Once category_tracker.go is available:
		//   if !halfwayAlertSent && metrics.ToolCallCount > 0 {
		//       if deadline, hasDL := ctx.Deadline(); hasDL {
		//           elapsed := time.Since(metricsStartTime)
		//           totalBudget := time.Until(deadline) + elapsed
		//           if elapsed > totalBudget/2 {
		//               shouldAlert, alertMsg := categoryTracker.CheckHalfwayAlert()
		//               if shouldAlert {
		//                   halfwayAlertSent = true
		//                   chain = append(chain, llms.MessageContent{
		//                       Role: llms.ChatMessageTypeHuman,
		//                       Parts: []llms.ContentPart{
		//                           llms.TextContent{Text: "[SYSTEM-AUTO] " + alertMsg},
		//                       },
		//                   })
		//                   if err := fp.updateMsgChain(ctx, chainID, chain, rollLastUpdateTime()); err != nil {
		//                       logger.WithError(err).Error("failed to update msg chain after P0 coverage alert")
		//                   }
		//                   logger.Info("injected P0 coverage alert at 50% time mark")
		//               }
		//           }
		//       }
		//   }

		result, err := fp.callWithRetries(ctx, chain, optAgentType, executor)
		if err != nil {
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

			response, err := fp.execToolCall(ctx, chainID, idx, result, detector, executor, nTracker)

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

			// TODO(sprint2): Wire FindingTracker.RecordFinding(response) here.
			// Once finding_tracker.go is available:
			//   findingTracker.RecordFinding(response)
			//   if findingTracker.HasNewHighFindings() && chainSuggestionsInjected < 3 {
			//       chainMsg := findingTracker.GetChainSuggestions()
			//       chain = append(chain, llms.MessageContent{
			//           Role: llms.ChatMessageTypeHuman,
			//           Parts: []llms.ContentPart{
			//               llms.TextContent{Text: "[SYSTEM-AUTO] [ATTACK CHAIN SUGGESTION] " + chainMsg},
			//           },
			//       })
			//       chainSuggestionsInjected++
			//       if err := fp.updateMsgChain(ctx, chainID, chain, rollLastUpdateTime()); err != nil {
			//           logger.WithError(err).Error("failed to update msg chain after chain suggestion")
			//       }
			//       logger.Info("injected attack chain suggestion into agent chain")
			//   }

			// TODO(sprint2): Wire CategoryTracker.RecordToolCall(funcName, toolCall.FunctionCall.Arguments) here.
			// Once category_tracker.go is available:
			//   categoryTracker.RecordToolCall(funcName, toolCall.FunctionCall.Arguments)

			if executor.IsBarrierFunction(funcName) {
				wantToStop = true
			}
		}

		toolCallCount += len(result.funcCalls)
		metrics.ToolCallCount = toolCallCount

		// Persist execution state to DB asynchronously after each tool call batch.
		if subtaskID != nil {
			phase := "executing"
			if wantToStop {
				phase = "finishing"
			}
			execState.Update(metrics, phase)

			// Every 10 tool calls, generate and persist resume context so that
			// if the subtask times out and resumes, the agent has a summary of
			// what was already done and doesn't waste time re-bootstrapping.
			if toolCallCount > 0 && toolCallCount%10 == 0 {
				resumeContent := buildResumeContent(toolHistory, metrics)
				if resumeContent != "" {
					execState.ResumeContext = resumeContent
					logger.WithField("tool_call_count", toolCallCount).
						Debug("persisted resume context to execution state")
				}
			}

			if stateJSON, err := execState.ToJSON(); err == nil {
				stateWriter.Write(*subtaskID, stateJSON)
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
