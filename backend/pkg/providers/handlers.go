package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"pentagi/pkg/cast"
	"pentagi/pkg/csum"
	"pentagi/pkg/database"
	"pentagi/pkg/docker"
	obs "pentagi/pkg/observability"
	"pentagi/pkg/observability/langfuse"
	"pentagi/pkg/providers/pconfig"
	"pentagi/pkg/schema"
	"pentagi/pkg/templates"
	"pentagi/pkg/tools"

	"github.com/sirupsen/logrus"
)

func wrapError(ctx context.Context, msg string, err error) error {
	if err == nil {
		logrus.WithContext(ctx).Error(msg)
		return errors.New(msg)
	}
	logrus.WithContext(ctx).WithError(err).Error(msg)
	return fmt.Errorf("%s: %w", msg, err)
}

// checkDelegationAllowed verifies that nesting depth and remaining time
// permit spawning another nested agent chain. Returns a user-friendly error
// message string (empty if delegation is allowed).
func checkDelegationAllowed(ctx context.Context, agentName string) string {
	maxDepth := getMaxNestingDepth()
	depth := getNestingDepth(ctx)
	if depth >= maxDepth {
		return fmt.Sprintf(
			"Maximum agent delegation depth reached (%d/%d). "+
				"Consider using terminal directly for faster execution instead of "+
				"delegating to %s. Write scripts directly, use 'apt-get install' in terminal, etc.",
			depth, maxDepth, agentName,
		)
	}

	// Deadline gating: block delegation if <20% of timeout remains.
	// Use 20% threshold (not 30%) to give nested agents more opportunity to work.
	// Nested agents get their own fresh timeout anyway, so this is mainly a safety net.
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		threshold := getSubtaskMaxDuration() / 5 // 20%
		if remaining < threshold {
			return fmt.Sprintf(
				"Low time remaining (%v) for delegation to %s. "+
					"Consider using terminal directly for faster execution.",
				remaining.Round(time.Second), agentName,
			)
		}
	}

	return ""
}

func wrapErrorEndAgentSpan(ctx context.Context, span langfuse.Agent, msg string, err error) error {
	logrus.WithContext(ctx).WithError(err).Error(msg)
	err = fmt.Errorf("%s: %w", msg, err)
	span.End(
		langfuse.WithAgentStatus(err.Error()),
		langfuse.WithAgentLevel(langfuse.ObservationLevelError),
	)
	return err
}

func wrapErrorEndEvaluatorSpan(ctx context.Context, span langfuse.Evaluator, msg string, err error) error {
	logrus.WithContext(ctx).WithError(err).Error(msg)
	err = fmt.Errorf("%s: %w", msg, err)
	span.End(
		langfuse.WithEvaluatorStatus(err.Error()),
		langfuse.WithEvaluatorLevel(langfuse.ObservationLevelError),
	)
	return err
}

func (fp *flowProvider) getTaskAndSubtask(ctx context.Context, taskID, subtaskID *int64) (*database.Task, *database.Subtask, error) {
	var (
		ptrTask    *database.Task
		ptrSubtask *database.Subtask
	)

	if taskID != nil {
		task, err := fp.db.GetTask(ctx, *taskID)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get task: %w", err)
		}
		ptrTask = &task
	}
	if subtaskID != nil {
		subtask, err := fp.db.GetSubtask(ctx, *subtaskID)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get subtask: %w", err)
		}
		ptrSubtask = &subtask
	}

	return ptrTask, ptrSubtask, nil
}

func (fp *flowProvider) GetAskAdviceHandler(ctx context.Context, taskID, subtaskID *int64) (tools.ExecutorHandler, error) {
	ptrTask, ptrSubtask, err := fp.getTaskAndSubtask(ctx, taskID, subtaskID)
	if err != nil {
		return nil, err
	}

	executionContext, err := fp.getExecutionContext(ctx, taskID, subtaskID)
	if err != nil {
		return nil, fmt.Errorf("failed to get execution context: %w", err)
	}

	enricherHandler := func(ctx context.Context, ask tools.AskAdvice) (string, error) {
		enricherContext := map[string]map[string]any{
			"user": {
				"Question": ask.Question,
				"Code":     ask.Code,
				"Output":   ask.Output,
			},
			"system": {
				"EnricherToolName":        tools.EnricherResultToolName,
				"SummarizationToolName":   cast.SummarizationToolName,
				"SummarizedContentPrefix": strings.ReplaceAll(csum.SummarizedContentPrefix, "\n", "\\n"),
				"ExecutionContext":        executionContext,
				"Lang":                    fp.language,
				"CurrentTime":             getCurrentTime(),
				"ToolPlaceholder":         ToolPlaceholder,
			},
		}

		enricherCtx, observation := obs.Observer.NewObservation(ctx)
		enricherEvaluator := observation.Evaluator(
			langfuse.WithEvaluatorName("render enricher agent prompts"),
			langfuse.WithEvaluatorInput(enricherContext),
			langfuse.WithEvaluatorMetadata(langfuse.Metadata{
				"user_context":   enricherContext["user"],
				"system_context": enricherContext["system"],
			}),
		)

		userEnricherTmpl, err := fp.prompter.RenderTemplate(templates.PromptTypeQuestionEnricher, enricherContext["user"])
		if err != nil {
			return "", wrapErrorEndEvaluatorSpan(enricherCtx, enricherEvaluator, "failed to get user enricher template", err)
		}

		systemEnricherTmpl, err := fp.prompter.RenderTemplate(templates.PromptTypeEnricher, enricherContext["system"])
		if err != nil {
			return "", wrapErrorEndEvaluatorSpan(enricherCtx, enricherEvaluator, "failed to get system enricher template", err)
		}

		enricherEvaluator.End(
			langfuse.WithEvaluatorOutput(map[string]any{
				"user_template":   userEnricherTmpl,
				"system_template": systemEnricherTmpl,
				"task":            taskID,
				"subtask":         subtaskID,
				"lang":            fp.language,
			}),
			langfuse.WithEvaluatorStatus("success"),
			langfuse.WithEvaluatorLevel(langfuse.ObservationLevelDebug),
		)

		enriches, err := fp.performEnricher(ctx, taskID, subtaskID, systemEnricherTmpl, userEnricherTmpl, ask.Question)
		if err != nil {
			return "", wrapError(ctx, "failed to get enriches for the question", err)
		}

		return enriches, nil
	}

	adviserHandler := func(ctx context.Context, ask tools.AskAdvice, enriches string) (string, error) {
		adviserContext := map[string]map[string]any{
			"user": {
				"Question": ask.Question,
				"Code":     ask.Code,
				"Output":   ask.Output,
				"Enriches": enriches,
			},
			"system": {
				"ExecutionContext": executionContext,
				"CurrentTime":      getCurrentTime(),
			},
		}

		adviserCtx, observation := obs.Observer.NewObservation(ctx)
		adviserEvaluator := observation.Evaluator(
			langfuse.WithEvaluatorName("render adviser agent prompts"),
			langfuse.WithEvaluatorInput(adviserContext),
			langfuse.WithEvaluatorMetadata(langfuse.Metadata{
				"user_context":   adviserContext["user"],
				"system_context": adviserContext["system"],
				"task":           ptrTask,
				"subtask":        ptrSubtask,
				"lang":           fp.language,
			}),
		)

		userAdviserTmpl, err := fp.prompter.RenderTemplate(templates.PromptTypeQuestionAdviser, adviserContext["user"])
		if err != nil {
			return "", wrapErrorEndEvaluatorSpan(adviserCtx, adviserEvaluator, "failed to get user adviser template", err)
		}

		systemAdviserTmpl, err := fp.prompter.RenderTemplate(templates.PromptTypeAdviser, adviserContext["system"])
		if err != nil {
			return "", wrapErrorEndEvaluatorSpan(adviserCtx, adviserEvaluator, "failed to get system adviser template", err)
		}

		adviserEvaluator.End(
			langfuse.WithEvaluatorOutput(map[string]any{
				"user_template":   userAdviserTmpl,
				"system_template": systemAdviserTmpl,
			}),
			langfuse.WithEvaluatorStatus("success"),
			langfuse.WithEvaluatorLevel(langfuse.ObservationLevelDebug),
		)

		opt := pconfig.OptionsTypeAdviser
		msgChainType := database.MsgchainTypeAdviser
		advice, err := fp.performSimpleChain(ctx, taskID, subtaskID, opt, msgChainType, systemAdviserTmpl, userAdviserTmpl)
		if err != nil {
			return "", wrapError(ctx, "failed to get advice", err)
		}

		return advice, nil
	}

	return func(ctx context.Context, name string, args json.RawMessage) (string, error) {
		ctx, span := obs.Observer.NewSpan(ctx, obs.SpanKindInternal, "providers.flowProvider.getAskAdviceHandler")
		defer span.End()

		var ask tools.AskAdvice
		if err := json.Unmarshal(args, &ask); err != nil {
			logrus.WithContext(ctx).WithError(err).Error("failed to unmarshal ask advice payload")
			return "", fmt.Errorf("failed to unmarshal ask advice payload: %w", err)
		}

		enriches, err := enricherHandler(ctx, ask)
		if err != nil {
			return "", err
		}

		advice, err := adviserHandler(ctx, ask, enriches)
		if err != nil {
			return "", err
		}

		return advice, nil
	}, nil
}

func (fp *flowProvider) GetCoderHandler(ctx context.Context, taskID, subtaskID *int64) (tools.ExecutorHandler, error) {
	ptrTask, ptrSubtask, err := fp.getTaskAndSubtask(ctx, taskID, subtaskID)
	if err != nil {
		return nil, err
	}

	executionContext, err := fp.getExecutionContext(ctx, taskID, subtaskID)
	if err != nil {
		return nil, fmt.Errorf("failed to get execution context: %w", err)
	}

	coderHandler := func(ctx context.Context, action tools.CoderAction) (string, error) {
		if msg := checkDelegationAllowed(ctx, "coder"); msg != "" {
			logrus.WithContext(ctx).WithField("depth", getNestingDepth(ctx)).Warn("coder delegation blocked: " + msg)
			return "", fmt.Errorf("%s", msg)
		}

		coderContext := map[string]map[string]any{
			"user": {
				"Question": action.Question,
			},
			"system": {
				"CodeResultToolName":      tools.CodeResultToolName,
				"SearchCodeToolName":      tools.SearchCodeToolName,
				"StoreCodeToolName":       tools.StoreCodeToolName,
				"GraphitiEnabled":         fp.graphitiClient != nil && fp.graphitiClient.IsEnabled(),
				"GraphitiSearchToolName":  tools.GraphitiSearchToolName,
				"SearchToolName":          tools.SearchToolName,
				"AdviceToolName":          tools.AdviceToolName,
				"MemoristToolName":        tools.MemoristToolName,
				"MaintenanceToolName":     tools.MaintenanceToolName,
				"SummarizationToolName":   cast.SummarizationToolName,
				"SummarizedContentPrefix": strings.ReplaceAll(csum.SummarizedContentPrefix, "\n", "\\n"),
				"DockerImage":             fp.image,
				"Cwd":                     docker.WorkFolderPathInContainer,
				"ContainerPorts":          fp.getContainerPortsDescription(),
				"ExecutionContext":        executionContext,
				"Lang":                    fp.language,
				"CurrentTime":             getCurrentTime(),
				"ToolPlaceholder":         ToolPlaceholder,
			},
		}

		coderCtx, observation := obs.Observer.NewObservation(ctx)
		coderEvaluator := observation.Evaluator(
			langfuse.WithEvaluatorName("render coder agent prompts"),
			langfuse.WithEvaluatorInput(coderContext),
			langfuse.WithEvaluatorMetadata(langfuse.Metadata{
				"user_context":   coderContext["user"],
				"system_context": coderContext["system"],
				"task":           ptrTask,
				"subtask":        ptrSubtask,
				"lang":           fp.language,
			}),
		)

		userCoderTmpl, err := fp.prompter.RenderTemplate(templates.PromptTypeQuestionCoder, coderContext["user"])
		if err != nil {
			return "", wrapErrorEndEvaluatorSpan(coderCtx, coderEvaluator, "failed to get user coder template", err)
		}

		systemCoderTmpl, err := fp.prompter.RenderTemplate(templates.PromptTypeCoder, coderContext["system"])
		if err != nil {
			return "", wrapErrorEndEvaluatorSpan(coderCtx, coderEvaluator, "failed to get system coder template", err)
		}

		coderEvaluator.End(
			langfuse.WithEvaluatorOutput(map[string]any{
				"user_template":   userCoderTmpl,
				"system_template": systemCoderTmpl,
			}),
			langfuse.WithEvaluatorStatus("success"),
			langfuse.WithEvaluatorLevel(langfuse.ObservationLevelDebug),
		)

		code, err := fp.performCoder(ctx, taskID, subtaskID, systemCoderTmpl, userCoderTmpl, action.Question)
		if err != nil {
			return "", wrapError(ctx, "failed to get coder result", err)
		}

		return code, nil
	}

	return func(ctx context.Context, name string, args json.RawMessage) (string, error) {
		ctx, span := obs.Observer.NewSpan(ctx, obs.SpanKindInternal, "providers.flowProvider.getCoderHandler")
		defer span.End()

		var action tools.CoderAction
		if err := json.Unmarshal(args, &action); err != nil {
			logrus.WithContext(ctx).WithError(err).Error("failed to unmarshal code payload")
			return "", fmt.Errorf("failed to unmarshal code payload: %w", err)
		}

		coderResult, err := coderHandler(ctx, action)
		if err != nil {
			return "", err
		}

		return coderResult, nil
	}, nil
}

func (fp *flowProvider) GetInstallerHandler(ctx context.Context, taskID, subtaskID *int64) (tools.ExecutorHandler, error) {
	ptrTask, ptrSubtask, err := fp.getTaskAndSubtask(ctx, taskID, subtaskID)
	if err != nil {
		return nil, err
	}

	executionContext, err := fp.getExecutionContext(ctx, taskID, subtaskID)
	if err != nil {
		return nil, fmt.Errorf("failed to get execution context: %w", err)
	}

	installerHandler := func(ctx context.Context, action tools.MaintenanceAction) (string, error) {
		if msg := checkDelegationAllowed(ctx, "installer"); msg != "" {
			logrus.WithContext(ctx).WithField("depth", getNestingDepth(ctx)).Warn("installer delegation blocked: " + msg)
			return "", fmt.Errorf("%s", msg)
		}

		installerContext := map[string]map[string]any{
			"user": {
				"Question": action.Question,
			},
			"system": {
				"MaintenanceResultToolName": tools.MaintenanceResultToolName,
				"SearchGuideToolName":       tools.SearchGuideToolName,
				"StoreGuideToolName":        tools.StoreGuideToolName,
				"SearchToolName":            tools.SearchToolName,
				"AdviceToolName":            tools.AdviceToolName,
				"MemoristToolName":          tools.MemoristToolName,
				"SummarizationToolName":     cast.SummarizationToolName,
				"SummarizedContentPrefix":   strings.ReplaceAll(csum.SummarizedContentPrefix, "\n", "\\n"),
				"DockerImage":               fp.image,
				"Cwd":                       docker.WorkFolderPathInContainer,
				"ContainerPorts":            fp.getContainerPortsDescription(),
				"ExecutionContext":          executionContext,
				"Lang":                      fp.language,
				"CurrentTime":               getCurrentTime(),
				"ToolPlaceholder":           ToolPlaceholder,
			},
		}

		installerCtx, observation := obs.Observer.NewObservation(ctx)
		installerEvaluator := observation.Evaluator(
			langfuse.WithEvaluatorName("render installer agent prompts"),
			langfuse.WithEvaluatorInput(installerContext),
			langfuse.WithEvaluatorMetadata(langfuse.Metadata{
				"user_context":   installerContext["user"],
				"system_context": installerContext["system"],
				"task":           ptrTask,
				"subtask":        ptrSubtask,
				"lang":           fp.language,
			}),
		)

		userInstallerTmpl, err := fp.prompter.RenderTemplate(templates.PromptTypeQuestionInstaller, installerContext["user"])
		if err != nil {
			return "", wrapErrorEndEvaluatorSpan(installerCtx, installerEvaluator, "failed to get user installer template", err)
		}

		systemInstallerTmpl, err := fp.prompter.RenderTemplate(templates.PromptTypeInstaller, installerContext["system"])
		if err != nil {
			return "", wrapErrorEndEvaluatorSpan(installerCtx, installerEvaluator, "failed to get system installer template", err)
		}

		installerEvaluator.End(
			langfuse.WithEvaluatorOutput(map[string]any{
				"user_template":   userInstallerTmpl,
				"system_template": systemInstallerTmpl,
			}),
			langfuse.WithEvaluatorStatus("success"),
			langfuse.WithEvaluatorLevel(langfuse.ObservationLevelDebug),
		)

		installerResult, err := fp.performInstaller(ctx, taskID, subtaskID, systemInstallerTmpl, userInstallerTmpl, action.Question)
		if err != nil {
			return "", wrapError(ctx, "failed to get installer result", err)
		}

		return installerResult, nil
	}

	return func(ctx context.Context, name string, args json.RawMessage) (string, error) {
		ctx, span := obs.Observer.NewSpan(ctx, obs.SpanKindInternal, "providers.flowProvider.getInstallerHandler")
		defer span.End()

		var action tools.MaintenanceAction
		if err := json.Unmarshal(args, &action); err != nil {
			logrus.WithContext(ctx).WithError(err).Error("failed to unmarshal installer payload")
			return "", fmt.Errorf("failed to unmarshal installer payload: %w", err)
		}

		installerResult, err := installerHandler(ctx, action)
		if err != nil {
			return "", err
		}

		return installerResult, nil
	}, nil
}

func (fp *flowProvider) GetMemoristHandler(ctx context.Context, taskID, subtaskID *int64) (tools.ExecutorHandler, error) {
	ptrTask, ptrSubtask, err := fp.getTaskAndSubtask(ctx, taskID, subtaskID)
	if err != nil {
		return nil, err
	}

	executionContext, err := fp.getExecutionContext(ctx, taskID, subtaskID)
	if err != nil {
		return nil, fmt.Errorf("failed to get execution context: %w", err)
	}

	memoristHandler := func(ctx context.Context, action tools.MemoristAction) (string, error) {
		executionDetails := ""

		var requestedTask *database.Task
		if action.TaskID != nil && taskID != nil && action.TaskID.Int64() == *taskID {
			executionDetails += fmt.Sprintf("user requested current task '%d'\n", *taskID)
		} else if action.TaskID != nil {
			requestedTaskID := action.TaskID.Int64()
			t, err := fp.db.GetFlowTask(ctx, database.GetFlowTaskParams{
				ID:     requestedTaskID,
				FlowID: fp.flowID,
			})
			if err != nil {
				executionDetails += fmt.Sprintf("failed to get requested task '%d': %s\n", requestedTaskID, err)
			}
			requestedTask = &t
		} else if taskID != nil {
			executionDetails += fmt.Sprintf("user did not specify a task, using current task '%d'\n", *taskID)
		} else {
			executionDetails += "user did not specify a task and no current task is set\n"
		}

		var requestedSubtask *database.Subtask
		if action.SubtaskID != nil && subtaskID != nil && action.SubtaskID.Int64() == *subtaskID {
			executionDetails += fmt.Sprintf("user requested current subtask '%d'\n", *subtaskID)
		} else if action.SubtaskID != nil {
			requestedSubtaskID := action.SubtaskID.Int64()
			st, err := fp.db.GetFlowSubtask(ctx, database.GetFlowSubtaskParams{
				ID:     requestedSubtaskID,
				FlowID: fp.flowID,
			})
			if err != nil {
				executionDetails += fmt.Sprintf("failed to get requested subtask '%d': %s\n", requestedSubtaskID, err)
			}
			requestedSubtask = &st
		} else if subtaskID != nil {
			executionDetails += fmt.Sprintf("user did not specify a subtask, using current subtask '%d'\n", *subtaskID)
		} else {
			executionDetails += "user did not specify a subtask, using all subtasks related to the task\n"
		}

		memoristContext := map[string]map[string]any{
			"user": {
				"Question":         action.Question,
				"Task":             requestedTask,
				"Subtask":          requestedSubtask,
				"ExecutionDetails": executionDetails,
			},
			"system": {
				"MemoristResultToolName":  tools.MemoristResultToolName,
				"GraphitiEnabled":         fp.graphitiClient != nil && fp.graphitiClient.IsEnabled(),
				"GraphitiSearchToolName":  tools.GraphitiSearchToolName,
				"TerminalToolName":        tools.TerminalToolName,
				"FileToolName":            tools.FileToolName,
				"SummarizationToolName":   cast.SummarizationToolName,
				"SummarizedContentPrefix": strings.ReplaceAll(csum.SummarizedContentPrefix, "\n", "\\n"),
				"DockerImage":             fp.image,
				"Cwd":                     docker.WorkFolderPathInContainer,
				"ContainerPorts":          fp.getContainerPortsDescription(),
				"ExecutionContext":        executionContext,
				"Lang":                    fp.language,
				"CurrentTime":             getCurrentTime(),
				"ToolPlaceholder":         ToolPlaceholder,
			},
		}

		memoristCtx, observation := obs.Observer.NewObservation(ctx)
		memoristEvaluator := observation.Evaluator(
			langfuse.WithEvaluatorName("render memorist agent prompts"),
			langfuse.WithEvaluatorInput(memoristContext),
			langfuse.WithEvaluatorMetadata(langfuse.Metadata{
				"user_context":      memoristContext["user"],
				"system_context":    memoristContext["system"],
				"requested_task":    requestedTask,
				"requested_subtask": requestedSubtask,
				"execution_details": executionDetails,
				"task":              ptrTask,
				"subtask":           ptrSubtask,
				"lang":              fp.language,
			}),
		)

		userMemoristTmpl, err := fp.prompter.RenderTemplate(templates.PromptTypeQuestionMemorist, memoristContext["user"])
		if err != nil {
			return "", wrapErrorEndEvaluatorSpan(memoristCtx, memoristEvaluator, "failed to get user memorist template", err)
		}

		systemMemoristTmpl, err := fp.prompter.RenderTemplate(templates.PromptTypeMemorist, memoristContext["system"])
		if err != nil {
			return "", wrapErrorEndEvaluatorSpan(memoristCtx, memoristEvaluator, "failed to get system memorist template", err)
		}

		memoristEvaluator.End(
			langfuse.WithEvaluatorOutput(map[string]any{
				"user_template":   userMemoristTmpl,
				"system_template": systemMemoristTmpl,
			}),
			langfuse.WithEvaluatorStatus("success"),
			langfuse.WithEvaluatorLevel(langfuse.ObservationLevelDebug),
		)

		memoristResult, err := fp.performMemorist(ctx, taskID, subtaskID, systemMemoristTmpl, userMemoristTmpl, action.Question)
		if err != nil {
			logrus.WithContext(ctx).WithError(err).Warn("memorist failed, returning degraded result")
			return "Memory lookup is temporarily unavailable. Please proceed without historical context.", nil
		}

		return memoristResult, nil
	}

	return func(ctx context.Context, name string, args json.RawMessage) (string, error) {
		ctx, span := obs.Observer.NewSpan(ctx, obs.SpanKindInternal, "providers.flowProvider.getMemoristHandler")
		defer span.End()

		var action tools.MemoristAction
		if err := json.Unmarshal(args, &action); err != nil {
			logrus.WithContext(ctx).WithError(err).Error("failed to unmarshal memorist payload")
			return "", fmt.Errorf("failed to unmarshal memorist payload: %w", err)
		}

		memoristResult, err := memoristHandler(ctx, action)
		if err != nil {
			return "", err
		}

		return memoristResult, nil
	}, nil
}

func (fp *flowProvider) GetPentesterHandler(ctx context.Context, taskID, subtaskID *int64) (tools.ExecutorHandler, error) {
	ptrTask, ptrSubtask, err := fp.getTaskAndSubtask(ctx, taskID, subtaskID)
	if err != nil {
		return nil, err
	}

	executionContext, err := fp.getExecutionContext(ctx, taskID, subtaskID)
	if err != nil {
		return nil, fmt.Errorf("failed to get execution context: %w", err)
	}

	pentesterHandler := func(ctx context.Context, action tools.PentesterAction) (string, error) {
		if msg := checkDelegationAllowed(ctx, "pentester"); msg != "" {
			logrus.WithContext(ctx).WithField("depth", getNestingDepth(ctx)).Warn("pentester delegation blocked: " + msg)
			return "", fmt.Errorf("%s", msg)
		}

		// Load persisted execution state for this subtask (if any).
		var subtaskContext string
		if subtaskID != nil {
			if st, err := fp.db.GetSubtask(ctx, *subtaskID); err == nil && st.Context != "" {
				if parsed := ParseExecutionState(st.Context); parsed != nil {
					if j, err := parsed.ToJSON(); err == nil {
						subtaskContext = j
					}
				}
			}
		}

		// Query cross-flow findings to share intelligence between concurrent assessments.
		var crossFlowInsights string
		crossFlowRows, err := fp.db.GetRecentCrossFlowFindings(ctx, fp.flowID)
		if err != nil {
			logrus.WithContext(ctx).WithError(err).Warn("failed to query cross-flow findings, continuing without them")
		} else if len(crossFlowRows) > 0 {
			insights := ExtractCrossFlowInsights(crossFlowRows)
			crossFlowInsights = FormatInsightsForPrompt(insights)
		}

		pentesterContext := map[string]map[string]any{
			"user": {
				"Question": action.Question,
			},
			"system": {
				"HackResultToolName":      tools.HackResultToolName,
				"SearchGuideToolName":     tools.SearchGuideToolName,
				"StoreGuideToolName":      tools.StoreGuideToolName,
				"GraphitiEnabled":         fp.graphitiClient != nil && fp.graphitiClient.IsEnabled(),
				"GraphitiSearchToolName":  tools.GraphitiSearchToolName,
				"InteractshEnabled":       fp.interactshEnabled,
				"InteractshGetURLToolName":  tools.InteractshGetURLToolName,
				"InteractshPollToolName":    tools.InteractshPollToolName,
				"InteractshStatusToolName":  tools.InteractshStatusToolName,
				"AuthStoreEnabled":          fp.authStoreEnabled,
				"AuthLoginToolName":         tools.AuthLoginToolName,
				"AuthStatusToolName":        tools.AuthStatusToolName,
				"AuthInjectToolName":        tools.AuthInjectToolName,
				"AuthRefreshToolName":       tools.AuthRefreshToolName,
				"AuthLogoutToolName":        tools.AuthLogoutToolName,
				"SearchToolName":          tools.SearchToolName,
				"CoderToolName":           tools.CoderToolName,
				"AdviceToolName":          tools.AdviceToolName,
				"MemoristToolName":        tools.MemoristToolName,
				"MaintenanceToolName":     tools.MaintenanceToolName,
				"SummarizationToolName":   cast.SummarizationToolName,
				"SummarizedContentPrefix": strings.ReplaceAll(csum.SummarizedContentPrefix, "\n", "\\n"),
				"IsDefaultDockerImage":    strings.HasPrefix(strings.ToLower(fp.image), pentestDockerImage),
				"DockerImage":             fp.image,
				"Cwd":                     docker.WorkFolderPathInContainer,
				"ContainerPorts":          fp.getContainerPortsDescription(),
				"ExecutionContext":        executionContext,
				"SubtaskContext":          subtaskContext,
				"CrossFlowInsights":      crossFlowInsights,
				"Lang":                    fp.language,
				"CurrentTime":             getCurrentTime(),
				"ToolPlaceholder":         ToolPlaceholder,
				"ExecutionMetrics":        &ExecutionMetrics{}, // zero-valued; refreshed in agent loop
			},
		}

		pentesterCtx, observation := obs.Observer.NewObservation(ctx)
		pentesterEvaluator := observation.Evaluator(
			langfuse.WithEvaluatorName("render pentester agent prompts"),
			langfuse.WithEvaluatorInput(pentesterContext),
			langfuse.WithEvaluatorMetadata(langfuse.Metadata{
				"user_context":   pentesterContext["user"],
				"system_context": pentesterContext["system"],
				"task":           ptrTask,
				"subtask":        ptrSubtask,
				"lang":           fp.language,
			}),
		)

		userPentesterTmpl, err := fp.prompter.RenderTemplate(templates.PromptTypeQuestionPentester, pentesterContext["user"])
		if err != nil {
			return "", wrapErrorEndEvaluatorSpan(pentesterCtx, pentesterEvaluator, "failed to get user pentester template", err)
		}

		systemPentesterTmpl, err := fp.prompter.RenderTemplate(templates.PromptTypePentester, pentesterContext["system"])
		if err != nil {
			return "", wrapErrorEndEvaluatorSpan(pentesterCtx, pentesterEvaluator, "failed to get system pentester template", err)
		}

		pentesterEvaluator.End(
			langfuse.WithEvaluatorOutput(map[string]any{
				"user_template":   userPentesterTmpl,
				"system_template": systemPentesterTmpl,
			}),
			langfuse.WithEvaluatorStatus("success"),
			langfuse.WithEvaluatorLevel(langfuse.ObservationLevelDebug),
		)

		pentesterResult, err := fp.performPentester(ctx, taskID, subtaskID, systemPentesterTmpl, userPentesterTmpl, action.Question)
		if err != nil {
			return "", wrapError(ctx, "failed to get pentester result", err)
		}

		return pentesterResult, nil
	}

	return func(ctx context.Context, name string, args json.RawMessage) (string, error) {
		ctx, span := obs.Observer.NewSpan(ctx, obs.SpanKindInternal, "providers.flowProvider.getPentesterHandler")
		defer span.End()

		var action tools.PentesterAction
		if err := json.Unmarshal(args, &action); err != nil {
			logrus.WithContext(ctx).WithError(err).Error("failed to unmarshal pentester payload")
			return "", fmt.Errorf("failed to unmarshal pentester payload: %w", err)
		}

		pentesterResult, err := pentesterHandler(ctx, action)
		if err != nil {
			return "", err
		}

		return pentesterResult, nil
	}, nil
}

func (fp *flowProvider) GetSubtaskSearcherHandler(ctx context.Context, taskID, subtaskID *int64) (tools.ExecutorHandler, error) {
	ptrTask, ptrSubtask, err := fp.getTaskAndSubtask(ctx, taskID, subtaskID)
	if err != nil {
		return nil, err
	}

	executionContext, err := fp.getExecutionContext(ctx, taskID, subtaskID)
	if err != nil {
		return nil, fmt.Errorf("failed to get execution context: %w", err)
	}

	searcherHandler := func(ctx context.Context, search tools.ComplexSearch) (string, error) {
		searcherContext := map[string]map[string]any{
			"user": {
				"Question": search.Question,
				"Task":     ptrTask,
				"Subtask":  ptrSubtask,
			},
			"system": {
				"SearchResultToolName":    tools.SearchResultToolName,
				"SearchAnswerToolName":    tools.SearchAnswerToolName,
				"StoreAnswerToolName":     tools.StoreAnswerToolName,
				"SummarizationToolName":   cast.SummarizationToolName,
				"SummarizedContentPrefix": strings.ReplaceAll(csum.SummarizedContentPrefix, "\n", "\\n"),
				"ExecutionContext":        executionContext,
				"Lang":                    fp.language,
				"CurrentTime":             getCurrentTime(),
				"ToolPlaceholder":         ToolPlaceholder,
			},
		}

		searcherCtx, observation := obs.Observer.NewObservation(ctx)
		searcherEvaluator := observation.Evaluator(
			langfuse.WithEvaluatorName("render searcher agent prompts"),
			langfuse.WithEvaluatorInput(searcherContext),
			langfuse.WithEvaluatorMetadata(langfuse.Metadata{
				"user_context":   searcherContext["user"],
				"system_context": searcherContext["system"],
				"task":           ptrTask,
				"subtask":        ptrSubtask,
				"lang":           fp.language,
			}),
		)

		userSearcherTmpl, err := fp.prompter.RenderTemplate(templates.PromptTypeQuestionSearcher, searcherContext["user"])
		if err != nil {
			return "", wrapErrorEndEvaluatorSpan(searcherCtx, searcherEvaluator, "failed to get user searcher template", err)
		}

		systemSearcherTmpl, err := fp.prompter.RenderTemplate(templates.PromptTypeSearcher, searcherContext["system"])
		if err != nil {
			return "", wrapErrorEndEvaluatorSpan(searcherCtx, searcherEvaluator, "failed to get system searcher template", err)
		}

		searcherEvaluator.End(
			langfuse.WithEvaluatorOutput(map[string]any{
				"user_template":   userSearcherTmpl,
				"system_template": systemSearcherTmpl,
			}),
			langfuse.WithEvaluatorStatus("success"),
			langfuse.WithEvaluatorLevel(langfuse.ObservationLevelDebug),
		)

		searcherResult, err := fp.performSearcher(ctx, taskID, subtaskID, systemSearcherTmpl, userSearcherTmpl, search.Question)
		if err != nil {
			return "", wrapError(ctx, "failed to get searcher result", err)
		}

		return searcherResult, nil
	}

	return func(ctx context.Context, name string, args json.RawMessage) (string, error) {
		ctx, span := obs.Observer.NewSpan(ctx, obs.SpanKindInternal, "providers.flowProvider.getSubtaskSearcherHandler")
		defer span.End()

		var search tools.ComplexSearch
		if err := json.Unmarshal(args, &search); err != nil {
			logrus.WithContext(ctx).WithError(err).Error("failed to unmarshal search payload")
			return "", fmt.Errorf("failed to unmarshal search payload: %w", err)
		}

		searcherResult, err := searcherHandler(ctx, search)
		if err != nil {
			return "", err
		}

		return searcherResult, nil
	}, nil
}

func (fp *flowProvider) GetTaskSearcherHandler(ctx context.Context, taskID int64) (tools.ExecutorHandler, error) {
	task, err := fp.db.GetTask(ctx, taskID)
	if err != nil {
		return nil, fmt.Errorf("failed to get task: %w", err)
	}

	executionContext, err := fp.getExecutionContext(ctx, &taskID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get execution context: %w", err)
	}

	searcherHandler := func(ctx context.Context, search tools.ComplexSearch) (string, error) {
		searcherContext := map[string]map[string]any{
			"user": {
				"Question": search.Question,
				"Task":     task,
			},
			"system": {
				"SearchResultToolName":    tools.SearchResultToolName,
				"SearchAnswerToolName":    tools.SearchAnswerToolName,
				"StoreAnswerToolName":     tools.StoreAnswerToolName,
				"SummarizationToolName":   cast.SummarizationToolName,
				"SummarizedContentPrefix": strings.ReplaceAll(csum.SummarizedContentPrefix, "\n", "\\n"),
				"ExecutionContext":        executionContext,
				"Lang":                    fp.language,
				"CurrentTime":             getCurrentTime(),
				"ToolPlaceholder":         ToolPlaceholder,
			},
		}

		searcherCtx, observation := obs.Observer.NewObservation(ctx)
		searcherEvaluator := observation.Evaluator(
			langfuse.WithEvaluatorName("render searcher agent prompts"),
			langfuse.WithEvaluatorInput(searcherContext),
			langfuse.WithEvaluatorMetadata(langfuse.Metadata{
				"user_context":   searcherContext["user"],
				"system_context": searcherContext["system"],
				"task":           task,
				"lang":           fp.language,
			}),
		)

		userSearcherTmpl, err := fp.prompter.RenderTemplate(templates.PromptTypeQuestionSearcher, searcherContext["user"])
		if err != nil {
			return "", wrapErrorEndEvaluatorSpan(searcherCtx, searcherEvaluator, "failed to get user searcher template", err)
		}

		systemSearcherTmpl, err := fp.prompter.RenderTemplate(templates.PromptTypeSearcher, searcherContext["system"])
		if err != nil {
			return "", wrapErrorEndEvaluatorSpan(searcherCtx, searcherEvaluator, "failed to get system searcher template", err)
		}

		searcherEvaluator.End(
			langfuse.WithEvaluatorOutput(map[string]any{
				"user_template":   userSearcherTmpl,
				"system_template": systemSearcherTmpl,
			}),
			langfuse.WithEvaluatorStatus("success"),
			langfuse.WithEvaluatorLevel(langfuse.ObservationLevelDebug),
		)

		searcherResult, err := fp.performSearcher(ctx, &taskID, nil, systemSearcherTmpl, userSearcherTmpl, search.Question)
		if err != nil {
			return "", wrapError(ctx, "failed to get searcher result", err)
		}

		return searcherResult, nil
	}

	return func(ctx context.Context, name string, args json.RawMessage) (string, error) {
		ctx, span := obs.Observer.NewSpan(ctx, obs.SpanKindInternal, "providers.flowProvider.getTaskSearcherHandler")
		defer span.End()

		var search tools.ComplexSearch
		if err := json.Unmarshal(args, &search); err != nil {
			logrus.WithContext(ctx).WithError(err).Error("failed to unmarshal search payload")
			return "", fmt.Errorf("failed to unmarshal search payload: %w", err)
		}

		searcherResult, err := searcherHandler(ctx, search)
		if err != nil {
			return "", err
		}

		return searcherResult, nil
	}, nil
}

func (fp *flowProvider) GetSummarizeResultHandler(taskID, subtaskID *int64) tools.SummarizeHandler {
	return func(ctx context.Context, result string) (string, error) {
		ctx, span := obs.Observer.NewSpan(ctx, obs.SpanKindInternal, "providers.flowProvider.getSummarizeResultHandler")
		defer span.End()

		ctx, observation := obs.Observer.NewObservation(ctx)
		summarizerAgent := observation.Agent(
			langfuse.WithAgentName("chain summarizer"),
			langfuse.WithAgentInput(result),
			langfuse.WithAgentMetadata(langfuse.Metadata{
				"task_id":    taskID,
				"subtask_id": subtaskID,
				"lang":       fp.language,
			}),
		)
		ctx, _ = summarizerAgent.Observation(ctx)

		systemSummarizerTmpl, err := fp.prompter.RenderTemplate(templates.PromptTypeSummarizer, map[string]any{
			"TaskID":                  taskID,
			"SubtaskID":               subtaskID,
			"CurrentTime":             getCurrentTime(),
			"SummarizedContentPrefix": strings.ReplaceAll(csum.SummarizedContentPrefix, "\n", "\\n"),
		})
		if err != nil {
			return "", wrapErrorEndAgentSpan(ctx, summarizerAgent, "failed to get summarizer template", err)
		}

		// Context-aware content preservation: extract findings/critical content
		// before applying size-based truncation. Findings must NEVER be lost.
		findingsBlock := ExtractFindings(result)

		// Preserve beginning, middle samples, and end to avoid silently dropping important content
		if len(result) > 2*msgSummarizerLimit {
			chunkSize := msgSummarizerLimit / 2
			totalBudget := 2 * msgSummarizerLimit

			// Reserve space for findings block if present
			findingsOverhead := len(findingsBlock)
			if findingsOverhead > 0 {
				// Reduce available budget for head/middle/tail to make room for findings
				totalBudget = max(totalBudget-findingsOverhead, msgSummarizerLimit)
				chunkSize = totalBudget / 4
			}

			// Always keep the first and last chunk
			head := result[:min(chunkSize, len(result))]
			tail := result[max(len(result)-chunkSize, 0):]

			// Sample from the middle to fill remaining budget
			middleBudget := totalBudget - 2*chunkSize
			middleStart := chunkSize
			middleEnd := len(result) - chunkSize
			middleLen := middleEnd - middleStart

			var middle string
			if middleBudget > 0 && middleLen > 0 {
				if middleLen <= middleBudget {
					middle = result[middleStart:middleEnd]
				} else {
					// Take evenly spaced samples from the middle
					numSamples := 3
					sampleSize := middleBudget / numSamples
					var samples []string
					for i := 0; i < numSamples; i++ {
						offset := middleStart + (middleLen*i)/numSamples
						end := offset + sampleSize
						if end > middleEnd {
							end = middleEnd
						}
						samples = append(samples, result[offset:end])
					}
					middle = strings.Join(samples, "\n\n{...}\n\n")
				}
			}

			truncated := head +
				"\n\n{SAMPLED_MIDDLE}...\n\n" +
				middle +
				"\n\n{...END_SECTION}...\n\n" +
				tail

			// Prepend preserved findings so the LLM summarizer always sees them
			if findingsBlock != "" {
				truncated = "{PRESERVED_FINDINGS}\n" + findingsBlock + "\n{END_PRESERVED_FINDINGS}\n\n" + truncated
			}

			result = database.SanitizeUTF8(truncated)
		}

		opt := pconfig.OptionsTypeSimple
		msgChainType := database.MsgchainTypeSummarizer
		summary, err := fp.performSimpleChain(ctx, taskID, subtaskID, opt, msgChainType, systemSummarizerTmpl, result)
		if err != nil {
			return "", wrapErrorEndAgentSpan(ctx, summarizerAgent, "failed to get summary", err)
		}

		summary = database.SanitizeUTF8(summary)
		summarizerAgent.End(
			langfuse.WithAgentStatus("success"),
			langfuse.WithAgentOutput(summary),
			langfuse.WithAgentLevel(langfuse.ObservationLevelDebug),
		)

		return summary, nil
	}
}

func (fp *flowProvider) fixToolCallArgs(
	ctx context.Context,
	funcName string,
	funcArgs json.RawMessage,
	funcSchema *schema.Schema,
	funcExecErr error,
) (json.RawMessage, error) {
	ctx, span := obs.Observer.NewSpan(ctx, obs.SpanKindInternal, "providers.flowProvider.fixToolCallArgsHandler")
	defer span.End()

	funcJsonSchema, err := json.Marshal(funcSchema)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal tool call schema: %w", err)
	}

	ctx, observation := obs.Observer.NewObservation(ctx)
	toolCallFixerAgent := observation.Agent(
		langfuse.WithAgentName("tool call fixer"),
		langfuse.WithAgentInput(string(funcArgs)),
		langfuse.WithAgentMetadata(langfuse.Metadata{
			"func_name":     funcName,
			"func_schema":   string(funcJsonSchema),
			"func_exec_err": funcExecErr.Error(),
		}),
	)
	ctx, _ = toolCallFixerAgent.Observation(ctx)

	userToolCallFixerTmpl, err := fp.prompter.RenderTemplate(templates.PromptTypeInputToolCallFixer, map[string]any{
		"ToolCallName":   funcName,
		"ToolCallArgs":   string(funcArgs),
		"ToolCallSchema": string(funcJsonSchema),
		"ToolCallError":  funcExecErr.Error(),
	})
	if err != nil {
		return nil, wrapErrorEndAgentSpan(ctx, toolCallFixerAgent, "failed to get user tool call fixer template", err)
	}

	systemToolCallFixerTmpl, err := fp.prompter.RenderTemplate(templates.PromptTypeToolCallFixer, map[string]any{})
	if err != nil {
		return nil, wrapErrorEndAgentSpan(ctx, toolCallFixerAgent, "failed to get system tool call fixer template", err)
	}

	opt := pconfig.OptionsTypeSimpleJSON
	msgChainType := database.MsgchainTypeToolCallFixer
	toolCallFixerResult, err := fp.performSimpleChain(ctx, nil, nil, opt, msgChainType, systemToolCallFixerTmpl, userToolCallFixerTmpl)
	if err != nil {
		return nil, wrapErrorEndAgentSpan(ctx, toolCallFixerAgent, "failed to get tool call fixer result", err)
	}

	// Validate that the fixer produced valid JSON before returning
	var fixedArgs map[string]any
	if err := json.Unmarshal([]byte(toolCallFixerResult), &fixedArgs); err != nil {
		toolCallFixerAgent.End(
			langfuse.WithAgentStatus("invalid_json"),
			langfuse.WithAgentOutput(toolCallFixerResult),
			langfuse.WithAgentLevel(langfuse.ObservationLevelWarning),
		)
		return nil, fmt.Errorf("tool call fixer produced invalid JSON: %w", err)
	}

	toolCallFixerAgent.End(
		langfuse.WithAgentStatus("success"),
		langfuse.WithAgentOutput(toolCallFixerResult),
		langfuse.WithAgentLevel(langfuse.ObservationLevelDebug),
	)

	return json.RawMessage(toolCallFixerResult), nil
}
