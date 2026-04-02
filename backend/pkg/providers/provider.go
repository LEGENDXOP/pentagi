package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"pentagi/pkg/cast"
	"pentagi/pkg/csum"
	"pentagi/pkg/database"
	"pentagi/pkg/docker"
	"pentagi/pkg/graphiti"
	obs "pentagi/pkg/observability"
	"pentagi/pkg/observability/langfuse"
	"pentagi/pkg/providers/embeddings"
	"pentagi/pkg/providers/pconfig"
	"pentagi/pkg/providers/provider"
	"pentagi/pkg/templates"
	"pentagi/pkg/tools"

	"github.com/sirupsen/logrus"
	"github.com/vxcontrol/langchaingo/llms"
	"github.com/vxcontrol/langchaingo/llms/reasoning"
	"github.com/vxcontrol/langchaingo/llms/streaming"
)

// FlowControlCheckpoint is a function called at each iteration of the agent loop.
// It returns a steer message (if any) and an error if the flow was aborted.
// The function blocks while the flow is paused.
type FlowControlCheckpoint func(ctx context.Context, flowID int64) (steerMessage string, err error)

const ToolPlaceholder = "Always use your function calling functionality, instead of returning a text result."

const TasksNumberLimit = 15

const (
	msgGeneratorSizeLimit = 150 * 1024 // 150 KB
	msgRefinerSizeLimit   = 100 * 1024 // 100 KB
	msgReporterSizeLimit  = 100 * 1024 // 100 KB
	msgSummarizerLimit    = 16 * 1024  // 16 KB
)

const textTruncateMessage = "\n\n[...truncated]"

type PerformResult int

const (
	PerformResultError PerformResult = iota
	PerformResultWaiting
	PerformResultDone
)

type StreamMessageChunkType streaming.ChunkType

const (
	StreamMessageChunkTypeThinking StreamMessageChunkType = "thinking"
	StreamMessageChunkTypeContent  StreamMessageChunkType = "content"
	StreamMessageChunkTypeResult   StreamMessageChunkType = "result"
	StreamMessageChunkTypeFlush    StreamMessageChunkType = "flush"
	StreamMessageChunkTypeUpdate   StreamMessageChunkType = "update"
)

type StreamMessageChunk struct {
	Type         StreamMessageChunkType
	MsgType      database.MsglogType
	Content      string
	Thinking     *reasoning.ContentReasoning
	Result       string
	ResultFormat database.MsglogResultFormat
	StreamID     int64
}

type StreamMessageHandler func(ctx context.Context, chunk *StreamMessageChunk) error

type FlowProvider interface {
	ID() int64
	DB() database.Querier
	Type() provider.ProviderType
	Model(opt pconfig.ProviderOptionsType) string
	Image() string
	Title() string
	Language() string
	ToolCallIDTemplate() string
	Embedder() embeddings.Embedder
	Executor() tools.FlowToolsExecutor
	Prompter() templates.Prompter

	SetTitle(title string)
	SetAgentLogProvider(agentLog tools.AgentLogProvider)
	SetMsgLogProvider(msgLog tools.MsgLogProvider)
	SetFlowControlCheckpoint(checkpoint FlowControlCheckpoint)

	GetTaskTitle(ctx context.Context, input string) (string, error)
	GenerateSubtasks(ctx context.Context, taskID int64) ([]tools.SubtaskInfo, error)
	RefineSubtasks(ctx context.Context, taskID int64) ([]tools.SubtaskInfo, error)
	GetTaskResult(ctx context.Context, taskID int64) (*tools.TaskResult, error)

	PrepareAgentChain(ctx context.Context, taskID, subtaskID int64) (int64, error)
	PerformAgentChain(ctx context.Context, taskID, subtaskID, msgChainID int64) (PerformResult, error)
	PutInputToAgentChain(ctx context.Context, msgChainID int64, input string) error
	EnsureChainConsistency(ctx context.Context, msgChainID int64) error

	FlowProviderHandlers
}

type FlowProviderHandlers interface {
	GetAskAdviceHandler(ctx context.Context, taskID, subtaskID *int64) (tools.ExecutorHandler, error)
	GetCoderHandler(ctx context.Context, taskID, subtaskID *int64) (tools.ExecutorHandler, error)
	GetInstallerHandler(ctx context.Context, taskID, subtaskID *int64) (tools.ExecutorHandler, error)
	GetMemoristHandler(ctx context.Context, taskID, subtaskID *int64) (tools.ExecutorHandler, error)
	GetPentesterHandler(ctx context.Context, taskID, subtaskID *int64) (tools.ExecutorHandler, error)
	GetSubtaskSearcherHandler(ctx context.Context, taskID, subtaskID *int64) (tools.ExecutorHandler, error)
	GetTaskSearcherHandler(ctx context.Context, taskID int64) (tools.ExecutorHandler, error)
	GetSummarizeResultHandler(taskID, subtaskID *int64) tools.SummarizeHandler
}

// memoristBreaker tracks consecutive memorist unavailability responses at the
// flow level. Unlike the GraphitiAvailability tracker (which prevents the memorist
// agent chain from starting), this operates at the CALLING AGENT level — it
// prevents the LLM from even invoking the memorist tool after repeated failures.
//
// Thread-safe via atomic operations. Shared across all subtasks within a flow.
type memoristBreaker struct {
	consecutiveFails atomic.Int32
	disabled         atomic.Bool
	disabledAt       atomic.Int64 // unix timestamp
	reopenAfter      time.Duration
}

const (
	memoristBreakerThreshold   = 2
	memoristBreakerReopenAfter = 10 * time.Minute
	memoristBreakerMessage     = "⚡ Memorist service unavailable — skipped (circuit breaker). " +
		"The memory/knowledge graph service has been down for this entire flow. " +
		"This tool call was blocked BEFORE execution to save time. " +
		"Do NOT call memorist again — use other tools and available context instead."
)

func newMemoristBreaker(reopenAfter time.Duration) *memoristBreaker {
	return &memoristBreaker{
		reopenAfter: reopenAfter,
	}
}

// shouldBlock returns true if the memorist tool call should be short-circuited.
func (mb *memoristBreaker) shouldBlock() bool {
	if !mb.disabled.Load() {
		return false
	}
	// Half-open: allow one probe after reopenAfter elapses
	disabledAt := time.Unix(mb.disabledAt.Load(), 0)
	if time.Since(disabledAt) >= mb.reopenAfter {
		// Allow one probe — reset disabled temporarily
		// If the probe fails, recordFailure will re-disable
		mb.disabled.Store(false)
		mb.consecutiveFails.Store(0)
		logrus.WithFields(logrus.Fields{
			"component":    "memorist_breaker",
			"reopen_after": mb.reopenAfter,
		}).Info("memorist breaker half-open — allowing probe request")
		return false
	}
	return true
}

// recordFailure increments the failure counter and trips the breaker if threshold reached.
func (mb *memoristBreaker) recordFailure() {
	count := mb.consecutiveFails.Add(1)
	if count >= int32(memoristBreakerThreshold) && !mb.disabled.Load() {
		mb.disabled.Store(true)
		mb.disabledAt.Store(time.Now().Unix())
		logrus.WithFields(logrus.Fields{
			"component":         "memorist_breaker",
			"consecutive_fails": count,
			"threshold":         memoristBreakerThreshold,
		}).Warn("memorist breaker TRIPPED — blocking all memorist calls for this flow")
	}
}

// recordSuccess resets the breaker (e.g., after a successful half-open probe).
func (mb *memoristBreaker) recordSuccess() {
	wasDisabled := mb.disabled.Load()
	mb.consecutiveFails.Store(0)
	mb.disabled.Store(false)
	if wasDisabled {
		logrus.WithField("component", "memorist_breaker").
			Info("memorist breaker RECOVERED — re-enabling memorist calls")
	}
}

// isUnavailableResponse checks if a memorist response indicates the service is down.
func isUnavailableResponse(response string) bool {
	return strings.Contains(response, "currently unavailable") ||
		strings.Contains(response, "temporarily unavailable") ||
		strings.Contains(response, "service is currently unavailable") ||
		strings.Contains(response, "UNREACHABLE")
}

type tasksInfo struct {
	Task     database.Task
	Tasks    []database.Task
	Subtasks []database.Subtask
}

type subtasksInfo struct {
	Subtask   *database.Subtask
	Planned   []database.Subtask
	Completed []database.Subtask
}

type flowProvider struct {
	db database.Querier
	mx *sync.RWMutex

	embedder          embeddings.Embedder
	graphitiClient    *graphiti.Client
	interactshEnabled bool
	authStoreEnabled  bool

	flowID   int64
	publicIP string

	callCounter *atomic.Int64

	// v14: Flow-level memorist circuit breaker — prevents LLMs from calling
	// memorist after repeated failures. See memoristBreaker doc.
	memoristCB *memoristBreaker

	image    string
	title    string
	language string
	askUser  bool

	tcIDTemplate string

	prompter     templates.Prompter
	executor     tools.FlowToolsExecutor
	agentLog     tools.AgentLogProvider
	msgLog       tools.MsgLogProvider
	streamCb     StreamMessageHandler
	flowControl  FlowControlCheckpoint

	summarizer csum.Summarizer

	provider.Provider
}

func (fp *flowProvider) SetFlowControlCheckpoint(checkpoint FlowControlCheckpoint) {
	fp.mx.Lock()
	defer fp.mx.Unlock()

	fp.flowControl = checkpoint
}

func (fp *flowProvider) SetAgentLogProvider(agentLog tools.AgentLogProvider) {
	fp.mx.Lock()
	defer fp.mx.Unlock()

	fp.agentLog = agentLog
}

func (fp *flowProvider) SetMsgLogProvider(msgLog tools.MsgLogProvider) {
	fp.mx.Lock()
	defer fp.mx.Unlock()

	fp.msgLog = msgLog
}

func (fp *flowProvider) ID() int64 {
	fp.mx.RLock()
	defer fp.mx.RUnlock()

	return fp.flowID
}

func (fp *flowProvider) DB() database.Querier {
	fp.mx.RLock()
	defer fp.mx.RUnlock()

	return fp.db
}

func (fp *flowProvider) Image() string {
	fp.mx.RLock()
	defer fp.mx.RUnlock()

	return fp.image
}

func (fp *flowProvider) Title() string {
	fp.mx.RLock()
	defer fp.mx.RUnlock()

	return fp.title
}

func (fp *flowProvider) SetTitle(title string) {
	fp.mx.Lock()
	defer fp.mx.Unlock()

	fp.title = title
}

func (fp *flowProvider) Language() string {
	fp.mx.RLock()
	defer fp.mx.RUnlock()

	return fp.language
}

func (fp *flowProvider) ToolCallIDTemplate() string {
	fp.mx.RLock()
	defer fp.mx.RUnlock()

	return fp.tcIDTemplate
}

func (fp *flowProvider) Embedder() embeddings.Embedder {
	fp.mx.RLock()
	defer fp.mx.RUnlock()

	return fp.embedder
}

func (fp *flowProvider) Executor() tools.FlowToolsExecutor {
	fp.mx.RLock()
	defer fp.mx.RUnlock()

	return fp.executor
}

func (fp *flowProvider) Prompter() templates.Prompter {
	fp.mx.RLock()
	defer fp.mx.RUnlock()

	return fp.prompter
}

func (fp *flowProvider) GetTaskTitle(ctx context.Context, input string) (string, error) {
	ctx, span := obs.Observer.NewSpan(ctx, obs.SpanKindInternal, "providers.flowProvider.GetTaskTitle")
	defer span.End()

	ctx, observation := obs.Observer.NewObservation(ctx)
	getterEvaluator := observation.Evaluator(
		langfuse.WithEvaluatorName("get task title"),
		langfuse.WithEvaluatorInput(input),
		langfuse.WithEvaluatorMetadata(langfuse.Metadata{
			"lang": fp.language,
		}),
	)
	ctx, _ = getterEvaluator.Observation(ctx)

	titleTmpl, err := fp.prompter.RenderTemplate(templates.PromptTypeTaskDescriptor, map[string]any{
		"Input":       input,
		"Lang":        fp.language,
		"CurrentTime": getCurrentTime(),
		"N":           150,
	})
	if err != nil {
		return "", wrapErrorEndEvaluatorSpan(ctx, getterEvaluator, "failed to get flow title template", err)
	}

	title, err := fp.Call(ctx, pconfig.OptionsTypeSimple, titleTmpl)
	if err != nil {
		return "", wrapErrorEndEvaluatorSpan(ctx, getterEvaluator, "failed to get flow title", err)
	}

	getterEvaluator.End(
		langfuse.WithEvaluatorStatus("success"),
		langfuse.WithEvaluatorOutput(title),
	)

	return title, nil
}

func (fp *flowProvider) GenerateSubtasks(ctx context.Context, taskID int64) ([]tools.SubtaskInfo, error) {
	ctx, span := obs.Observer.NewSpan(ctx, obs.SpanKindInternal, "providers.flowProvider.GenerateSubtasks")
	defer span.End()

	logger := logrus.WithContext(ctx).WithField("task_id", taskID)

	tasksInfo, err := fp.getTasksInfo(ctx, taskID)
	if err != nil {
		logger.WithError(err).Error("failed to get tasks info")
		return nil, fmt.Errorf("failed to get tasks info: %w", err)
	}

	// Collect workspace files so the generator knows what already exists in /work/
	var workspaceFiles []tools.FileInfo
	if files, err := fp.executor.ListWorkspaceFiles(ctx); err != nil {
		logger.WithError(err).Warn("failed to list workspace files for generator context, continuing without them")
	} else {
		workspaceFiles = files
	}

	// Render the strategy planner template to inject budget awareness into subtask generation.
	budgetCfg := LoadAttackBudgetConfigFromEnv()
	strategyContext, strategyErr := RenderStrategyPlanner(fp.prompter, tasksInfo.Task.Input, budgetCfg)
	if strategyErr != nil {
		logger.WithError(strategyErr).Warn("failed to render strategy planner template, continuing without it")
		strategyContext = ""
	}

	generatorContext := map[string]map[string]any{
		"user": {
			"Task":           tasksInfo.Task,
			"Tasks":          tasksInfo.Tasks,
			"Subtasks":       tasksInfo.Subtasks,
			"WorkspaceFiles": workspaceFiles,
			"Cwd":            docker.WorkFolderPathInContainer,
		},
		"system": {
			"SubtaskListToolName":     tools.SubtaskListToolName,
			"SearchToolName":          tools.SearchToolName,
			"TerminalToolName":        tools.TerminalToolName,
			"FileToolName":            tools.FileToolName,
			"BrowserToolName":         tools.BrowserToolName,
			"SummarizationToolName":   cast.SummarizationToolName,
			"SummarizedContentPrefix": strings.ReplaceAll(csum.SummarizedContentPrefix, "\n", "\\n"),
			"DockerImage":             fp.image,
			"Lang":                    fp.language,
			"CurrentTime":             getCurrentTime(),
			"N":                       TasksNumberLimit,
			"ToolPlaceholder":         ToolPlaceholder,
		},
	}

	// Inject strategy planner context into the user context for budget-aware subtask generation.
	if strategyContext != "" {
		generatorContext["user"]["ExecutionState"] = strategyContext
	}

	// Sprint 3: Inject methodology coverage into generator if available.
	if mc := GetMethodologyCoverage(ctx); mc != nil {
		if coverage := mc.FormatCoverageForGenerator(); coverage != "" {
			generatorContext["user"]["MethodologyCoverage"] = coverage
		}
	}

	ctx, observation := obs.Observer.NewObservation(ctx)
	generatorEvaluator := observation.Evaluator(
		langfuse.WithEvaluatorName("subtasks generator"),
		langfuse.WithEvaluatorInput(tasksInfo),
		langfuse.WithEvaluatorMetadata(langfuse.Metadata{
			"user_context":   generatorContext["user"],
			"system_context": generatorContext["system"],
		}),
	)
	ctx, _ = generatorEvaluator.Observation(ctx)

	generatorTmpl, err := fp.prompter.RenderTemplate(templates.PromptTypeSubtasksGenerator, generatorContext["user"])
	if err != nil {
		return nil, wrapErrorEndEvaluatorSpan(ctx, generatorEvaluator, "failed to get task generator template", err)
	}

	subtasksLen := len(tasksInfo.Subtasks)
	for l := subtasksLen; l > 2; l /= 2 {
		if len(generatorTmpl) < msgGeneratorSizeLimit {
			break
		}

		generatorContext["user"]["Subtasks"] = tasksInfo.Subtasks[(subtasksLen - l):]
		generatorTmpl, err = fp.prompter.RenderTemplate(templates.PromptTypeSubtasksGenerator, generatorContext["user"])
		if err != nil {
			return nil, wrapErrorEndEvaluatorSpan(ctx, generatorEvaluator, "failed to get task generator template", err)
		}
	}

	systemGeneratorTmpl, err := fp.prompter.RenderTemplate(templates.PromptTypeGenerator, generatorContext["system"])
	if err != nil {
		return nil, wrapErrorEndEvaluatorSpan(ctx, generatorEvaluator, "failed to get task system generator template", err)
	}

	subtasks, err := fp.performSubtasksGenerator(ctx, taskID, systemGeneratorTmpl, generatorTmpl, tasksInfo.Task.Input)
	if err != nil {
		return nil, wrapErrorEndEvaluatorSpan(ctx, generatorEvaluator, "failed to perform subtasks generator", err)
	}

	generatorEvaluator.End(
		langfuse.WithEvaluatorStatus("success"),
		langfuse.WithEvaluatorOutput(subtasks),
	)

	return subtasks, nil
}

func (fp *flowProvider) RefineSubtasks(ctx context.Context, taskID int64) ([]tools.SubtaskInfo, error) {
	ctx, span := obs.Observer.NewSpan(ctx, obs.SpanKindInternal, "providers.flowProvider.RefineSubtasks")
	defer span.End()

	logger := logrus.WithContext(ctx).WithField("task_id", taskID)

	tasksInfo, err := fp.getTasksInfo(ctx, taskID)
	if err != nil {
		logger.WithError(err).Error("failed to get tasks info")
		return nil, fmt.Errorf("failed to get tasks info: %w", err)
	}

	subtasksInfo := fp.getSubtasksInfo(taskID, tasksInfo.Subtasks)

	logger.WithFields(logrus.Fields{
		"planned_count":   len(subtasksInfo.Planned),
		"completed_count": len(subtasksInfo.Completed),
	}).Debug("retrieved subtasks info for refinement")

	// Collect workspace files so the refiner knows what already exists in /work/
	var workspaceFiles []tools.FileInfo
	if files, err := fp.executor.ListWorkspaceFiles(ctx); err != nil {
		logger.WithError(err).Warn("failed to list workspace files for refiner context, continuing without them")
	} else {
		workspaceFiles = files
	}

	refinerContext := map[string]map[string]any{
		"user": {
			"Task":              tasksInfo.Task,
			"Tasks":             tasksInfo.Tasks,
			"PlannedSubtasks":   subtasksInfo.Planned,
			"CompletedSubtasks": subtasksInfo.Completed,
			"WorkspaceFiles":    workspaceFiles,
		},
		"system": {
			"SubtaskPatchToolName":    tools.SubtaskPatchToolName,
			"SubtaskListToolName":     tools.SubtaskListToolName,
			"SearchToolName":          tools.SearchToolName,
			"TerminalToolName":        tools.TerminalToolName,
			"FileToolName":            tools.FileToolName,
			"BrowserToolName":         tools.BrowserToolName,
			"SummarizationToolName":   cast.SummarizationToolName,
			"SummarizedContentPrefix": strings.ReplaceAll(csum.SummarizedContentPrefix, "\n", "\\n"),
			"DockerImage":             fp.image,
			"Lang":                    fp.language,
			"CurrentTime":             getCurrentTime(),
			"N":                       max(TasksNumberLimit-len(subtasksInfo.Completed), 0),
			"ToolPlaceholder":         ToolPlaceholder,
		},
	}

	ctx, observation := obs.Observer.NewObservation(ctx)
	refinerEvaluator := observation.Evaluator(
		langfuse.WithEvaluatorName("subtasks refiner"),
		langfuse.WithEvaluatorInput(refinerContext),
		langfuse.WithEvaluatorMetadata(langfuse.Metadata{
			"user_context":   refinerContext["user"],
			"system_context": refinerContext["system"],
		}),
	)
	ctx, _ = refinerEvaluator.Observation(ctx)

	refinerTmpl, err := fp.prompter.RenderTemplate(templates.PromptTypeSubtasksRefiner, refinerContext["user"])
	if err != nil {
		return nil, wrapErrorEndEvaluatorSpan(ctx, refinerEvaluator, "failed to get task subtasks refiner template (1)", err)
	}

	// TODO: here need to store it in the database and use it as a cache for next runs
	if len(refinerTmpl) < msgRefinerSizeLimit {
		summarizerHandler := fp.GetSummarizeResultHandler(&taskID, nil)
		executionState, err := fp.getTaskPrimaryAgentChainSummary(ctx, taskID, summarizerHandler)
		if err != nil {
			return nil, wrapErrorEndEvaluatorSpan(ctx, refinerEvaluator, "failed to prepare execution state", err)
		}

		refinerContext["user"]["ExecutionState"] = executionState

		// Sprint 3: Inject methodology coverage into refiner.
		if mc := GetMethodologyCoverage(ctx); mc != nil {
			refinerContext["user"]["MethodologyCoverage"] = mc.FormatCoverageForRefiner()
		}

		refinerTmpl, err = fp.prompter.RenderTemplate(templates.PromptTypeSubtasksRefiner, refinerContext["user"])
		if err != nil {
			return nil, wrapErrorEndEvaluatorSpan(ctx, refinerEvaluator, "failed to get task subtasks refiner template (2)", err)
		}

		if len(refinerTmpl) < msgRefinerSizeLimit {
			msgLogsSummary, err := fp.getTaskMsgLogsSummary(ctx, taskID, summarizerHandler)
			if err != nil {
				return nil, wrapErrorEndEvaluatorSpan(ctx, refinerEvaluator, "failed to get task msg logs summary", err)
			}

			refinerContext["user"]["ExecutionLogs"] = msgLogsSummary
			refinerTmpl, err = fp.prompter.RenderTemplate(templates.PromptTypeSubtasksRefiner, refinerContext["user"])
			if err != nil {
				return nil, wrapErrorEndEvaluatorSpan(ctx, refinerEvaluator, "failed to get task subtasks refiner template (3)", err)
			}
		}
	}

	systemRefinerTmpl, err := fp.prompter.RenderTemplate(templates.PromptTypeRefiner, refinerContext["system"])
	if err != nil {
		return nil, wrapErrorEndEvaluatorSpan(ctx, refinerEvaluator, "failed to get task system refiner template", err)
	}

	subtasks, err := fp.performSubtasksRefiner(ctx, taskID, subtasksInfo.Planned, systemRefinerTmpl, refinerTmpl, tasksInfo.Task.Input)
	if err != nil {
		return nil, wrapErrorEndEvaluatorSpan(ctx, refinerEvaluator, "failed to perform subtasks refiner", err)
	}

	refinerEvaluator.End(
		langfuse.WithEvaluatorStatus("success"),
		langfuse.WithEvaluatorOutput(subtasks),
	)

	return subtasks, nil
}

func (fp *flowProvider) GetTaskResult(ctx context.Context, taskID int64) (*tools.TaskResult, error) {
	ctx, span := obs.Observer.NewSpan(ctx, obs.SpanKindInternal, "providers.flowProvider.GetTaskResult")
	defer span.End()

	logger := logrus.WithContext(ctx).WithField("task_id", taskID)

	tasksInfo, err := fp.getTasksInfo(ctx, taskID)
	if err != nil {
		logger.WithError(err).Error("failed to get tasks info")
		return nil, fmt.Errorf("failed to get tasks info: %w", err)
	}

	subtasksInfo := fp.getSubtasksInfo(taskID, tasksInfo.Subtasks)

	// Collect cost summary from the flow-level usage stats in the database.
	costSummaryText := fp.buildFlowCostSummary(ctx, taskID)

	reporterContext := map[string]map[string]any{
		"user": {
			"Task":              tasksInfo.Task,
			"Tasks":             tasksInfo.Tasks,
			"CompletedSubtasks": subtasksInfo.Completed,
			"PlannedSubtasks":   subtasksInfo.Planned,
			"CostSummary":       costSummaryText,
		},
		"system": {
			"ReportResultToolName":    tools.ReportResultToolName,
			"SummarizationToolName":   cast.SummarizationToolName,
			"SummarizedContentPrefix": strings.ReplaceAll(csum.SummarizedContentPrefix, "\n", "\\n"),
			"Lang":                    fp.language,
			"N":                       4000,
			"ToolPlaceholder":         ToolPlaceholder,
		},
	}

	ctx, observation := obs.Observer.NewObservation(ctx)
	reporterEvaluator := observation.Evaluator(
		langfuse.WithEvaluatorName("reporter agent"),
		langfuse.WithEvaluatorInput(reporterContext),
		langfuse.WithEvaluatorMetadata(langfuse.Metadata{
			"user_context":   reporterContext["user"],
			"system_context": reporterContext["system"],
		}),
	)
	ctx, _ = reporterEvaluator.Observation(ctx)

	reporterTmpl, err := fp.prompter.RenderTemplate(templates.PromptTypeTaskReporter, reporterContext["user"])
	if err != nil {
		return nil, wrapErrorEndEvaluatorSpan(ctx, reporterEvaluator, "failed to get task reporter template (1)", err)
	}

	if len(reporterTmpl) < msgReporterSizeLimit {
		summarizerHandler := fp.GetSummarizeResultHandler(&taskID, nil)
		executionState, err := fp.getTaskPrimaryAgentChainSummary(ctx, taskID, summarizerHandler)
		if err != nil {
			return nil, wrapErrorEndEvaluatorSpan(ctx, reporterEvaluator, "failed to prepare execution state", err)
		}

		reporterContext["user"]["ExecutionState"] = executionState
		reporterTmpl, err = fp.prompter.RenderTemplate(templates.PromptTypeTaskReporter, reporterContext["user"])
		if err != nil {
			return nil, wrapErrorEndEvaluatorSpan(ctx, reporterEvaluator, "failed to get task reporter template (2)", err)
		}

		if len(reporterTmpl) < msgReporterSizeLimit {
			msgLogsSummary, err := fp.getTaskMsgLogsSummary(ctx, taskID, summarizerHandler)
			if err != nil {
				return nil, wrapErrorEndEvaluatorSpan(ctx, reporterEvaluator, "failed to get task msg logs summary", err)
			}

			reporterContext["user"]["ExecutionLogs"] = msgLogsSummary
			reporterTmpl, err = fp.prompter.RenderTemplate(templates.PromptTypeTaskReporter, reporterContext["user"])
			if err != nil {
				return nil, wrapErrorEndEvaluatorSpan(ctx, reporterEvaluator, "failed to get task reporter template (3)", err)
			}
		}
	}

	systemReporterTmpl, err := fp.prompter.RenderTemplate(templates.PromptTypeReporter, reporterContext["system"])
	if err != nil {
		return nil, wrapErrorEndEvaluatorSpan(ctx, reporterEvaluator, "failed to get task system reporter template", err)
	}

	result, err := fp.performTaskResultReporter(ctx, &taskID, nil, systemReporterTmpl, reporterTmpl, tasksInfo.Task.Input)
	if err != nil {
		return nil, wrapErrorEndEvaluatorSpan(ctx, reporterEvaluator, "failed to perform task result reporter", err)
	}

	reporterEvaluator.End(
		langfuse.WithEvaluatorStatus("success"),
		langfuse.WithEvaluatorOutput(result),
	)

	return result, nil
}

func (fp *flowProvider) PrepareAgentChain(ctx context.Context, taskID, subtaskID int64) (int64, error) {
	ctx, span := obs.Observer.NewSpan(ctx, obs.SpanKindInternal, "providers.flowProvider.PrepareAgentChain")
	defer span.End()

	optAgentType := pconfig.OptionsTypePrimaryAgent
	msgChainType := database.MsgchainTypePrimaryAgent

	logger := logrus.WithContext(ctx).WithFields(logrus.Fields{
		"provider":   fp.Type(),
		"agent":      optAgentType,
		"flow_id":    fp.flowID,
		"task_id":    taskID,
		"subtask_id": subtaskID,
	})

	subtask, err := fp.db.GetSubtask(ctx, subtaskID)
	if err != nil {
		logger.WithError(err).Error("failed to get subtask")
		return 0, fmt.Errorf("failed to get subtask: %w", err)
	}

	executionContext, err := fp.prepareExecutionContext(ctx, taskID, subtaskID)
	if err != nil {
		logger.WithError(err).Error("failed to prepare execution context")
		return 0, fmt.Errorf("failed to prepare execution context: %w", err)
	}

	subtask, err = fp.db.UpdateSubtaskContext(ctx, database.UpdateSubtaskContextParams{
		Context: executionContext,
		ID:      subtaskID,
	})
	if err != nil {
		logger.WithError(err).Error("failed to update subtask context")
		return 0, fmt.Errorf("failed to update subtask context: %w", err)
	}

	// Collect workspace files for the primary agent prompt context.
	var primaryWorkspaceFiles []tools.FileInfo
	if files, err := fp.executor.ListWorkspaceFiles(ctx); err != nil {
		logger.WithError(err).Warn("failed to list workspace files for primary agent context, continuing without them")
	} else {
		primaryWorkspaceFiles = files
	}

	systemAgentTmpl, err := fp.prompter.RenderTemplate(templates.PromptTypePrimaryAgent, map[string]any{
		"FinalyToolName":          tools.FinalyToolName,
		"SearchToolName":          tools.SearchToolName,
		"PentesterToolName":       tools.PentesterToolName,
		"CoderToolName":           tools.CoderToolName,
		"AdviceToolName":          tools.AdviceToolName,
		"MemoristToolName":        tools.MemoristToolName,
		"MaintenanceToolName":     tools.MaintenanceToolName,
		"SummarizationToolName":   cast.SummarizationToolName,
		"SummarizedContentPrefix": strings.ReplaceAll(csum.SummarizedContentPrefix, "\n", "\\n"),
		"AskUserToolName":         tools.AskUserToolName,
		"AskUserEnabled":          fp.askUser,
		"ExecutionContext":        executionContext,
		"WorkspaceFiles":          primaryWorkspaceFiles,
		"Lang":                    fp.language,
		"DockerImage":             fp.image,
		"CurrentTime":             getCurrentTime(),
		"ToolPlaceholder":         ToolPlaceholder,
	})
	if err != nil {
		logger.WithError(err).Error("failed to get system prompt for primary agent template")
		return 0, fmt.Errorf("failed to get system prompt for primary agent template: %w", err)
	}

	msgChainID, _, err := fp.restoreChain(
		ctx, &taskID, &subtaskID, optAgentType, msgChainType, systemAgentTmpl, subtask.Description,
	)
	if err != nil {
		logger.WithError(err).Error("failed to restore primary agent msg chain")
		return 0, fmt.Errorf("failed to restore primary agent msg chain: %w", err)
	}

	return msgChainID, nil
}

func (fp *flowProvider) PerformAgentChain(ctx context.Context, taskID, subtaskID, msgChainID int64) (PerformResult, error) {
	ctx, span := obs.Observer.NewSpan(ctx, obs.SpanKindInternal, "providers.flowProvider.PerformAgentChain")
	defer span.End()

	optAgentType := pconfig.OptionsTypePrimaryAgent
	msgChainType := database.MsgchainTypePrimaryAgent

	logger := logrus.WithContext(ctx).WithFields(logrus.Fields{
		"provider":     fp.Type(),
		"agent":        optAgentType,
		"flow_id":      fp.flowID,
		"task_id":      taskID,
		"subtask_id":   subtaskID,
		"msg_chain_id": msgChainID,
	})

	msgChain, err := fp.db.GetMsgChain(ctx, msgChainID)
	if err != nil {
		logger.WithError(err).Error("failed to get primary agent msg chain")
		return PerformResultError, fmt.Errorf("failed to get primary agent msg chain %d: %w", msgChainID, err)
	}

	var chain []llms.MessageContent
	if err := json.Unmarshal(msgChain.Chain, &chain); err != nil {
		logger.WithError(err).Error("failed to unmarshal primary agent msg chain")
		return PerformResultError, fmt.Errorf("failed to unmarshal primary agent msg chain %d: %w", msgChainID, err)
	}

	// Validate chain integrity on load. Even though PrepareAgentChain uses
	// restoreChain (which parses via NewChainAST with force=true), there could
	// be corruption from race conditions or interrupted DB writes.
	if repairedChain, repairCount := validateAndRepairChain(chain); repairCount > 0 {
		chain = repairedChain
		logger.WithField("repaired_tool_results", repairCount).
			Warn("repaired orphaned tool_use blocks on chain load in PerformAgentChain")
		// Persist the repaired chain back to DB
		if chainBlob, err := json.Marshal(chain); err == nil {
			if _, err := fp.db.UpdateMsgChain(ctx, database.UpdateMsgChainParams{
				Chain: chainBlob,
				ID:    msgChainID,
			}); err != nil {
				logger.WithError(err).Error("failed to persist repaired chain to DB")
			}
		}
	}

	adviser, err := fp.GetAskAdviceHandler(ctx, &taskID, &subtaskID)
	if err != nil {
		logger.WithError(err).Error("failed to get ask advice handler")
		return PerformResultError, fmt.Errorf("failed to get ask advice handler: %w", err)
	}

	coder, err := fp.GetCoderHandler(ctx, &taskID, &subtaskID)
	if err != nil {
		logger.WithError(err).Error("failed to get coder handler")
		return PerformResultError, fmt.Errorf("failed to get coder handler: %w", err)
	}

	installer, err := fp.GetInstallerHandler(ctx, &taskID, &subtaskID)
	if err != nil {
		logger.WithError(err).Error("failed to get installer handler")
		return PerformResultError, fmt.Errorf("failed to get installer handler: %w", err)
	}

	memorist, err := fp.GetMemoristHandler(ctx, &taskID, &subtaskID)
	if err != nil {
		logger.WithError(err).Error("failed to get memorist handler")
		return PerformResultError, fmt.Errorf("failed to get memorist handler: %w", err)
	}

	pentester, err := fp.GetPentesterHandler(ctx, &taskID, &subtaskID)
	if err != nil {
		logger.WithError(err).Error("failed to get pentester handler")
		return PerformResultError, fmt.Errorf("failed to get pentester handler: %w", err)
	}

	searcher, err := fp.GetSubtaskSearcherHandler(ctx, &taskID, &subtaskID)
	if err != nil {
		logger.WithError(err).Error("failed to get searcher handler")
		return PerformResultError, fmt.Errorf("failed to get searcher handler: %w", err)
	}

	subtask, err := fp.db.GetSubtask(ctx, subtaskID)
	if err != nil {
		logger.WithError(err).Error("failed to get subtask")
		return PerformResultError, fmt.Errorf("failed to get subtask: %w", err)
	}

	// v5: Inject subtask metadata into context for per-type time-boxing.
	ctx = WithSubtaskMeta(ctx, subtask.Title, subtask.Description)

	ctx, observation := obs.Observer.NewObservation(ctx)
	executorAgent := observation.Agent(
		langfuse.WithAgentName(fmt.Sprintf("primary agent for subtask %d: %s", subtaskID, subtask.Title)),
		langfuse.WithAgentInput(chain),
		langfuse.WithAgentMetadata(langfuse.Metadata{
			"flow_id":      fp.flowID,
			"task_id":      taskID,
			"subtask_id":   subtaskID,
			"msg_chain_id": msgChainID,
			"provider":     fp.Type(),
			"image":        fp.image,
			"lang":         fp.language,
			"description":  subtask.Description,
		}),
	)
	ctx, _ = executorAgent.Observation(ctx)

	var performResultVal atomic.Int32
	performResultVal.Store(int32(PerformResultError))
	var endAgentOnce sync.Once
	endAgent := func(opts ...langfuse.AgentOption) {
		endAgentOnce.Do(func() { executorAgent.End(opts...) })
	}
	cfg := tools.PrimaryExecutorConfig{
		TaskID:    taskID,
		SubtaskID: subtaskID,
		Adviser:   adviser,
		Coder:     coder,
		Installer: installer,
		Memorist:  memorist,
		Pentester: pentester,
		Searcher:  searcher,
		Barrier: func(ctx context.Context, name string, args json.RawMessage) (string, error) {
			loggerFunc := logger.WithContext(ctx).WithFields(logrus.Fields{
				"name": name,
				"args": string(args),
			})

			switch name {
			case tools.FinalyToolName:
				var done tools.Done
				if err := json.Unmarshal(args, &done); err != nil {
					loggerFunc.WithError(err).Error("failed to unmarshal done result")
					return "", fmt.Errorf("failed to unmarshal done result: %w", err)
				}

				loggerFunc = loggerFunc.WithFields(logrus.Fields{
					"status": done.Success,
					"result": done.Result[:min(len(done.Result), 1000)],
				})

				opts := []langfuse.AgentOption{
					langfuse.WithAgentOutput(done.Result),
				}
				defer func() {
					endAgent(opts...)
				}()

				if !done.Success {
					performResultVal.Store(int32(PerformResultError))
					opts = append(opts,
						langfuse.WithAgentStatus("done handler: failed"),
						langfuse.WithAgentLevel(langfuse.ObservationLevelWarning),
					)
				} else {
					performResultVal.Store(int32(PerformResultDone))
					opts = append(opts,
						langfuse.WithAgentStatus("done handler: success"),
					)
				}

				// TODO: here need to call SetResult from SubtaskWorker interface
				subtask, err = fp.db.UpdateSubtaskResult(ctx, database.UpdateSubtaskResultParams{
					Result: done.Result,
					ID:     subtaskID,
				})
				if err != nil {
					opts = append(opts,
						langfuse.WithAgentStatus(err.Error()),
						langfuse.WithAgentLevel(langfuse.ObservationLevelError),
					)
					loggerFunc.WithError(err).Error("failed to update subtask result")
					return "", fmt.Errorf("failed to update subtask %d result: %w", subtaskID, err)
				}

				// report result to msg log as a final message for the subtask execution
				reportMsgID, err := fp.putMsgLog(
					ctx,
					database.MsglogTypeReport,
					&taskID, &subtaskID, 0,
					"", subtask.Description,
				)
				if err != nil {
					opts = append(opts,
						langfuse.WithAgentStatus(err.Error()),
						langfuse.WithAgentLevel(langfuse.ObservationLevelError),
					)
					loggerFunc.WithError(err).Error("failed to put report msg")
					return "", fmt.Errorf("failed to put report msg: %w", err)
				}

				err = fp.updateMsgLogResult(
					ctx,
					reportMsgID, 0,
					done.Result, database.MsglogResultFormatMarkdown,
				)
				if err != nil {
					opts = append(opts,
						langfuse.WithAgentStatus(err.Error()),
						langfuse.WithAgentLevel(langfuse.ObservationLevelError),
					)
					loggerFunc.WithError(err).Error("failed to update report msg result")
					return "", fmt.Errorf("failed to update report msg result: %w", err)
				}

			case tools.AskUserToolName:
				performResultVal.Store(int32(PerformResultWaiting))

				var askUser tools.AskUser
				if err := json.Unmarshal(args, &askUser); err != nil {
					loggerFunc.WithError(err).Error("failed to unmarshal ask user result")
					return "", fmt.Errorf("failed to unmarshal ask user result: %w", err)
				}

				endAgent(
					langfuse.WithAgentOutput(askUser.Message),
					langfuse.WithAgentStatus("ask user handler"),
				)
			}

			return fmt.Sprintf("function %s successfully processed arguments", name), nil
		},
		Summarizer: fp.GetSummarizeResultHandler(&taskID, &subtaskID),
	}

	executor, err := fp.executor.GetPrimaryExecutor(cfg)
	if err != nil {
		return PerformResultError, wrapErrorEndAgentSpan(ctx, executorAgent, "failed to get primary executor", err)
	}

	// Create a global execution budget if one doesn't exist yet (top-level entry).
	// Sub-agents inherit the budget from their parent via context.
	if GetBudget(ctx) == nil {
		ctx = WithBudget(ctx, NewExecutionBudget(getGlobalMaxToolCalls(), getGlobalMaxDuration()))
	}

	// Create a CostTracker for this flow if one doesn't exist yet.
	// Sub-agents inherit the tracker from their parent via context, so all
	// costs within a single user request accumulate in one place.
	if GetCostTracker(ctx) == nil {
		ctx = WithCostTracker(ctx, NewCostTracker(fp.Model(optAgentType)))
	}

	// Create an AttackBudgetManager if one doesn't exist yet.
	// This tracks per-phase/vector time and failure budgets to prevent rabbit-holing.
	// Sub-agents inherit the manager from their parent via context.
	if GetAttackBudget(ctx) == nil {
		ctx = WithAttackBudget(ctx, NewAttackBudgetManager(LoadAttackBudgetConfigFromEnv()))
	}

	ctx = tools.PutAgentContext(ctx, msgChainType)
	err = fp.performAgentChain(
		ctx, optAgentType, msgChain.ID, &taskID, &subtaskID, chain, executor, fp.summarizer,
	)
	if err != nil {
		logrus.WithContext(ctx).WithError(err).Error("failed to perform primary agent chain")
		endAgent(
			langfuse.WithAgentStatus(err.Error()),
			langfuse.WithAgentLevel(langfuse.ObservationLevelError),
		)
		return PerformResultError, fmt.Errorf("failed to perform primary agent chain: %w", err)
	}

	endAgent()

	// v5: If the agent chain completed without calling the barrier function
	// (e.g., timebox force-finish), promote to Done if partial results exist.
	result := PerformResult(performResultVal.Load())
	if result == PerformResultError {
		if st, dbErr := fp.db.GetSubtask(ctx, subtaskID); dbErr == nil && st.Result != "" {
			if strings.Contains(st.Result, "[TIMEBOX EXPIRED") {
				result = PerformResultDone
				logrus.WithContext(ctx).WithFields(logrus.Fields{
					"subtask_id": subtaskID,
					"task_id":    taskID,
				}).Info("subtask timebox force-finished, promoting to Done")
			}
		}
	}

	return result, nil
}

const maxUserInputSize = 32 * 1024 // 32KB maximum user input size

func (fp *flowProvider) PutInputToAgentChain(ctx context.Context, msgChainID int64, input string) error {
	ctx, span := obs.Observer.NewSpan(ctx, obs.SpanKindInternal, "providers.flowProvider.PutInputToAgentChain")
	defer span.End()

	if len(input) == 0 {
		return fmt.Errorf("user input is empty")
	}

	if len(input) > maxUserInputSize {
		return fmt.Errorf("user input exceeds maximum size (%d > %d bytes)", len(input), maxUserInputSize)
	}

	logger := logrus.WithContext(ctx).WithFields(logrus.Fields{
		"provider":     fp.Type(),
		"flow_id":      fp.flowID,
		"msg_chain_id": msgChainID,
		"input":        input[:min(len(input), 1000)],
	})

	return fp.processChain(ctx, msgChainID, logger, func(chain []llms.MessageContent) ([]llms.MessageContent, error) {
		return fp.updateMsgChainResult(chain, tools.AskUserToolName, input)
	})
}

// EnsureChainConsistency ensures a message chain is in a consistent state by adding
// default responses to any unresponded tool calls.
func (fp *flowProvider) EnsureChainConsistency(ctx context.Context, msgChainID int64) error {
	ctx, span := obs.Observer.NewSpan(ctx, obs.SpanKindInternal, "providers.flowProvider.EnsureChainConsistency")
	defer span.End()

	logger := logrus.WithContext(ctx).WithFields(logrus.Fields{
		"provider":     fp.Type(),
		"flow_id":      fp.flowID,
		"msg_chain_id": msgChainID,
	})

	return fp.processChain(ctx, msgChainID, logger, func(chain []llms.MessageContent) ([]llms.MessageContent, error) {
		return fp.ensureChainConsistency(chain)
	})
}

func (fp *flowProvider) putMsgLog(
	ctx context.Context,
	msgType database.MsglogType,
	taskID, subtaskID *int64,
	streamID int64,
	thinking, msg string,
) (int64, error) {
	fp.mx.RLock()
	msgLog := fp.msgLog
	fp.mx.RUnlock()

	if msgLog == nil {
		return 0, nil
	}

	return msgLog.PutMsg(ctx, msgType, taskID, subtaskID, streamID, thinking, msg)
}

func (fp *flowProvider) updateMsgLogResult(
	ctx context.Context,
	msgID, streamID int64,
	result string,
	resultFormat database.MsglogResultFormat,
) error {
	fp.mx.RLock()
	msgLog := fp.msgLog
	fp.mx.RUnlock()

	if msgLog == nil || msgID <= 0 {
		return nil
	}

	return msgLog.UpdateMsgResult(ctx, msgID, streamID, result, resultFormat)
}

func (fp *flowProvider) putAgentLog(
	ctx context.Context,
	initiator, executor database.MsgchainType,
	task, result string,
	taskID, subtaskID *int64,
) (int64, error) {
	fp.mx.RLock()
	agentLog := fp.agentLog
	fp.mx.RUnlock()

	if agentLog == nil {
		return 0, nil
	}

	return agentLog.PutLog(ctx, initiator, executor, task, result, taskID, subtaskID)
}

// buildFlowCostSummary queries the database for flow-level usage stats and
// returns a formatted cost summary string for inclusion in reporter context.
// It also supplements with in-memory CostTracker data if available.
// Returns empty string on error (non-fatal).
func (fp *flowProvider) buildFlowCostSummary(ctx context.Context, taskID int64) string {
	logger := logrus.WithContext(ctx).WithFields(logrus.Fields{
		"flow_id": fp.flowID,
		"task_id": taskID,
	})

	// Primary source: database aggregation (most accurate, includes all historical calls)
	flowStats, err := fp.db.GetFlowUsageStats(ctx, fp.flowID)
	if err != nil {
		logger.WithError(err).Warn("failed to get flow usage stats for cost summary")
		// Fall back to in-memory tracker if DB query fails
		if ct := GetCostTracker(ctx); ct != nil {
			return ct.FormatCostSummary(0)
		}
		return ""
	}

	totalCost := flowStats.TotalUsageCostIn + flowStats.TotalUsageCostOut
	if flowStats.TotalUsageIn == 0 && flowStats.TotalUsageOut == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Total Input Tokens: %d\n", flowStats.TotalUsageIn))
	sb.WriteString(fmt.Sprintf("Total Output Tokens: %d\n", flowStats.TotalUsageOut))
	if flowStats.TotalUsageCacheIn > 0 || flowStats.TotalUsageCacheOut > 0 {
		sb.WriteString(fmt.Sprintf("Cache Read Tokens: %d\n", flowStats.TotalUsageCacheIn))
		sb.WriteString(fmt.Sprintf("Cache Write Tokens: %d\n", flowStats.TotalUsageCacheOut))
	}
	sb.WriteString(fmt.Sprintf("Total Estimated Cost: $%.4f USD\n", totalCost))

	// Add per-agent-type breakdown
	typeStats, err := fp.db.GetUsageStatsByTypeForFlow(ctx, fp.flowID)
	if err != nil {
		logger.WithError(err).Warn("failed to get usage stats by type for cost summary")
	} else if len(typeStats) > 0 {
		sb.WriteString("\nCost by Agent Type:\n")
		for _, ts := range typeStats {
			typeCost := ts.TotalUsageCostIn + ts.TotalUsageCostOut
			sb.WriteString(fmt.Sprintf("  %-20s  in: %-10d  out: %-10d  cost: $%.4f\n",
				ts.Type, ts.TotalUsageIn, ts.TotalUsageOut, typeCost))
		}
	}

	return sb.String()
}
