package controller

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"pentagi/pkg/database"
	obs "pentagi/pkg/observability"
	"pentagi/pkg/providers"
	"pentagi/pkg/tools"

	"github.com/sirupsen/logrus"
)

type FlowUpdater interface {
	SetStatus(ctx context.Context, status database.FlowStatus) error
}

type TaskWorker interface {
	GetTaskID() int64
	GetFlowID() int64
	GetUserID() int64
	GetTitle() string
	IsCompleted() bool
	IsWaiting() bool
	GetStatus(ctx context.Context) (database.TaskStatus, error)
	SetStatus(ctx context.Context, status database.TaskStatus) error
	GetResult(ctx context.Context) (string, error)
	SetResult(ctx context.Context, result string) error
	PutInput(ctx context.Context, input string) error
	Run(ctx context.Context) error
	Finish(ctx context.Context) error
}

type taskWorker struct {
	mx        *sync.RWMutex
	stc       SubtaskController
	taskCtx   *TaskContext
	updater   FlowUpdater
	completed bool
	waiting   bool
}

func NewTaskWorker(
	ctx context.Context,
	flowCtx *FlowContext,
	input string,
	updater FlowUpdater,
) (TaskWorker, error) {
	ctx, span := obs.Observer.NewSpan(ctx, obs.SpanKindInternal, "controller.NewTaskWorker")
	defer span.End()

	ctx = tools.PutAgentContext(ctx, database.MsgchainTypePrimaryAgent)

	title, err := flowCtx.Provider.GetTaskTitle(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to get task title: %w", err)
	}

	task, err := flowCtx.DB.CreateTask(ctx, database.CreateTaskParams{
		Status: database.TaskStatusCreated,
		Title:  title,
		Input:  input,
		FlowID: flowCtx.FlowID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create task in DB: %w", err)
	}

	flowCtx.Publisher.TaskCreated(ctx, task, []database.Subtask{})

	taskCtx := &TaskContext{
		FlowContext: *flowCtx,
		TaskID:      task.ID,
		TaskTitle:   title,
		TaskInput:   input,
	}
	stc := NewSubtaskController(taskCtx)

	_, err = taskCtx.MsgLog.PutTaskMsg(
		ctx,
		database.MsglogTypeInput,
		taskCtx.TaskID,
		"", // thinking is empty because this is input
		input,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to put input for task %d: %w", taskCtx.TaskID, err)
	}

	err = stc.GenerateSubtasks(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to generate subtasks: %w", err)
	}

	subtasks, err := flowCtx.DB.GetTaskSubtasks(ctx, task.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get subtasks for task %d: %w", task.ID, err)
	}

	flowCtx.Publisher.TaskUpdated(ctx, task, subtasks)

	return &taskWorker{
		mx:        &sync.RWMutex{},
		stc:       stc,
		taskCtx:   taskCtx,
		updater:   updater,
		completed: false,
		waiting:   false,
	}, nil
}

func LoadTaskWorker(
	ctx context.Context,
	task database.Task,
	flowCtx *FlowContext,
	updater FlowUpdater,
) (TaskWorker, error) {
	ctx, span := obs.Observer.NewSpan(ctx, obs.SpanKindInternal, "controller.LoadTaskWorker")
	defer span.End()

	ctx = tools.PutAgentContext(ctx, database.MsgchainTypePrimaryAgent)
	taskCtx := &TaskContext{
		FlowContext: *flowCtx,
		TaskID:      task.ID,
		TaskTitle:   task.Title,
		TaskInput:   task.Input,
	}

	stc := NewSubtaskController(taskCtx)
	var completed, waiting bool
	switch task.Status {
	case database.TaskStatusFinished, database.TaskStatusFailed:
		completed = true
	case database.TaskStatusWaiting:
		waiting = true
	case database.TaskStatusRunning:
	case database.TaskStatusCreated:
		return nil, fmt.Errorf("task %d has created yet: loading aborted: %w", task.ID, ErrNothingToLoad)
	}

	tw := &taskWorker{
		mx:        &sync.RWMutex{},
		stc:       stc,
		taskCtx:   taskCtx,
		updater:   updater,
		completed: completed,
		waiting:   waiting,
	}

	if err := tw.stc.LoadSubtasks(ctx, task.ID, tw); err != nil {
		return nil, fmt.Errorf("failed to load subtasks for task %d: %w", task.ID, err)
	}

	return tw, nil
}

func (tw *taskWorker) GetTaskID() int64 {
	return tw.taskCtx.TaskID
}

func (tw *taskWorker) GetFlowID() int64 {
	return tw.taskCtx.FlowID
}

func (tw *taskWorker) GetUserID() int64 {
	return tw.taskCtx.UserID
}

func (tw *taskWorker) GetTitle() string {
	return tw.taskCtx.TaskTitle
}

func (tw *taskWorker) IsCompleted() bool {
	tw.mx.RLock()
	defer tw.mx.RUnlock()

	return tw.completed
}

func (tw *taskWorker) IsWaiting() bool {
	tw.mx.RLock()
	defer tw.mx.RUnlock()

	return tw.waiting
}

func (tw *taskWorker) GetStatus(ctx context.Context) (database.TaskStatus, error) {
	task, err := tw.taskCtx.DB.GetTask(ctx, tw.taskCtx.TaskID)
	if err != nil {
		return database.TaskStatusFailed, err
	}

	return task.Status, nil
}

// this function is exclusively change task internal properties "completed" and "waiting"
func (tw *taskWorker) SetStatus(ctx context.Context, status database.TaskStatus) error {
	// Acquire lock FIRST to prevent race between DB write and in-memory state read
	tw.mx.Lock()

	task, err := tw.taskCtx.DB.UpdateTaskStatus(ctx, database.UpdateTaskStatusParams{
		Status: status,
		ID:     tw.taskCtx.TaskID,
	})
	if err != nil {
		tw.mx.Unlock()
		return fmt.Errorf("failed to set task %d status: %w", tw.taskCtx.TaskID, err)
	}

	subtasks, err := tw.taskCtx.DB.GetTaskSubtasks(ctx, tw.taskCtx.TaskID)
	if err != nil {
		tw.mx.Unlock()
		return fmt.Errorf("failed to get task %d subtasks: %w", tw.taskCtx.TaskID, err)
	}

	tw.taskCtx.Publisher.TaskUpdated(ctx, task, subtasks)

	// Update in-memory state while holding the lock
	var flowStatus database.FlowStatus
	switch status {
	case database.TaskStatusRunning:
		tw.completed = false
		tw.waiting = false
		flowStatus = database.FlowStatusRunning
	case database.TaskStatusWaiting:
		tw.completed = false
		tw.waiting = true
		flowStatus = database.FlowStatusWaiting
	case database.TaskStatusFinished, database.TaskStatusFailed:
		tw.completed = true
		tw.waiting = false
		// the last task was done, set flow status to Waiting new user input
		flowStatus = database.FlowStatusWaiting
	default:
		tw.mx.Unlock()
		// status Created is not possible to set by this call
		return fmt.Errorf("unsupported task status: %s", status)
	}

	// Release lock BEFORE calling updater to prevent deadlock in the
	// Task→Flow status propagation chain
	tw.mx.Unlock()

	if err := tw.updater.SetStatus(ctx, flowStatus); err != nil {
		return fmt.Errorf("failed to set flow status in back propagation: %w", err)
	}

	return nil
}

func (tw *taskWorker) GetResult(ctx context.Context) (string, error) {
	task, err := tw.taskCtx.DB.GetTask(ctx, tw.taskCtx.TaskID)
	if err != nil {
		return "", err
	}

	return task.Result, nil
}

func (tw *taskWorker) SetResult(ctx context.Context, result string) error {
	_, err := tw.taskCtx.DB.UpdateTaskResult(ctx, database.UpdateTaskResultParams{
		Result: result,
		ID:     tw.taskCtx.TaskID,
	})
	if err != nil {
		return fmt.Errorf("failed to set task %d result: %w", tw.taskCtx.TaskID, err)
	}

	return nil
}

func (tw *taskWorker) PutInput(ctx context.Context, input string) error {
	if !tw.IsWaiting() {
		return fmt.Errorf("task is not waiting")
	}

	for _, st := range tw.stc.ListSubtasks(ctx) {
		if !st.IsCompleted() && st.IsWaiting() {
			if err := st.PutInput(ctx, input); err != nil {
				return fmt.Errorf("failed to put input to subtask %d: %w", st.GetSubtaskID(), err)
			}
			return nil
		}
	}

	return fmt.Errorf("task %d is waiting but no subtask is waiting for input", tw.taskCtx.TaskID)
}

func (tw *taskWorker) Run(ctx context.Context) error {
	ctx = tools.PutAgentContext(ctx, database.MsgchainTypePrimaryAgent)

	maxRetries := getSubtaskMaxRetries()
	logger := logrus.WithContext(ctx).WithFields(logrus.Fields{
		"task_id": tw.taskCtx.TaskID,
		"flow_id": tw.taskCtx.FlowID,
	})

	for len(tw.stc.ListSubtasks(ctx)) < providers.TasksNumberLimit+3 {
		st, err := tw.stc.PopSubtask(ctx, tw)
		if err != nil {
			return err
		}

		// empty queue for subtasks means that task is done
		if st == nil {
			break
		}

		// Subtask execution with retry logic
		subtaskErr := tw.runSubtaskWithRetry(ctx, st, maxRetries, logger)
		if subtaskErr != nil {
			// Context cancellation is always fatal — propagate immediately
			if errors.Is(subtaskErr, context.Canceled) {
				return subtaskErr
			}

			// If subtask is waiting for user input, propagate
			if tw.IsWaiting() {
				return nil
			}

			// After exhausting retries, skip this subtask and continue to next
			logger.WithError(subtaskErr).WithFields(logrus.Fields{
				"subtask_id":    st.GetSubtaskID(),
				"subtask_title": st.GetTitle(),
			}).Warn("subtask failed after all retries, skipping to next subtask")

			// Mark as failed and continue
			_ = st.SetStatus(ctx, database.SubtaskStatusFailed)
			continue
		}

		// pass through if task is waiting from back status propagation
		if tw.IsWaiting() {
			return nil
		} // otherwise subtask is done

		if err := tw.stc.RefineSubtasks(ctx); err != nil {
			if errors.Is(err, context.Canceled) {
				ctx = context.Background()
			}
			_ = tw.SetStatus(ctx, database.TaskStatusWaiting)
			return fmt.Errorf("failed to refine subtasks list for the task %d: %w", tw.taskCtx.TaskID, err)
		}
	}

	jobResult, err := tw.taskCtx.Provider.GetTaskResult(ctx, tw.taskCtx.TaskID)
	if err != nil {
		return fmt.Errorf("failed to get task %d result: %w", tw.taskCtx.TaskID, err)
	}

	var taskStatus database.TaskStatus
	if jobResult.Success {
		taskStatus = database.TaskStatusFinished
	} else {
		taskStatus = database.TaskStatusFailed
	}

	if err := tw.SetResult(ctx, jobResult.Result); err != nil {
		return err
	}

	if err := tw.SetStatus(ctx, taskStatus); err != nil {
		return err
	}

	format := database.MsglogResultFormatMarkdown
	_, err = tw.taskCtx.MsgLog.PutTaskMsgResult(
		ctx,
		database.MsglogTypeReport,
		tw.taskCtx.TaskID,
		"", // thinking is empty because agent can't return it
		tw.taskCtx.TaskTitle,
		jobResult.Result,
		format,
	)
	if err != nil {
		return fmt.Errorf("failed to put report for task %d: %w", tw.taskCtx.TaskID, err)
	}

	return nil
}

func (tw *taskWorker) Finish(ctx context.Context) error {
	if tw.IsCompleted() {
		return fmt.Errorf("task has already completed")
	}

	for _, st := range tw.stc.ListSubtasks(ctx) {
		if !st.IsCompleted() {
			if err := st.Finish(ctx); err != nil {
				return err
			}
		}
	}

	if err := tw.SetStatus(ctx, database.TaskStatusFinished); err != nil {
		return err
	}

	return nil
}

// runSubtaskWithRetry executes a subtask with exponential backoff retry.
// Returns nil on success, context.Canceled if cancelled, or the last error
// after exhausting all retries.
func (tw *taskWorker) runSubtaskWithRetry(
	ctx context.Context,
	st SubtaskWorker,
	maxRetries int,
	logger *logrus.Entry,
) error {
	var lastErr error
	backoffs := []time.Duration{30 * time.Second, 90 * time.Second, 270 * time.Second}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// Wait with exponential backoff before retry
			backoffIdx := attempt - 1
			if backoffIdx >= len(backoffs) {
				backoffIdx = len(backoffs) - 1
			}
			delay := backoffs[backoffIdx]

			logger.WithFields(logrus.Fields{
				"subtask_id":    st.GetSubtaskID(),
				"subtask_title": st.GetTitle(),
				"attempt":       attempt,
				"max_retries":   maxRetries,
				"backoff":       delay.String(),
			}).Warn("subtask failed, retrying after backoff")

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}

			// Reset subtask status to created for re-run
			if err := st.SetStatus(ctx, database.SubtaskStatusCreated); err != nil {
				logger.WithError(err).Error("failed to reset subtask status for retry")
				return err
			}
		}

		lastErr = st.Run(ctx)
		if lastErr == nil {
			return nil // success
		}

		// Context cancellation is not retryable
		if errors.Is(lastErr, context.Canceled) {
			return lastErr
		}

		// If subtask went to waiting state (user input needed), not retryable
		if tw.IsWaiting() || st.IsWaiting() {
			return lastErr
		}
	}

	return lastErr
}

// getSubtaskMaxRetries returns the max retry count from env var or default.
func getSubtaskMaxRetries() int {
	if v := os.Getenv("SUBTASK_MAX_RETRIES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return 2 // default
}
