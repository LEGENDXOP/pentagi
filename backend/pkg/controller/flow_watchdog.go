package controller

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"pentagi/pkg/database"

	"github.com/sirupsen/logrus"
)

// flowWatchdog monitors a flow for stalled states and auto-resumes when possible.
// It runs as a background goroutine tied to the flow worker's lifetime.
type flowWatchdog struct {
	fw          *flowWorker
	interval    time.Duration
	maxResumes  int
	resumeCount int
	logger      *logrus.Entry
}

func newFlowWatchdog(fw *flowWorker) *flowWatchdog {
	return &flowWatchdog{
		fw:         fw,
		interval:   getWatchdogInterval(),
		maxResumes: getWatchdogMaxResumes(),
		logger: logrus.WithFields(logrus.Fields{
			"flow_id":   fw.flowCtx.FlowID,
			"component": "watchdog",
		}),
	}
}

// run starts the watchdog loop. It blocks until the flow context is cancelled.
func (wd *flowWatchdog) run(ctx context.Context) {
	ticker := time.NewTicker(wd.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			wd.logger.Debug("flow watchdog stopped: context cancelled")
			return
		case <-ticker.C:
			wd.check(ctx)
		}
	}
}

// check examines the flow state and auto-resumes if stalled.
func (wd *flowWatchdog) check(ctx context.Context) {
	if wd.resumeCount >= wd.maxResumes {
		wd.logger.WithField("resume_count", wd.resumeCount).
			Debug("flow watchdog: max auto-resumes reached, skipping check")
		return
	}

	// Only act when the flow is in Waiting status
	flowStatus, err := wd.fw.GetStatus(ctx)
	if err != nil {
		wd.logger.WithError(err).Debug("flow watchdog: failed to get flow status")
		return
	}

	if flowStatus != database.FlowStatusWaiting {
		return
	}

	// Check if there are any tasks in a waiting state that could be resumed
	for _, task := range wd.fw.tc.ListTasks(ctx) {
		if task.IsCompleted() || !task.IsWaiting() {
			continue
		}

		// Found a waiting, non-completed task in a waiting flow.
		// Before attempting resume, check for zombie state: task is waiting
		// but no subtask has "waiting" status (e.g., after a refiner crash).
		if err := wd.recoverZombieSubtasks(ctx, task.GetTaskID()); err != nil {
			wd.logger.WithError(err).WithField("task_id", task.GetTaskID()).
				Warn("flow watchdog: zombie recovery failed, skipping resume attempt")
			return
		}

		wd.resumeCount++
		wd.logger.WithFields(logrus.Fields{
			"task_id":      task.GetTaskID(),
			"task_title":   task.GetTitle(),
			"resume_count": wd.resumeCount,
			"max_resumes":  wd.maxResumes,
		}).Info("flow watchdog: auto-resuming stalled flow")

		if err := wd.fw.PutInput(ctx, "Continue — auto-resumed by flow watchdog after stall detected"); err != nil {
			wd.logger.WithError(err).Error("flow watchdog: failed to auto-resume flow")
			wd.resumeCount-- // don't count a failed resume attempt
		}
		return
	}
}

// recoverZombieSubtasks detects the zombie state where a task is "waiting" but
// no subtask has "waiting" status. This happens when the refiner crashes (e.g.,
// context deadline exceeded) after a subtask completes — the remaining subtasks
// stay in "created" status and PutInput would normally fail.
//
// This method logs the zombie state for diagnostics. The actual recovery happens
// in task.PutInput() which detects the zombie condition and resets the task to
// "running" so that Run() can pick up the next created subtask via PopSubtask().
//
// Returns nil to allow the resume attempt to proceed (PutInput handles recovery),
// or an error only if the DB check itself fails.
func (wd *flowWatchdog) recoverZombieSubtasks(ctx context.Context, taskID int64) error {
	subtasks, err := wd.fw.flowCtx.DB.GetTaskSubtasks(ctx, taskID)
	if err != nil {
		return fmt.Errorf("failed to get subtasks for task %d: %w", taskID, err)
	}

	// Check if any subtask already has "waiting" status — if so, no zombie state
	hasWaiting := false
	hasCreated := false
	for _, st := range subtasks {
		if st.Status == database.SubtaskStatusWaiting {
			hasWaiting = true
		}
		if st.Status == database.SubtaskStatusCreated {
			hasCreated = true
		}
	}

	if hasWaiting {
		return nil // Normal stall, not a zombie — PutInput should work fine
	}

	if hasCreated {
		// Zombie state: task waiting, no subtask waiting, but created subtasks exist.
		// PutInput will handle recovery by resetting task to running.
		wd.logger.WithField("task_id", taskID).
			Info("flow watchdog: detected zombie state (task waiting, no subtask waiting, created subtasks exist) — PutInput will recover")
	} else {
		// All subtasks are finished/failed/running — no created subtasks left.
		wd.logger.WithField("task_id", taskID).
			Warn("flow watchdog: zombie state but no created subtasks remain — task may need manual intervention")
	}

	return nil
}

// isWatchdogEnabled checks the FLOW_WATCHDOG_ENABLED env var (default true).
func isWatchdogEnabled() bool {
	v := os.Getenv("FLOW_WATCHDOG_ENABLED")
	if v == "" {
		return true // default enabled
	}
	enabled, err := strconv.ParseBool(v)
	if err != nil {
		return true
	}
	return enabled
}

// getWatchdogInterval returns the watchdog check interval from env var (default 300s).
func getWatchdogInterval() time.Duration {
	if v := os.Getenv("FLOW_WATCHDOG_INTERVAL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return 300 * time.Second // 5 minutes
}

// getWatchdogMaxResumes returns max auto-resumes per flow from env var (default 5).
func getWatchdogMaxResumes() int {
	if v := os.Getenv("FLOW_WATCHDOG_MAX_RESUMES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 5
}
