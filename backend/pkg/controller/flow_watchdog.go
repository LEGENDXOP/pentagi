package controller

import (
	"context"
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
		// This is the stall condition: a subtask failed, the error propagated up,
		// and now the flow is stuck waiting for user input.
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
