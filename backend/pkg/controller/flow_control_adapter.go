package controller

import (
	"context"
	"fmt"

	"pentagi/pkg/database"

	"github.com/sirupsen/logrus"
)

// flowControlMasterAgentAdapter wraps FlowControlManager and flowController
// to implement the masteragent.FlowControlAdapter interface without creating
// an import cycle.
type flowControlMasterAgentAdapter struct {
	mgr FlowControlManager
	fc  *flowController // for HardStop (full flow termination)
}

// NewFlowControlMasterAgentAdapter creates an adapter that satisfies
// masteragent.FlowControlAdapter using a FlowControlManager and flowController.
func NewFlowControlMasterAgentAdapter(mgr FlowControlManager, fc *flowController) *flowControlMasterAgentAdapter {
	return &flowControlMasterAgentAdapter{mgr: mgr, fc: fc}
}

func (a *flowControlMasterAgentAdapter) GetControlStatus(flowID int64) (status string, steerMessage string) {
	state := a.mgr.GetState(flowID)
	return string(state.Status), state.SteerMessage
}

func (a *flowControlMasterAgentAdapter) Steer(flowID int64, message string) error {
	_, err := a.mgr.Steer(flowID, message)
	return err
}

func (a *flowControlMasterAgentAdapter) Pause(flowID int64) error {
	_, err := a.mgr.Pause(flowID)
	return err
}

func (a *flowControlMasterAgentAdapter) Resume(flowID int64) error {
	_, err := a.mgr.Resume(flowID)
	return err
}

func (a *flowControlMasterAgentAdapter) Abort(flowID int64) error {
	_, err := a.mgr.Abort(flowID)
	return err
}

func (a *flowControlMasterAgentAdapter) AbortChannel(flowID int64) <-chan struct{} {
	return a.mgr.AbortChannel(flowID)
}

// HardStop performs full flow termination: abort flag + DB status + container cleanup + goroutine wait.
// Uses FinishFlow for complete cleanup (DB status, container release, tool call cleanup).
func (a *flowControlMasterAgentAdapter) HardStop(flowID int64) error {
	if a.fc == nil {
		// Fallback: if no flowController, just abort
		_, err := a.mgr.Abort(flowID)
		return err
	}
	return a.fc.FinishFlow(context.Background(), flowID)
}

// SkipSubtask (Fix 5): Force-completes the current running subtask for the given flow
// and lets the task loop advance to the next subtask naturally.
func (a *flowControlMasterAgentAdapter) SkipSubtask(flowID int64) error {
	if a.fc == nil {
		return fmt.Errorf("skip_subtask: no flow controller available")
	}

	ctx := context.Background()

	// Find the active task for this flow
	tasks, err := a.fc.db.GetFlowTasks(ctx, flowID)
	if err != nil {
		return fmt.Errorf("skip_subtask: failed to get flow tasks: %w", err)
	}

	var activeTaskID int64
	for _, t := range tasks {
		if t.Status == database.TaskStatusRunning {
			activeTaskID = t.ID
			break
		}
	}
	if activeTaskID == 0 {
		return fmt.Errorf("skip_subtask: no running task found for flow %d", flowID)
	}

	// Find the running subtask
	subtasks, err := a.fc.db.GetTaskSubtasks(ctx, activeTaskID)
	if err != nil {
		return fmt.Errorf("skip_subtask: failed to get subtasks: %w", err)
	}

	for _, st := range subtasks {
		if st.Status == database.SubtaskStatusRunning {
			// Force-complete this subtask
			_, err := a.fc.db.UpdateSubtaskStatus(ctx, database.UpdateSubtaskStatusParams{
				ID:     st.ID,
				Status: database.SubtaskStatusFinished,
			})
			if err != nil {
				return fmt.Errorf("skip_subtask: failed to update subtask status: %w", err)
			}

			// Save a partial result
			_, _ = a.fc.db.UpdateSubtaskResult(ctx, database.UpdateSubtaskResultParams{
				ID:     st.ID,
				Result: "[SKIPPED BY MASTER AGENT] Subtask force-completed to advance the flow.",
			})

			logrus.WithFields(logrus.Fields{
				"flow_id":    flowID,
				"task_id":    activeTaskID,
				"subtask_id": st.ID,
				"title":      st.Title,
			}).Info("master agent: subtask skipped")

			// Also inject a steer message so the performer loop knows to stop.
			_, _ = a.mgr.Steer(flowID, "[SKIP_SUBTASK] The Master Agent has force-completed this subtask. Call your result tool NOW and move to the next subtask.")
			return nil
		}
	}

	return fmt.Errorf("skip_subtask: no running subtask found for task %d", activeTaskID)
}

// InjectSubtask (Fix 6): Creates a new subtask with the given description and inserts
// it as the next subtask to execute (status=created, it will be popped next by PopSubtask).
func (a *flowControlMasterAgentAdapter) InjectSubtask(flowID int64, description string) error {
	if a.fc == nil {
		return fmt.Errorf("inject_subtask: no flow controller available")
	}

	ctx := context.Background()

	// Find the active task for this flow
	tasks, err := a.fc.db.GetFlowTasks(ctx, flowID)
	if err != nil {
		return fmt.Errorf("inject_subtask: failed to get flow tasks: %w", err)
	}

	var activeTaskID int64
	for _, t := range tasks {
		if t.Status == database.TaskStatusRunning {
			activeTaskID = t.ID
			break
		}
	}
	if activeTaskID == 0 {
		return fmt.Errorf("inject_subtask: no running task found for flow %d", flowID)
	}

	// Create the new subtask with status=created so it's picked up by PopSubtask.
	// Title is derived from the first 80 chars of description.
	title := description
	if len(title) > 80 {
		title = title[:77] + "..."
	}
	title = "[MA-INJECTED] " + title

	newSt, err := a.fc.db.CreateSubtask(ctx, database.CreateSubtaskParams{
		Status:      database.SubtaskStatusCreated,
		TaskID:      activeTaskID,
		Title:       title,
		Description: description,
	})
	if err != nil {
		return fmt.Errorf("inject_subtask: failed to create subtask: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"flow_id":        flowID,
		"task_id":        activeTaskID,
		"new_subtask_id": newSt.ID,
		"description":    description,
	}).Info("master agent: subtask injected")

	return nil
}
