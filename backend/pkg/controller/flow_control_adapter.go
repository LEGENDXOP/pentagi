package controller

import "context"

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
