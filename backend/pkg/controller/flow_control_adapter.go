package controller

// flowControlMasterAgentAdapter wraps FlowControlManager to implement
// the masteragent.FlowControlAdapter interface without creating an import cycle.
type flowControlMasterAgentAdapter struct {
	mgr FlowControlManager
}

// NewFlowControlMasterAgentAdapter creates an adapter that satisfies
// masteragent.FlowControlAdapter using a FlowControlManager.
func NewFlowControlMasterAgentAdapter(mgr FlowControlManager) *flowControlMasterAgentAdapter {
	return &flowControlMasterAgentAdapter{mgr: mgr}
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
