package services

import (
	"net/http"
	"slices"
	"strconv"
	"time"

	"pentagi/pkg/controller"
	"pentagi/pkg/server/logger"
	"pentagi/pkg/server/response"

	"github.com/gin-gonic/gin"
)

// FlowControlStateResponse is the API response for flow control state.
type FlowControlStateResponse struct {
	FlowID       int64  `json:"flowId"`
	Status       string `json:"status"`
	SteerMessage string `json:"steerMessage,omitempty"`
	UpdatedAt    string `json:"updatedAt"`
}

// SteerRequest is the request body for the steer endpoint.
type SteerRequest struct {
	Message string `json:"message" binding:"required"`
}

func stateToResponse(s controller.FlowControlState) FlowControlStateResponse {
	return FlowControlStateResponse{
		FlowID:       s.FlowID,
		Status:       string(s.Status),
		SteerMessage: s.SteerMessage,
		UpdatedAt:    s.UpdatedAt.Format(time.RFC3339),
	}
}

// FlowControlService provides REST endpoints for flow control operations.
type FlowControlService struct {
	fc controller.FlowController
}

// NewFlowControlService creates a new FlowControlService.
func NewFlowControlService(fc controller.FlowController) *FlowControlService {
	return &FlowControlService{fc: fc}
}

func (s *FlowControlService) getFlowID(c *gin.Context) (int64, bool) {
	flowIDStr := c.Param("flowID")
	flowID, err := strconv.ParseInt(flowIDStr, 10, 64)
	if err != nil {
		logger.FromContext(c).WithError(err).Error("invalid flow ID")
		response.Error(c, response.ErrFlowControlInvalidRequest, err)
		return 0, false
	}
	return flowID, true
}

func (s *FlowControlService) checkFlowPermission(c *gin.Context, flowID int64) bool {
	privs := c.GetStringSlice("prm")
	if slices.Contains(privs, "flows.admin") {
		return true
	}
	if !slices.Contains(privs, "flows.edit") {
		logger.FromContext(c).Error("flow control: permission denied")
		response.Error(c, response.ErrNotPermitted, nil)
		return false
	}

	// Check that the flow belongs to the user
	uid := c.GetUint64("uid")
	fw, err := s.fc.GetFlow(c, flowID)
	if err != nil {
		logger.FromContext(c).WithError(err).Error("flow not found")
		response.Error(c, response.ErrFlowsNotFound, err)
		return false
	}
	if fw.GetUserID() != int64(uid) {
		logger.FromContext(c).Error("flow control: not owner")
		response.Error(c, response.ErrNotPermitted, nil)
		return false
	}
	return true
}

// GetFlowControlState returns the current control state for a flow.
// @Summary Get flow control state
// @Tags FlowControl
// @Produce json
// @Security BearerAuth
// @Param flowID path int true "Flow ID"
// @Success 200 {object} response.successResp{data=FlowControlStateResponse} "flow control state"
// @Failure 400 {object} response.errorResp "invalid request"
// @Failure 403 {object} response.errorResp "not permitted"
// @Failure 404 {object} response.errorResp "flow not found"
// @Router /flows/{flowID}/control [get]
func (s *FlowControlService) GetFlowControlState(c *gin.Context) {
	flowID, ok := s.getFlowID(c)
	if !ok {
		return
	}
	if !s.checkFlowPermission(c, flowID) {
		return
	}

	state := s.fc.GetFlowControlManager().GetState(flowID)
	response.Success(c, http.StatusOK, stateToResponse(state))
}

// PauseFlow pauses a running flow.
// @Summary Pause a flow
// @Tags FlowControl
// @Produce json
// @Security BearerAuth
// @Param flowID path int true "Flow ID"
// @Success 200 {object} response.successResp{data=FlowControlStateResponse} "flow paused"
// @Failure 400 {object} response.errorResp "invalid request"
// @Failure 403 {object} response.errorResp "not permitted"
// @Failure 500 {object} response.errorResp "flow control failed"
// @Router /flows/{flowID}/control/pause [post]
func (s *FlowControlService) PauseFlow(c *gin.Context) {
	flowID, ok := s.getFlowID(c)
	if !ok {
		return
	}
	if !s.checkFlowPermission(c, flowID) {
		return
	}

	state, err := s.fc.GetFlowControlManager().Pause(flowID)
	if err != nil {
		logger.FromContext(c).WithError(err).Error("failed to pause flow")
		response.Error(c, response.ErrFlowControlFailed, err)
		return
	}

	response.Success(c, http.StatusOK, stateToResponse(state))
}

// ResumeFlow resumes a paused flow.
// @Summary Resume a paused flow
// @Tags FlowControl
// @Produce json
// @Security BearerAuth
// @Param flowID path int true "Flow ID"
// @Success 200 {object} response.successResp{data=FlowControlStateResponse} "flow resumed"
// @Failure 400 {object} response.errorResp "invalid request"
// @Failure 403 {object} response.errorResp "not permitted"
// @Failure 500 {object} response.errorResp "flow control failed"
// @Router /flows/{flowID}/control/resume [post]
func (s *FlowControlService) ResumeFlow(c *gin.Context) {
	flowID, ok := s.getFlowID(c)
	if !ok {
		return
	}
	if !s.checkFlowPermission(c, flowID) {
		return
	}

	state, err := s.fc.GetFlowControlManager().Resume(flowID)
	if err != nil {
		logger.FromContext(c).WithError(err).Error("failed to resume flow")
		response.Error(c, response.ErrFlowControlFailed, err)
		return
	}

	response.Success(c, http.StatusOK, stateToResponse(state))
}

// SteerFlow injects an operator instruction into the flow.
// @Summary Steer a flow with operator instruction
// @Tags FlowControl
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param flowID path int true "Flow ID"
// @Param request body SteerRequest true "steer message"
// @Success 200 {object} response.successResp{data=FlowControlStateResponse} "flow steered"
// @Failure 400 {object} response.errorResp "invalid request"
// @Failure 403 {object} response.errorResp "not permitted"
// @Failure 500 {object} response.errorResp "flow control failed"
// @Router /flows/{flowID}/control/steer [post]
func (s *FlowControlService) SteerFlow(c *gin.Context) {
	flowID, ok := s.getFlowID(c)
	if !ok {
		return
	}
	if !s.checkFlowPermission(c, flowID) {
		return
	}

	var req SteerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.FromContext(c).WithError(err).Error("invalid steer request body")
		response.Error(c, response.ErrFlowControlInvalidRequest, err)
		return
	}

	state, err := s.fc.GetFlowControlManager().Steer(flowID, req.Message)
	if err != nil {
		logger.FromContext(c).WithError(err).Error("failed to steer flow")
		response.Error(c, response.ErrFlowControlFailed, err)
		return
	}

	response.Success(c, http.StatusOK, stateToResponse(state))
}

// AbortFlow gracefully aborts a flow.
// @Summary Abort a flow
// @Tags FlowControl
// @Produce json
// @Security BearerAuth
// @Param flowID path int true "Flow ID"
// @Success 200 {object} response.successResp{data=FlowControlStateResponse} "flow aborted"
// @Failure 400 {object} response.errorResp "invalid request"
// @Failure 403 {object} response.errorResp "not permitted"
// @Failure 500 {object} response.errorResp "flow control failed"
// @Router /flows/{flowID}/control/abort [post]
func (s *FlowControlService) AbortFlow(c *gin.Context) {
	flowID, ok := s.getFlowID(c)
	if !ok {
		return
	}
	if !s.checkFlowPermission(c, flowID) {
		return
	}

	state, err := s.fc.GetFlowControlManager().Abort(flowID)
	if err != nil {
		logger.FromContext(c).WithError(err).Error("failed to abort flow")
		response.Error(c, response.ErrFlowControlFailed, err)
		return
	}

	response.Success(c, http.StatusOK, stateToResponse(state))
}
