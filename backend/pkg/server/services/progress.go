package services

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"pentagi/pkg/database"
	"pentagi/pkg/server/models"
	"pentagi/pkg/server/response"

	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
)

var (
	errProgressInvalidFlowID = response.NewHttpError(http.StatusBadRequest, "Progress.InvalidFlowID", "invalid flow ID")
	errProgressFlowNotFound  = response.NewHttpError(http.StatusNotFound, "Progress.FlowNotFound", "flow not found")
	errProgressInternal      = response.NewHttpError(http.StatusInternalServerError, "Progress.Internal", "internal error")
)

// ProgressService provides real-time flow progress endpoints for dashboard consumption.
type ProgressService struct {
	db    *gorm.DB
	dbc   database.Querier
	cache sync.Map // flowID -> cachedProgress
}

type cachedProgress struct {
	data      *models.FlowProgressResponse
	timestamp time.Time
}

const progressCacheTTL = 5 * time.Second

func NewProgressService(db *gorm.DB, dbc database.Querier) *ProgressService {
	return &ProgressService{
		db:  db,
		dbc: dbc,
	}
}

// GetFlowProgress returns real-time execution progress for a flow.
// @Summary Get flow execution progress
// @Tags Progress
// @Produce json
// @Security BearerAuth
// @Param flowID path int true "flow ID"
// @Success 200 {object} response.successResp{data=models.FlowProgressResponse} "flow progress"
// @Failure 400 {object} response.errorResp "invalid flow ID"
// @Failure 404 {object} response.errorResp "flow not found"
// @Failure 500 {object} response.errorResp "internal error"
// @Router /flows/{flowID}/progress [get]
func (s *ProgressService) GetFlowProgress(c *gin.Context) {
	flowID, err := strconv.ParseInt(c.Param("flowID"), 10, 64)
	if err != nil {
		response.Error(c, errProgressInvalidFlowID, err)
		return
	}

	// Check cache
	if cached, ok := s.cache.Load(flowID); ok {
		cp := cached.(*cachedProgress)
		if time.Since(cp.timestamp) < progressCacheTTL {
			response.Success(c, http.StatusOK, cp.data)
			return
		}
	}

	ctx := c.Request.Context()

	// Get flow
	flow, err := s.dbc.GetFlow(ctx, flowID)
	if err != nil {
		response.Error(c, errProgressFlowNotFound, err)
		return
	}

	// Get tasks for this flow
	tasks, err := s.dbc.GetFlowTasks(ctx, flowID)
	if err != nil {
		tasks = nil // non-fatal
	}

	// Get subtasks with context
	var totalSubtasks, doneSubtasks, runningSubtasks int
	var toolCallCount, errorCount, findingsCount int
	var phase, currentAttack string
	var attacksDone int

	for _, task := range tasks {
		subtasks, stErr := s.dbc.GetTaskSubtasks(ctx, task.ID)
		if stErr != nil {
			continue
		}
		for _, st := range subtasks {
			totalSubtasks++
			switch st.Status {
			case database.SubtaskStatusFinished, database.SubtaskStatusFailed:
				doneSubtasks++
			case database.SubtaskStatusRunning:
				runningSubtasks++
			}

			// Parse execution state from context
			if st.Context != "" {
				var state struct {
					Phase         string   `json:"phase"`
					ToolCallCount int      `json:"tool_call_count"`
					FindingsCount int      `json:"findings_count"`
					AttacksDone   []string `json:"attacks_done"`
					CurrentAttack string   `json:"current_attack"`
					ErrorCount    int      `json:"error_count"`
				}
				if json.Unmarshal([]byte(st.Context), &state) == nil {
					toolCallCount += state.ToolCallCount
					errorCount += state.ErrorCount
					findingsCount += state.FindingsCount
					if state.Phase != "" {
						phase = state.Phase
					}
					if state.CurrentAttack != "" {
						currentAttack = state.CurrentAttack
					}
					attacksDone += len(state.AttacksDone)
				}
			}

			// Count findings from results
			if strings.Contains(st.Result, "[FINDING") {
				findingsCount += strings.Count(st.Result, "[FINDING")
			}
		}
	}

	// Calculate elapsed time
	var elapsed int
	if flow.CreatedAt.Valid {
		elapsed = int(time.Since(flow.CreatedAt.Time).Seconds())
	}

	progress := &models.FlowProgressResponse{
		FlowID:          flowID,
		Status:          string(flow.Status),
		Phase:           phase,
		ToolCallCount:   toolCallCount,
		ElapsedSeconds:  elapsed,
		FindingsCount:   findingsCount,
		UniqueFindings:  findingsCount,
		AttacksDone:     attacksDone,
		AttacksTotal:    19,
		ErrorCount:      errorCount,
		CurrentAttack:   currentAttack,
		TasksCount:      len(tasks),
		SubtasksCount:   totalSubtasks,
		SubtasksDone:    doneSubtasks,
		SubtasksRunning: runningSubtasks,
	}

	// Cache result
	s.cache.Store(flowID, &cachedProgress{
		data:      progress,
		timestamp: time.Now(),
	})

	response.Success(c, http.StatusOK, progress)
}

// GetFlowFindings returns structured findings for a flow.
// @Summary Get flow findings
// @Tags Progress
// @Produce json
// @Security BearerAuth
// @Param flowID path int true "flow ID"
// @Success 200 {object} response.successResp{data=models.FlowFindingsResponse} "flow findings"
// @Failure 400 {object} response.errorResp "invalid flow ID"
// @Failure 500 {object} response.errorResp "internal error"
// @Router /flows/{flowID}/findings [get]
func (s *ProgressService) GetFlowFindings(c *gin.Context) {
	flowID, err := strconv.ParseInt(c.Param("flowID"), 10, 64)
	if err != nil {
		response.Error(c, errProgressInvalidFlowID, err)
		return
	}

	ctx := c.Request.Context()
	tasks, err := s.dbc.GetFlowTasks(ctx, flowID)
	if err != nil {
		response.Error(c, errProgressInternal, err)
		return
	}

	var findings []models.FlowFinding
	for _, task := range tasks {
		subtasks, stErr := s.dbc.GetTaskSubtasks(ctx, task.ID)
		if stErr != nil {
			continue
		}
		for _, st := range subtasks {
			if !strings.Contains(st.Result, "FINDING") {
				continue
			}
			extracted := extractFindingsFromResult(st.Result)
			findings = append(findings, extracted...)
		}
	}

	resp := &models.FlowFindingsResponse{
		FlowID:     flowID,
		Findings:   findings,
		TotalCount: len(findings),
	}

	response.Success(c, http.StatusOK, resp)
}

// GetFlowCost returns cost tracking data for a flow.
// @Summary Get flow cost data
// @Tags Progress
// @Produce json
// @Security BearerAuth
// @Param flowID path int true "flow ID"
// @Success 200 {object} response.successResp{data=models.FlowCostResponse} "flow cost data"
// @Failure 400 {object} response.errorResp "invalid flow ID"
// @Failure 500 {object} response.errorResp "internal error"
// @Router /flows/{flowID}/cost [get]
func (s *ProgressService) GetFlowCost(c *gin.Context) {
	flowID, err := strconv.ParseInt(c.Param("flowID"), 10, 64)
	if err != nil {
		response.Error(c, errProgressInvalidFlowID, err)
		return
	}

	ctx := c.Request.Context()

	// Query usage stats from DB
	stats, err := s.dbc.GetFlowUsageStats(ctx, flowID)
	if err != nil {
		response.Error(c, errProgressInternal, err)
		return
	}

	totalIn := stats.TotalUsageIn
	totalOut := stats.TotalUsageOut
	totalCost := stats.TotalUsageCostIn + stats.TotalUsageCostOut

	// Get findings count for cost-per-finding
	findingsCount := 0
	tasks, _ := s.dbc.GetFlowTasks(ctx, flowID)
	for _, task := range tasks {
		subtasks, _ := s.dbc.GetTaskSubtasks(ctx, task.ID)
		for _, st := range subtasks {
			findingsCount += strings.Count(st.Result, "[FINDING")
		}
	}

	costPerFinding := 0.0
	if findingsCount > 0 {
		costPerFinding = totalCost / float64(findingsCount)
	}

	resp := &models.FlowCostResponse{
		FlowID:         flowID,
		TotalTokensIn:  totalIn,
		TotalTokensOut: totalOut,
		TotalCostUSD:   totalCost,
		CostPerFinding: costPerFinding,
	}

	response.Success(c, http.StatusOK, resp)
}

// GetFlowTimeline returns a timeline of events for a flow.
// @Summary Get flow event timeline
// @Tags Progress
// @Produce json
// @Security BearerAuth
// @Param flowID path int true "flow ID"
// @Success 200 {object} response.successResp{data=[]models.FlowTimelineEvent} "flow timeline"
// @Failure 400 {object} response.errorResp "invalid flow ID"
// @Failure 500 {object} response.errorResp "internal error"
// @Router /flows/{flowID}/timeline [get]
func (s *ProgressService) GetFlowTimeline(c *gin.Context) {
	flowID, err := strconv.ParseInt(c.Param("flowID"), 10, 64)
	if err != nil {
		response.Error(c, errProgressInvalidFlowID, err)
		return
	}

	ctx := c.Request.Context()
	tasks, err := s.dbc.GetFlowTasks(ctx, flowID)
	if err != nil {
		response.Error(c, errProgressInternal, err)
		return
	}

	var events []models.FlowTimelineEvent

	// Add flow creation event
	flow, fErr := s.dbc.GetFlow(ctx, flowID)
	if fErr == nil && flow.CreatedAt.Valid {
		events = append(events, models.FlowTimelineEvent{
			Timestamp:   flow.CreatedAt.Time,
			EventType:   models.TimelineEventTaskCreated,
			Description: "Flow started: " + flow.Title,
		})
	}

	// Add subtask events
	for _, task := range tasks {
		subtasks, stErr := s.dbc.GetTaskSubtasks(ctx, task.ID)
		if stErr != nil {
			continue
		}
		for _, st := range subtasks {
			if st.CreatedAt.Valid {
				events = append(events, models.FlowTimelineEvent{
					Timestamp:   st.CreatedAt.Time,
					EventType:   models.TimelineEventSubtask,
					Description: "Started: " + st.Title,
				})
			}
			if st.UpdatedAt.Valid && (st.Status == database.SubtaskStatusFinished || st.Status == database.SubtaskStatusFailed) {
				evtType := models.TimelineEventSubtask
				if st.Status == database.SubtaskStatusFailed {
					evtType = models.TimelineEventError
				}
				events = append(events, models.FlowTimelineEvent{
					Timestamp:   st.UpdatedAt.Time,
					EventType:   evtType,
					Description: string(st.Status) + ": " + st.Title,
				})
			}
			// Extract finding events from results
			if strings.Contains(st.Result, "[FINDING") && st.UpdatedAt.Valid {
				events = append(events, models.FlowTimelineEvent{
					Timestamp:   st.UpdatedAt.Time,
					EventType:   models.TimelineEventFinding,
					Description: "Finding discovered in: " + st.Title,
				})
			}
		}
	}

	response.Success(c, http.StatusOK, events)
}

// extractFindingsFromResult parses finding entries from a subtask result string.
func extractFindingsFromResult(result string) []models.FlowFinding {
	var findings []models.FlowFinding
	lines := strings.Split(result, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "[FINDING") {
			continue
		}
		finding := models.FlowFinding{
			Description: line,
			Severity:    "MEDIUM",
		}
		// Extract severity
		for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
			if strings.Contains(strings.ToUpper(line), sev) {
				finding.Severity = sev
				break
			}
		}
		// Extract vuln type from [VULN_TYPE: xxx]
		if idx := strings.Index(line, "[VULN_TYPE:"); idx >= 0 {
			end := strings.Index(line[idx:], "]")
			if end > 0 {
				finding.VulnType = strings.TrimSpace(line[idx+11 : idx+end])
			}
		}
		findings = append(findings, finding)
	}
	return findings
}
