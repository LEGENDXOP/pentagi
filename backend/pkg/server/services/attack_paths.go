package services

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"pentagi/pkg/database"
	"pentagi/pkg/server/models"
	"pentagi/pkg/server/response"
	"pentagi/pkg/tools"

	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
)

var (
	errAttackPathsInvalidFlowID = response.NewHttpError(http.StatusBadRequest, "AttackPaths.InvalidFlowID", "invalid flow ID")
	errAttackPathsFlowNotFound  = response.NewHttpError(http.StatusNotFound, "AttackPaths.FlowNotFound", "flow not found")
	errAttackPathsInternal      = response.NewHttpError(http.StatusInternalServerError, "AttackPaths.Internal", "internal error")
)

// AttackPathService provides the REST endpoint for attack-path visualization.
type AttackPathService struct {
	db  *gorm.DB
	dbc database.Querier
}

// NewAttackPathService creates a new service instance.
func NewAttackPathService(db *gorm.DB, dbc database.Querier) *AttackPathService {
	return &AttackPathService{db: db, dbc: dbc}
}

// GetFlowAttackPaths computes and returns attack paths for a flow.
// @Summary Get attack paths for a flow
// @Tags AttackPaths
// @Produce json
// @Security BearerAuth
// @Param flowID path int true "flow ID"
// @Param max_hops query int false "maximum hops per path (2-10, default 6)"
// @Param target query string false "optional target filter (IP/hostname/URL prefix)"
// @Success 200 {object} response.successResp{data=models.AttackPathGraphResponse} "attack paths"
// @Failure 400 {object} response.errorResp "invalid flow ID"
// @Failure 404 {object} response.errorResp "flow not found"
// @Failure 500 {object} response.errorResp "internal error"
// @Router /flows/{flowID}/attack-paths [get]
func (s *AttackPathService) GetFlowAttackPaths(c *gin.Context) {
	flowID, err := strconv.ParseInt(c.Param("flowID"), 10, 64)
	if err != nil {
		response.Error(c, errAttackPathsInvalidFlowID, err)
		return
	}

	ctx := c.Request.Context()

	// Verify flow exists.
	_, err = s.dbc.GetFlow(ctx, flowID)
	if err != nil {
		response.Error(c, errAttackPathsFlowNotFound, err)
		return
	}

	// Parse optional query params.
	maxHops := 6
	if mh := c.Query("max_hops"); mh != "" {
		if v, parseErr := strconv.Atoi(mh); parseErr == nil {
			if v >= 2 && v <= 10 {
				maxHops = v
			}
		}
	}
	targetFilter := strings.TrimSpace(c.Query("target"))

	// Collect finding results from subtasks.
	findingResults, err := collectFlowFindingResults(ctx, s.dbc, flowID, targetFilter)
	if err != nil {
		response.Error(c, errAttackPathsInternal, err)
		return
	}

	emptyResp := &models.AttackPathGraphResponse{
		FlowID:        flowID,
		FindingsCount: 0,
		Nodes:         []models.AttackPathNode{},
		Edges:         []models.AttackPathEdge{},
		Paths:         []models.AttackPathResponse{},
	}

	if len(findingResults) == 0 {
		response.Success(c, http.StatusOK, emptyResp)
		return
	}

	// Reuse the tools package parsing + graph builder.
	findings := tools.ParseFindingsFromResults(findingResults)
	if len(findings) == 0 {
		response.Success(c, http.StatusOK, emptyResp)
		return
	}

	ag := tools.BuildAttackGraphFromParsed(findings, maxHops)

	// Convert to response models.
	respNodes := make([]models.AttackPathNode, len(ag.Nodes))
	for i, n := range ag.Nodes {
		respNodes[i] = models.AttackPathNode{
			ID:    n.ID,
			Type:  string(n.Type),
			Label: n.Label,
		}
	}

	respEdges := make([]models.AttackPathEdge, len(ag.Edges))
	for i, e := range ag.Edges {
		respEdges[i] = models.AttackPathEdge{
			Source:      e.Source,
			Target:      e.Target,
			Label:       e.Label,
			Severity:    e.Severity,
			FindingID:   e.FindingID,
			Weight:      e.Weight,
			Description: e.Description,
		}
	}

	respPaths := make([]models.AttackPathResponse, len(ag.Paths))
	for i, p := range ag.Paths {
		steps := make([]models.AttackPathStepResponse, len(p.Steps))
		for j, s := range p.Steps {
			steps[j] = models.AttackPathStepResponse{
				From:        s.From,
				To:          s.To,
				FindingID:   s.FindingID,
				Description: s.Description,
				Severity:    s.Severity,
				Weight:      s.Weight,
			}
		}
		respPaths[i] = models.AttackPathResponse{
			Steps:       steps,
			TotalWeight: p.TotalWeight,
			Feasibility: p.Feasibility,
			StepsCount:  p.StepsCount,
			Summary:     p.Summary,
		}
	}

	resp := &models.AttackPathGraphResponse{
		FlowID:        flowID,
		FindingsCount: len(findings),
		Nodes:         respNodes,
		Edges:         respEdges,
		Paths:         respPaths,
	}
	response.Success(c, http.StatusOK, resp)
}

// collectFlowFindingResults returns all subtask result strings that contain [FINDING markers.
func collectFlowFindingResults(ctx context.Context, dbc database.Querier, flowID int64, targetFilter string) ([]string, error) {
	tasks, err := dbc.GetFlowTasks(ctx, flowID)
	if err != nil {
		return nil, err
	}

	var results []string
	for _, task := range tasks {
		subtasks, stErr := dbc.GetTaskSubtasks(ctx, task.ID)
		if stErr != nil {
			continue
		}
		for _, st := range subtasks {
			if !strings.Contains(st.Result, "[FINDING") {
				continue
			}
			if targetFilter != "" && !strings.Contains(strings.ToLower(st.Result), strings.ToLower(targetFilter)) {
				continue
			}
			results = append(results, st.Result)
		}
	}
	return results, nil
}
