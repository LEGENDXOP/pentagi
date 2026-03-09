package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"pentagi/pkg/database"
	"pentagi/pkg/server/logger"
	"pentagi/pkg/server/response"

	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	"github.com/sirupsen/logrus"
)

// ==================== SSE Event Types ====================

const (
	SSEEventPhaseChange   = "phase_change"
	SSEEventFinding       = "finding"
	SSEEventCommand       = "command"
	SSEEventMetric        = "metric"
	SSEEventAgentActivity = "agent_activity"
	SSEEventHeartbeat     = "heartbeat"
)

// PhaseChangeEvent represents a phase transition in the pentest flow.
type PhaseChangeEvent struct {
	Phase     string `json:"phase"`
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
}

// FindingEvent represents a new vulnerability finding.
type FindingEvent struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Target   string `json:"target"`
	VulnType string `json:"vuln_type"`
}

// CommandEvent represents an executed command.
type CommandEvent struct {
	CmdSummary string `json:"cmd_summary"`
	Agent      string `json:"agent"`
	Status     string `json:"status"`
	ExitCode   int    `json:"exit_code"`
}

// MetricEvent represents aggregated metrics.
type MetricEvent struct {
	CommandsRun    int `json:"commands_run"`
	FindingsCount  int `json:"findings_count"`
	ElapsedSeconds int `json:"elapsed_seconds"`
	AttacksDone    int `json:"attacks_done"`
	AttacksBlocked int `json:"attacks_blocked"`
}

// AgentActivityEvent represents agent activity.
type AgentActivityEvent struct {
	AgentName     string `json:"agent_name"`
	ActionSummary string `json:"action_summary"`
}

// ==================== Event Bus ====================

// FlowEvent is a structured event emitted for a flow.
type FlowEvent struct {
	EventType string      `json:"event_type"`
	Data      interface{} `json:"data"`
}

// flowEventBus manages per-flow event channels with fan-out to multiple listeners.
type flowEventBus struct {
	mu        sync.RWMutex
	listeners map[int64]map[int64]chan FlowEvent // flowID -> listenerID -> channel
	nextID    int64
}

var globalEventBus = &flowEventBus{
	listeners: make(map[int64]map[int64]chan FlowEvent),
}

// subscribe registers a new listener for a flow and returns the channel + unsubscribe func.
func (b *flowEventBus) subscribe(flowID int64) (<-chan FlowEvent, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.nextID++
	id := b.nextID

	ch := make(chan FlowEvent, 64)
	if b.listeners[flowID] == nil {
		b.listeners[flowID] = make(map[int64]chan FlowEvent)
	}
	b.listeners[flowID][id] = ch

	unsub := func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if m, ok := b.listeners[flowID]; ok {
			delete(m, id)
			if len(m) == 0 {
				delete(b.listeners, flowID)
			}
		}
		// drain and close
		close(ch)
	}

	return ch, unsub
}

// publish sends an event to all listeners for a flow (non-blocking).
func (b *flowEventBus) publish(flowID int64, event FlowEvent) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if listeners, ok := b.listeners[flowID]; ok {
		for _, ch := range listeners {
			select {
			case ch <- event:
			default:
				// drop if listener is too slow
			}
		}
	}
}

// EmitFlowEvent is the global function for backend code to emit events to the SSE bus.
func EmitFlowEvent(flowID int64, eventType string, data interface{}) {
	globalEventBus.publish(flowID, FlowEvent{
		EventType: eventType,
		Data:      data,
	})
}

// ==================== Flow Events Service ====================

// FlowEventsService provides the SSE endpoint for real-time flow events.
type FlowEventsService struct {
	db  *gorm.DB
	dbc database.Querier
}

// NewFlowEventsService creates a new FlowEventsService.
func NewFlowEventsService(db *gorm.DB, dbc database.Querier) *FlowEventsService {
	return &FlowEventsService{
		db:  db,
		dbc: dbc,
	}
}

// StreamFlowEvents handles GET /api/v1/flows/:flowID/events as an SSE endpoint.
// @Summary Stream real-time flow events via SSE
// @Tags FlowEvents
// @Produce text/event-stream
// @Security BearerAuth
// @Param flowID path int true "flow ID"
// @Success 200 {string} string "SSE event stream"
// @Failure 400 {object} response.errorResp "invalid flow ID"
// @Failure 404 {object} response.errorResp "flow not found"
// @Router /flows/{flowID}/events [get]
func (s *FlowEventsService) StreamFlowEvents(c *gin.Context) {
	flowID, err := strconv.ParseInt(c.Param("flowID"), 10, 64)
	if err != nil {
		response.Error(c, response.ErrFlowsInvalidRequest, err)
		return
	}

	// Verify flow exists
	ctx := c.Request.Context()
	flow, err := s.dbc.GetFlow(ctx, flowID)
	if err != nil {
		response.Error(c, response.ErrFlowsNotFound, err)
		return
	}

	// Set SSE headers
	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering
	c.Writer.WriteHeader(http.StatusOK)
	c.Writer.Flush()

	// Subscribe to flow events
	eventCh, unsub := globalEventBus.subscribe(flowID)
	defer unsub()

	// Send initial snapshot of current state
	s.sendInitialState(c, flowID, flow)

	// Heartbeat ticker
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	// Periodic metric ticker — poll DB for updated metrics every 5s
	metricTicker := time.NewTicker(5 * time.Second)
	defer metricTicker.Stop()

	clientGone := c.Request.Context().Done()

	for {
		select {
		case <-clientGone:
			logger.FromContext(c).Info("SSE client disconnected")
			return

		case event, ok := <-eventCh:
			if !ok {
				return
			}
			s.writeSSE(c, event.EventType, event.Data)

		case <-heartbeat.C:
			s.writeSSE(c, SSEEventHeartbeat, map[string]string{
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			})

		case <-metricTicker.C:
			s.sendMetrics(c, flowID)
		}
	}
}

// sendInitialState sends the current state of the flow as initial SSE events.
func (s *FlowEventsService) sendInitialState(c *gin.Context, flowID int64, flow database.Flow) {
	// Send current phase
	phase := inferPhaseFromFlow(c.Request.Context(), s.dbc, flowID)
	s.writeSSE(c, SSEEventPhaseChange, PhaseChangeEvent{
		Phase:     phase,
		Status:    string(flow.Status),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})

	// Send initial metrics
	s.sendMetrics(c, flowID)

	// Send existing findings
	s.sendExistingFindings(c, flowID)
}

// sendMetrics polls the DB and sends a metric event.
func (s *FlowEventsService) sendMetrics(c *gin.Context, flowID int64) {
	ctx := c.Request.Context()
	flow, err := s.dbc.GetFlow(ctx, flowID)
	if err != nil {
		return
	}

	tasks, err := s.dbc.GetFlowTasks(ctx, flowID)
	if err != nil {
		tasks = nil
	}

	var commandsRun, findingsCount, attacksDone, attacksBlocked int
	for _, task := range tasks {
		subtasks, stErr := s.dbc.GetTaskSubtasks(ctx, task.ID)
		if stErr != nil {
			continue
		}
		for _, st := range subtasks {
			if st.Context != "" {
				var state struct {
					ToolCallCount  int      `json:"tool_call_count"`
					FindingsCount  int      `json:"findings_count"`
					AttacksDone    []string `json:"attacks_done"`
					AttacksBlocked int      `json:"attacks_blocked"`
				}
				if json.Unmarshal([]byte(st.Context), &state) == nil {
					commandsRun += state.ToolCallCount
					findingsCount += state.FindingsCount
					attacksDone += len(state.AttacksDone)
					attacksBlocked += state.AttacksBlocked
				}
			}
			if strings.Contains(st.Result, "[FINDING") {
				findingsCount += strings.Count(st.Result, "[FINDING")
			}
		}
	}

	var elapsed int
	if flow.CreatedAt.Valid {
		elapsed = int(time.Since(flow.CreatedAt.Time).Seconds())
	}

	s.writeSSE(c, SSEEventMetric, MetricEvent{
		CommandsRun:    commandsRun,
		FindingsCount:  findingsCount,
		ElapsedSeconds: elapsed,
		AttacksDone:    attacksDone,
		AttacksBlocked: attacksBlocked,
	})
}

// sendExistingFindings sends all existing findings for the flow.
func (s *FlowEventsService) sendExistingFindings(c *gin.Context, flowID int64) {
	ctx := c.Request.Context()
	tasks, err := s.dbc.GetFlowTasks(ctx, flowID)
	if err != nil {
		return
	}

	findingID := 0
	for _, task := range tasks {
		subtasks, stErr := s.dbc.GetTaskSubtasks(ctx, task.ID)
		if stErr != nil {
			continue
		}
		for _, st := range subtasks {
			if !strings.Contains(st.Result, "FINDING") {
				continue
			}
			lines := strings.Split(st.Result, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if !strings.Contains(line, "[FINDING") {
					continue
				}
				findingID++
				severity := "MEDIUM"
				for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
					if strings.Contains(strings.ToUpper(line), sev) {
						severity = sev
						break
					}
				}
				vulnType := ""
				if idx := strings.Index(line, "[VULN_TYPE:"); idx >= 0 {
					end := strings.Index(line[idx:], "]")
					if end > 0 {
						vulnType = strings.TrimSpace(line[idx+11 : idx+end])
					}
				}
				s.writeSSE(c, SSEEventFinding, FindingEvent{
					ID:       fmt.Sprintf("finding-%d", findingID),
					Severity: severity,
					Title:    truncate(line, 120),
					Target:   "",
					VulnType: vulnType,
				})
			}
		}
	}
}

// writeSSE writes an SSE-formatted event to the response writer.
func (s *FlowEventsService) writeSSE(c *gin.Context, eventType string, data interface{}) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		logrus.WithError(err).Error("failed to marshal SSE event data")
		return
	}

	_, writeErr := fmt.Fprintf(c.Writer, "event: %s\ndata: %s\n\n", eventType, string(jsonData))
	if writeErr != nil {
		logrus.WithError(writeErr).Debug("failed to write SSE event (client likely disconnected)")
		return
	}
	c.Writer.Flush()
}

// inferPhaseFromFlow determines the current phase based on flow state.
func inferPhaseFromFlow(ctx context.Context, dbc database.Querier, flowID int64) string {
	tasks, err := dbc.GetFlowTasks(ctx, flowID)
	if err != nil || len(tasks) == 0 {
		return "recon"
	}

	// Check subtask contexts for explicit phase
	for i := len(tasks) - 1; i >= 0; i-- {
		subtasks, stErr := dbc.GetTaskSubtasks(ctx, tasks[i].ID)
		if stErr != nil {
			continue
		}
		for j := len(subtasks) - 1; j >= 0; j-- {
			if subtasks[j].Context != "" {
				var state struct {
					Phase string `json:"phase"`
				}
				if json.Unmarshal([]byte(subtasks[j].Context), &state) == nil && state.Phase != "" {
					return state.Phase
				}
			}
		}
	}

	// Heuristic: based on task count and status
	lastTask := tasks[len(tasks)-1]
	if lastTask.Status == database.TaskStatusFinished {
		return "report"
	}

	totalSubtasks := 0
	for _, t := range tasks {
		subs, _ := dbc.GetTaskSubtasks(ctx, t.ID)
		totalSubtasks += len(subs)
	}

	switch {
	case totalSubtasks <= 2:
		return "recon"
	case totalSubtasks <= 5:
		return "auth"
	case totalSubtasks <= 10:
		return "triage"
	case totalSubtasks <= 15:
		return "deep_dive"
	case totalSubtasks <= 20:
		return "chains"
	default:
		return "report"
	}
}

// truncate shortens a string to max length.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
