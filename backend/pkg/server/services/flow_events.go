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

	// Periodic poll ticker — poll DB for updated metrics + agent activity every 5s
	pollTicker := time.NewTicker(5 * time.Second)
	defer pollTicker.Stop()

	// Track last seen agent log ID to detect new activity
	var lastAgentLogID int64

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

		case <-pollTicker.C:
			// Send updated metrics from DB
			s.sendMetrics(c, flowID)
			// Send updated phase
			s.sendPhaseUpdate(c, flowID)
			// Send new agent activity if any
			lastAgentLogID = s.sendNewAgentActivity(c, flowID, lastAgentLogID)
			// Send any new findings from subtask results
			s.sendFindingsUpdate(c, flowID)
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

	// Send existing findings from subtask results
	s.sendExistingFindings(c, flowID)

	// Send latest agent activity
	s.sendLatestAgentActivity(c, flowID)
}

// sendMetrics queries real DB tables for metrics and sends a metric event.
func (s *FlowEventsService) sendMetrics(c *gin.Context, flowID int64) {
	ctx := c.Request.Context()

	flow, err := s.dbc.GetFlow(ctx, flowID)
	if err != nil {
		return
	}

	// Get tool call count from toolcalls table
	var commandsRun int
	toolStats, err := s.dbc.GetFlowToolcallsStats(ctx, flowID)
	if err == nil {
		commandsRun = int(toolStats.TotalCount)
	}

	// Get terminal log count as additional command indicator
	termLogs, err := s.dbc.GetFlowTermLogs(ctx, flowID)
	if err == nil && commandsRun == 0 {
		// If no toolcalls, count terminal commands instead
		commandsRun = len(termLogs)
	}

	// Count findings from subtask results (the real data source)
	findingsCount := s.countFindings(ctx, flowID)

	// Estimate attacks done based on toolcall function names
	attacksDone, attacksBlocked := s.countAttacks(ctx, flowID)

	// Calculate elapsed time
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

// countFindings counts findings from subtask results AND agentlog results.
func (s *FlowEventsService) countFindings(ctx context.Context, flowID int64) int {
	count := 0

	// Check subtask results for finding markers
	tasks, err := s.dbc.GetFlowTasks(ctx, flowID)
	if err != nil {
		return 0
	}

	for _, task := range tasks {
		subtasks, stErr := s.dbc.GetTaskSubtasks(ctx, task.ID)
		if stErr != nil {
			continue
		}
		for _, st := range subtasks {
			count += countFindingMarkers(st.Result)
			// Also check subtask context for explicit findings_count
			if st.Context != "" {
				var state struct {
					FindingsCount int `json:"findings_count"`
				}
				if json.Unmarshal([]byte(st.Context), &state) == nil && state.FindingsCount > 0 {
					if state.FindingsCount > count {
						count = state.FindingsCount
					}
				}
			}
		}
	}

	// Also check agentlog results for findings
	agentLogs, err := s.dbc.GetFlowAgentLogs(ctx, flowID)
	if err == nil {
		for _, log := range agentLogs {
			count += countFindingMarkers(log.Result)
		}
	}

	return count
}

// countAttacks estimates attacks done/blocked from toolcalls and termlogs.
func (s *FlowEventsService) countAttacks(ctx context.Context, flowID int64) (done, blocked int) {
	// First check subtask contexts for explicit attack tracking
	tasks, err := s.dbc.GetFlowTasks(ctx, flowID)
	if err != nil {
		return 0, 0
	}

	for _, task := range tasks {
		subtasks, stErr := s.dbc.GetTaskSubtasks(ctx, task.ID)
		if stErr != nil {
			continue
		}
		for _, st := range subtasks {
			if st.Context != "" {
				var state struct {
					AttacksDone    []string `json:"attacks_done"`
					AttacksBlocked int      `json:"attacks_blocked"`
				}
				if json.Unmarshal([]byte(st.Context), &state) == nil {
					done += len(state.AttacksDone)
					blocked += state.AttacksBlocked
				}
			}
		}
	}

	// If no explicit tracking, estimate from toolcalls grouped by function name
	if done == 0 {
		funcStats, tcErr := s.dbc.GetToolcallsStatsByFunctionForFlow(ctx, flowID)
		if tcErr == nil {
			attackTools := map[string]bool{
				"terminal":    true,
				"nuclei":      true,
				"nmap":        true,
				"sqlmap":      true,
				"interactsh":  true,
				"exec_cmd":    true,
				"run_command": true,
			}
			for _, fs := range funcStats {
				name := strings.ToLower(fs.FunctionName)
				if attackTools[name] || strings.Contains(name, "scan") || strings.Contains(name, "exploit") || strings.Contains(name, "attack") {
					done += int(fs.TotalCount)
				}
			}
		}
	}

	return done, blocked
}

// sendPhaseUpdate sends the current phase.
func (s *FlowEventsService) sendPhaseUpdate(c *gin.Context, flowID int64) {
	ctx := c.Request.Context()
	flow, err := s.dbc.GetFlow(ctx, flowID)
	if err != nil {
		return
	}

	phase := inferPhaseFromFlow(ctx, s.dbc, flowID)
	s.writeSSE(c, SSEEventPhaseChange, PhaseChangeEvent{
		Phase:     phase,
		Status:    string(flow.Status),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
}

// sendLatestAgentActivity sends the most recent agent activity.
func (s *FlowEventsService) sendLatestAgentActivity(c *gin.Context, flowID int64) {
	ctx := c.Request.Context()
	agentLogs, err := s.dbc.GetFlowAgentLogs(ctx, flowID)
	if err != nil || len(agentLogs) == 0 {
		return
	}

	// agentLogs are ordered by created_at ASC, so last is latest
	latest := agentLogs[len(agentLogs)-1]
	agentName := string(latest.Executor)
	if agentName == "" {
		agentName = string(latest.Initiator)
	}
	if agentName == "" {
		agentName = "agent"
	}

	summary := latest.Task
	if summary == "" {
		summary = truncate(latest.Result, 200)
	}

	s.writeSSE(c, SSEEventAgentActivity, AgentActivityEvent{
		AgentName:     agentName,
		ActionSummary: summary,
	})
}

// sendNewAgentActivity sends agent activity that's newer than lastSeenID.
// Returns the new lastSeenID.
func (s *FlowEventsService) sendNewAgentActivity(c *gin.Context, flowID int64, lastSeenID int64) int64 {
	ctx := c.Request.Context()
	agentLogs, err := s.dbc.GetFlowAgentLogs(ctx, flowID)
	if err != nil || len(agentLogs) == 0 {
		return lastSeenID
	}

	// agentLogs are ordered by created_at ASC, so last is latest
	latest := agentLogs[len(agentLogs)-1]
	latestID := latest.ID
	if latestID <= lastSeenID {
		return lastSeenID // no new activity
	}
	agentName := string(latest.Executor)
	if agentName == "" {
		agentName = string(latest.Initiator)
	}
	if agentName == "" {
		agentName = "agent"
	}

	summary := latest.Task
	if summary == "" {
		summary = truncate(latest.Result, 200)
	}

	s.writeSSE(c, SSEEventAgentActivity, AgentActivityEvent{
		AgentName:     agentName,
		ActionSummary: summary,
	})

	return latestID
}

// findingsTracker keeps track of which findings have already been sent.
// This is a simple approach - in production you'd use a more robust dedup mechanism.
var findingsSentPerFlow = sync.Map{} // flowID -> map[string]bool

func (s *FlowEventsService) sendFindingsUpdate(c *gin.Context, flowID int64) {
	ctx := c.Request.Context()

	sentI, _ := findingsSentPerFlow.LoadOrStore(flowID, &sync.Map{})
	sent := sentI.(*sync.Map)

	findings := s.extractAllFindings(ctx, flowID)
	for _, f := range findings {
		if _, already := sent.LoadOrStore(f.ID, true); !already {
			s.writeSSE(c, SSEEventFinding, f)
		}
	}
}

// sendExistingFindings sends all existing findings for the flow on initial connect.
func (s *FlowEventsService) sendExistingFindings(c *gin.Context, flowID int64) {
	ctx := c.Request.Context()

	sentI, _ := findingsSentPerFlow.LoadOrStore(flowID, &sync.Map{})
	sent := sentI.(*sync.Map)

	findings := s.extractAllFindings(ctx, flowID)
	for _, f := range findings {
		sent.Store(f.ID, true)
		s.writeSSE(c, SSEEventFinding, f)
	}
}

// extractAllFindings extracts findings from subtask results and agentlog results.
func (s *FlowEventsService) extractAllFindings(ctx context.Context, flowID int64) []FindingEvent {
	var findings []FindingEvent
	findingID := 0

	// Extract from subtask results
	tasks, err := s.dbc.GetFlowTasks(ctx, flowID)
	if err == nil {
		for _, task := range tasks {
			subtasks, stErr := s.dbc.GetTaskSubtasks(ctx, task.ID)
			if stErr != nil {
				continue
			}
			for _, st := range subtasks {
				extracted := extractFindingEvents(st.Result, &findingID)
				findings = append(findings, extracted...)
			}
		}
	}

	// Also extract from agentlog results
	agentLogs, err := s.dbc.GetFlowAgentLogs(ctx, flowID)
	if err == nil {
		for _, log := range agentLogs {
			extracted := extractFindingEvents(log.Result, &findingID)
			findings = append(findings, extracted...)
		}
	}

	return findings
}

// extractFindingEvents extracts FindingEvent entries from a text block.
func extractFindingEvents(text string, idCounter *int) []FindingEvent {
	if !strings.Contains(text, "FINDING") && !strings.Contains(text, "finding") &&
		!strings.Contains(text, "vulnerability") && !strings.Contains(text, "Vulnerability") {
		return nil
	}

	var findings []FindingEvent
	lines := strings.Split(text, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Match various finding formats:
		// - [FINDING: ...] style markers
		// - Lines with severity keywords that look like findings
		// - Markdown list items describing vulnerabilities
		isFinding := false
		if strings.Contains(line, "[FINDING") || strings.Contains(line, "[finding") {
			isFinding = true
		} else if (strings.Contains(line, "CRITICAL") || strings.Contains(line, "HIGH") ||
			strings.Contains(line, "MEDIUM") || strings.Contains(line, "LOW")) &&
			(strings.Contains(strings.ToLower(line), "vuln") ||
				strings.Contains(strings.ToLower(line), "finding") ||
				strings.Contains(strings.ToLower(line), "exploit")) {
			isFinding = true
		}

		if !isFinding {
			continue
		}

		*idCounter++
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

		findings = append(findings, FindingEvent{
			ID:       fmt.Sprintf("finding-%d", *idCounter),
			Severity: severity,
			Title:    truncate(line, 120),
			Target:   "",
			VulnType: vulnType,
		})
	}

	return findings
}

// countFindingMarkers counts finding-related markers in text.
func countFindingMarkers(text string) int {
	if text == "" {
		return 0
	}
	count := strings.Count(text, "[FINDING")
	count += strings.Count(text, "[finding")
	return count
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

	// Check agentlog content for phase hints (iterate from latest to oldest)
	agentLogs, err := dbc.GetFlowAgentLogs(ctx, flowID)
	if err == nil {
		for i := len(agentLogs) - 1; i >= 0; i-- {
			log := agentLogs[i]
			combined := strings.ToLower(log.Task + " " + log.Result)
			if strings.Contains(combined, "report") || strings.Contains(combined, "summary") || strings.Contains(combined, "final") {
				return "report"
			}
			if strings.Contains(combined, "exploit") || strings.Contains(combined, "chain") || strings.Contains(combined, "attack chain") {
				return "chains"
			}
			if strings.Contains(combined, "deep dive") || strings.Contains(combined, "injection") || strings.Contains(combined, "xss") || strings.Contains(combined, "sqli") {
				return "deep_dive"
			}
			if strings.Contains(combined, "triage") || strings.Contains(combined, "priorit") || strings.Contains(combined, "classif") {
				return "triage"
			}
			if strings.Contains(combined, "auth") || strings.Contains(combined, "login") || strings.Contains(combined, "session") || strings.Contains(combined, "cookie") {
				return "auth"
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
