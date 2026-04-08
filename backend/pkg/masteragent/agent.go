package masteragent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"pentagi/pkg/config"
	"pentagi/pkg/database"
	"pentagi/pkg/notifications"
	"pentagi/pkg/system"

	"github.com/sirupsen/logrus"
	"github.com/vxcontrol/langchaingo/llms"
	"github.com/vxcontrol/langchaingo/llms/anthropic"
)

// FlowControlAdapter is the interface used by the Master Agent to interact with
// the flow control system. This avoids an import cycle with the controller package.
type FlowControlAdapter interface {
	GetControlStatus(flowID int64) (status string, steerMessage string)
	Steer(flowID int64, message string) error
	Pause(flowID int64) error
	Resume(flowID int64) error
	Abort(flowID int64) error
}

// Agent is the LLM-powered Master Agent that supervises a single flow.
// Each cycle it gathers flow data, builds a prompt, calls Claude, and executes the decision.
type Agent struct {
	flowID      int64
	cfg         *config.Config
	maCfg       MasterAgentConfig
	db          database.Querier
	flowControl FlowControlAdapter
	notifier    *notifications.NotificationManager
	state       *CycleState
	logger      *logrus.Entry
}

// NewAgent creates a new Master Agent for the given flow.
func NewAgent(
	flowID int64,
	cfg *config.Config,
	maCfg MasterAgentConfig,
	db database.Querier,
	flowControl FlowControlAdapter,
	notifier *notifications.NotificationManager,
) *Agent {
	return &Agent{
		flowID:      flowID,
		cfg:         cfg,
		maCfg:       maCfg,
		db:          db,
		flowControl: flowControl,
		notifier:    notifier,
		state:       NewCycleState(flowID),
		logger: logrus.WithFields(logrus.Fields{
			"component": "master_agent",
			"flow_id":   flowID,
		}),
	}
}

// isFlowTerminal checks the flow status in the DB and returns true if the flow
// is no longer active (finished, failed, or created). This is a cheap safety net
// to avoid expensive data gathering and LLM calls on dead flows.
func (a *Agent) isFlowTerminal(ctx context.Context) (bool, string) {
	flow, err := a.db.GetFlow(ctx, a.flowID)
	if err != nil {
		a.logger.WithError(err).Warn("failed to check flow status (terminal check), assuming non-terminal")
		return false, ""
	}
	switch flow.Status {
	case database.FlowStatusFinished, database.FlowStatusFailed, database.FlowStatusCreated:
		return true, string(flow.Status)
	default:
		return false, ""
	}
}

// RunCycle executes a single supervision cycle: gather → analyze → decide → act.
func (a *Agent) RunCycle(ctx context.Context) error {
	cycle := a.state.IncrementCycle()
	a.logger.WithField("cycle", cycle).Info("starting master agent cycle")

	// 0. Early terminal check — cheap DB query to avoid wasting LLM calls on dead flows
	if terminal, status := a.isFlowTerminal(ctx); terminal {
		a.logger.WithFields(logrus.Fields{
			"cycle":  cycle,
			"status": status,
		}).Info("flow is terminal before cycle, skipping entirely")
		return nil
	}

	// 1. Gather flow data
	data, err := a.gatherFlowData(ctx)
	if err != nil {
		a.logger.WithError(err).Error("failed to gather flow data")
		return fmt.Errorf("gather flow data: %w", err)
	}

	// Check terminal conditions
	if data.FlowStatus == string(database.FlowStatusFinished) || data.FlowStatus == string(database.FlowStatusFailed) {
		a.logger.WithField("status", data.FlowStatus).Info("flow is terminal, skipping LLM call")
		a.state.RecordHealth(HealthHealthy)
		return nil
	}

	// 2. Build the LLM prompt
	prompt := a.buildPrompt(data)

	// 3. Call Claude
	decision, err := a.callLLM(ctx, prompt)
	if err != nil {
		a.logger.WithError(err).Error("LLM call failed")
		a.state.RecordHealth(HealthWarning)
		return fmt.Errorf("llm call: %w", err)
	}

	a.logger.WithFields(logrus.Fields{
		"action":  decision.Action,
		"health":  decision.Health,
		"reason":  decision.Reasoning,
	}).Info("LLM decision received")

	// 4. Record state
	a.state.RecordHealth(decision.Health)

	// 5. Execute the decision
	if err := a.executeDecision(ctx, decision); err != nil {
		a.logger.WithError(err).Error("failed to execute decision")
		return fmt.Errorf("execute decision: %w", err)
	}

	a.logger.WithField("cycle", cycle).Info("master agent cycle complete")
	return nil
}

// flowData holds all the data gathered for a single cycle.
type flowData struct {
	FlowID        int64
	FlowStatus    string
	FlowTitle     string
	FlowCreatedAt time.Time
	ElapsedTime   time.Duration

	// Messages (recent)
	RecentMessages []database.Msglog

	// Subtasks
	Subtasks []database.Subtask

	// Tasks
	Tasks []database.Task

	// Findings
	Findings      []database.Finding
	FindingsTotal int
	FindingsConfirmed int

	// Tool call stats
	ToolCallStats database.GetFlowToolcallsStatsRow
	ToolCallsByFunc []database.GetToolcallsStatsByFunctionForFlowRow

	// Control state
	ControlStatus string
	SteerMessage  string
}

// gatherFlowData reads all relevant data from the database.
func (a *Agent) gatherFlowData(ctx context.Context) (*flowData, error) {
	data := &flowData{
		FlowID: a.flowID,
	}

	// Get flow info
	flow, err := a.db.GetFlow(ctx, a.flowID)
	if err != nil {
		return nil, fmt.Errorf("get flow: %w", err)
	}
	data.FlowStatus = string(flow.Status)
	data.FlowTitle = flow.Title
	if flow.CreatedAt.Valid {
		data.FlowCreatedAt = flow.CreatedAt.Time
		data.ElapsedTime = time.Since(flow.CreatedAt.Time)
	}

	// Get recent messages
	msgs, err := a.db.GetFlowMsgLogs(ctx, a.flowID)
	if err != nil {
		a.logger.WithError(err).Warn("failed to get flow messages")
	} else {
		// Take last 50 messages
		if len(msgs) > 50 {
			msgs = msgs[len(msgs)-50:]
		}
		data.RecentMessages = msgs

		// Update message cursor
		if len(msgs) > 0 {
			a.state.UpdateMessageCursor(msgs[len(msgs)-1].ID)
		}
	}

	// Get subtasks
	subtasks, err := a.db.GetFlowSubtasks(ctx, a.flowID)
	if err != nil {
		a.logger.WithError(err).Warn("failed to get flow subtasks")
	} else {
		data.Subtasks = subtasks
	}

	// Get tasks
	tasks, err := a.db.GetFlowTasks(ctx, a.flowID)
	if err != nil {
		a.logger.WithError(err).Warn("failed to get flow tasks")
	} else {
		data.Tasks = tasks
	}

	// Get findings
	findings, err := a.db.GetFlowFindings(ctx, a.flowID)
	if err != nil {
		a.logger.WithError(err).Warn("failed to get flow findings")
	} else {
		data.Findings = findings
		data.FindingsTotal = len(findings)
		for _, f := range findings {
			if f.Confirmed {
				data.FindingsConfirmed++
			}
		}
		a.state.UpdateFindingsCounts(data.FindingsTotal, data.FindingsConfirmed)
	}

	// Get tool call stats
	tcStats, err := a.db.GetFlowToolcallsStats(ctx, a.flowID)
	if err != nil {
		a.logger.WithError(err).Warn("failed to get tool call stats")
	} else {
		data.ToolCallStats = tcStats
	}

	// Get tool calls by function
	tcByFunc, err := a.db.GetToolcallsStatsByFunctionForFlow(ctx, a.flowID)
	if err != nil {
		a.logger.WithError(err).Warn("failed to get tool calls by function")
	} else {
		data.ToolCallsByFunc = tcByFunc
	}

	// Get control state
	status, steerMsg := a.flowControl.GetControlStatus(a.flowID)
	data.ControlStatus = status
	data.SteerMessage = steerMsg

	return data, nil
}

// buildPrompt constructs the LLM prompt from gathered flow data.
func (a *Agent) buildPrompt(data *flowData) string {
	var b strings.Builder
	snap := a.state.Snapshot()

	b.WriteString(fmt.Sprintf("# Flow Supervision Data — Cycle %d\n\n", snap.Cycle))

	// Flow overview
	b.WriteString("## Flow Overview\n")
	b.WriteString(fmt.Sprintf("- **Flow ID:** %d\n", data.FlowID))
	b.WriteString(fmt.Sprintf("- **Title:** %s\n", data.FlowTitle))
	b.WriteString(fmt.Sprintf("- **Status:** %s\n", data.FlowStatus))
	b.WriteString(fmt.Sprintf("- **Elapsed:** %s\n", formatDuration(data.ElapsedTime)))
	b.WriteString(fmt.Sprintf("- **Control Status:** %s\n", data.ControlStatus))
	if data.SteerMessage != "" {
		b.WriteString(fmt.Sprintf("- **Pending Steer:** %s\n", data.SteerMessage))
	}
	b.WriteString("\n")

	// Cycle state
	b.WriteString("## Master Agent State\n")
	b.WriteString(fmt.Sprintf("- **Cycle:** %d\n", snap.Cycle))
	b.WriteString(fmt.Sprintf("- **Total Steers:** %d\n", snap.TotalSteers))
	b.WriteString(fmt.Sprintf("- **Last Steer Cycle:** %d\n", snap.LastSteerCycle))
	b.WriteString(fmt.Sprintf("- **In Steer Cooldown:** %v\n", a.state.IsInSteerCooldown()))
	b.WriteString(fmt.Sprintf("- **Warmup Phase:** %v\n", a.state.IsWarmup()))
	if len(snap.HealthHistory) > 0 {
		healths := make([]string, len(snap.HealthHistory))
		for i, h := range snap.HealthHistory {
			healths[i] = string(h)
		}
		b.WriteString(fmt.Sprintf("- **Health History:** [%s]\n", strings.Join(healths, ", ")))
	}
	if len(snap.CriticalEvents) > 0 {
		b.WriteString("- **Critical Events:**\n")
		for _, e := range snap.CriticalEvents {
			b.WriteString(fmt.Sprintf("  - %s\n", e))
		}
	}
	b.WriteString("\n")

	// Tasks
	if len(data.Tasks) > 0 {
		b.WriteString("## Tasks\n")
		for _, t := range data.Tasks {
			b.WriteString(fmt.Sprintf("- [%s] Task %d: %s\n", t.Status, t.ID, t.Title))
		}
		b.WriteString("\n")
	}

	// Subtasks
	if len(data.Subtasks) > 0 {
		b.WriteString("## Subtasks\n")
		for _, s := range data.Subtasks {
			elapsed := ""
			if s.CreatedAt.Valid {
				elapsed = formatDuration(time.Since(s.CreatedAt.Time))
			}
			b.WriteString(fmt.Sprintf("- [%s] Subtask %d: %s (running %s)\n",
				s.Status, s.ID, s.Title, elapsed))
		}
		b.WriteString("\n")
	}

	// Findings
	b.WriteString("## Findings\n")
	b.WriteString(fmt.Sprintf("- **Total:** %d\n", data.FindingsTotal))
	b.WriteString(fmt.Sprintf("- **Confirmed:** %d\n", data.FindingsConfirmed))
	if len(data.Findings) > 0 {
		b.WriteString("- **List:**\n")
		for _, f := range data.Findings {
			confirmed := "✗"
			if f.Confirmed {
				confirmed = "✓"
			}
			b.WriteString(fmt.Sprintf("  - [%s] [%s] %s — %s\n",
				f.Severity, confirmed, f.Title, f.Endpoint))
		}
	}
	b.WriteString("\n")

	// Tool call stats
	b.WriteString("## Tool Call Statistics\n")
	b.WriteString(fmt.Sprintf("- **Total Completed:** %d\n", data.ToolCallStats.TotalCount))
	b.WriteString(fmt.Sprintf("- **Total Duration:** %.1fs\n", data.ToolCallStats.TotalDurationSeconds))

	budgetMax := getGlobalMaxToolCallsForMasterAgent()
	budgetUsed := int(data.ToolCallStats.TotalCount)
	budgetRemaining := budgetMax - budgetUsed
	if budgetRemaining < 0 {
		budgetRemaining = 0
	}
	budgetPct := float64(0)
	if budgetMax > 0 {
		budgetPct = float64(budgetUsed) / float64(budgetMax) * 100
	}
	b.WriteString(fmt.Sprintf("- **Global Budget:** %d/%d (%.0f%% consumed, %d remaining)\n",
		budgetUsed, budgetMax, budgetPct, budgetRemaining))
	if budgetPct >= 90 {
		b.WriteString("- **⚠️ BUDGET CRITICAL:** Less than 10% remaining. Report phase must start NOW.\n")
	} else if budgetPct >= 80 {
		b.WriteString("- **⚠️ BUDGET WARNING:** Less than 20% remaining. Agent should wrap up and start report.\n")
	}

	if len(data.ToolCallsByFunc) > 0 {
		b.WriteString("- **By Function (top 10):**\n")
		limit := 10
		if len(data.ToolCallsByFunc) < limit {
			limit = len(data.ToolCallsByFunc)
		}
		for _, tc := range data.ToolCallsByFunc[:limit] {
			b.WriteString(fmt.Sprintf("  - %s: %d calls (%.1fs total, %.1fs avg)\n",
				tc.FunctionName, tc.TotalCount, tc.TotalDurationSeconds, tc.AvgDurationSeconds))
		}
	}
	b.WriteString("\n")

	// Recent messages (last 20 for LLM context)
	if len(data.RecentMessages) > 0 {
		b.WriteString("## Recent Messages (newest last)\n")
		msgs := data.RecentMessages
		if len(msgs) > 20 {
			msgs = msgs[len(msgs)-20:]
		}
		for _, m := range msgs {
			ts := ""
			if m.CreatedAt.Valid {
				ts = m.CreatedAt.Time.Format("15:04:05")
			}
			// Truncate long messages
			msg := m.Message
			if len(msg) > 300 {
				msg = msg[:300] + "..."
			}
			result := m.Result
			if len(result) > 200 {
				result = result[:200] + "..."
			}
			b.WriteString(fmt.Sprintf("- [%s] [%s] %s", ts, m.Type, msg))
			if result != "" {
				b.WriteString(fmt.Sprintf(" → %s", result))
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	return b.String()
}

// callLLM sends the prompt to Claude and parses the response.
func (a *Agent) callLLM(ctx context.Context, flowDataPrompt string) (*LLMDecision, error) {
	// Create Anthropic client
	httpClient, err := system.GetHTTPClient(a.cfg)
	if err != nil {
		return nil, fmt.Errorf("get http client: %w", err)
	}

	client, err := anthropic.New(
		anthropic.WithToken(a.maCfg.AnthropicAPIKey),
		anthropic.WithModel(a.maCfg.Model),
		anthropic.WithBaseURL(a.maCfg.AnthropicServerURL),
		anthropic.WithHTTPClient(httpClient),
	)
	if err != nil {
		return nil, fmt.Errorf("create anthropic client: %w", err)
	}

	// Build messages
	messages := []llms.MessageContent{
		{
			Role: llms.ChatMessageTypeSystem,
			Parts: []llms.ContentPart{
				llms.TextContent{Text: instructions},
			},
		},
		{
			Role: llms.ChatMessageTypeHuman,
			Parts: []llms.ContentPart{
				llms.TextContent{Text: flowDataPrompt},
			},
		},
	}

	// Call the LLM
	response, err := client.GenerateContent(ctx, messages,
		llms.WithMaxTokens(4096),
		llms.WithTemperature(0.3),
	)
	if err != nil {
		return nil, fmt.Errorf("generate content: %w", err)
	}

	if len(response.Choices) == 0 {
		return nil, fmt.Errorf("no choices in LLM response")
	}

	responseText := response.Choices[0].Content

	a.logger.WithField("response_length", len(responseText)).Debug("LLM response received")

	// Parse the JSON response
	decision, err := parseLLMResponse(responseText)
	if err != nil {
		a.logger.WithError(err).WithField("response", responseText).Warn("failed to parse LLM response, defaulting to NONE")
		return &LLMDecision{
			Action:    ActionNone,
			Health:    HealthWarning,
			Reasoning: fmt.Sprintf("Failed to parse LLM response: %v. Raw: %s", err, truncate(responseText, 200)),
		}, nil
	}

	return decision, nil
}

// parseLLMResponse extracts the JSON decision from the LLM's response text.
func parseLLMResponse(text string) (*LLMDecision, error) {
	// Try to extract JSON from markdown code blocks
	cleaned := text
	if idx := strings.Index(text, "```json"); idx != -1 {
		start := idx + 7
		end := strings.Index(text[start:], "```")
		if end != -1 {
			cleaned = strings.TrimSpace(text[start : start+end])
		}
	} else if idx := strings.Index(text, "```"); idx != -1 {
		start := idx + 3
		// Skip optional language tag on same line
		if nlIdx := strings.Index(text[start:], "\n"); nlIdx != -1 {
			start = start + nlIdx + 1
		}
		end := strings.Index(text[start:], "```")
		if end != -1 {
			cleaned = strings.TrimSpace(text[start : start+end])
		}
	}

	// Try to find raw JSON
	if !strings.HasPrefix(strings.TrimSpace(cleaned), "{") {
		// Look for first { to last }
		first := strings.Index(text, "{")
		last := strings.LastIndex(text, "}")
		if first != -1 && last > first {
			cleaned = text[first : last+1]
		}
	}

	var decision LLMDecision
	if err := json.Unmarshal([]byte(cleaned), &decision); err != nil {
		return nil, fmt.Errorf("json unmarshal: %w (text: %s)", err, truncate(cleaned, 200))
	}

	// Normalize action
	decision.Action = Action(strings.ToUpper(string(decision.Action)))

	// Handle STEER:<message> format
	if strings.HasPrefix(string(decision.Action), "STEER") {
		if decision.SteerMessage == "" && strings.Contains(string(decision.Action), ":") {
			parts := strings.SplitN(string(decision.Action), ":", 2)
			if len(parts) == 2 {
				decision.SteerMessage = strings.TrimSpace(parts[1])
			}
		}
		decision.Action = ActionSteer
	}

	// Validate
	switch decision.Action {
	case ActionNone, ActionSteer, ActionPause, ActionResume, ActionStop:
		// valid
	default:
		return nil, fmt.Errorf("unknown action: %s", decision.Action)
	}

	switch decision.Health {
	case HealthHealthy, HealthWarning, HealthCritical:
		// valid
	default:
		decision.Health = HealthWarning // default to warning if unknown
	}

	return &decision, nil
}

// executeDecision takes the LLM's decision and executes it using internal flow control.
func (a *Agent) executeDecision(ctx context.Context, decision *LLMDecision) error {
	switch decision.Action {
	case ActionNone:
		a.logger.Info("decision: no action needed")
		return nil

	case ActionSteer:
		if decision.SteerMessage == "" {
			a.logger.Warn("steer action with empty message, skipping")
			return nil
		}
		// Safety: check steer cooldown
		if a.state.IsInSteerCooldown() {
			a.logger.Info("in steer cooldown, skipping steer")
			return nil
		}
		// Safety: check if there's already a pending steer
		ctrlStatus, _ := a.flowControl.GetControlStatus(a.flowID)
		if ctrlStatus == "steered" {
			a.logger.Info("steer already pending, skipping")
			return nil
		}

		msg := decision.SteerMessage
		snap := a.state.Snapshot()
		if !strings.HasPrefix(msg, "[MASTER AGENT") {
			msg = fmt.Sprintf("[MASTER AGENT | Cycle %d] %s", snap.Cycle, msg)
		}

		// Execute steer via internal FlowControlManager
		if err := a.flowControl.Steer(a.flowID, msg); err != nil {
			return fmt.Errorf("steer flow: %w", err)
		}
		a.state.RecordSteer()
		a.state.RecordCriticalEvent(fmt.Sprintf("cycle %d: steered — %s",
			snap.Cycle, truncate(decision.Reasoning, 100)))

		// Notify via Telegram
		a.sendTelegramNotification(fmt.Sprintf("🟡 [MASTER AGENT] Flow %d STEERED (Cycle %d)\n%s",
			a.flowID, snap.Cycle, truncate(msg, 200)))

		a.logger.WithField("message", msg).Info("flow steered")
		return nil

	case ActionPause:
		if err := a.flowControl.Pause(a.flowID); err != nil {
			return fmt.Errorf("pause flow: %w", err)
		}
		a.state.RecordPause()
		snap := a.state.Snapshot()
		a.state.RecordCriticalEvent(fmt.Sprintf("cycle %d: paused — %s",
			snap.Cycle, truncate(decision.Reasoning, 100)))

		a.sendTelegramNotification(fmt.Sprintf("⏸ [MASTER AGENT] Flow %d PAUSED (Cycle %d)\n%s",
			a.flowID, snap.Cycle, truncate(decision.Reasoning, 200)))

		a.logger.Info("flow paused")
		return nil

	case ActionResume:
		if err := a.flowControl.Resume(a.flowID); err != nil {
			return fmt.Errorf("resume flow: %w", err)
		}
		snap := a.state.Snapshot()
		a.state.RecordCriticalEvent(fmt.Sprintf("cycle %d: resumed — %s",
			snap.Cycle, truncate(decision.Reasoning, 100)))

		a.logger.Info("flow resumed")
		return nil

	case ActionStop:
		if err := a.flowControl.Abort(a.flowID); err != nil {
			return fmt.Errorf("abort flow: %w", err)
		}
		snap := a.state.Snapshot()
		a.state.RecordCriticalEvent(fmt.Sprintf("cycle %d: aborted — %s",
			snap.Cycle, truncate(decision.Reasoning, 100)))

		a.sendTelegramNotification(fmt.Sprintf("🔴 [MASTER AGENT] Flow %d ABORTED (Cycle %d)\n%s",
			a.flowID, snap.Cycle, truncate(decision.Reasoning, 200)))

		a.logger.Info("flow aborted")
		return nil

	default:
		a.logger.WithField("action", decision.Action).Warn("unknown action, doing nothing")
		return nil
	}
}

// sendTelegramNotification sends a notification if Telegram is configured.
func (a *Agent) sendTelegramNotification(message string) {
	if a.notifier == nil || !a.notifier.IsEnabled() {
		return
	}
	a.notifier.SendRaw(message)
}

// formatDuration formats a duration in a human-readable way.
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
}

// truncate shortens a string to maxLen characters.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func getGlobalMaxToolCallsForMasterAgent() int {
	if v := os.Getenv("GLOBAL_MAX_TOOL_CALLS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 500
}
