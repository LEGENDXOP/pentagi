package notifications

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"pentagi/pkg/database"
	"pentagi/pkg/graph/subscriptions"
	"pentagi/pkg/providers/pconfig"

	"github.com/sirupsen/logrus"
)

// NotifyingPublisher wraps a FlowPublisher and emits notification events
// when flow/task status changes are published. This is a transparent decorator:
// all calls are forwarded to the inner publisher unchanged.
type NotifyingPublisher struct {
	inner     subscriptions.FlowPublisher
	notifier  *NotificationManager
	flowStart time.Time

	// Phase tracking for detecting phase changes
	lastPhase   string
	lastPhaseMu sync.Mutex

	// Finding dedup: track finding IDs already emitted from this publisher
	emittedFindings sync.Map // findingKey -> bool
	findingCounter  int
	findingMu       sync.Mutex
}

// WrapPublisher creates a NotifyingPublisher if the notifier is active.
// If notifier is nil or disabled, returns the original publisher unchanged.
func WrapPublisher(pub subscriptions.FlowPublisher, notifier *NotificationManager) subscriptions.FlowPublisher {
	if notifier == nil || !notifier.enabled {
		return pub
	}

	return &NotifyingPublisher{
		inner:     pub,
		notifier:  notifier,
		flowStart: time.Now(),
	}
}

// ==================== FlowContext methods (delegated) ====================

func (p *NotifyingPublisher) GetFlowID() int64     { return p.inner.GetFlowID() }
func (p *NotifyingPublisher) SetFlowID(id int64)    { p.inner.SetFlowID(id) }
func (p *NotifyingPublisher) GetUserID() int64      { return p.inner.GetUserID() }
func (p *NotifyingPublisher) SetUserID(id int64)     { p.inner.SetUserID(id) }

// ==================== Flow events ====================

func (p *NotifyingPublisher) FlowCreated(ctx context.Context, flow database.Flow, terms []database.Container) {
	p.inner.FlowCreated(ctx, flow, terms)
	p.flowStart = time.Now()
}

func (p *NotifyingPublisher) FlowDeleted(ctx context.Context, flow database.Flow, terms []database.Container) {
	p.inner.FlowDeleted(ctx, flow, terms)
}

func (p *NotifyingPublisher) FlowUpdated(ctx context.Context, flow database.Flow, terms []database.Container) {
	p.inner.FlowUpdated(ctx, flow, terms)

	// Emit notification on meaningful flow status changes
	p.notifyFlowStatus(flow)
}

// notifyFlowStatus emits a notification event based on flow status.
func (p *NotifyingPublisher) notifyFlowStatus(flow database.Flow) {
	defer func() {
		if r := recover(); r != nil {
			logrus.WithField("panic", r).Error("panic in notifyFlowStatus")
		}
	}()

	switch flow.Status {
	case database.FlowStatusRunning:
		// Only notify on first transition to running (flow start)
		p.notifier.Notify(NotificationEvent{
			Type:   EventFlowStatusChange,
			FlowID: flow.ID,
			Title:  flow.Title,
			Status: "running",
		})

	case database.FlowStatusFinished:
		p.notifier.Notify(NotificationEvent{
			Type:     EventFlowStatusChange,
			FlowID:   flow.ID,
			Title:    flow.Title,
			Status:   "finished",
			Duration: time.Since(p.flowStart),
		})

	case database.FlowStatusFailed:
		p.notifier.Notify(NotificationEvent{
			Type:   EventFlowStatusChange,
			FlowID: flow.ID,
			Title:  flow.Title,
			Status: "failed",
		})

	default:
		// "created", "waiting" — don't notify
	}
}

// ==================== Task events ====================

func (p *NotifyingPublisher) TaskCreated(ctx context.Context, task database.Task, subtasks []database.Subtask) {
	p.inner.TaskCreated(ctx, task, subtasks)
}

func (p *NotifyingPublisher) TaskUpdated(ctx context.Context, task database.Task, subtasks []database.Subtask) {
	p.inner.TaskUpdated(ctx, task, subtasks)

	// Notify on task failure
	if task.Status == database.TaskStatusFailed {
		p.notifier.Notify(NotificationEvent{
			Type:   EventFlowError,
			FlowID: p.inner.GetFlowID(),
			Title:  task.Title,
			Error:  task.Result,
		})
	}

	// Scan subtask results for findings
	p.scanSubtasksForFindings(subtasks)
}

// ==================== All other events (pass-through) ====================

func (p *NotifyingPublisher) AssistantCreated(ctx context.Context, assistant database.Assistant) {
	p.inner.AssistantCreated(ctx, assistant)
}

func (p *NotifyingPublisher) AssistantUpdated(ctx context.Context, assistant database.Assistant) {
	p.inner.AssistantUpdated(ctx, assistant)
}

func (p *NotifyingPublisher) AssistantDeleted(ctx context.Context, assistant database.Assistant) {
	p.inner.AssistantDeleted(ctx, assistant)
}

func (p *NotifyingPublisher) ScreenshotAdded(ctx context.Context, screenshot database.Screenshot) {
	p.inner.ScreenshotAdded(ctx, screenshot)
}

func (p *NotifyingPublisher) TerminalLogAdded(ctx context.Context, terminalLog database.Termlog) {
	p.inner.TerminalLogAdded(ctx, terminalLog)
}

func (p *NotifyingPublisher) MessageLogAdded(ctx context.Context, messageLog database.Msglog) {
	p.inner.MessageLogAdded(ctx, messageLog)
}

func (p *NotifyingPublisher) MessageLogUpdated(ctx context.Context, messageLog database.Msglog) {
	p.inner.MessageLogUpdated(ctx, messageLog)
}

func (p *NotifyingPublisher) AgentLogAdded(ctx context.Context, agentLog database.Agentlog) {
	p.inner.AgentLogAdded(ctx, agentLog)

	// Scan agent log result for findings
	p.scanTextForFindings(agentLog.Result)
}

func (p *NotifyingPublisher) SearchLogAdded(ctx context.Context, searchLog database.Searchlog) {
	p.inner.SearchLogAdded(ctx, searchLog)
}

func (p *NotifyingPublisher) VectorStoreLogAdded(ctx context.Context, vectorStoreLog database.Vecstorelog) {
	p.inner.VectorStoreLogAdded(ctx, vectorStoreLog)
}

func (p *NotifyingPublisher) AssistantLogAdded(ctx context.Context, assistantLog database.Assistantlog) {
	p.inner.AssistantLogAdded(ctx, assistantLog)
}

func (p *NotifyingPublisher) AssistantLogUpdated(ctx context.Context, assistantLog database.Assistantlog, appendPart bool) {
	p.inner.AssistantLogUpdated(ctx, assistantLog, appendPart)
}

func (p *NotifyingPublisher) ProviderCreated(ctx context.Context, provider database.Provider, cfg *pconfig.ProviderConfig) {
	p.inner.ProviderCreated(ctx, provider, cfg)
}

func (p *NotifyingPublisher) ProviderUpdated(ctx context.Context, provider database.Provider, cfg *pconfig.ProviderConfig) {
	p.inner.ProviderUpdated(ctx, provider, cfg)
}

func (p *NotifyingPublisher) ProviderDeleted(ctx context.Context, provider database.Provider, cfg *pconfig.ProviderConfig) {
	p.inner.ProviderDeleted(ctx, provider, cfg)
}

func (p *NotifyingPublisher) APITokenCreated(ctx context.Context, apiToken database.APITokenWithSecret) {
	p.inner.APITokenCreated(ctx, apiToken)
}

func (p *NotifyingPublisher) APITokenUpdated(ctx context.Context, apiToken database.ApiToken) {
	p.inner.APITokenUpdated(ctx, apiToken)
}

func (p *NotifyingPublisher) APITokenDeleted(ctx context.Context, apiToken database.ApiToken) {
	p.inner.APITokenDeleted(ctx, apiToken)
}

func (p *NotifyingPublisher) SettingsUserUpdated(ctx context.Context, userPreferences database.UserPreference) {
	p.inner.SettingsUserUpdated(ctx, userPreferences)
}

// ==================== Finding extraction ====================

// scanSubtasksForFindings checks subtask results for vulnerability findings.
func (p *NotifyingPublisher) scanSubtasksForFindings(subtasks []database.Subtask) {
	for _, st := range subtasks {
		// Only scan completed subtasks with results
		if st.Result == "" {
			continue
		}
		p.scanTextForFindings(st.Result)

		// Also check subtask context for phase info
		p.checkPhaseFromContext(st.Context)
	}
}

// scanTextForFindings extracts finding events from text and notifies.
func (p *NotifyingPublisher) scanTextForFindings(text string) {
	if text == "" {
		return
	}

	// Quick check: skip if no finding-related keywords
	if !strings.Contains(text, "FINDING") && !strings.Contains(text, "finding") &&
		!strings.Contains(text, "vulnerability") && !strings.Contains(text, "Vulnerability") {
		return
	}

	flowID := p.inner.GetFlowID()
	lines := strings.Split(text, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

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

		// Dedup by line content hash
		dedupKey := fmt.Sprintf("%d:%s", flowID, line)
		if _, already := p.emittedFindings.LoadOrStore(dedupKey, true); already {
			continue
		}

		p.findingMu.Lock()
		p.findingCounter++
		findingID := fmt.Sprintf("finding-%d", p.findingCounter)
		p.findingMu.Unlock()

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

		title := line
		if len(title) > 120 {
			title = title[:117] + "..."
		}

		p.notifier.Notify(NotificationEvent{
			Type:            EventFindingDiscovered,
			FlowID:          flowID,
			FindingID:       findingID,
			Title:           title,
			FindingSeverity: MapSeverity(severity),
			FindingVulnType: vulnType,
		})
	}
}

// checkPhaseFromContext checks subtask context JSON for phase information
// and emits a phase change notification when the phase changes.
func (p *NotifyingPublisher) checkPhaseFromContext(contextJSON string) {
	if contextJSON == "" {
		return
	}

	// Quick check for "phase" key
	if !strings.Contains(contextJSON, `"phase"`) {
		return
	}

	// Simple JSON extraction — avoid importing encoding/json just for this
	// Look for "phase":"value" pattern
	idx := strings.Index(contextJSON, `"phase"`)
	if idx < 0 {
		return
	}
	rest := contextJSON[idx+7:]
	// Skip whitespace and colon
	rest = strings.TrimLeft(rest, " \t\n\r:")
	if len(rest) == 0 || rest[0] != '"' {
		return
	}
	rest = rest[1:]
	end := strings.Index(rest, `"`)
	if end <= 0 {
		return
	}
	phase := rest[:end]
	if phase == "" {
		return
	}

	p.lastPhaseMu.Lock()
	oldPhase := p.lastPhase
	if phase == oldPhase {
		p.lastPhaseMu.Unlock()
		return
	}
	p.lastPhase = phase
	p.lastPhaseMu.Unlock()

	if oldPhase == "" {
		// First phase seen — don't notify transition, just track
		return
	}

	p.notifier.Notify(NotificationEvent{
		Type:     EventPhaseChange,
		FlowID:   p.inner.GetFlowID(),
		OldPhase: oldPhase,
		NewPhase: phase,
	})
}
