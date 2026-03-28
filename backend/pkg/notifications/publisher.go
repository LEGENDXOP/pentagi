package notifications

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"pentagi/pkg/database"
	"pentagi/pkg/docker"
	"pentagi/pkg/graph/subscriptions"
	"pentagi/pkg/providers/pconfig"

	"github.com/sirupsen/logrus"
)

// NotifyingPublisher wraps a FlowPublisher and emits notification events
// when flow/task status changes are published. This is a transparent decorator:
// all calls are forwarded to the inner publisher unchanged.
//
// It also runs a FINDINGS.md polling goroutine that periodically reads the
// file from the flow's Docker container and sends only new content to Telegram.
type NotifyingPublisher struct {
	inner     subscriptions.FlowPublisher
	notifier  *NotificationManager
	flowStart time.Time
	flowTitle string

	// Flow status dedup: track the last notified status to avoid duplicate
	// notifications when FlowUpdated fires multiple times for the same status.
	notifiedStatus sync.Map // statusString -> bool (set once per status)

	// Docker client for container file reading
	dockerClient docker.DockerClient

	// FINDINGS.md polling state
	pollInterval  time.Duration
	pollCancel    context.CancelFunc
	pollWg        sync.WaitGroup
	lastFindings  string // last FINDINGS.md full text (for diffing)
	lastFindingsMu sync.Mutex
}

// WrapPublisher creates a NotifyingPublisher if the notifier is active.
// If notifier is nil or disabled, returns the original publisher unchanged.
// The docker client is optional — if nil, FINDINGS.md polling is disabled
// but flow status notifications work normally.
func WrapPublisher(pub subscriptions.FlowPublisher, notifier *NotificationManager, dc docker.DockerClient) subscriptions.FlowPublisher {
	if notifier == nil || !notifier.enabled {
		logrus.WithFields(logrus.Fields{
			"notifier_nil": notifier == nil,
			"enabled":      notifier != nil && notifier.enabled,
		}).Debug("WrapPublisher: notifier inactive, returning raw publisher")
		return pub
	}

	logrus.WithFields(logrus.Fields{
		"flow_id":    pub.GetFlowID(),
		"has_docker": dc != nil,
	}).Debug("WrapPublisher: wrapping publisher with notifications")
	return &NotifyingPublisher{
		inner:        pub,
		notifier:     notifier,
		dockerClient: dc,
		flowStart:    time.Now(),
		pollInterval: notifier.pollInterval,
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
	p.flowTitle = flow.Title
}

func (p *NotifyingPublisher) FlowDeleted(ctx context.Context, flow database.Flow, terms []database.Container) {
	p.inner.FlowDeleted(ctx, flow, terms)
	p.stopPolling()
}

func (p *NotifyingPublisher) FlowUpdated(ctx context.Context, flow database.Flow, terms []database.Container) {
	p.inner.FlowUpdated(ctx, flow, terms)

	// Track the flow title
	if flow.Title != "" {
		p.flowTitle = flow.Title
	}

	// Emit notification on meaningful flow status changes
	p.notifyFlowStatus(flow)
}

// notifyFlowStatus emits a notification event based on flow status.
// Each of "running", "finished", "failed" is sent at most once per flow.
func (p *NotifyingPublisher) notifyFlowStatus(flow database.Flow) {
	defer func() {
		if r := recover(); r != nil {
			logrus.WithField("panic", r).Error("panic in notifyFlowStatus")
		}
	}()

	statusStr := string(flow.Status)

	switch flow.Status {
	case database.FlowStatusRunning:
		if _, already := p.notifiedStatus.LoadOrStore(statusStr, true); already {
			return
		}
		p.flowTitle = flow.Title
		p.notifier.Notify(NotificationEvent{
			Type:   EventFlowStatusChange,
			FlowID: flow.ID,
			Title:  flow.Title,
			Status: "running",
		})
		// Start FINDINGS.md polling when flow starts running
		p.startPolling()

	case database.FlowStatusFinished:
		if _, already := p.notifiedStatus.LoadOrStore(statusStr, true); already {
			return
		}
		// Stop polling before sending completion notification
		p.stopPolling()
		// Do one final poll to catch any last findings
		p.pollFindingsOnce()

		p.notifier.Notify(NotificationEvent{
			Type:     EventFlowStatusChange,
			FlowID:   flow.ID,
			Title:    flow.Title,
			Status:   "finished",
			Duration: time.Since(p.flowStart),
		})

	case database.FlowStatusFailed:
		if _, already := p.notifiedStatus.LoadOrStore(statusStr, true); already {
			return
		}
		// Stop polling
		p.stopPolling()

		p.notifier.Notify(NotificationEvent{
			Type:     EventFlowStatusChange,
			FlowID:   flow.ID,
			Title:    flow.Title,
			Status:   "failed",
			Duration: time.Since(p.flowStart),
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

// ==================== FINDINGS.md Polling ====================

// startPolling begins the FINDINGS.md polling goroutine.
func (p *NotifyingPublisher) startPolling() {
	if p.dockerClient == nil || p.pollInterval <= 0 {
		logrus.WithField("flow_id", p.inner.GetFlowID()).Debug("findings polling disabled: no docker client or zero interval")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	p.pollCancel = cancel

	p.pollWg.Add(1)
	go p.pollLoop(ctx)

	logrus.WithFields(logrus.Fields{
		"flow_id":  p.inner.GetFlowID(),
		"interval": p.pollInterval,
	}).Info("started FINDINGS.md polling")
}

// stopPolling stops the FINDINGS.md polling goroutine and waits for it to finish.
func (p *NotifyingPublisher) stopPolling() {
	if p.pollCancel != nil {
		p.pollCancel()
		p.pollWg.Wait()
		p.pollCancel = nil
		logrus.WithField("flow_id", p.inner.GetFlowID()).Debug("stopped FINDINGS.md polling")
	}
}

// pollLoop runs periodically to check FINDINGS.md for new content.
func (p *NotifyingPublisher) pollLoop(ctx context.Context) {
	defer p.pollWg.Done()
	defer func() {
		if r := recover(); r != nil {
			logrus.WithField("panic", r).Error("panic in findings poll loop")
		}
	}()

	ticker := time.NewTicker(p.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.pollFindingsOnce()
		}
	}
}

// pollFindingsOnce reads FINDINGS.md from the container and sends new content.
func (p *NotifyingPublisher) pollFindingsOnce() {
	defer func() {
		if r := recover(); r != nil {
			logrus.WithField("panic", r).Error("panic in pollFindingsOnce")
		}
	}()

	flowID := p.inner.GetFlowID()
	containerName := fmt.Sprintf("pentagi-terminal-%d", flowID)

	readCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	content, err := ReadContainerFile(readCtx, p.dockerClient, containerName, "/work/FINDINGS.md")
	if err != nil {
		// File might not exist yet — that's normal
		logrus.WithFields(logrus.Fields{
			"flow_id": flowID,
			"error":   err,
		}).Debug("could not read FINDINGS.md from container")
		return
	}

	p.lastFindingsMu.Lock()
	defer p.lastFindingsMu.Unlock()

	// Compare with previously stored content
	if content == "" || content == p.lastFindings {
		return // no change
	}

	// Extract only new content (delta)
	delta := diffFindings(p.lastFindings, content)
	if delta == "" {
		return
	}

	// Update stored state (cap at 50KB to prevent memory bloat)
	if len(content) > 50*1024 {
		p.lastFindings = content[len(content)-50*1024:]
	} else {
		p.lastFindings = content
	}

	// Send notification via NotificationManager
	title := p.flowTitle
	if title == "" {
		title = fmt.Sprintf("Flow #%d", flowID)
	}

	p.notifier.Notify(NotificationEvent{
		Type:            EventNewFindings,
		FlowID:          flowID,
		Title:           title,
		FindingsContent: delta,
	})
}

// diffFindings returns only the NEW content in FINDINGS.md since last check.
// It handles both append-mode (new lines added at end) and full rewrite scenarios.
func diffFindings(oldText, newText string) string {
	if oldText == "" {
		// First time seeing findings — return everything
		return strings.TrimSpace(newText)
	}

	oldLines := strings.Split(oldText, "\n")
	newLines := strings.Split(newText, "\n")

	if len(newLines) > len(oldLines) {
		// Likely appended — return only new lines
		delta := strings.Join(newLines[len(oldLines):], "\n")
		return strings.TrimSpace(delta)
	}

	// File was rewritten or content changed — if different, return all
	if oldText != newText {
		return strings.TrimSpace(newText)
	}

	return "" // no change
}
