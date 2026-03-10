package notifications

import (
	"context"
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
