package notifications

import (
	"context"
	"sync"
	"testing"
	"time"

	"pentagi/pkg/database"
	"pentagi/pkg/providers/pconfig"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockFlowPublisher implements subscriptions.FlowPublisher for testing.
type mockFlowPublisher struct {
	flowID int64
	userID int64

	flowCreatedCalls  int
	flowUpdatedCalls  int
	flowDeletedCalls  int
	taskCreatedCalls  int
	taskUpdatedCalls  int
	mu               sync.Mutex
}

func (m *mockFlowPublisher) GetFlowID() int64         { return m.flowID }
func (m *mockFlowPublisher) SetFlowID(id int64)        { m.flowID = id }
func (m *mockFlowPublisher) GetUserID() int64          { return m.userID }
func (m *mockFlowPublisher) SetUserID(id int64)         { m.userID = id }

func (m *mockFlowPublisher) FlowCreated(_ context.Context, _ database.Flow, _ []database.Container)  { m.mu.Lock(); m.flowCreatedCalls++; m.mu.Unlock() }
func (m *mockFlowPublisher) FlowDeleted(_ context.Context, _ database.Flow, _ []database.Container)  { m.mu.Lock(); m.flowDeletedCalls++; m.mu.Unlock() }
func (m *mockFlowPublisher) FlowUpdated(_ context.Context, _ database.Flow, _ []database.Container)  { m.mu.Lock(); m.flowUpdatedCalls++; m.mu.Unlock() }
func (m *mockFlowPublisher) TaskCreated(_ context.Context, _ database.Task, _ []database.Subtask)     { m.mu.Lock(); m.taskCreatedCalls++; m.mu.Unlock() }
func (m *mockFlowPublisher) TaskUpdated(_ context.Context, _ database.Task, _ []database.Subtask)     { m.mu.Lock(); m.taskUpdatedCalls++; m.mu.Unlock() }

func (m *mockFlowPublisher) AssistantCreated(_ context.Context, _ database.Assistant)                                         {}
func (m *mockFlowPublisher) AssistantUpdated(_ context.Context, _ database.Assistant)                                         {}
func (m *mockFlowPublisher) AssistantDeleted(_ context.Context, _ database.Assistant)                                         {}
func (m *mockFlowPublisher) ScreenshotAdded(_ context.Context, _ database.Screenshot)                                        {}
func (m *mockFlowPublisher) TerminalLogAdded(_ context.Context, _ database.Termlog)                                          {}
func (m *mockFlowPublisher) MessageLogAdded(_ context.Context, _ database.Msglog)                                            {}
func (m *mockFlowPublisher) MessageLogUpdated(_ context.Context, _ database.Msglog)                                          {}
func (m *mockFlowPublisher) AgentLogAdded(_ context.Context, _ database.Agentlog)                                            {}
func (m *mockFlowPublisher) SearchLogAdded(_ context.Context, _ database.Searchlog)                                          {}
func (m *mockFlowPublisher) VectorStoreLogAdded(_ context.Context, _ database.Vecstorelog)                                   {}
func (m *mockFlowPublisher) AssistantLogAdded(_ context.Context, _ database.Assistantlog)                                    {}
func (m *mockFlowPublisher) AssistantLogUpdated(_ context.Context, _ database.Assistantlog, _ bool)                          {}

func (m *mockFlowPublisher) ProviderCreated(_ context.Context, _ database.Provider, _ *pconfig.ProviderConfig)  {}
func (m *mockFlowPublisher) ProviderUpdated(_ context.Context, _ database.Provider, _ *pconfig.ProviderConfig)  {}
func (m *mockFlowPublisher) ProviderDeleted(_ context.Context, _ database.Provider, _ *pconfig.ProviderConfig)  {}
func (m *mockFlowPublisher) APITokenCreated(_ context.Context, _ database.APITokenWithSecret)       {}
func (m *mockFlowPublisher) APITokenUpdated(_ context.Context, _ database.ApiToken)                 {}
func (m *mockFlowPublisher) APITokenDeleted(_ context.Context, _ database.ApiToken)                 {}
func (m *mockFlowPublisher) SettingsUserUpdated(_ context.Context, _ database.UserPreference)       {}

// ==================== Tests ====================

func TestDiffFindings_EmptyOld(t *testing.T) {
	result := diffFindings("", "New finding: port 80 open")
	assert.Equal(t, "New finding: port 80 open", result)
}

func TestDiffFindings_NoChange(t *testing.T) {
	text := "Finding 1\nFinding 2"
	result := diffFindings(text, text)
	assert.Empty(t, result)
}

func TestDiffFindings_AppendedLines(t *testing.T) {
	old := "Line 1\nLine 2"
	new := "Line 1\nLine 2\nLine 3\nLine 4"
	result := diffFindings(old, new)
	assert.Equal(t, "Line 3\nLine 4", result)
}

func TestDiffFindings_CompleteRewrite(t *testing.T) {
	old := "Old content"
	new := "Completely new"
	result := diffFindings(old, new)
	assert.Equal(t, "Completely new", result)
}

func TestDiffFindings_BothEmpty(t *testing.T) {
	result := diffFindings("", "")
	assert.Empty(t, result)
}

func TestDiffFindings_NewEmpty(t *testing.T) {
	result := diffFindings("old content", "")
	assert.Empty(t, result)
}

func TestDiffFindings_Trimming(t *testing.T) {
	old := "Line 1"
	new := "Line 1\n  New finding  \n"
	result := diffFindings(old, new)
	assert.Equal(t, "New finding", result)
}

func TestDiffFindings_ShorterNewContent(t *testing.T) {
	old := "Line 1\nLine 2\nLine 3"
	new := "Rewritten content"
	result := diffFindings(old, new)
	assert.Equal(t, "Rewritten content", result)
}

func TestWrapPublisher_NilNotifier(t *testing.T) {
	mock := &mockFlowPublisher{flowID: 1, userID: 1}
	result := WrapPublisher(mock, nil, nil)
	assert.Equal(t, mock, result, "should return the original publisher when notifier is nil")
}

func TestWrapPublisher_DisabledNotifier(t *testing.T) {
	mock := &mockFlowPublisher{flowID: 1, userID: 1}
	nm := NewNotificationManager(nil, false, 2)
	result := WrapPublisher(mock, nm, nil)
	assert.Equal(t, mock, result, "should return the original publisher when notifier is disabled")
}

func TestWrapPublisher_Enabled(t *testing.T) {
	mock := &mockFlowPublisher{flowID: 1, userID: 1}
	tg := NewTelegramNotifier("token", "chat")
	nm := NewNotificationManager(tg, true, 2)
	defer nm.Close() // nm.Close() calls tg.Close() internally

	result := WrapPublisher(mock, nm, nil)
	np, ok := result.(*NotifyingPublisher)
	require.True(t, ok, "should return a NotifyingPublisher")
	assert.Equal(t, int64(1), np.GetFlowID())
	assert.Equal(t, int64(1), np.GetUserID())
}

func TestNotifyingPublisher_DelegatesFlowCreated(t *testing.T) {
	mock := &mockFlowPublisher{flowID: 1, userID: 1}
	nm := NewNotificationManager(nil, false, 2)

	np := &NotifyingPublisher{
		inner:    mock,
		notifier: nm,
	}

	flow := database.Flow{Title: "Test Flow"}
	np.FlowCreated(context.Background(), flow, nil)

	mock.mu.Lock()
	assert.Equal(t, 1, mock.flowCreatedCalls)
	mock.mu.Unlock()
	assert.Equal(t, "Test Flow", np.flowTitle)
}

func TestNotifyingPublisher_FlowUpdatedStatusDedup(t *testing.T) {
	mock := &mockFlowPublisher{flowID: 1, userID: 1}
	tg := NewTelegramNotifier("token", "chat")
	nm := NewNotificationManager(tg, true, 2)
	defer nm.Close()

	np := &NotifyingPublisher{
		inner:     mock,
		notifier:  nm,
		flowStart: time.Now(),
		flowTitle: "Test Flow",
		pollInterval: 2 * time.Minute,
	}

	flow := database.Flow{
		ID:     1,
		Title:  "Test Flow",
		Status: database.FlowStatusRunning,
	}

	// First call should emit notification
	np.FlowUpdated(context.Background(), flow, nil)

	// Second call with same status should not emit (dedup)
	np.FlowUpdated(context.Background(), flow, nil)

	mock.mu.Lock()
	assert.Equal(t, 2, mock.flowUpdatedCalls) // inner is always called
	mock.mu.Unlock()

	// The notifiedStatus map should have "running"
	_, exists := np.notifiedStatus.Load("running")
	assert.True(t, exists)
}

func TestNotifyingPublisher_FlowContext(t *testing.T) {
	mock := &mockFlowPublisher{flowID: 42, userID: 7}
	nm := NewNotificationManager(nil, false, 2)

	np := &NotifyingPublisher{
		inner:    mock,
		notifier: nm,
	}

	assert.Equal(t, int64(42), np.GetFlowID())
	assert.Equal(t, int64(7), np.GetUserID())

	np.SetFlowID(100)
	np.SetUserID(200)
	assert.Equal(t, int64(100), mock.flowID)
	assert.Equal(t, int64(200), mock.userID)
}

func TestNotifyingPublisher_TaskFailedNotification(t *testing.T) {
	mock := &mockFlowPublisher{flowID: 1, userID: 1}
	tg := NewTelegramNotifier("token", "chat")
	nm := NewNotificationManager(tg, true, 2)
	defer nm.Close()

	np := &NotifyingPublisher{
		inner:    mock,
		notifier: nm,
	}

	task := database.Task{
		ID:     1,
		Title:  "Nmap Scan",
		Status: database.TaskStatusFailed,
		Result: "connection timeout",
	}

	// Should not panic and should delegate
	np.TaskUpdated(context.Background(), task, nil)

	mock.mu.Lock()
	assert.Equal(t, 1, mock.taskUpdatedCalls)
	mock.mu.Unlock()
}

func TestNotifyingPublisher_StopPolling_NoOp(t *testing.T) {
	mock := &mockFlowPublisher{flowID: 1, userID: 1}
	nm := NewNotificationManager(nil, false, 2)

	np := &NotifyingPublisher{
		inner:    mock,
		notifier: nm,
	}

	// stopPolling should be safe when never started
	np.stopPolling()
}
