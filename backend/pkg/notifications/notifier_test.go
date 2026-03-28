package notifications

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewNotificationManager_Disabled(t *testing.T) {
	nm := NewNotificationManager(nil, false, 2)
	assert.NotNil(t, nm)
	assert.False(t, nm.IsEnabled())
}

func TestNewNotificationManager_Enabled(t *testing.T) {
	tg := NewTelegramNotifier("token", "chat")
	nm := NewNotificationManager(tg, true, 3)
	defer nm.Close()
	assert.NotNil(t, nm)
	assert.True(t, nm.IsEnabled())
	assert.Equal(t, 3*time.Minute, nm.pollInterval)
}

func TestNewNotificationManager_DefaultPollInterval(t *testing.T) {
	nm := NewNotificationManager(nil, false, 0)
	assert.Equal(t, 2*time.Minute, nm.pollInterval)

	nm2 := NewNotificationManager(nil, false, -5)
	assert.Equal(t, 2*time.Minute, nm2.pollInterval)
}

func TestNotify_DisabledManager(t *testing.T) {
	nm := NewNotificationManager(nil, false, 2)

	// Should not panic when manager is disabled
	nm.Notify(NotificationEvent{
		Type:   EventFlowStatusChange,
		FlowID: 1,
		Title:  "test",
		Status: "running",
	})
}

func TestNotify_NilTelegram(t *testing.T) {
	nm := NewNotificationManager(nil, true, 2)

	// Should not panic even if enabled but telegram is nil
	nm.Notify(NotificationEvent{
		Type:   EventFlowStatusChange,
		FlowID: 1,
		Title:  "test",
		Status: "running",
	})
}

func TestSendRaw_Disabled(t *testing.T) {
	nm := NewNotificationManager(nil, false, 2)

	// Should not panic
	nm.SendRaw("test message")
}

func TestFormatFlowStarted(t *testing.T) {
	event := NotificationEvent{
		Type:   EventFlowStatusChange,
		FlowID: 1,
		Title:  "Scan Target",
		Status: "running",
	}

	msg := formatFlowStarted(event)
	assert.Contains(t, msg, "🔍 Flow: Scan Target")
	assert.Contains(t, msg, "📊 Status: Running")
	assert.Contains(t, msg, "⏱ Started:")
}

func TestFormatFlowComplete(t *testing.T) {
	event := NotificationEvent{
		Type:     EventFlowStatusChange,
		FlowID:   1,
		Title:    "Scan Target",
		Status:   "finished",
		Duration: 30 * time.Minute,
	}

	msg := formatFlowComplete(event)
	assert.Contains(t, msg, "✅ Flow: Scan Target")
	assert.Contains(t, msg, "📊 Status: Completed")
	assert.Contains(t, msg, "⏱ Duration: 30m")
	assert.Contains(t, msg, "📋 Total Findings: Check FINDINGS.md for full report")
}

func TestFormatFlowComplete_LongDuration(t *testing.T) {
	event := NotificationEvent{
		Duration: 90 * time.Minute,
		Title:    "Long Flow",
	}

	msg := formatFlowComplete(event)
	assert.Contains(t, msg, "⏱ Duration: 1h 30m")
}

func TestFormatFlowFailed(t *testing.T) {
	event := NotificationEvent{
		Type:     EventFlowStatusChange,
		FlowID:   1,
		Title:    "Scan Target",
		Status:   "failed",
		Duration: 5 * time.Minute,
		Error:    "connection refused",
	}

	msg := formatFlowFailed(event)
	assert.Contains(t, msg, "❌ Flow: Scan Target")
	assert.Contains(t, msg, "📊 Status: Failed")
	assert.Contains(t, msg, "⚠️ Error: connection refused")
	assert.Contains(t, msg, "⏱ Duration: 5m")
}

func TestFormatFlowError(t *testing.T) {
	event := NotificationEvent{
		Type:   EventFlowError,
		FlowID: 1,
		Title:  "Subtask 3",
		Error:  "timeout exceeded",
	}

	msg := formatFlowError(event)
	assert.Contains(t, msg, "⚠️")
	assert.Contains(t, msg, "Flow: Subtask 3")
	assert.Contains(t, msg, "timeout exceeded")
}

func TestFormatNewFindings(t *testing.T) {
	event := NotificationEvent{
		Type:            EventNewFindings,
		FlowID:          1,
		Title:           "Pentest Flow",
		FindingsContent: "Found open port 22 (SSH)\nFound open port 80 (HTTP)",
	}

	msg := formatNewFindings(event)
	assert.Contains(t, msg, "🔍 Flow: Pentest Flow")
	assert.Contains(t, msg, "📋 New Findings Update")
	assert.Contains(t, msg, "Found open port 22 (SSH)")
	assert.Contains(t, msg, "⏱ Updated:")
}

func TestFormatNewFindings_Truncation(t *testing.T) {
	longContent := make([]byte, 4000)
	for i := range longContent {
		longContent[i] = 'X'
	}

	event := NotificationEvent{
		Type:            EventNewFindings,
		FlowID:          1,
		Title:           "Test",
		FindingsContent: string(longContent),
	}

	msg := formatNewFindings(event)
	// The findings content should be truncated to ~3500 chars
	assert.True(t, len(msg) < telegramMaxMsgLen+200, "formatted message should not exceed limits")
}

func TestEscapeHTML(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello", "hello"},
		{"a < b", "a &lt; b"},
		{"a > b", "a &gt; b"},
		{"a & b", "a &amp; b"},
		{"<script>alert('xss')</script>", "&lt;script&gt;alert('xss')&lt;/script&gt;"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, escapeHTML(tt.input))
		})
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		duration time.Duration
		expected string
	}{
		{5 * time.Minute, "5m"},
		{30 * time.Minute, "30m"},
		{60 * time.Minute, "1h 0m"},
		{90 * time.Minute, "1h 30m"},
		{0, "0m"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, formatDuration(tt.duration))
		})
	}
}

func TestFormatFlowStatus_UnknownStatus(t *testing.T) {
	nm := NewNotificationManager(nil, false, 2)
	event := NotificationEvent{
		Type:   EventFlowStatusChange,
		Status: "waiting",
	}

	msg := nm.formatFlowStatus(event)
	assert.Empty(t, msg)
}

func TestClose_NilTelegram(t *testing.T) {
	nm := NewNotificationManager(nil, false, 2)
	// Should not panic
	nm.Close()
}
