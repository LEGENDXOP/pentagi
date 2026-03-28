package notifications

import (
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// EventType represents the kind of notification event.
type EventType int

const (
	EventFlowStatusChange EventType = iota
	EventFlowError
	EventNewFindings
)

// NotificationEvent is the event payload dispatched to the notification manager.
type NotificationEvent struct {
	Type   EventType
	FlowID int64
	Title  string // flow title

	// Flow status fields
	Status   string // "running", "finished", "failed"
	Duration time.Duration
	Error    string

	// New findings content (from FINDINGS.md polling)
	FindingsContent string
}

// NotificationManager is the central hub for dispatching notification events.
// It handles formatting and routing to the Telegram notifier.
type NotificationManager struct {
	telegram     *TelegramNotifier
	enabled      bool
	pollInterval time.Duration
	logger       *logrus.Entry
}

// NewNotificationManager creates a NotificationManager.
// If telegram is nil or enabled is false, all events are silently dropped.
// pollIntervalMinutes controls how often FINDINGS.md is polled (default 2 minutes).
func NewNotificationManager(telegram *TelegramNotifier, enabled bool, pollIntervalMinutes int) *NotificationManager {
	if pollIntervalMinutes <= 0 {
		pollIntervalMinutes = 2
	}
	return &NotificationManager{
		telegram:     telegram,
		enabled:      enabled,
		pollInterval: time.Duration(pollIntervalMinutes) * time.Minute,
		logger:       logrus.WithField("component", "notifications"),
	}
}

// IsEnabled returns whether the notification manager is active.
func (nm *NotificationManager) IsEnabled() bool {
	return nm.enabled && nm.telegram != nil
}

// Notify dispatches a notification event.
// This method is safe to call from any goroutine and never blocks the caller.
func (nm *NotificationManager) Notify(event NotificationEvent) {
	if !nm.enabled || nm.telegram == nil {
		nm.logger.WithFields(logrus.Fields{
			"enabled":      nm.enabled,
			"has_telegram": nm.telegram != nil,
			"event_type":   event.Type,
			"flow_id":      event.FlowID,
		}).Debug("notification dropped: manager disabled or no telegram")
		return
	}

	nm.logger.WithFields(logrus.Fields{
		"event_type": event.Type,
		"flow_id":    event.FlowID,
		"status":     event.Status,
	}).Debug("dispatching notification event")

	// Fire-and-forget: never let notification failures affect the caller
	go nm.processEvent(event)
}

// SendRaw sends a pre-formatted message through the notification pipeline.
// Use this for messages that don't fit the standard event types.
func (nm *NotificationManager) SendRaw(message string) {
	if !nm.enabled || nm.telegram == nil {
		return
	}
	nm.telegram.Send(message)
}

// Close shuts down the notification manager and its telegram notifier.
func (nm *NotificationManager) Close() {
	if nm.telegram != nil {
		nm.telegram.Close()
	}
}

// processEvent handles formatting and dispatch for each event type.
func (nm *NotificationManager) processEvent(event NotificationEvent) {
	defer func() {
		if r := recover(); r != nil {
			nm.logger.WithField("panic", r).Error("panic in notification processing")
		}
	}()

	var msg string
	switch event.Type {
	case EventFlowStatusChange:
		msg = nm.formatFlowStatus(event)
	case EventFlowError:
		msg = formatFlowError(event)
	case EventNewFindings:
		msg = formatNewFindings(event)
	default:
		return
	}

	if msg != "" {
		nm.telegram.Send(msg)
	}
}

// ==================== Message Formatting ====================

func (nm *NotificationManager) formatFlowStatus(event NotificationEvent) string {
	switch event.Status {
	case "running":
		return formatFlowStarted(event)
	case "finished":
		return formatFlowComplete(event)
	case "failed":
		return formatFlowFailed(event)
	default:
		return ""
	}
}

func formatFlowStarted(e NotificationEvent) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("🔍 Flow: %s\n", escapeHTML(e.Title)))
	b.WriteString("📊 Status: Running\n")
	b.WriteString(fmt.Sprintf("⏱ Started: %s", time.Now().UTC().Format("15:04 UTC")))
	return b.String()
}

func formatFlowComplete(e NotificationEvent) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("✅ Flow: %s\n", escapeHTML(e.Title)))
	b.WriteString("📊 Status: Completed\n")
	if e.Duration > 0 {
		b.WriteString(fmt.Sprintf("⏱ Duration: %s\n", formatDuration(e.Duration)))
	}
	b.WriteString("📋 Total Findings: Check FINDINGS.md for full report")
	return b.String()
}

func formatFlowFailed(e NotificationEvent) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("❌ Flow: %s\n", escapeHTML(e.Title)))
	b.WriteString("📊 Status: Failed\n")
	if e.Error != "" {
		b.WriteString(fmt.Sprintf("⚠️ Error: %s\n", escapeHTML(e.Error)))
	}
	if e.Duration > 0 {
		b.WriteString(fmt.Sprintf("⏱ Duration: %s", formatDuration(e.Duration)))
	}
	return b.String()
}

func formatFlowError(e NotificationEvent) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("⚠️ <b>Flow Error</b>\n"))
	b.WriteString(fmt.Sprintf("🔍 Flow: %s\n", escapeHTML(e.Title)))
	if e.Error != "" {
		b.WriteString(fmt.Sprintf("Error: %s", escapeHTML(e.Error)))
	}
	return b.String()
}

func formatNewFindings(e NotificationEvent) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("🔍 Flow: %s\n", escapeHTML(e.Title)))
	b.WriteString("📋 New Findings Update\n\n")

	content := e.FindingsContent
	// Smart truncation: keep within Telegram limits with room for header/footer
	if len(content) > 3500 {
		content = content[:3497] + "..."
	}
	b.WriteString(fmt.Sprintf("<pre>%s</pre>\n\n", escapeHTML(content)))
	b.WriteString(fmt.Sprintf("⏱ Updated: %s", time.Now().UTC().Format("15:04 UTC")))

	return b.String()
}

func formatDuration(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
}

// escapeHTML escapes special HTML characters for Telegram HTML parse mode.
func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}
