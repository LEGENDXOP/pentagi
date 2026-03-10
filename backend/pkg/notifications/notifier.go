package notifications

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// EventType represents the kind of notification event.
type EventType int

const (
	EventFlowStatusChange EventType = iota
	EventFindingDiscovered
	EventPhaseChange
	EventFlowError
)

// FindingSeverity represents the severity level of a finding.
type FindingSeverity string

const (
	SeverityCritical FindingSeverity = "CRITICAL"
	SeverityHigh     FindingSeverity = "HIGH"
	SeverityMedium   FindingSeverity = "MEDIUM"
	SeverityLow      FindingSeverity = "LOW"
	SeverityInfo     FindingSeverity = "INFO"
)

// NotificationEvent is the event payload dispatched to the notification manager.
type NotificationEvent struct {
	Type   EventType
	FlowID int64
	Title  string // flow title or finding title

	// Flow status fields
	Status   string // "running", "finished", "failed", "waiting"
	Duration time.Duration
	Error    string

	// Finding fields
	FindingID       string
	FindingSeverity FindingSeverity
	FindingTarget   string
	FindingVulnType string

	// Phase change fields
	OldPhase      string
	NewPhase      string
	FindingsCount int
	AttacksDone   int
	AttacksTotal  int

	// Flow completion stats
	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int
}

const (
	// findingBatchWindow is the time to wait before sending batched findings.
	findingBatchWindow = 60 * time.Second
	// findingBatchThreshold triggers batching when this many findings arrive within the window.
	findingBatchThreshold = 3
	// quietHoursStart is the hour (0-23) when quiet hours begin.
	quietHoursStart = 0
	// quietHoursEnd is the hour (0-23) when quiet hours end.
	quietHoursEnd = 8
)

// NotificationManager is the central hub for dispatching notification events.
// It handles filtering, deduplication, batching, and quiet hours.
type NotificationManager struct {
	telegram *TelegramNotifier
	enabled  bool

	// Dedup: track sent finding IDs
	sentFindings sync.Map // findingID -> bool

	// Batching: accumulate findings per flow within a time window
	batchMu      sync.Mutex
	batchMap     map[int64]*findingBatch // flowID -> batch
	batchTimers  map[int64]*time.Timer   // flowID -> flush timer

	// Timezone offset for quiet hours (default UTC)
	quietTZOffset time.Duration

	logger *logrus.Entry
}

// findingBatch holds accumulated findings for a single flow.
type findingBatch struct {
	flowID   int64
	title    string // flow title
	findings []NotificationEvent
	firstAt  time.Time
}

// NewNotificationManager creates a NotificationManager.
// If telegram is nil or enabled is false, all events are silently dropped.
func NewNotificationManager(telegram *TelegramNotifier, enabled bool, quietTZOffsetHours int) *NotificationManager {
	nm := &NotificationManager{
		telegram:      telegram,
		enabled:       enabled,
		batchMap:      make(map[int64]*findingBatch),
		batchTimers:   make(map[int64]*time.Timer),
		quietTZOffset: time.Duration(quietTZOffsetHours) * time.Hour,
		logger:        logrus.WithField("component", "notifications"),
	}

	return nm
}

// Notify dispatches a notification event.
// This method is safe to call from any goroutine and never blocks the caller.
func (nm *NotificationManager) Notify(event NotificationEvent) {
	if !nm.enabled || nm.telegram == nil {
		return
	}

	// Fire-and-forget: never let notification failures affect the caller
	go nm.processEvent(event)
}

// Close shuts down the notification manager and its telegram notifier.
func (nm *NotificationManager) Close() {
	if nm.telegram != nil {
		// Flush any pending batches
		nm.batchMu.Lock()
		for flowID, batch := range nm.batchMap {
			if timer, ok := nm.batchTimers[flowID]; ok {
				timer.Stop()
			}
			nm.flushBatchLocked(batch)
		}
		nm.batchMap = make(map[int64]*findingBatch)
		nm.batchTimers = make(map[int64]*time.Timer)
		nm.batchMu.Unlock()

		nm.telegram.Close()
	}
}

// processEvent handles filtering, dedup, batching, quiet hours, and dispatch.
func (nm *NotificationManager) processEvent(event NotificationEvent) {
	defer func() {
		if r := recover(); r != nil {
			nm.logger.WithField("panic", r).Error("panic in notification processing")
		}
	}()

	switch event.Type {
	case EventFlowStatusChange:
		nm.handleFlowStatus(event)
	case EventFindingDiscovered:
		nm.handleFinding(event)
	case EventPhaseChange:
		nm.handlePhaseChange(event)
	case EventFlowError:
		nm.handleFlowError(event)
	}
}

// handleFlowStatus handles flow start/complete/fail events.
func (nm *NotificationManager) handleFlowStatus(event NotificationEvent) {
	// Only notify on meaningful status changes
	switch event.Status {
	case "running":
		// Flow started — notify
		if nm.isQuietHours() {
			return // don't spam on flow starts during quiet hours
		}
		msg := fmt.Sprintf("▶️ <b>Flow #%d Started</b>\n%s", event.FlowID, escapeHTML(event.Title))
		nm.telegram.Send(msg)

	case "finished":
		// Flow completed
		msg := formatFlowComplete(event)
		nm.telegram.Send(msg)

	case "failed":
		// Flow failed — always notify (even during quiet hours)
		msg := formatFlowFailed(event)
		nm.telegram.Send(msg)

	default:
		// "waiting", "created" — skip
		return
	}
}

// handleFinding handles new finding events with dedup and batching.
func (nm *NotificationManager) handleFinding(event NotificationEvent) {
	// Filter: only MEDIUM+ severity
	switch event.FindingSeverity {
	case SeverityCritical, SeverityHigh, SeverityMedium:
		// proceed
	default:
		return // skip LOW/INFO
	}

	// Dedup: skip if we've already sent this finding
	dedupKey := fmt.Sprintf("%d:%s", event.FlowID, event.FindingID)
	if _, already := nm.sentFindings.LoadOrStore(dedupKey, true); already {
		return
	}

	// CRITICAL findings bypass batching and quiet hours
	if event.FindingSeverity == SeverityCritical {
		msg := formatCriticalFinding(event)
		nm.telegram.Send(msg)
		return
	}

	// Quiet hours: skip non-critical findings
	if nm.isQuietHours() {
		return
	}

	// Batch findings
	nm.batchMu.Lock()
	defer nm.batchMu.Unlock()

	batch, exists := nm.batchMap[event.FlowID]
	if !exists {
		batch = &findingBatch{
			flowID:  event.FlowID,
			title:   event.Title,
			firstAt: time.Now(),
		}
		nm.batchMap[event.FlowID] = batch
	}
	batch.findings = append(batch.findings, event)

	// If we hit the batch threshold, flush immediately
	if len(batch.findings) >= findingBatchThreshold {
		if timer, ok := nm.batchTimers[event.FlowID]; ok {
			timer.Stop()
		}
		nm.flushBatchLocked(batch)
		delete(nm.batchMap, event.FlowID)
		delete(nm.batchTimers, event.FlowID)
		return
	}

	// Set/reset flush timer for this flow
	if timer, ok := nm.batchTimers[event.FlowID]; ok {
		timer.Stop()
	}
	nm.batchTimers[event.FlowID] = time.AfterFunc(findingBatchWindow, func() {
		nm.batchMu.Lock()
		defer nm.batchMu.Unlock()

		if b, ok := nm.batchMap[event.FlowID]; ok {
			nm.flushBatchLocked(b)
			delete(nm.batchMap, event.FlowID)
			delete(nm.batchTimers, event.FlowID)
		}
	})
}

// flushBatchLocked sends batched findings. Must be called with batchMu held.
func (nm *NotificationManager) flushBatchLocked(batch *findingBatch) {
	if len(batch.findings) == 0 {
		return
	}

	if len(batch.findings) == 1 {
		// Single finding — send individually
		msg := formatSingleFinding(batch.findings[0])
		nm.telegram.Send(msg)
		return
	}

	// Multiple findings — send as batch
	msg := formatBatchFindings(batch.flowID, batch.findings)
	nm.telegram.Send(msg)
}

// handlePhaseChange handles phase transition events.
func (nm *NotificationManager) handlePhaseChange(event NotificationEvent) {
	if nm.isQuietHours() {
		return
	}

	msg := formatPhaseChange(event)
	nm.telegram.Send(msg)
}

// handleFlowError handles flow error events (always notify).
func (nm *NotificationManager) handleFlowError(event NotificationEvent) {
	msg := formatFlowError(event)
	nm.telegram.Send(msg)
}

// isQuietHours returns true if the current time is within quiet hours.
func (nm *NotificationManager) isQuietHours() bool {
	now := time.Now().UTC().Add(nm.quietTZOffset)
	hour := now.Hour()
	return hour >= quietHoursStart && hour < quietHoursEnd
}

// ==================== Message Formatting ====================

func formatCriticalFinding(e NotificationEvent) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("🔴 <b>CRITICAL Finding — Flow #%d</b>\n", e.FlowID))
	b.WriteString("━━━━━━━━━━━━━━━━━━\n")
	b.WriteString(fmt.Sprintf("%s: %s\n", escapeHTML(e.FindingID), escapeHTML(e.Title)))
	if e.FindingTarget != "" {
		b.WriteString(fmt.Sprintf("🎯 %s\n", escapeHTML(e.FindingTarget)))
	}
	if e.FindingVulnType != "" {
		b.WriteString(fmt.Sprintf("🔓 %s\n", escapeHTML(e.FindingVulnType)))
	}
	b.WriteString("━━━━━━━━━━━━━━━━━━")
	return b.String()
}

func formatSingleFinding(e NotificationEvent) string {
	emoji := severityEmoji(e.FindingSeverity)
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s <b>%s Finding — Flow #%d</b>\n", emoji, e.FindingSeverity, e.FlowID))
	b.WriteString("━━━━━━━━━━━━━━━━━━\n")
	b.WriteString(fmt.Sprintf("%s: %s\n", escapeHTML(e.FindingID), escapeHTML(e.Title)))
	if e.FindingTarget != "" {
		b.WriteString(fmt.Sprintf("🎯 %s\n", escapeHTML(e.FindingTarget)))
	}
	if e.FindingVulnType != "" {
		b.WriteString(fmt.Sprintf("🔓 %s\n", escapeHTML(e.FindingVulnType)))
	}
	b.WriteString("━━━━━━━━━━━━━━━━━━")
	return b.String()
}

func formatBatchFindings(flowID int64, findings []NotificationEvent) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("🔍 <b>%d New Findings — Flow #%d</b>\n", len(findings), flowID))
	b.WriteString("━━━━━━━━━━━━━━━━━━\n")

	for _, f := range findings {
		emoji := severityEmoji(f.FindingSeverity)
		b.WriteString(fmt.Sprintf("%s %s: %s\n", emoji, escapeHTML(f.FindingID), escapeHTML(f.Title)))
		if f.FindingTarget != "" {
			b.WriteString(fmt.Sprintf("   🎯 %s\n", escapeHTML(f.FindingTarget)))
		}
	}

	b.WriteString("━━━━━━━━━━━━━━━━━━")
	return b.String()
}

func formatPhaseChange(e NotificationEvent) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("📊 <b>Flow #%d — Phase Change</b>\n", e.FlowID))
	b.WriteString(fmt.Sprintf("%s → %s\n", escapeHTML(e.OldPhase), escapeHTML(e.NewPhase)))
	if e.FindingsCount > 0 || e.AttacksDone > 0 {
		b.WriteString(fmt.Sprintf("📈 Findings: %d", e.FindingsCount))
		if e.AttacksTotal > 0 {
			b.WriteString(fmt.Sprintf(" | Attacks: %d/%d", e.AttacksDone, e.AttacksTotal))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func formatFlowComplete(e NotificationEvent) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("✅ <b>Flow #%d Complete</b>\n", e.FlowID))
	if e.Title != "" {
		b.WriteString(fmt.Sprintf("%s\n", escapeHTML(e.Title)))
	}
	if e.Duration > 0 {
		b.WriteString(fmt.Sprintf("Duration: %s\n", formatDuration(e.Duration)))
	}
	total := e.CriticalCount + e.HighCount + e.MediumCount + e.LowCount
	if total > 0 {
		b.WriteString(fmt.Sprintf("Findings: %d", total))
		parts := make([]string, 0, 4)
		if e.CriticalCount > 0 {
			parts = append(parts, fmt.Sprintf("%d🔴", e.CriticalCount))
		}
		if e.HighCount > 0 {
			parts = append(parts, fmt.Sprintf("%d🟠", e.HighCount))
		}
		if e.MediumCount > 0 {
			parts = append(parts, fmt.Sprintf("%d🟡", e.MediumCount))
		}
		if e.LowCount > 0 {
			parts = append(parts, fmt.Sprintf("%d🟢", e.LowCount))
		}
		if len(parts) > 0 {
			b.WriteString(fmt.Sprintf(" (%s)", strings.Join(parts, " ")))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func formatFlowFailed(e NotificationEvent) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("❌ <b>Flow #%d Failed</b>\n", e.FlowID))
	if e.Title != "" {
		b.WriteString(fmt.Sprintf("%s\n", escapeHTML(e.Title)))
	}
	if e.Error != "" {
		b.WriteString(fmt.Sprintf("Error: %s\n", escapeHTML(e.Error)))
	}
	if e.NewPhase != "" {
		b.WriteString(fmt.Sprintf("Last Phase: %s\n", escapeHTML(e.NewPhase)))
	}
	return b.String()
}

func formatFlowError(e NotificationEvent) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("⚠️ <b>Flow #%d Error</b>\n", e.FlowID))
	if e.Title != "" {
		b.WriteString(fmt.Sprintf("%s\n", escapeHTML(e.Title)))
	}
	if e.Error != "" {
		b.WriteString(fmt.Sprintf("Error: %s\n", escapeHTML(e.Error)))
	}
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

func severityEmoji(sev FindingSeverity) string {
	switch sev {
	case SeverityCritical:
		return "🔴"
	case SeverityHigh:
		return "🟠"
	case SeverityMedium:
		return "🟡"
	case SeverityLow:
		return "🟢"
	default:
		return "⚪"
	}
}

// MapSeverity converts a severity string to FindingSeverity.
func MapSeverity(sev string) FindingSeverity {
	switch sev {
	case "CRITICAL":
		return SeverityCritical
	case "HIGH":
		return SeverityHigh
	case "MEDIUM":
		return SeverityMedium
	case "LOW":
		return SeverityLow
	default:
		return SeverityInfo
	}
}

// escapeHTML escapes special HTML characters for Telegram HTML parse mode.
func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}
