package notifications

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
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
type NotifyingPublisher struct {
	inner     subscriptions.FlowPublisher
	notifier  *NotificationManager
	flowStart time.Time

	// Flow status dedup: track the last notified status to avoid duplicate
	// notifications when FlowUpdated fires multiple times for the same status
	// (e.g. on rename, container changes, or repeated SetStatus calls).
	notifiedStatus sync.Map // statusString -> bool (set once per status)

	// Phase tracking for detecting phase changes
	lastPhase   string
	lastPhaseMu sync.Mutex

	// Finding dedup: track finding IDs already emitted from this publisher
	emittedFindings sync.Map // findingKey -> bool
	findingCounter  int
	findingMu       sync.Mutex

	// Container file state tracking (smart notifications)
	dockerClient     docker.DockerClient
	lastFindingsText string    // last FINDINGS.md full text (for diffing)
	lastStateJSON    string    // last STATE.json content
	lastHandoffHash  string    // last HANDOFF.md content hash
	lastReadAt       time.Time // debounce: last container read time
	lastProgressAt   time.Time // rate limit: last progress message time
	readMu           sync.Mutex
	readScheduled    int32 // atomic: is a read already scheduled?
}

// WrapPublisher creates a NotifyingPublisher if the notifier is active.
// If notifier is nil or disabled, returns the original publisher unchanged.
// The docker client is optional — if nil, container file monitoring is disabled
// but all other notifications work normally.
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
// It deduplicates by tracking which statuses have already been notified:
// each of "running", "finished", "failed" is sent at most once per flow.
// This prevents duplicate Telegram messages when FlowUpdated fires multiple
// times for the same status (e.g. on rename, container changes, or repeated
// SetStatus calls during created→waiting→running transitions).
func (p *NotifyingPublisher) notifyFlowStatus(flow database.Flow) {
	defer func() {
		if r := recover(); r != nil {
			logrus.WithField("panic", r).Error("panic in notifyFlowStatus")
		}
	}()

	statusStr := string(flow.Status)

	switch flow.Status {
	case database.FlowStatusRunning:
		// Only notify ONCE on first transition to running
		if _, already := p.notifiedStatus.LoadOrStore(statusStr, true); already {
			return
		}
		p.notifier.Notify(NotificationEvent{
			Type:   EventFlowStatusChange,
			FlowID: flow.ID,
			Title:  flow.Title,
			Status: "running",
		})

	case database.FlowStatusFinished:
		// Only notify ONCE on first transition to finished
		if _, already := p.notifiedStatus.LoadOrStore(statusStr, true); already {
			return
		}
		p.notifier.Notify(NotificationEvent{
			Type:     EventFlowStatusChange,
			FlowID:   flow.ID,
			Title:    flow.Title,
			Status:   "finished",
			Duration: time.Since(p.flowStart),
		})

	case database.FlowStatusFailed:
		// Only notify ONCE on first transition to failed
		if _, already := p.notifiedStatus.LoadOrStore(statusStr, true); already {
			return
		}
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

	// Smart notifications: detect writes to tracked state files
	if p.dockerClient == nil {
		return
	}

	if isStateFileWrite(terminalLog.Text) {
		p.scheduleContainerRead()
	}
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
// It detects multiple finding formats commonly used in pentest reports:
//   - ### [CRITICAL] / ### [HIGH] / ### [MEDIUM] / ### [LOW]  (markdown headers)
//   - [FINDING ...] / [finding ...]                            (bracket tags)
//   - F-001: / F-002: etc.                                     (finding IDs)
//   - [VULN_TYPE: ...]                                         (vuln type tags)
//   - Lines with severity + vulnerability/finding/exploit keywords
func (p *NotifyingPublisher) scanTextForFindings(text string) {
	if text == "" {
		return
	}

	textUpper := strings.ToUpper(text)

	// Quick check: skip if no finding-related keywords present anywhere
	hasFindingKeyword := strings.Contains(textUpper, "FINDING") ||
		strings.Contains(textUpper, "VULNERABILITY") ||
		strings.Contains(textUpper, "VULN") ||
		strings.Contains(textUpper, "EXPLOIT") ||
		strings.Contains(textUpper, "F-0") // F-001, F-002, etc.
	if !hasFindingKeyword {
		return
	}

	flowID := p.inner.GetFlowID()
	lines := strings.Split(text, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		lineUpper := strings.ToUpper(line)
		isFinding := false

		// Pattern 1: Markdown severity headers — ### [CRITICAL], ### [HIGH], etc.
		if strings.HasPrefix(line, "###") || strings.HasPrefix(line, "##") {
			for _, sev := range []string{"[CRITICAL]", "[HIGH]", "[MEDIUM]", "[LOW]", "[INFO]"} {
				if strings.Contains(lineUpper, sev) {
					isFinding = true
					break
				}
			}
		}

		// Pattern 2: [FINDING ...] or [finding ...] bracket tags
		if !isFinding {
			if strings.Contains(line, "[FINDING") || strings.Contains(line, "[finding") {
				isFinding = true
			}
		}

		// Pattern 3: Finding IDs like F-001:, F-002:, F-123:
		if !isFinding {
			if isFindingID(line) {
				isFinding = true
			}
		}

		// Pattern 4: [VULN_TYPE: ...] tags
		if !isFinding {
			if strings.Contains(lineUpper, "[VULN_TYPE:") {
				isFinding = true
			}
		}

		// Pattern 5: Severity keyword + vulnerability/finding/exploit context
		if !isFinding {
			hasSeverity := strings.Contains(lineUpper, "CRITICAL") ||
				strings.Contains(lineUpper, "HIGH") ||
				strings.Contains(lineUpper, "MEDIUM") ||
				strings.Contains(lineUpper, "LOW")
			hasContext := strings.Contains(lineUpper, "VULN") ||
				strings.Contains(lineUpper, "FINDING") ||
				strings.Contains(lineUpper, "EXPLOIT")
			if hasSeverity && hasContext {
				isFinding = true
			}
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
			if strings.Contains(lineUpper, sev) {
				severity = sev
				break
			}
		}

		vulnType := ""
		if idx := strings.Index(lineUpper, "[VULN_TYPE:"); idx >= 0 {
			end := strings.Index(line[idx:], "]")
			if end > 0 {
				vulnType = strings.TrimSpace(line[idx+11 : idx+end])
			}
		}

		// Extract a clean title: strip markdown prefixes and brackets
		title := line
		title = strings.TrimLeft(title, "#")
		title = strings.TrimSpace(title)
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

// isFindingID checks if a line starts with a finding ID pattern like "F-001:", "F-12:".
func isFindingID(line string) bool {
	if len(line) < 4 {
		return false
	}
	if line[0] != 'F' && line[0] != 'f' {
		return false
	}
	if line[1] != '-' {
		return false
	}
	// Expect digits after F- followed by :
	i := 2
	for i < len(line) && line[i] >= '0' && line[i] <= '9' {
		i++
	}
	if i == 2 {
		return false // no digits
	}
	if i < len(line) && line[i] == ':' {
		return true
	}
	return false
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

// ==================== Smart Container File Notifications ====================

// isStateFileWrite detects terminal log entries that indicate a write to tracked state files.
func isStateFileWrite(text string) bool {
	if text == "" {
		return false
	}

	textUpper := strings.ToUpper(text)
	trackedFiles := []string{"FINDINGS.MD", "STATE.JSON", "HANDOFF.MD"}

	hasTrackedFile := false
	for _, f := range trackedFiles {
		if strings.Contains(textUpper, f) {
			hasTrackedFile = true
			break
		}
	}
	if !hasTrackedFile {
		return false
	}

	// Check for write patterns — commands or tool output indicating a file was written
	writePatterns := []string{
		"cat >", "cat >>", "Wrote to", "<<", "mv /tmp/",
		"jq ", "tee ", "written successfully", "echo ", "printf ",
		"> /work/", ">> /work/",
	}
	for _, pat := range writePatterns {
		if strings.Contains(text, pat) {
			return true
		}
	}

	// Also check uppercase variants for tool output
	if strings.Contains(textUpper, "WRITTEN") || strings.Contains(textUpper, "WROTE") {
		return true
	}

	return false
}

// scheduleContainerRead schedules a debounced container file read.
// If a read is already scheduled, this is a no-op (debounce).
func (p *NotifyingPublisher) scheduleContainerRead() {
	if !atomic.CompareAndSwapInt32(&p.readScheduled, 0, 1) {
		return // already scheduled
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logrus.WithField("panic", r).Error("panic in scheduleContainerRead")
			}
		}()

		// Wait for debounce window — agent may write multiple files in quick succession
		time.Sleep(10 * time.Second)
		atomic.StoreInt32(&p.readScheduled, 0)

		p.readMu.Lock()
		defer p.readMu.Unlock()

		// Rate limit: minimum 30s between container reads
		if time.Since(p.lastReadAt) < 30*time.Second {
			return
		}
		p.lastReadAt = time.Now()

		flowID := p.inner.GetFlowID()
		containerName := fmt.Sprintf("pentagi-terminal-%d", flowID)

		// Use a fresh context with timeout — the original ctx may be cancelled
		readCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		// Read all three files (best-effort: don't fail if file doesn't exist)
		findings, _ := ReadContainerFile(readCtx, p.dockerClient, containerName, "/work/FINDINGS.md")
		stateJSON, _ := ReadContainerFile(readCtx, p.dockerClient, containerName, "/work/STATE.json")
		handoff, _ := ReadContainerFile(readCtx, p.dockerClient, containerName, "/work/HANDOFF.md")

		// Process changes and send notifications
		p.processContainerState(flowID, findings, stateJSON, handoff)
	}()
}

// processContainerState compares container file contents against last known state
// and sends a Telegram notification with any changes.
func (p *NotifyingPublisher) processContainerState(flowID int64, findings, stateJSON, handoff string) {
	defer func() {
		if r := recover(); r != nil {
			logrus.WithField("panic", r).Error("panic in processContainerState")
		}
	}()

	var parts []string

	// 1. Check for new findings (diff against last known)
	if findings != "" && findings != p.lastFindingsText {
		newFindings := diffFindings(p.lastFindingsText, findings)
		if newFindings != "" {
			parts = append(parts, formatNewFindings(newFindings))
		}
		// Cap stored findings text at 50KB to prevent memory bloat on long runs
		if len(findings) > 50*1024 {
			p.lastFindingsText = findings[len(findings)-50*1024:]
		} else {
			p.lastFindingsText = findings
		}
	}

	// 2. Parse and format STATE.json changes
	if stateJSON != "" && stateJSON != p.lastStateJSON {
		stateMsg := formatStateJSON(stateJSON)
		if stateMsg != "" {
			parts = append(parts, stateMsg)
		}
		p.lastStateJSON = stateJSON
	}

	// 3. Check HANDOFF.md changes (just notify it was updated, don't dump content)
	if handoff != "" {
		handoffHash := hashContent(handoff)
		if handoffHash != p.lastHandoffHash {
			parts = append(parts, "📋 HANDOFF.md updated (agent transition)")
			p.lastHandoffHash = handoffHash
		}
	}

	if len(parts) == 0 {
		return // no changes
	}

	// Rate limit: max 1 progress message every 2 minutes
	// Exception: if findings contain CRITICAL keyword, bypass rate limit
	isCritical := false
	for _, part := range parts {
		if strings.Contains(strings.ToUpper(part), "CRITICAL") {
			isCritical = true
			break
		}
	}

	if !isCritical && time.Since(p.lastProgressAt) < 2*time.Minute {
		logrus.WithField("flow_id", flowID).Debug("progress message rate limited")
		return
	}
	p.lastProgressAt = time.Now()

	msg := fmt.Sprintf("📊 <b>Flow #%d — Progress Update</b>\n", flowID)
	msg += "━━━━━━━━━━━━━━━━━━\n"
	msg += strings.Join(parts, "\n\n")

	if p.notifier != nil && p.notifier.telegram != nil {
		p.notifier.telegram.Send(msg)
	}
}

// diffFindings returns only the NEW content in FINDINGS.md since last check.
// It handles both append-mode (new lines added at end) and full rewrite scenarios.
func diffFindings(oldText, newText string) string {
	if oldText == "" {
		// First time seeing findings — return everything
		return newText
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
		return newText
	}

	return "" // no change
}

// PentestState represents the expected structure of STATE.json.
// All fields are optional — we handle any subset gracefully.
type PentestState struct {
	Phase          string   `json:"phase"`
	Target         string   `json:"target"`
	AttacksDone    []string `json:"attacks_done"`
	AttacksBlocked []string `json:"attacks_blocked"`
	CurrentAttack  string   `json:"current_attack"`
	AuthStatus     string   `json:"auth_status"`
	FindingsCount  int      `json:"findings_count"`
}

// formatStateJSON parses STATE.json and returns a formatted string for Telegram.
func formatStateJSON(raw string) string {
	if raw == "" {
		return ""
	}

	var state PentestState
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		// Try as generic map for unexpected schemas
		var generic map[string]interface{}
		if err2 := json.Unmarshal([]byte(raw), &generic); err2 != nil {
			return "" // completely malformed — skip silently
		}
		return formatGenericState(generic)
	}

	var b strings.Builder
	b.WriteString("🎯 <b>Current State</b>\n")

	hasContent := false
	if state.Phase != "" {
		b.WriteString(fmt.Sprintf("Phase: %s\n", escapeHTML(state.Phase)))
		hasContent = true
	}
	if state.Target != "" {
		b.WriteString(fmt.Sprintf("Target: <code>%s</code>\n", escapeHTML(state.Target)))
		hasContent = true
	}
	if state.CurrentAttack != "" {
		b.WriteString(fmt.Sprintf("Attack: %s\n", escapeHTML(state.CurrentAttack)))
		hasContent = true
	}
	if state.AuthStatus != "" {
		b.WriteString(fmt.Sprintf("Auth: %s\n", escapeHTML(state.AuthStatus)))
		hasContent = true
	}
	if state.FindingsCount > 0 {
		b.WriteString(fmt.Sprintf("Findings: %d\n", state.FindingsCount))
		hasContent = true
	}
	if len(state.AttacksDone) > 0 {
		b.WriteString(fmt.Sprintf("Completed: %d attacks\n", len(state.AttacksDone)))
		hasContent = true
	}
	if len(state.AttacksBlocked) > 0 {
		b.WriteString(fmt.Sprintf("Blocked: %d attacks\n", len(state.AttacksBlocked)))
		hasContent = true
	}

	if !hasContent {
		return ""
	}

	return b.String()
}

// formatGenericState handles unexpected STATE.json schemas by showing key-value pairs.
func formatGenericState(m map[string]interface{}) string {
	if len(m) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("🎯 <b>Current State</b>\n")

	count := 0
	for key, val := range m {
		if count >= 8 {
			b.WriteString("...\n")
			break
		}
		valStr := fmt.Sprintf("%v", val)
		if len(valStr) > 100 {
			valStr = valStr[:97] + "..."
		}
		b.WriteString(fmt.Sprintf("%s: %s\n", escapeHTML(key), escapeHTML(valStr)))
		count++
	}

	return b.String()
}

// formatNewFindings formats new findings content for Telegram.
func formatNewFindings(delta string) string {
	delta = strings.TrimSpace(delta)
	if delta == "" {
		return ""
	}

	var b strings.Builder
	b.WriteString("🔍 <b>New Findings</b>\n")

	// Smart truncation: max 1500 chars for findings section
	content := delta
	if len(content) > 1500 {
		content = content[:1497] + "..."
	}
	b.WriteString(fmt.Sprintf("<pre>%s</pre>", escapeHTML(content)))

	return b.String()
}

// hashContent returns a short SHA256 hash of the given content.
func hashContent(s string) string {
	if s == "" {
		return ""
	}
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}
