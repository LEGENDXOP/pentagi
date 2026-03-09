package tools

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"pentagi/pkg/database"

	"github.com/sirupsen/logrus"
)

const (
	defaultMonitorPollInterval = 10 * time.Second
	monitorShutdownTimeout     = 5 * time.Second
)

// InteractshMonitor polls for OOB interactions in the background and
// calls a callback when interactions are detected.
type InteractshMonitor struct {
	mu            sync.Mutex
	client        *interactshClient
	pollInterval  time.Duration
	cancel        context.CancelFunc
	done          chan struct{}
	running       bool
	onInteraction InteractionCallback

	// Track already-seen interactions to avoid duplicate reports
	seenInteractions map[string]struct{}
}

// InteractionCallback is called when OOB interactions are detected.
// It receives the flow ID and the list of new interactions.
type InteractionCallback func(ctx context.Context, flowID int64, interactions []InteractshInteraction)

// NewInteractshMonitor creates a new background monitor for OOB interactions.
// The monitor will not start until Start() is called.
func NewInteractshMonitor(
	client *interactshClient,
	pollInterval time.Duration,
	onInteraction InteractionCallback,
) *InteractshMonitor {
	if pollInterval <= 0 {
		pollInterval = defaultMonitorPollInterval
	}
	return &InteractshMonitor{
		client:           client,
		pollInterval:     pollInterval,
		onInteraction:    onInteraction,
		seenInteractions: make(map[string]struct{}),
	}
}

// Start begins the background polling goroutine.
// It is safe to call Start multiple times — only the first call starts the monitor.
func (m *InteractshMonitor) Start(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return
	}

	monitorCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	m.done = make(chan struct{})
	m.running = true

	go m.pollLoop(monitorCtx)

	logrus.WithField("flow_id", m.client.flowID).
		WithField("poll_interval", m.pollInterval).
		Info("interactsh monitor started")
}

// Stop gracefully shuts down the background polling goroutine.
func (m *InteractshMonitor) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return
	}

	m.cancel()

	// Wait for the goroutine to finish with a timeout
	select {
	case <-m.done:
	case <-time.After(monitorShutdownTimeout):
		logrus.WithField("flow_id", m.client.flowID).
			Warn("interactsh monitor shutdown timed out")
	}

	m.running = false
	logrus.WithField("flow_id", m.client.flowID).
		Info("interactsh monitor stopped")
}

// pollLoop is the main background loop that polls for interactions
func (m *InteractshMonitor) pollLoop(ctx context.Context) {
	defer close(m.done)

	ticker := time.NewTicker(m.pollInterval)
	defer ticker.Stop()

	logger := logrus.WithFields(logrus.Fields{
		"flow_id":   m.client.flowID,
		"component": "interactsh_monitor",
	})

	for {
		select {
		case <-ctx.Done():
			logger.Debug("monitor context cancelled, exiting poll loop")
			return
		case <-ticker.C:
			m.pollOnce(ctx, logger)
		}
	}
}

// pollOnce performs a single poll for interactions
func (m *InteractshMonitor) pollOnce(ctx context.Context, logger *logrus.Entry) {
	if !m.client.IsRunning() {
		return
	}

	interactions, err := m.client.PollInteractions(ctx)
	if err != nil {
		logger.WithError(err).Debug("error polling interactsh interactions")
		return
	}

	if len(interactions) == 0 {
		return
	}

	// Filter out already-seen interactions
	var newInteractions []InteractshInteraction
	for _, interaction := range interactions {
		key := fmt.Sprintf("%s:%s:%s", interaction.FullID, interaction.Protocol, interaction.Timestamp)
		if _, seen := m.seenInteractions[key]; !seen {
			m.seenInteractions[key] = struct{}{}
			newInteractions = append(newInteractions, interaction)
		}
	}

	if len(newInteractions) == 0 {
		return
	}

	logger.WithField("count", len(newInteractions)).Info("new OOB interactions detected")

	// Log interactions
	for _, interaction := range newInteractions {
		logger.WithFields(logrus.Fields{
			"attack_id": interaction.AttackID,
			"protocol":  interaction.Protocol,
			"remote":    interaction.RemoteAddr,
			"full_id":   interaction.FullID,
		}).Info("OOB interaction received")
	}

	// Log to terminal if TLP is available
	if m.client.tlp != nil {
		summary := formatMonitorAlert(newInteractions)
		formattedMsg := FormatTerminalSystemOutput(summary)
		_, _ = m.client.tlp.PutMsg(
			ctx,
			database.TermlogTypeStdout,
			formattedMsg,
			m.client.containerID,
			m.client.taskID,
			m.client.subtaskID,
		)
	}

	// Call the interaction callback if set
	if m.onInteraction != nil {
		m.onInteraction(ctx, m.client.flowID, newInteractions)
	}
}

// formatMonitorAlert creates a concise terminal alert for detected interactions
func formatMonitorAlert(interactions []InteractshInteraction) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[OOB] 🚨 %d new interaction(s) detected:\n", len(interactions)))
	for _, i := range interactions {
		sb.WriteString(fmt.Sprintf("  • [%s] %s from %s (attack: %s)\n",
			strings.ToUpper(i.Protocol), i.FullID, i.RemoteAddr, i.AttackID))
	}
	return sb.String()
}
