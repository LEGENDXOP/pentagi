package masteragent

import (
	"context"
	"sync"
	"time"

	"pentagi/pkg/config"
	"pentagi/pkg/database"
	"pentagi/pkg/notifications"

	"github.com/sirupsen/logrus"
)

// agentEntry tracks a running Master Agent goroutine for a flow.
type agentEntry struct {
	cancel context.CancelFunc
	agent  *Agent
}

// Supervisor manages Master Agent goroutines for active flows.
// Each flow gets its own goroutine that runs supervision cycles at a configured interval.
type Supervisor struct {
	mx          sync.Mutex
	cfg         *config.Config
	maCfg       MasterAgentConfig
	db          database.Querier
	flowControl FlowControlAdapter
	notifier    *notifications.NotificationManager
	agents      map[int64]*agentEntry
	logger      *logrus.Entry
}

// NewSupervisor creates a new Master Agent supervisor.
func NewSupervisor(
	cfg *config.Config,
	maCfg MasterAgentConfig,
	db database.Querier,
	flowControl FlowControlAdapter,
	notifier *notifications.NotificationManager,
) *Supervisor {
	return &Supervisor{
		cfg:         cfg,
		maCfg:       maCfg,
		db:          db,
		flowControl: flowControl,
		notifier:    notifier,
		agents:      make(map[int64]*agentEntry),
		logger: logrus.WithFields(logrus.Fields{
			"component": "master_agent_supervisor",
		}),
	}
}

// StartForFlow spawns a Master Agent goroutine for the given flow.
// If an agent is already running for this flow, this is a no-op.
func (s *Supervisor) StartForFlow(flowID int64) {
	s.mx.Lock()
	defer s.mx.Unlock()

	if _, exists := s.agents[flowID]; exists {
		s.logger.WithField("flow_id", flowID).Debug("master agent already running for flow")
		return
	}

	agent := NewAgent(flowID, s.cfg, s.maCfg, s.db, s.flowControl, s.notifier)
	ctx, cancel := context.WithCancel(context.Background())

	entry := &agentEntry{
		cancel: cancel,
		agent:  agent,
	}
	s.agents[flowID] = entry

	go s.runLoop(ctx, flowID, agent)

	s.logger.WithFields(logrus.Fields{
		"flow_id":  flowID,
		"interval": s.maCfg.Interval.String(),
	}).Info("master agent started for flow")
}

// StopForFlow cancels the Master Agent goroutine for the given flow.
func (s *Supervisor) StopForFlow(flowID int64) {
	s.mx.Lock()
	defer s.mx.Unlock()

	entry, exists := s.agents[flowID]
	if !exists {
		return
	}

	entry.cancel()
	delete(s.agents, flowID)

	s.logger.WithField("flow_id", flowID).Info("master agent stopped for flow")
}

// StopAll cancels all running Master Agent goroutines.
func (s *Supervisor) StopAll() {
	s.mx.Lock()
	defer s.mx.Unlock()

	for flowID, entry := range s.agents {
		entry.cancel()
		s.logger.WithField("flow_id", flowID).Info("master agent stopped (shutdown)")
	}

	s.agents = make(map[int64]*agentEntry)
	s.logger.Info("all master agents stopped")
}

// ActiveCount returns the number of currently running Master Agent goroutines.
func (s *Supervisor) ActiveCount() int {
	s.mx.Lock()
	defer s.mx.Unlock()
	return len(s.agents)
}

// runLoop is the goroutine body for a single flow's Master Agent.
// It runs cycles at the configured interval until the context is cancelled.
func (s *Supervisor) runLoop(ctx context.Context, flowID int64, agent *Agent) {
	logger := s.logger.WithField("flow_id", flowID)

	// Initial delay: wait one interval before first cycle to let the flow start
	select {
	case <-ctx.Done():
		logger.Debug("master agent loop cancelled before first cycle")
		return
	case <-time.After(s.maCfg.Interval):
	}

	ticker := time.NewTicker(s.maCfg.Interval)
	defer ticker.Stop()

	for {
		// Pre-cycle terminal check — avoid RunCycle entirely if flow is already dead.
		// This catches flows that were aborted/finished between ticks.
		flow, err := s.db.GetFlow(ctx, flowID)
		if err != nil {
			logger.WithError(err).Warn("failed to check flow status before cycle")
		} else if flow.Status == database.FlowStatusFinished || flow.Status == database.FlowStatusFailed || flow.Status == database.FlowStatusCreated {
			logger.WithField("status", flow.Status).Info("flow is terminal before cycle, stopping master agent")
			s.mx.Lock()
			delete(s.agents, flowID)
			s.mx.Unlock()
			return
		}

		// Run a cycle
		if err := agent.RunCycle(ctx); err != nil {
			logger.WithError(err).Error("master agent cycle failed")
		}

		// Post-cycle terminal check — stop if flow ended during the cycle.
		flow, err = s.db.GetFlow(ctx, flowID)
		if err != nil {
			logger.WithError(err).Warn("failed to check flow status after cycle")
		} else if flow.Status == database.FlowStatusFinished || flow.Status == database.FlowStatusFailed {
			logger.WithField("status", flow.Status).Info("flow reached terminal state, stopping master agent")
			s.mx.Lock()
			delete(s.agents, flowID)
			s.mx.Unlock()
			return
		}

		// Wait for next cycle
		select {
		case <-ctx.Done():
			logger.Debug("master agent loop cancelled")
			return
		case <-ticker.C:
			// next cycle
		}
	}
}
