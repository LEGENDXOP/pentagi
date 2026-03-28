package controller

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// FlowControlStatus represents the current control state of a flow.
type FlowControlStatus string

const (
	FlowControlStatusRunning FlowControlStatus = "running"
	FlowControlStatusPaused  FlowControlStatus = "paused"
	FlowControlStatusSteered FlowControlStatus = "steered"
	FlowControlStatusAborted FlowControlStatus = "aborted"
)

// FlowControlState holds the current control state for a single flow.
type FlowControlState struct {
	FlowID       int64             `json:"flowId"`
	Status       FlowControlStatus `json:"status"`
	SteerMessage string            `json:"steerMessage,omitempty"`
	UpdatedAt    time.Time         `json:"updatedAt"`
}

// FlowControlChangeHandler is called when flow control state changes.
type FlowControlChangeHandler func(state FlowControlState)

// FlowControlManager provides per-flow pause/resume/steer/abort capabilities.
// It is an in-memory system: flow control state does not persist across restarts.
// This is intentional — control actions are ephemeral operator interventions.
type FlowControlManager interface {
	// GetState returns the current control state for a flow.
	GetState(flowID int64) FlowControlState
	// Pause sets the flow to PAUSED status. The agent loop will block.
	Pause(flowID int64) (FlowControlState, error)
	// Resume unblocks a paused flow by setting status back to RUNNING.
	Resume(flowID int64) (FlowControlState, error)
	// Steer injects an operator message into the flow's next LLM context.
	Steer(flowID int64, message string) (FlowControlState, error)
	// Abort signals the flow to gracefully shut down.
	Abort(flowID int64) (FlowControlState, error)
	// CheckPoint is called from the agent execution loop.
	// It blocks while paused, returns steer message if steered (and resets to running),
	// and returns an error if aborted.
	CheckPoint(ctx context.Context, flowID int64) (steerMessage string, err error)
	// Remove cleans up state for a finished/deleted flow.
	Remove(flowID int64)
	// OnChange registers a handler for control state changes.
	OnChange(handler FlowControlChangeHandler)
}

// ErrFlowAborted is returned by CheckPoint when the flow has been aborted.
var ErrFlowAborted = fmt.Errorf("flow aborted by operator")

type flowControlManager struct {
	mx       sync.RWMutex
	states   map[int64]*flowControlEntry
	handlers []FlowControlChangeHandler
}

type flowControlEntry struct {
	state  FlowControlState
	signal chan struct{} // signaled on resume/steer/abort to unblock paused agents
}

// NewFlowControlManager creates a new in-memory flow control manager.
func NewFlowControlManager() FlowControlManager {
	return &flowControlManager{
		states:   make(map[int64]*flowControlEntry),
		handlers: make([]FlowControlChangeHandler, 0),
	}
}

func (m *flowControlManager) getOrCreate(flowID int64) *flowControlEntry {
	entry, ok := m.states[flowID]
	if !ok {
		entry = &flowControlEntry{
			state: FlowControlState{
				FlowID:    flowID,
				Status:    FlowControlStatusRunning,
				UpdatedAt: time.Now(),
			},
			signal: make(chan struct{}, 1),
		}
		m.states[flowID] = entry
	}
	return entry
}

func (m *flowControlManager) GetState(flowID int64) FlowControlState {
	m.mx.RLock()
	defer m.mx.RUnlock()

	entry, ok := m.states[flowID]
	if !ok {
		return FlowControlState{
			FlowID:    flowID,
			Status:    FlowControlStatusRunning,
			UpdatedAt: time.Now(),
		}
	}
	return entry.state
}

func (m *flowControlManager) Pause(flowID int64) (FlowControlState, error) {
	m.mx.Lock()
	defer m.mx.Unlock()

	entry := m.getOrCreate(flowID)
	if entry.state.Status == FlowControlStatusAborted {
		return entry.state, fmt.Errorf("cannot pause an aborted flow")
	}
	if entry.state.Status == FlowControlStatusPaused {
		return entry.state, nil // already paused
	}

	entry.state.Status = FlowControlStatusPaused
	entry.state.UpdatedAt = time.Now()

	logrus.WithFields(logrus.Fields{
		"flow_id": flowID,
		"status":  entry.state.Status,
	}).Info("flow control: paused")

	m.notifyHandlers(entry.state)
	return entry.state, nil
}

func (m *flowControlManager) Resume(flowID int64) (FlowControlState, error) {
	m.mx.Lock()
	defer m.mx.Unlock()

	entry := m.getOrCreate(flowID)
	if entry.state.Status == FlowControlStatusAborted {
		return entry.state, fmt.Errorf("cannot resume an aborted flow")
	}
	if entry.state.Status == FlowControlStatusRunning {
		return entry.state, nil // already running
	}

	entry.state.Status = FlowControlStatusRunning
	entry.state.SteerMessage = ""
	entry.state.UpdatedAt = time.Now()

	// Signal to unblock any CheckPoint waiting
	m.signalEntry(entry)

	logrus.WithFields(logrus.Fields{
		"flow_id": flowID,
		"status":  entry.state.Status,
	}).Info("flow control: resumed")

	m.notifyHandlers(entry.state)
	return entry.state, nil
}

func (m *flowControlManager) Steer(flowID int64, message string) (FlowControlState, error) {
	m.mx.Lock()
	defer m.mx.Unlock()

	if message == "" {
		return FlowControlState{}, fmt.Errorf("steer message cannot be empty")
	}

	entry := m.getOrCreate(flowID)
	if entry.state.Status == FlowControlStatusAborted {
		return entry.state, fmt.Errorf("cannot steer an aborted flow")
	}

	entry.state.Status = FlowControlStatusSteered
	entry.state.SteerMessage = message
	entry.state.UpdatedAt = time.Now()

	// Signal to unblock any CheckPoint waiting (if paused)
	m.signalEntry(entry)

	logrus.WithFields(logrus.Fields{
		"flow_id": flowID,
		"status":  entry.state.Status,
		"message": message,
	}).Info("flow control: steered")

	m.notifyHandlers(entry.state)
	return entry.state, nil
}

func (m *flowControlManager) Abort(flowID int64) (FlowControlState, error) {
	m.mx.Lock()
	defer m.mx.Unlock()

	entry := m.getOrCreate(flowID)
	entry.state.Status = FlowControlStatusAborted
	entry.state.UpdatedAt = time.Now()

	// Signal to unblock any CheckPoint waiting
	m.signalEntry(entry)

	logrus.WithFields(logrus.Fields{
		"flow_id": flowID,
		"status":  entry.state.Status,
	}).Info("flow control: aborted")

	m.notifyHandlers(entry.state)
	return entry.state, nil
}

func (m *flowControlManager) CheckPoint(ctx context.Context, flowID int64) (string, error) {
	for {
		m.mx.Lock()
		entry := m.getOrCreate(flowID)
		status := entry.state.Status

		switch status {
		case FlowControlStatusRunning:
			m.mx.Unlock()
			return "", nil

		case FlowControlStatusSteered:
			msg := entry.state.SteerMessage
			entry.state.Status = FlowControlStatusRunning
			entry.state.SteerMessage = ""
			entry.state.UpdatedAt = time.Now()
			m.notifyHandlers(entry.state)
			m.mx.Unlock()
			return msg, nil

		case FlowControlStatusAborted:
			m.mx.Unlock()
			return "", ErrFlowAborted

		case FlowControlStatusPaused:
			// Drain any stale signal before waiting
			select {
			case <-entry.signal:
			default:
			}
			signal := entry.signal
			m.mx.Unlock()

			// Block until signal, context cancel, or timeout
			select {
			case <-signal:
				// State changed, loop around to re-check
				continue
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}
	}
}

func (m *flowControlManager) Remove(flowID int64) {
	m.mx.Lock()
	defer m.mx.Unlock()

	delete(m.states, flowID)
}

func (m *flowControlManager) OnChange(handler FlowControlChangeHandler) {
	m.mx.Lock()
	defer m.mx.Unlock()

	m.handlers = append(m.handlers, handler)
}

// signalEntry sends a non-blocking signal to wake up any blocked CheckPoint.
// Must be called with m.mx held.
func (m *flowControlManager) signalEntry(entry *flowControlEntry) {
	select {
	case entry.signal <- struct{}{}:
	default:
	}
}

// notifyHandlers calls all registered change handlers.
// Must be called with m.mx held (handlers are append-only so this is safe).
func (m *flowControlManager) notifyHandlers(state FlowControlState) {
	for _, h := range m.handlers {
		go h(state)
	}
}
