package masteragent

import (
	"sync"
	"time"
)

// HealthStatus represents the health assessment of a flow.
type HealthStatus string

const (
	HealthHealthy    HealthStatus = "HEALTHY"
	HealthWarning    HealthStatus = "WARNING"
	HealthCritical   HealthStatus = "CRITICAL"
)

// Action represents the Master Agent's decision.
type Action string

const (
	ActionNone   Action = "NONE"
	ActionSteer  Action = "STEER"
	ActionPause  Action = "PAUSE"
	ActionResume Action = "RESUME"
	ActionStop   Action = "STOP"
)

// LLMDecision represents the parsed response from the LLM.
type LLMDecision struct {
	Action       Action       `json:"action"`
	SteerMessage string       `json:"steer_message,omitempty"`
	Health       HealthStatus `json:"health"`
	Reasoning    string       `json:"reasoning"`
}

// CycleState tracks the Master Agent's state for a flow across cycles.
// In-memory only (resets on restart — acceptable for v1).
type CycleState struct {
	mx sync.Mutex

	FlowID          int64        `json:"flow_id"`
	Cycle           int          `json:"cycle"`
	LastMessageID   int64        `json:"last_message_id"`
	LastCheckTS     time.Time    `json:"last_check_ts"`
	FindingsCount   int          `json:"findings_count"`
	ConfirmedCount  int          `json:"confirmed_count"`
	TotalSteers     int          `json:"total_steers"`
	TotalPauses     int          `json:"total_pauses"`
	LastSteerCycle  int          `json:"last_steer_cycle"`
	HealthHistory   []HealthStatus `json:"health_history"`    // last 10
	CriticalEvents  []string     `json:"critical_events"`    // last 20
	NoProgressWindow []bool      `json:"no_progress_window"` // last 10
}

// NewCycleState creates a fresh cycle state for a flow.
func NewCycleState(flowID int64) *CycleState {
	return &CycleState{
		FlowID:          flowID,
		Cycle:           0,
		HealthHistory:   make([]HealthStatus, 0, 10),
		CriticalEvents:  make([]string, 0, 20),
		NoProgressWindow: make([]bool, 0, 10),
	}
}

// IncrementCycle advances the cycle counter and returns the new cycle number.
func (cs *CycleState) IncrementCycle() int {
	cs.mx.Lock()
	defer cs.mx.Unlock()

	cs.Cycle++
	cs.LastCheckTS = time.Now()
	return cs.Cycle
}

// RecordHealth appends a health status (keeps last 10).
func (cs *CycleState) RecordHealth(h HealthStatus) {
	cs.mx.Lock()
	defer cs.mx.Unlock()

	cs.HealthHistory = append(cs.HealthHistory, h)
	if len(cs.HealthHistory) > 10 {
		cs.HealthHistory = cs.HealthHistory[len(cs.HealthHistory)-10:]
	}
}

// RecordProgress appends a progress indicator (keeps last 10).
func (cs *CycleState) RecordProgress(madeProgress bool) {
	cs.mx.Lock()
	defer cs.mx.Unlock()

	cs.NoProgressWindow = append(cs.NoProgressWindow, !madeProgress)
	if len(cs.NoProgressWindow) > 10 {
		cs.NoProgressWindow = cs.NoProgressWindow[len(cs.NoProgressWindow)-10:]
	}
}

// RecordCriticalEvent logs a key event (keeps last 20).
func (cs *CycleState) RecordCriticalEvent(event string) {
	cs.mx.Lock()
	defer cs.mx.Unlock()

	cs.CriticalEvents = append(cs.CriticalEvents, event)
	if len(cs.CriticalEvents) > 20 {
		cs.CriticalEvents = cs.CriticalEvents[len(cs.CriticalEvents)-20:]
	}
}

// RecordSteer records that a steer was performed this cycle.
func (cs *CycleState) RecordSteer() {
	cs.mx.Lock()
	defer cs.mx.Unlock()

	cs.TotalSteers++
	cs.LastSteerCycle = cs.Cycle
}

// RecordPause records that a pause was performed this cycle.
func (cs *CycleState) RecordPause() {
	cs.mx.Lock()
	defer cs.mx.Unlock()

	cs.TotalPauses++
}

// IsInSteerCooldown returns true if a steer was sent within the last 2 cycles.
func (cs *CycleState) IsInSteerCooldown() bool {
	cs.mx.Lock()
	defer cs.mx.Unlock()

	if cs.LastSteerCycle == 0 {
		return false
	}
	return cs.Cycle-cs.LastSteerCycle < 2
}

// IsWarmup returns true if the flow is in warmup phase (first 2 cycles).
func (cs *CycleState) IsWarmup() bool {
	cs.mx.Lock()
	defer cs.mx.Unlock()

	return cs.Cycle <= 2
}

// GetNoProgressCount returns how many of the last N entries show no progress.
func (cs *CycleState) GetNoProgressCount(lastN int) int {
	cs.mx.Lock()
	defer cs.mx.Unlock()

	count := 0
	start := len(cs.NoProgressWindow) - lastN
	if start < 0 {
		start = 0
	}
	for _, np := range cs.NoProgressWindow[start:] {
		if np {
			count++
		}
	}
	return count
}

// UpdateMessageCursor updates the last seen message ID.
func (cs *CycleState) UpdateMessageCursor(msgID int64) {
	cs.mx.Lock()
	defer cs.mx.Unlock()

	if msgID > cs.LastMessageID {
		cs.LastMessageID = msgID
	}
}

// UpdateFindingsCounts updates findings counters.
func (cs *CycleState) UpdateFindingsCounts(total, confirmed int) {
	cs.mx.Lock()
	defer cs.mx.Unlock()

	cs.FindingsCount = total
	cs.ConfirmedCount = confirmed
}

// Snapshot returns a copy of the state for building prompts.
func (cs *CycleState) Snapshot() CycleState {
	cs.mx.Lock()
	defer cs.mx.Unlock()

	snap := CycleState{
		FlowID:         cs.FlowID,
		Cycle:          cs.Cycle,
		LastMessageID:  cs.LastMessageID,
		LastCheckTS:    cs.LastCheckTS,
		FindingsCount:  cs.FindingsCount,
		ConfirmedCount: cs.ConfirmedCount,
		TotalSteers:    cs.TotalSteers,
		TotalPauses:    cs.TotalPauses,
		LastSteerCycle: cs.LastSteerCycle,
	}
	snap.HealthHistory = make([]HealthStatus, len(cs.HealthHistory))
	copy(snap.HealthHistory, cs.HealthHistory)
	snap.CriticalEvents = make([]string, len(cs.CriticalEvents))
	copy(snap.CriticalEvents, cs.CriticalEvents)
	snap.NoProgressWindow = make([]bool, len(cs.NoProgressWindow))
	copy(snap.NoProgressWindow, cs.NoProgressWindow)
	return snap
}
