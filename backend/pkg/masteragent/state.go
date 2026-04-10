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
	ActionNone          Action = "NONE"
	ActionSteer         Action = "STEER"
	ActionPause         Action = "PAUSE"
	ActionResume        Action = "RESUME"
	ActionStop          Action = "STOP"
	ActionHardStop      Action = "HARD_STOP"       // forced termination with full cleanup
	ActionSkipSubtask   Action = "SKIP_SUBTASK"    // force-complete current subtask, advance to next
	ActionInjectSubtask Action = "INJECT_SUBTASK"  // create new subtask as next-to-execute
)

// LLMDecision represents the parsed response from the LLM.
type LLMDecision struct {
	Action              Action       `json:"action"`
	SteerMessage        string       `json:"steer_message,omitempty"`
	SubtaskDescription  string       `json:"subtask_description,omitempty"` // Fix 6: for INJECT_SUBTASK
	Health              HealthStatus `json:"health"`
	Reasoning           string       `json:"reasoning"`
}

// SteerRecord tracks a single steer's lifecycle: sent → consumed → effective/ignored.
type SteerRecord struct {
	Cycle        int    `json:"cycle"`
	Message      string `json:"message"`
	ConsumedAt   int    `json:"consumed_at"`   // cycle when steer was consumed (0 = still pending)
	WasEffective bool   `json:"was_effective"` // true if agent behavior changed after consumption
	Evaluated    bool   `json:"evaluated"`     // true if effectiveness was checked
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

	// Steer effectiveness tracking (Issue A: HARD_STOP authority)
	SteerHistory             []SteerRecord `json:"steer_history"`              // last 10 steers
	ConsecutiveIgnoredSteers int           `json:"consecutive_ignored_steers"` // reset on effective steer or HARD_STOP
	LastSteerConsumedCycle   int           `json:"last_steer_consumed_cycle"` // cycle when last steer was consumed
	PreSteerToolPattern      string        `json:"pre_steer_tool_pattern"`    // tool call pattern before steer (for comparison)
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

// RecordSteer records that a steer was performed this cycle (legacy — used when no pattern tracking needed).
func (cs *CycleState) RecordSteer() {
	cs.mx.Lock()
	defer cs.mx.Unlock()

	cs.TotalSteers++
	cs.LastSteerCycle = cs.Cycle
}

// RecordSteerSent records a new steer with pre-steer context for later effectiveness evaluation.
func (cs *CycleState) RecordSteerSent(cycle int, message string, currentToolPattern string) {
	cs.mx.Lock()
	defer cs.mx.Unlock()

	cs.TotalSteers++
	cs.LastSteerCycle = cycle
	cs.PreSteerToolPattern = currentToolPattern

	record := SteerRecord{
		Cycle:   cycle,
		Message: message,
	}
	cs.SteerHistory = append(cs.SteerHistory, record)
	if len(cs.SteerHistory) > 10 {
		cs.SteerHistory = cs.SteerHistory[len(cs.SteerHistory)-10:]
	}
}

// MarkSteerConsumed records that the pending steer was consumed by the agent checkpoint.
func (cs *CycleState) MarkSteerConsumed(cycle int) {
	cs.mx.Lock()
	defer cs.mx.Unlock()

	if len(cs.SteerHistory) == 0 {
		return
	}
	last := &cs.SteerHistory[len(cs.SteerHistory)-1]
	if last.ConsumedAt == 0 {
		last.ConsumedAt = cycle
		cs.LastSteerConsumedCycle = cycle
	}
}

// EvaluateSteerEffectiveness checks if the most recent consumed steer changed agent behavior.
// Call this 2 cycles after a steer was consumed.
// currentToolPattern is a fingerprint of recent tool calls.
func (cs *CycleState) EvaluateSteerEffectiveness(currentToolPattern string) {
	cs.mx.Lock()
	defer cs.mx.Unlock()

	if len(cs.SteerHistory) == 0 {
		return
	}

	last := &cs.SteerHistory[len(cs.SteerHistory)-1]
	if last.Evaluated || last.ConsumedAt == 0 {
		return // not consumed yet or already evaluated
	}

	// Compare: if tool pattern is substantially the same, steer was ignored
	last.Evaluated = true
	if currentToolPattern == cs.PreSteerToolPattern || currentToolPattern == "" {
		last.WasEffective = false
		cs.ConsecutiveIgnoredSteers++
	} else {
		last.WasEffective = true
		cs.ConsecutiveIgnoredSteers = 0 // reset on success
	}
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

// Snapshot returns a pointer to a copy of the state for building prompts.
// Returns *CycleState (not value) to avoid copying the embedded sync.Mutex.
func (cs *CycleState) Snapshot() *CycleState {
	cs.mx.Lock()
	defer cs.mx.Unlock()

	snap := &CycleState{
		FlowID:                  cs.FlowID,
		Cycle:                   cs.Cycle,
		LastMessageID:           cs.LastMessageID,
		LastCheckTS:             cs.LastCheckTS,
		FindingsCount:           cs.FindingsCount,
		ConfirmedCount:          cs.ConfirmedCount,
		TotalSteers:             cs.TotalSteers,
		TotalPauses:             cs.TotalPauses,
		LastSteerCycle:          cs.LastSteerCycle,
		ConsecutiveIgnoredSteers: cs.ConsecutiveIgnoredSteers,
		LastSteerConsumedCycle:  cs.LastSteerConsumedCycle,
		PreSteerToolPattern:     cs.PreSteerToolPattern,
	}
	snap.HealthHistory = make([]HealthStatus, len(cs.HealthHistory))
	copy(snap.HealthHistory, cs.HealthHistory)
	snap.CriticalEvents = make([]string, len(cs.CriticalEvents))
	copy(snap.CriticalEvents, cs.CriticalEvents)
	snap.NoProgressWindow = make([]bool, len(cs.NoProgressWindow))
	copy(snap.NoProgressWindow, cs.NoProgressWindow)
	snap.SteerHistory = make([]SteerRecord, len(cs.SteerHistory))
	copy(snap.SteerHistory, cs.SteerHistory)
	return snap
}
