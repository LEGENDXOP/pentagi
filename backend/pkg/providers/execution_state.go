package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"pentagi/pkg/database"

	"github.com/sirupsen/logrus"
)

// ExecutionState captures the agent's execution progress for crash recovery.
// It is serialized to JSON and persisted in the subtask's Context column.
//
// V2 additions:
//   - CompletedTasks: tracks which semantic work items (subdomain_enumeration,
//     port_scan, etc.) have been completed. Prevents the agent from re-running
//     reconnaissance tasks it already finished (Flow 23 problem).
//   - LoopDetectorState: persists the loop detector's alert count so the
//     escalation level survives context switches (Flow 24 problem).
type ExecutionState struct {
	Phase          string              `json:"phase"`
	ToolCallCount  int                 `json:"tool_call_count"`
	FindingsCount  int                 `json:"findings_count"`
	AttacksDone    []string            `json:"attacks_done"`
	CurrentAttack  string              `json:"current_attack"`
	ErrorCount     int                 `json:"error_count"`
	LastUpdate     string              `json:"last_update"`
	ResumeContext  string              `json:"resume_context,omitempty"`

	// V2: Completed work items — persists across context switches so the agent
	// knows which recon/attack tasks are done even after chain summarization
	// strips the execution history.
	CompletedTasks []CompletedTaskJSON `json:"completed_tasks,omitempty"`

	// V2: Loop detector alert count — persists escalation level across context
	// switches. If the agent was already warned 2x about looping, the 3rd
	// warning after resume will be CRITICAL, not informational.
	LoopAlertCount int `json:"loop_alert_count,omitempty"`
}

// MarshalJSON serializes the execution state to JSON.
func (es *ExecutionState) ToJSON() (string, error) {
	data, err := json.Marshal(es)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ParseExecutionState deserializes an ExecutionState from a JSON string.
// Returns nil if the input is empty or malformed (first-run case).
func ParseExecutionState(data string) *ExecutionState {
	if data == "" {
		return nil
	}
	var state ExecutionState
	if err := json.Unmarshal([]byte(data), &state); err != nil {
		return nil
	}
	return &state
}

// NewExecutionState creates a fresh execution state for a new subtask run.
func NewExecutionState() *ExecutionState {
	return &ExecutionState{
		Phase:          "init",
		AttacksDone:    make([]string, 0),
		CompletedTasks: make([]CompletedTaskJSON, 0),
		LastUpdate:     time.Now().UTC().Format(time.RFC3339),
	}
}

// Update refreshes the state from current ExecutionMetrics.
func (es *ExecutionState) Update(metrics *ExecutionMetrics, phase string) {
	es.Phase = phase
	es.ToolCallCount = metrics.ToolCallCount
	es.ErrorCount = metrics.ErrorCount
	es.LastUpdate = time.Now().UTC().Format(time.RFC3339)

	// Build attacks_done from unique commands (deduplicated by metrics)
	es.AttacksDone = make([]string, len(metrics.UniqueCommands))
	copy(es.AttacksDone, metrics.UniqueCommands)

	if metrics.LastToolName != "" {
		es.CurrentAttack = metrics.LastToolName
	}
}

// UpdateCompletedTasks syncs the completed work tracker's state into the
// execution state for persistence. Call this after Update() and before ToJSON().
func (es *ExecutionState) UpdateCompletedTasks(tracker *CompletedWorkTracker) {
	if tracker == nil {
		return
	}
	es.CompletedTasks = tracker.ToJSON()
}

// UpdateLoopAlertCount syncs the loop detector's alert count into the
// execution state for persistence.
func (es *ExecutionState) UpdateLoopAlertCount(detector *ReadLoopDetector) {
	if detector == nil {
		return
	}
	_, alerts := detector.GetStats()
	es.LoopAlertCount = alerts
}

// BuildResumeInjectionMessage creates a human-role message that tells the LLM
// exactly what has already been done, preventing it from re-running completed work.
//
// V2 enhancement: includes the completed work items list so the agent knows
// exactly which recon/attack tasks are already done and where their results are.
func (es *ExecutionState) BuildResumeInjectionMessage() string {
	var sb strings.Builder
	sb.WriteString("[EXECUTION RESUME — READ CAREFULLY]\n\n")
	sb.WriteString("You are RESUMING a subtask that was interrupted. Here is your progress:\n\n")
	sb.WriteString(fmt.Sprintf("  Phase: %s\n", es.Phase))
	sb.WriteString(fmt.Sprintf("  Tool calls already made: %d\n", es.ToolCallCount))
	sb.WriteString(fmt.Sprintf("  Errors encountered: %d\n", es.ErrorCount))
	sb.WriteString(fmt.Sprintf("  Last update: %s\n", es.LastUpdate))

	if len(es.AttacksDone) > 0 {
		sb.WriteString(fmt.Sprintf("  Tools/attacks already executed: %s\n", strings.Join(es.AttacksDone, ", ")))
	}
	if es.CurrentAttack != "" {
		sb.WriteString(fmt.Sprintf("  Last tool used: %s\n", es.CurrentAttack))
	}

	// V2: Include completed work items
	if len(es.CompletedTasks) > 0 {
		sb.WriteString("\n## COMPLETED WORK ITEMS (DO NOT RE-RUN):\n")
		for _, task := range es.CompletedTasks {
			sb.WriteString(fmt.Sprintf("  ✅ %s — completed at %s", task.Description, task.CompletedAt))
			if task.ResultCount > 0 {
				sb.WriteString(fmt.Sprintf(" (%d results)", task.ResultCount))
			}
			if task.OutputFile != "" {
				sb.WriteString(fmt.Sprintf(" → saved to %s", task.OutputFile))
			}
			sb.WriteString("\n")
		}
	}

	sb.WriteString("\n⚠️ CRITICAL INSTRUCTIONS:\n")
	sb.WriteString("1. DO NOT re-run nmap, nuclei, subfinder, or any reconnaissance tool that was already executed\n")
	sb.WriteString("2. DO NOT re-read STATE.json, FINDINGS.md, or HANDOFF.md — their content was already processed\n")
	sb.WriteString("3. DO NOT re-install tools (jq, curl, nuclei, etc.) — they are already installed\n")
	sb.WriteString("4. CONTINUE from where you left off — proceed to the next UNFINISHED phase\n")
	sb.WriteString("5. If you completed reconnaissance, move to exploitation immediately\n")

	// V2: If loop alerts were generated before the context switch, warn more aggressively
	if es.LoopAlertCount > 0 {
		sb.WriteString(fmt.Sprintf(
			"\n🔴 LOOP WARNING: Before the interruption, you were detected looping %d time(s). "+
				"Do NOT fall back into the same pattern. Take DIRECT ACTION — do not re-read files.\n",
			es.LoopAlertCount,
		))
	}

	if es.ResumeContext != "" {
		sb.WriteString("\n--- Detailed Resume Context ---\n")
		sb.WriteString(es.ResumeContext)
	}

	return sb.String()
}

// stateWriteRequest is sent to the async writer goroutine.
type stateWriteRequest struct {
	subtaskID int64
	data      string
}

// AsyncStateWriter batches execution state writes to the DB without blocking
// the agent loop. It coalesces rapid updates — only the latest state for each
// subtask is persisted.
type AsyncStateWriter struct {
	db     database.Querier
	ch     chan stateWriteRequest
	wg     sync.WaitGroup
	cancel context.CancelFunc
}

const (
	stateWriterChanSize  = 64
	stateWriterFlushRate = 2 * time.Second
)

// NewAsyncStateWriter creates and starts the background state writer.
// Call Close() to flush pending writes and stop the goroutine.
func NewAsyncStateWriter(db database.Querier) *AsyncStateWriter {
	ctx, cancel := context.WithCancel(context.Background())
	w := &AsyncStateWriter{
		db:     db,
		ch:     make(chan stateWriteRequest, stateWriterChanSize),
		cancel: cancel,
	}
	w.wg.Add(1)
	go w.run(ctx)
	return w
}

// Write enqueues a state update. Non-blocking; drops if the channel is full
// (acceptable since state writes are best-effort).
func (w *AsyncStateWriter) Write(subtaskID int64, data string) {
	select {
	case w.ch <- stateWriteRequest{subtaskID: subtaskID, data: data}:
	default:
		logrus.WithField("subtask_id", subtaskID).
			Warn("execution state write channel full, dropping update")
	}
}

// Close stops the writer and flushes any pending writes.
func (w *AsyncStateWriter) Close() {
	w.cancel()
	w.wg.Wait()
}

// run is the background loop that coalesces and flushes writes.
func (w *AsyncStateWriter) run(ctx context.Context) {
	defer w.wg.Done()

	// pending holds the latest state per subtask (coalescing).
	pending := make(map[int64]string)
	ticker := time.NewTicker(stateWriterFlushRate)
	defer ticker.Stop()

	flush := func() {
		if len(pending) == 0 {
			return
		}
		// Use a fresh background context for DB writes so they succeed even
		// if the parent context is cancelled (graceful shutdown).
		writeCtx, writeCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer writeCancel()

		for id, data := range pending {
			if err := w.db.UpdateSubtaskContextWithTimestamp(writeCtx, database.UpdateSubtaskContextWithTimestampParams{
				ID:      id,
				Context: data,
			}); err != nil {
				logrus.WithError(err).WithField("subtask_id", id).
					Error("failed to write execution state to DB")
			}
		}
		// Clear pending after flush attempt (even on partial failure — stale
		// state is acceptable, and the next update will overwrite).
		for k := range pending {
			delete(pending, k)
		}
	}

	for {
		select {
		case req, ok := <-w.ch:
			if !ok {
				flush()
				return
			}
			pending[req.subtaskID] = req.data

		case <-ticker.C:
			flush()

		case <-ctx.Done():
			// Drain remaining items from channel before flushing.
			for {
				select {
				case req := <-w.ch:
					pending[req.subtaskID] = req.data
				default:
					flush()
					return
				}
			}
		}
	}
}
