package providers

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"pentagi/pkg/database"

	"github.com/sirupsen/logrus"
)

// ExecutionState captures the agent's execution progress for crash recovery.
// It is serialized to JSON and persisted in the subtask's Context column.
type ExecutionState struct {
	Phase         string   `json:"phase"`
	ToolCallCount int      `json:"tool_call_count"`
	FindingsCount int      `json:"findings_count"`
	AttacksDone   []string `json:"attacks_done"`
	CurrentAttack string   `json:"current_attack"`
	ErrorCount    int      `json:"error_count"`
	LastUpdate    string   `json:"last_update"`
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
		Phase:       "init",
		AttacksDone: make([]string, 0),
		LastUpdate:  time.Now().UTC().Format(time.RFC3339),
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
