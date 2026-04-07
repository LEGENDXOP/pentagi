package providers

import (
	"fmt"
	"sync"
	"time"
)

// Fix Issue-5: ToolCircuitBreaker tracks per-tool consecutive failures within a
// subtask and blocks calls to a tool after maxConsecutiveFailures.
// This prevents retry storms where broken tools (e.g. advice, search) consume
// the entire subtask time budget through repeated failures.
//
// VERDICT required: time-based reset (5 min) so transiently failing tools
// can recover within the same subtask.
type ToolCircuitBreaker struct {
	maxConsecutiveFailures int
	resetDuration          time.Duration
	mu                     sync.Mutex
	failures               map[string]int       // tool name → consecutive failure count
	lastFailure            map[string]time.Time // tool name → timestamp of last failure
}

// NewToolCircuitBreaker creates a new circuit breaker with the given max consecutive
// failures threshold and a 5-minute time-based reset window.
func NewToolCircuitBreaker(maxConsecutiveFailures int) *ToolCircuitBreaker {
	return &ToolCircuitBreaker{
		maxConsecutiveFailures: maxConsecutiveFailures,
		resetDuration:          5 * time.Minute,
		failures:               make(map[string]int),
		lastFailure:            make(map[string]time.Time),
	}
}

// Check returns (blocked, message). If the tool has failed maxConsecutiveFailures
// times in a row and less than resetDuration has passed since the last failure,
// the call is blocked with a helpful message.
func (cb *ToolCircuitBreaker) Check(toolName string) (bool, string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	count := cb.failures[toolName]
	if count < cb.maxConsecutiveFailures {
		return false, ""
	}

	// Time-based reset: if enough time has passed since last failure, reset the counter
	if lastFail, ok := cb.lastFailure[toolName]; ok {
		if time.Since(lastFail) >= cb.resetDuration {
			cb.failures[toolName] = 0
			return false, ""
		}
	}

	return true, fmt.Sprintf(
		"Tool '%s' has failed %d consecutive times and is temporarily blocked (resets after %v of no failures). "+
			"Use alternative approaches or different tools to accomplish this task.",
		toolName, count, cb.resetDuration,
	)
}

// RecordFailure increments the consecutive failure count for a tool.
func (cb *ToolCircuitBreaker) RecordFailure(toolName string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures[toolName]++
	cb.lastFailure[toolName] = time.Now()
}

// RecordSuccess resets the consecutive failure count for a tool.
func (cb *ToolCircuitBreaker) RecordSuccess(toolName string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures[toolName] = 0
	delete(cb.lastFailure, toolName)
}
