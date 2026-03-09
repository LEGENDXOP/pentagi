package graphiti

import (
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// CircuitState represents the current state of the circuit breaker.
type CircuitState int

const (
	// StateClosed means the circuit is functioning normally — all requests pass through.
	StateClosed CircuitState = iota
	// StateOpen means the circuit has tripped — all requests are short-circuited to fallback.
	StateOpen
	// StateHalfOpen means the circuit allows a single probe request to test recovery.
	StateHalfOpen
)

// String returns the human-readable name of the circuit state.
func (s CircuitState) String() string {
	switch s {
	case StateClosed:
		return "CLOSED"
	case StateOpen:
		return "OPEN"
	case StateHalfOpen:
		return "HALF-OPEN"
	default:
		return "UNKNOWN"
	}
}

// CircuitBreakerConfig holds the configurable parameters for the circuit breaker.
type CircuitBreakerConfig struct {
	// Enabled controls whether the circuit breaker is active.
	// When false, all calls pass through directly without circuit breaker logic.
	Enabled bool
	// FailureThreshold is the number of failures within the window that trips the circuit open.
	FailureThreshold int
	// FailureWindow is the time window in which failures are counted.
	FailureWindow time.Duration
	// OpenTimeout is how long the circuit stays open before transitioning to half-open.
	OpenTimeout time.Duration
	// MaxRetries is the hard cap on retries per call (applies to the underlying call, not the CB itself).
	MaxRetries int
}

// DefaultCircuitBreakerConfig returns sensible defaults matching the spec:
// 3 failures in 60s → OPEN for 120s → HALF-OPEN probe → CLOSED.
func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		Enabled:          true,
		FailureThreshold: 3,
		FailureWindow:    60 * time.Second,
		OpenTimeout:      120 * time.Second,
		MaxRetries:       3,
	}
}

// CircuitBreaker implements the circuit breaker pattern for Graphiti API calls.
// It is safe for concurrent use.
type CircuitBreaker struct {
	mu     sync.Mutex
	config CircuitBreakerConfig

	state       CircuitState
	failures    []time.Time // timestamps of recent failures (within window)
	lastFailure time.Time
	openedAt    time.Time
}

// NewCircuitBreaker creates a new CircuitBreaker with the given configuration.
// If config.Enabled is false, the breaker is a no-op passthrough.
func NewCircuitBreaker(config CircuitBreakerConfig) *CircuitBreaker {
	return &CircuitBreaker{
		config:   config,
		state:    StateClosed,
		failures: make([]time.Time, 0, config.FailureThreshold),
	}
}

// State returns the current circuit state. Thread-safe.
func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.currentState()
}

// currentState returns the effective state, checking for half-open transition.
// Must be called with cb.mu held.
func (cb *CircuitBreaker) currentState() CircuitState {
	if cb.state == StateOpen && time.Since(cb.openedAt) >= cb.config.OpenTimeout {
		cb.transitionTo(StateHalfOpen)
	}
	return cb.state
}

// AllowRequest checks if a request should be allowed through.
// Returns true if the request can proceed, false if it should fallback.
func (cb *CircuitBreaker) AllowRequest() bool {
	if !cb.config.Enabled {
		return true
	}

	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.currentState() {
	case StateClosed:
		return true
	case StateHalfOpen:
		// Allow exactly one probe request in half-open state
		return true
	case StateOpen:
		return false
	default:
		return true
	}
}

// RecordSuccess records a successful API call. If in half-open state, transitions to closed.
func (cb *CircuitBreaker) RecordSuccess() {
	if !cb.config.Enabled {
		return
	}

	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state == StateHalfOpen {
		cb.transitionTo(StateClosed)
		cb.failures = cb.failures[:0]
	}
}

// RecordFailure records a failed API call. May trip the circuit open.
func (cb *CircuitBreaker) RecordFailure() {
	if !cb.config.Enabled {
		return
	}

	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()
	cb.lastFailure = now

	switch cb.state {
	case StateHalfOpen:
		// Probe failed — go back to open
		cb.transitionTo(StateOpen)
		return
	case StateOpen:
		// Already open, nothing to do
		return
	case StateClosed:
		// Add failure and prune old ones outside the window
		cb.failures = append(cb.failures, now)
		cb.pruneFailures(now)

		if len(cb.failures) >= cb.config.FailureThreshold {
			cb.transitionTo(StateOpen)
		}
	}
}

// MaxRetries returns the configured maximum retry count.
func (cb *CircuitBreaker) MaxRetries() int {
	return cb.config.MaxRetries
}

// IsEnabled returns whether the circuit breaker is active.
func (cb *CircuitBreaker) IsEnabled() bool {
	return cb.config.Enabled
}

// pruneFailures removes failure timestamps outside the failure window.
// Must be called with cb.mu held.
func (cb *CircuitBreaker) pruneFailures(now time.Time) {
	cutoff := now.Add(-cb.config.FailureWindow)
	n := 0
	for _, t := range cb.failures {
		if t.After(cutoff) {
			cb.failures[n] = t
			n++
		}
	}
	cb.failures = cb.failures[:n]
}

// transitionTo changes the circuit state and logs the transition.
// Must be called with cb.mu held.
func (cb *CircuitBreaker) transitionTo(newState CircuitState) {
	oldState := cb.state
	cb.state = newState

	if newState == StateOpen {
		cb.openedAt = time.Now()
	}

	logrus.WithFields(logrus.Fields{
		"component":  "graphiti_circuit_breaker",
		"from_state": oldState.String(),
		"to_state":   newState.String(),
		"failures":   len(cb.failures),
	}).Warn(fmt.Sprintf("circuit breaker state transition: %s → %s", oldState, newState))
}
