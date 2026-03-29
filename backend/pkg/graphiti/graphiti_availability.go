package graphiti

import (
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// GraphitiAvailability tracks whether the Graphiti service is reachable at the
// flow level. Unlike the CircuitBreaker (which handles per-request backoff at
// the HTTP client level), this operates at the TOOL level — it fast-fails the
// entire graphiti search tool after a threshold of consecutive connection
// failures, returning a definitive "unavailable — proceed without it" message
// that does NOT encourage LLM retries.
//
// WHY this exists separately from CircuitBreaker:
// The circuit breaker trips correctly after 3 HTTP failures, but the layers
// above it (memorist agent chain, calling agents) keep retrying because:
//   1. Handle() catches CircuitOpenError and returns a soft "try again later"
//   2. The memorist LLM cycles through all 7 search types, each hitting the open CB
//   3. The calling agent retries memorist with rephrased questions
// This tracker short-circuits BEFORE any of that expensive work happens.
//
// Thread-safe via mutex. Intended to be shared across all agents within a flow.
type GraphitiAvailability struct {
	mu               sync.Mutex
	consecutiveFails int
	failThreshold    int
	disabled         bool
	disabledAt       time.Time
	reopenAfter      time.Duration // how long before allowing one probe to check recovery
	lastProbeAt      time.Time
}

// NewGraphitiAvailability creates a shared availability tracker.
//   - failThreshold: consecutive failures before disabling (recommend: 2)
//   - reopenAfter: duration before allowing a single probe request (recommend: 10m)
func NewGraphitiAvailability(failThreshold int, reopenAfter time.Duration) *GraphitiAvailability {
	return &GraphitiAvailability{
		failThreshold: failThreshold,
		reopenAfter:   reopenAfter,
	}
}

// IsAvailable returns true if graphiti should be attempted.
// When disabled, allows one probe attempt after reopenAfter has elapsed
// (half-open pattern).
func (ga *GraphitiAvailability) IsAvailable() bool {
	ga.mu.Lock()
	defer ga.mu.Unlock()

	if !ga.disabled {
		return true
	}

	// Half-open: allow one probe after reopenAfter elapses.
	// The lastProbeAt guard prevents multiple goroutines from all probing simultaneously.
	if time.Since(ga.disabledAt) >= ga.reopenAfter && time.Since(ga.lastProbeAt) >= ga.reopenAfter {
		ga.lastProbeAt = time.Now()
		return true // allow exactly one probe
	}

	return false
}

// RecordFailure records a connection failure. If threshold is exceeded, disables
// graphiti for this flow until reopenAfter elapses.
func (ga *GraphitiAvailability) RecordFailure() {
	ga.mu.Lock()
	defer ga.mu.Unlock()

	ga.consecutiveFails++
	if ga.consecutiveFails >= ga.failThreshold && !ga.disabled {
		ga.disabled = true
		ga.disabledAt = time.Now()
		logrus.WithFields(logrus.Fields{
			"component":         "graphiti_availability",
			"consecutive_fails": ga.consecutiveFails,
			"threshold":         ga.failThreshold,
		}).Warn("graphiti marked unavailable — fast-failing all future requests for this flow")
	}
}

// RecordSuccess resets the failure counter and re-enables graphiti if it was
// disabled (successful probe in half-open state).
func (ga *GraphitiAvailability) RecordSuccess() {
	ga.mu.Lock()
	defer ga.mu.Unlock()

	wasDisabled := ga.disabled
	ga.consecutiveFails = 0
	ga.disabled = false

	if wasDisabled {
		logrus.WithField("component", "graphiti_availability").
			Info("graphiti recovered — re-enabling after successful probe")
	}
}

// IsDisabled returns whether graphiti is currently disabled (for logging/checks).
func (ga *GraphitiAvailability) IsDisabled() bool {
	ga.mu.Lock()
	defer ga.mu.Unlock()
	return ga.disabled
}
