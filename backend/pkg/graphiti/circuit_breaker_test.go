package graphiti

import (
	"fmt"
	"testing"
	"time"
)

func TestCircuitBreakerInitialState(t *testing.T) {
	cb := NewCircuitBreaker(DefaultCircuitBreakerConfig())
	if cb.State() != StateClosed {
		t.Errorf("expected initial state CLOSED, got %s", cb.State())
	}
	if !cb.AllowRequest() {
		t.Error("expected AllowRequest to return true in CLOSED state")
	}
}

func TestCircuitBreakerDisabled(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{Enabled: false})
	if !cb.AllowRequest() {
		t.Error("expected AllowRequest to return true when disabled")
	}

	// Failures should not affect state when disabled
	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordFailure()
	if !cb.AllowRequest() {
		t.Error("expected AllowRequest to still return true when disabled after failures")
	}
}

func TestCircuitBreakerTripsOpen(t *testing.T) {
	cfg := CircuitBreakerConfig{
		Enabled:          true,
		FailureThreshold: 3,
		FailureWindow:    10 * time.Second,
		OpenTimeout:      5 * time.Second,
		MaxRetries:       3,
	}
	cb := NewCircuitBreaker(cfg)

	// Record 3 failures — should trip open
	cb.RecordFailure()
	cb.RecordFailure()
	if cb.State() != StateClosed {
		t.Errorf("expected CLOSED after 2 failures, got %s", cb.State())
	}

	cb.RecordFailure()
	if cb.State() != StateOpen {
		t.Errorf("expected OPEN after 3 failures, got %s", cb.State())
	}

	if cb.AllowRequest() {
		t.Error("expected AllowRequest to return false when OPEN")
	}
}

func TestCircuitBreakerSuccessResetsInHalfOpen(t *testing.T) {
	cfg := CircuitBreakerConfig{
		Enabled:          true,
		FailureThreshold: 2,
		FailureWindow:    10 * time.Second,
		OpenTimeout:      1 * time.Millisecond, // Very short for testing
		MaxRetries:       3,
	}
	cb := NewCircuitBreaker(cfg)

	// Trip open
	cb.RecordFailure()
	cb.RecordFailure()
	if cb.State() != StateOpen {
		t.Fatalf("expected OPEN, got %s", cb.State())
	}

	// Wait for open timeout
	time.Sleep(5 * time.Millisecond)

	// Should transition to half-open
	if cb.State() != StateHalfOpen {
		t.Errorf("expected HALF-OPEN after timeout, got %s", cb.State())
	}

	// Allow request in half-open
	if !cb.AllowRequest() {
		t.Error("expected AllowRequest to return true in HALF-OPEN state")
	}

	// Success in half-open → closed
	cb.RecordSuccess()
	if cb.State() != StateClosed {
		t.Errorf("expected CLOSED after success in HALF-OPEN, got %s", cb.State())
	}
}

func TestCircuitBreakerFailureInHalfOpen(t *testing.T) {
	cfg := CircuitBreakerConfig{
		Enabled:          true,
		FailureThreshold: 2,
		FailureWindow:    10 * time.Second,
		OpenTimeout:      1 * time.Millisecond,
		MaxRetries:       3,
	}
	cb := NewCircuitBreaker(cfg)

	// Trip open
	cb.RecordFailure()
	cb.RecordFailure()

	// Wait for transition to half-open
	time.Sleep(5 * time.Millisecond)
	if cb.State() != StateHalfOpen {
		t.Fatalf("expected HALF-OPEN, got %s", cb.State())
	}

	// Failure in half-open → back to open
	cb.RecordFailure()
	if cb.State() != StateOpen {
		t.Errorf("expected OPEN after failure in HALF-OPEN, got %s", cb.State())
	}
}

func TestCircuitBreakerFailuresExpireOutsideWindow(t *testing.T) {
	cfg := CircuitBreakerConfig{
		Enabled:          true,
		FailureThreshold: 3,
		FailureWindow:    50 * time.Millisecond, // Very short window
		OpenTimeout:      5 * time.Second,
		MaxRetries:       3,
	}
	cb := NewCircuitBreaker(cfg)

	// Record 2 failures
	cb.RecordFailure()
	cb.RecordFailure()

	// Wait for failures to expire
	time.Sleep(60 * time.Millisecond)

	// Third failure should not trip because the first two expired
	cb.RecordFailure()
	if cb.State() != StateClosed {
		t.Errorf("expected CLOSED (old failures expired), got %s", cb.State())
	}
}

func TestCircuitBreakerMaxRetries(t *testing.T) {
	cfg := CircuitBreakerConfig{
		Enabled:    true,
		MaxRetries: 5,
	}
	cb := NewCircuitBreaker(cfg)
	if cb.MaxRetries() != 5 {
		t.Errorf("expected MaxRetries=5, got %d", cb.MaxRetries())
	}
}

func TestCircuitBreakerStateString(t *testing.T) {
	tests := []struct {
		state    CircuitState
		expected string
	}{
		{StateClosed, "CLOSED"},
		{StateOpen, "OPEN"},
		{StateHalfOpen, "HALF-OPEN"},
		{CircuitState(99), "UNKNOWN"},
	}
	for _, tt := range tests {
		if got := tt.state.String(); got != tt.expected {
			t.Errorf("State(%d).String() = %q, want %q", tt.state, got, tt.expected)
		}
	}
}

func TestIsCircuitOpenError(t *testing.T) {
	coe := &CircuitOpenError{Query: "test", GroupID: "grp1"}
	if _, ok := IsCircuitOpenError(coe); !ok {
		t.Error("expected IsCircuitOpenError to return true for *CircuitOpenError")
	}

	if _, ok := IsCircuitOpenError(nil); ok {
		t.Error("expected IsCircuitOpenError to return false for nil")
	}

	regularErr := fmt.Errorf("some error")
	if _, ok := IsCircuitOpenError(regularErr); ok {
		t.Error("expected IsCircuitOpenError to return false for regular error")
	}

	wrappedErr := fmt.Errorf("wrapper: %w", coe)
	if _, ok := IsCircuitOpenError(wrappedErr); !ok {
		t.Error("expected IsCircuitOpenError to return true for wrapped CircuitOpenError")
	}
}
