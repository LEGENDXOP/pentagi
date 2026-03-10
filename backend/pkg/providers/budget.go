package providers

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"
)

const (
	defaultGlobalMaxToolCalls = 500
	defaultGlobalMaxDuration  = 60 * time.Minute
)

// getGlobalMaxToolCalls returns the global tool call budget, configurable via
// GLOBAL_MAX_TOOL_CALLS env var. Defaults to 500.
func getGlobalMaxToolCalls() int {
	if v := os.Getenv("GLOBAL_MAX_TOOL_CALLS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return defaultGlobalMaxToolCalls
}

// getGlobalMaxDuration returns the global time budget, configurable via
// GLOBAL_MAX_DURATION_MINUTES env var. Defaults to 60 minutes.
func getGlobalMaxDuration() time.Duration {
	if v := os.Getenv("GLOBAL_MAX_DURATION_MINUTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Minute
		}
	}
	return defaultGlobalMaxDuration
}

// ExecutionBudget tracks global resource consumption across the entire
// delegation tree (primary agent → pentester → coder → installer, etc.).
// A single user request shares one budget instance via context.
type ExecutionBudget struct {
	mu             sync.Mutex
	totalToolCalls int
	maxToolCalls   int
	startTime      time.Time
	maxDuration    time.Duration
}

// NewExecutionBudget creates a budget with the given limits.
func NewExecutionBudget(maxCalls int, maxDuration time.Duration) *ExecutionBudget {
	return &ExecutionBudget{
		maxToolCalls: maxCalls,
		maxDuration:  maxDuration,
		startTime:    time.Now(),
	}
}

// Consume records n tool calls and checks both call and time budgets.
func (b *ExecutionBudget) Consume(n int) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.totalToolCalls += n
	if b.totalToolCalls > b.maxToolCalls {
		return fmt.Errorf("global tool call budget exceeded (%d/%d)", b.totalToolCalls, b.maxToolCalls)
	}
	if time.Since(b.startTime) > b.maxDuration {
		return fmt.Errorf("global time budget exceeded (%v/%v)", time.Since(b.startTime), b.maxDuration)
	}
	return nil
}

type budgetKey struct{}

// WithBudget attaches an ExecutionBudget to a context.
func WithBudget(ctx context.Context, b *ExecutionBudget) context.Context {
	return context.WithValue(ctx, budgetKey{}, b)
}

// GetBudget retrieves the ExecutionBudget from a context, or nil if none is set.
func GetBudget(ctx context.Context) *ExecutionBudget {
	if b, ok := ctx.Value(budgetKey{}).(*ExecutionBudget); ok {
		return b
	}
	return nil
}
