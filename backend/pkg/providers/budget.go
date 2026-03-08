package providers

import (
	"context"
	"fmt"
	"sync"
	"time"
)

const (
	defaultGlobalMaxToolCalls = 200
	defaultGlobalMaxDuration  = 45 * time.Minute
)

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
