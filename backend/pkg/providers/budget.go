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
	reportReserve             = 50
	budgetWarningPercent      = 80
	budgetCriticalPercent     = 90
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

// NewExecutionBudgetFromEnv creates a budget using environment variable configuration
// (GLOBAL_MAX_TOOL_CALLS and GLOBAL_MAX_DURATION_MINUTES). This is the recommended
// constructor for task-level budget creation in the controller layer.
func NewExecutionBudgetFromEnv() *ExecutionBudget {
	return NewExecutionBudget(getGlobalMaxToolCalls(), getGlobalMaxDuration())
}

// MaxDuration returns the configured maximum duration for this budget.
// Useful for logging at creation time.
func (b *ExecutionBudget) MaxDuration() time.Duration {
	return b.maxDuration
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

// TimeRemaining returns the time left in the global budget.
// If the budget is already expired it returns 0.
func (b *ExecutionBudget) TimeRemaining() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()

	remaining := b.maxDuration - time.Since(b.startTime)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// Status returns the current budget usage: calls used, max allowed, and percentage consumed.
func (b *ExecutionBudget) Status() (used, max int, pct float64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.maxToolCalls == 0 {
		return b.totalToolCalls, b.maxToolCalls, 0
	}
	pct = float64(b.totalToolCalls) / float64(b.maxToolCalls) * 100
	return b.totalToolCalls, b.maxToolCalls, pct
}

// Remaining returns the number of tool calls remaining in the budget.
func (b *ExecutionBudget) Remaining() int {
	b.mu.Lock()
	defer b.mu.Unlock()

	r := b.maxToolCalls - b.totalToolCalls
	if r < 0 {
		return 0
	}
	return r
}

// IsWarning returns true when budget consumption exceeds 80%.
func (b *ExecutionBudget) IsWarning() bool {
	_, _, pct := b.Status()
	return pct >= budgetWarningPercent
}

// IsCritical returns true when budget consumption exceeds 90%.
func (b *ExecutionBudget) IsCritical() bool {
	_, _, pct := b.Status()
	return pct >= budgetCriticalPercent
}

// ReportReserve returns the number of tool calls reserved for the report phase.
func (b *ExecutionBudget) ReportReserve() int {
	return reportReserve
}

// GetBudget retrieves the ExecutionBudget from a context, or nil if none is set.
func GetBudget(ctx context.Context) *ExecutionBudget {
	if b, ok := ctx.Value(budgetKey{}).(*ExecutionBudget); ok {
		return b
	}
	return nil
}
