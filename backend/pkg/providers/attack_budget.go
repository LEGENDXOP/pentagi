package providers

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// AttackPhase represents the current phase of a penetration test.
type AttackPhase string

const (
	AttackPhaseRecon       AttackPhase = "recon"
	AttackPhaseAttack      AttackPhase = "attack"
	AttackPhasePostExploit AttackPhase = "post_exploit"
)

// Default budget configuration values. These can be overridden via environment variables:
//
//	BUDGET_RECON_MINUTES        — time budget for reconnaissance (default: 45)
//	BUDGET_ATTACK_MINUTES       — time budget per attack vector (default: 60)
//	BUDGET_POST_EXPLOIT_MINUTES — time budget for post-exploitation (default: 30)
//	BUDGET_FAILURE_LIMIT        — consecutive failures before auto-pivot (default: 8)
const (
	DefaultReconMinutes       = 45
	DefaultAttackMinutes      = 60
	DefaultPostExploitMinutes = 30
	DefaultFailureLimit       = 8
)

// AttackBudgetConfig holds the configurable budget limits.
type AttackBudgetConfig struct {
	ReconMinutes       int
	AttackMinutes      int
	PostExploitMinutes int
	FailureLimit       int
}

// DefaultAttackBudgetConfig returns a config with default values.
func DefaultAttackBudgetConfig() AttackBudgetConfig {
	return AttackBudgetConfig{
		ReconMinutes:       DefaultReconMinutes,
		AttackMinutes:      DefaultAttackMinutes,
		PostExploitMinutes: DefaultPostExploitMinutes,
		FailureLimit:       DefaultFailureLimit,
	}
}

// LoadAttackBudgetConfigFromEnv reads budget configuration from environment variables,
// falling back to defaults if not set or invalid.
func LoadAttackBudgetConfigFromEnv() AttackBudgetConfig {
	cfg := DefaultAttackBudgetConfig()

	if v := os.Getenv("BUDGET_RECON_MINUTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.ReconMinutes = n
		}
	}
	if v := os.Getenv("BUDGET_ATTACK_MINUTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.AttackMinutes = n
		}
	}
	if v := os.Getenv("BUDGET_POST_EXPLOIT_MINUTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.PostExploitMinutes = n
		}
	}
	if v := os.Getenv("BUDGET_FAILURE_LIMIT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.FailureLimit = n
		}
	}

	return cfg
}

// VectorBudget tracks the execution budget for a single attack vector within a phase.
type VectorBudget struct {
	Phase               AttackPhase `json:"phase"`
	Vector              string      `json:"vector"`
	StartTime           time.Time   `json:"start_time"`
	TimeLimit           time.Duration `json:"time_limit"`
	Attempts            int         `json:"attempts"`
	Successes           int         `json:"successes"`
	ConsecutiveFailures int         `json:"consecutive_failures"`
	FailureLimit        int         `json:"failure_limit"`
	Exhausted           bool        `json:"exhausted"`
	ExhaustReason       string      `json:"exhaust_reason"`
}

// IsTimedOut returns true if the time limit for this vector has been exceeded.
func (vb *VectorBudget) IsTimedOut() bool {
	return time.Since(vb.StartTime) > vb.TimeLimit
}

// IsFailureLimitReached returns true if consecutive failures have hit the limit.
func (vb *VectorBudget) IsFailureLimitReached() bool {
	return vb.ConsecutiveFailures >= vb.FailureLimit
}

// BudgetCheckResult contains the result of a budget check.
type BudgetCheckResult struct {
	OK     bool   // true if budget allows continuing
	Reason string // explanation if budget is exhausted
	Phase  AttackPhase
	Vector string
}

// PivotSuggestion contains a suggestion for what to do next when a budget is exhausted.
type PivotSuggestion struct {
	ExhaustedPhase  AttackPhase
	ExhaustedVector string
	Reason          string
	NextVectors     []string // suggested next vectors from attack chains
	TimeSpent       time.Duration
	Attempts        int
	Failures        int
}

// AttackBudgetManager tracks budgets per flow, per phase, per vector.
// It is designed to be in-memory only (per flow lifecycle) and goroutine-safe.
type AttackBudgetManager struct {
	mu      sync.RWMutex
	config  AttackBudgetConfig
	budgets map[string]*VectorBudget // key: "phase:vector"
	history []string                 // ordered list of exhausted vectors
}

// NewAttackBudgetManager creates a new budget manager with the given config.
func NewAttackBudgetManager(cfg AttackBudgetConfig) *AttackBudgetManager {
	return &AttackBudgetManager{
		config:  cfg,
		budgets: make(map[string]*VectorBudget),
		history: make([]string, 0),
	}
}

// vectorBudgetKey returns the map key for a phase+vector combination.
func vectorBudgetKey(phase AttackPhase, vector string) string {
	return string(phase) + ":" + vector
}

// getOrCreateBudget returns the existing budget for a phase+vector, or creates a new one.
func (m *AttackBudgetManager) getOrCreateBudget(phase AttackPhase, vector string) *VectorBudget {
	key := vectorBudgetKey(phase, vector)
	if vb, ok := m.budgets[key]; ok {
		return vb
	}

	timeLimit := m.getTimeLimit(phase)
	vb := &VectorBudget{
		Phase:        phase,
		Vector:       vector,
		StartTime:    time.Now(),
		TimeLimit:    timeLimit,
		FailureLimit: m.config.FailureLimit,
	}
	m.budgets[key] = vb
	return vb
}

// getTimeLimit returns the time limit for a given phase.
func (m *AttackBudgetManager) getTimeLimit(phase AttackPhase) time.Duration {
	switch phase {
	case AttackPhaseRecon:
		return time.Duration(m.config.ReconMinutes) * time.Minute
	case AttackPhaseAttack:
		return time.Duration(m.config.AttackMinutes) * time.Minute
	case AttackPhasePostExploit:
		return time.Duration(m.config.PostExploitMinutes) * time.Minute
	default:
		return time.Duration(m.config.AttackMinutes) * time.Minute
	}
}

// CheckBudget checks whether the budget for a given phase+vector is still available.
// Returns (true, "") if budget allows continuing, or (false, reason) if exhausted.
func (m *AttackBudgetManager) CheckBudget(phase AttackPhase, vector string) BudgetCheckResult {
	m.mu.Lock()
	defer m.mu.Unlock()

	vb := m.getOrCreateBudget(phase, vector)

	// Already marked exhausted from a previous check
	if vb.Exhausted {
		return BudgetCheckResult{
			OK:     false,
			Reason: vb.ExhaustReason,
			Phase:  phase,
			Vector: vector,
		}
	}

	// Check time budget
	if vb.IsTimedOut() {
		elapsed := time.Since(vb.StartTime).Round(time.Second)
		reason := fmt.Sprintf("time budget exhausted for %s/%s: spent %s (limit: %s) with %d attempts (%d successes, %d consecutive failures)",
			phase, vector, elapsed, vb.TimeLimit, vb.Attempts, vb.Successes, vb.ConsecutiveFailures)
		vb.Exhausted = true
		vb.ExhaustReason = reason
		m.history = append(m.history, vectorBudgetKey(phase, vector))
		return BudgetCheckResult{
			OK:     false,
			Reason: reason,
			Phase:  phase,
			Vector: vector,
		}
	}

	// Check failure budget
	if vb.IsFailureLimitReached() {
		elapsed := time.Since(vb.StartTime).Round(time.Second)
		reason := fmt.Sprintf("failure budget exhausted for %s/%s: %d consecutive failures (limit: %d) in %s with %d total attempts",
			phase, vector, vb.ConsecutiveFailures, vb.FailureLimit, elapsed, vb.Attempts)
		vb.Exhausted = true
		vb.ExhaustReason = reason
		m.history = append(m.history, vectorBudgetKey(phase, vector))
		return BudgetCheckResult{
			OK:     false,
			Reason: reason,
			Phase:  phase,
			Vector: vector,
		}
	}

	return BudgetCheckResult{
		OK:     true,
		Phase:  phase,
		Vector: vector,
	}
}

// RecordAttempt records a tool call attempt for a given phase+vector.
// If success is true, the consecutive failure counter resets.
// If success is false, the consecutive failure counter increments.
func (m *AttackBudgetManager) RecordAttempt(phase AttackPhase, vector string, success bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	vb := m.getOrCreateBudget(phase, vector)
	vb.Attempts++
	if success {
		vb.Successes++
		vb.ConsecutiveFailures = 0
	} else {
		vb.ConsecutiveFailures++
	}
}

// GetPivotSuggestion returns a pivot suggestion for the most recently exhausted vector.
// It uses the AttackChains from chains.go to suggest related vectors to try next.
func (m *AttackBudgetManager) GetPivotSuggestion() *PivotSuggestion {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.history) == 0 {
		return nil
	}

	// Get the most recently exhausted vector
	lastKey := m.history[len(m.history)-1]
	vb, ok := m.budgets[lastKey]
	if !ok {
		return nil
	}

	suggestion := &PivotSuggestion{
		ExhaustedPhase:  vb.Phase,
		ExhaustedVector: vb.Vector,
		Reason:          vb.ExhaustReason,
		TimeSpent:       time.Since(vb.StartTime).Round(time.Second),
		Attempts:        vb.Attempts,
		Failures:        vb.ConsecutiveFailures,
	}

	// Use attack chains to suggest next vectors
	chains := GetAttackChains(vb.Vector)
	if chains != nil {
		seen := make(map[string]bool)
		// Exclude already-exhausted vectors
		for _, key := range m.history {
			parts := strings.SplitN(key, ":", 2)
			if len(parts) == 2 {
				seen[parts[1]] = true
			}
		}
		// Also exclude currently active vectors that are NOT exhausted
		for key, budget := range m.budgets {
			if !budget.Exhausted {
				parts := strings.SplitN(key, ":", 2)
				if len(parts) == 2 {
					seen[parts[1]] = true
				}
			}
		}

		for _, chain := range chains {
			if !seen[chain.VulnType] {
				suggestion.NextVectors = append(suggestion.NextVectors, chain.VulnType)
				seen[chain.VulnType] = true
			}
			if len(suggestion.NextVectors) >= 3 {
				break
			}
		}
	}

	// If no chain suggestions, provide generic alternatives based on phase
	if len(suggestion.NextVectors) == 0 {
		switch vb.Phase {
		case AttackPhaseRecon:
			suggestion.NextVectors = []string{"active_scanning", "osint", "service_enumeration"}
		case AttackPhaseAttack:
			suggestion.NextVectors = []string{"alternative_exploit", "different_service", "credential_attack"}
		case AttackPhasePostExploit:
			suggestion.NextVectors = []string{"lateral_movement", "data_exfiltration", "persistence"}
		}
	}

	return suggestion
}

// GetExhaustedVectors returns a list of all exhausted phase:vector combinations.
func (m *AttackBudgetManager) GetExhaustedVectors() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]string, len(m.history))
	copy(result, m.history)
	return result
}

// GetActiveBudgets returns a snapshot of all active (non-exhausted) budgets.
func (m *AttackBudgetManager) GetActiveBudgets() []VectorBudget {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var active []VectorBudget
	for _, vb := range m.budgets {
		if !vb.Exhausted {
			active = append(active, *vb)
		}
	}
	return active
}

// GetBudgetSummary returns a human-readable summary of all budgets for logging/prompts.
func (m *AttackBudgetManager) GetBudgetSummary() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.budgets) == 0 {
		return "No attack budgets tracked yet."
	}

	var sb strings.Builder
	sb.WriteString("## Attack Budget Status\n")

	for key, vb := range m.budgets {
		elapsed := time.Since(vb.StartTime).Round(time.Second)
		remaining := vb.TimeLimit - time.Since(vb.StartTime)
		if remaining < 0 {
			remaining = 0
		}
		remaining = remaining.Round(time.Second)

		status := "✅ ACTIVE"
		if vb.Exhausted {
			status = "❌ EXHAUSTED"
		}

		sb.WriteString(fmt.Sprintf("- **%s** [%s]: %d attempts, %d successes, %d consecutive failures | time: %s/%s (remaining: %s)\n",
			key, status, vb.Attempts, vb.Successes, vb.ConsecutiveFailures, elapsed, vb.TimeLimit, remaining))
	}

	if len(m.history) > 0 {
		sb.WriteString(fmt.Sprintf("\nExhausted vectors: %s\n", strings.Join(m.history, ", ")))
	}

	return sb.String()
}

// FormatPivotContext produces a context block suitable for injection into agent prompts
// when a budget is exhausted and a pivot is needed.
func (m *AttackBudgetManager) FormatPivotContext(suggestion *PivotSuggestion) string {
	if suggestion == nil {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("<pivot_instruction>\n")
	sb.WriteString(fmt.Sprintf("  <exhausted_vector>%s/%s</exhausted_vector>\n", suggestion.ExhaustedPhase, suggestion.ExhaustedVector))
	sb.WriteString(fmt.Sprintf("  <reason>%s</reason>\n", suggestion.Reason))
	sb.WriteString(fmt.Sprintf("  <time_spent>%s</time_spent>\n", suggestion.TimeSpent))
	sb.WriteString(fmt.Sprintf("  <attempts>%d</attempts>\n", suggestion.Attempts))
	sb.WriteString(fmt.Sprintf("  <failures>%d</failures>\n", suggestion.Failures))

	if len(suggestion.NextVectors) > 0 {
		sb.WriteString("  <suggested_next_vectors>\n")
		for _, v := range suggestion.NextVectors {
			sb.WriteString(fmt.Sprintf("    <vector>%s</vector>\n", v))
		}
		sb.WriteString("  </suggested_next_vectors>\n")
	}

	sb.WriteString("</pivot_instruction>\n")
	return sb.String()
}

// --- Context-based AttackBudgetManager propagation ---

type attackBudgetKey struct{}

// WithAttackBudget attaches an AttackBudgetManager to a context.
func WithAttackBudget(ctx context.Context, m *AttackBudgetManager) context.Context {
	return context.WithValue(ctx, attackBudgetKey{}, m)
}

// GetAttackBudget retrieves the AttackBudgetManager from a context, or nil if none is set.
func GetAttackBudget(ctx context.Context) *AttackBudgetManager {
	if m, ok := ctx.Value(attackBudgetKey{}).(*AttackBudgetManager); ok {
		return m
	}
	return nil
}
