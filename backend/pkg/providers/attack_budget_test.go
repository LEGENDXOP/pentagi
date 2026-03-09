package providers

import (
	"context"
	"testing"
	"time"
)

func TestAttackBudgetManager_CheckBudget_OK(t *testing.T) {
	cfg := AttackBudgetConfig{
		ReconMinutes:       30,
		AttackMinutes:      45,
		PostExploitMinutes: 20,
		FailureLimit:       5,
	}
	mgr := NewAttackBudgetManager(cfg)

	result := mgr.CheckBudget(AttackPhaseRecon, "nmap_scan")
	if !result.OK {
		t.Errorf("expected budget check to be OK, got reason: %s", result.Reason)
	}
}

func TestAttackBudgetManager_FailureBudgetExhausted(t *testing.T) {
	cfg := AttackBudgetConfig{
		ReconMinutes:       30,
		AttackMinutes:      45,
		PostExploitMinutes: 20,
		FailureLimit:       3,
	}
	mgr := NewAttackBudgetManager(cfg)

	// Record 3 consecutive failures
	for i := 0; i < 3; i++ {
		mgr.RecordAttempt(AttackPhaseAttack, "sqli_test", false)
	}

	result := mgr.CheckBudget(AttackPhaseAttack, "sqli_test")
	if result.OK {
		t.Error("expected budget check to fail after consecutive failures")
	}
	if result.Phase != AttackPhaseAttack {
		t.Errorf("expected phase %s, got %s", AttackPhaseAttack, result.Phase)
	}
	if result.Vector != "sqli_test" {
		t.Errorf("expected vector sqli_test, got %s", result.Vector)
	}
}

func TestAttackBudgetManager_FailureResetOnSuccess(t *testing.T) {
	cfg := AttackBudgetConfig{
		ReconMinutes:       30,
		AttackMinutes:      45,
		PostExploitMinutes: 20,
		FailureLimit:       3,
	}
	mgr := NewAttackBudgetManager(cfg)

	// Record 2 failures then 1 success
	mgr.RecordAttempt(AttackPhaseAttack, "xss_test", false)
	mgr.RecordAttempt(AttackPhaseAttack, "xss_test", false)
	mgr.RecordAttempt(AttackPhaseAttack, "xss_test", true) // resets counter

	result := mgr.CheckBudget(AttackPhaseAttack, "xss_test")
	if !result.OK {
		t.Error("expected budget check to be OK after success reset")
	}
}

func TestAttackBudgetManager_TimeBudgetExhausted(t *testing.T) {
	cfg := AttackBudgetConfig{
		ReconMinutes:       0, // 0 minutes = immediate timeout
		AttackMinutes:      45,
		PostExploitMinutes: 20,
		FailureLimit:       5,
	}
	mgr := NewAttackBudgetManager(cfg)

	// Force the budget to have started in the past
	mgr.mu.Lock()
	key := vectorBudgetKey(AttackPhaseRecon, "port_scan")
	mgr.budgets[key] = &VectorBudget{
		Phase:        AttackPhaseRecon,
		Vector:       "port_scan",
		StartTime:    time.Now().Add(-31 * time.Minute),
		TimeLimit:    30 * time.Minute,
		FailureLimit: 5,
	}
	mgr.mu.Unlock()

	result := mgr.CheckBudget(AttackPhaseRecon, "port_scan")
	if result.OK {
		t.Error("expected budget check to fail after time exceeded")
	}
}

func TestAttackBudgetManager_GetPivotSuggestion(t *testing.T) {
	cfg := AttackBudgetConfig{
		ReconMinutes:       30,
		AttackMinutes:      45,
		PostExploitMinutes: 20,
		FailureLimit:       2,
	}
	mgr := NewAttackBudgetManager(cfg)

	// Exhaust a vector
	mgr.RecordAttempt(AttackPhaseAttack, "sqli", false)
	mgr.RecordAttempt(AttackPhaseAttack, "sqli", false)
	mgr.CheckBudget(AttackPhaseAttack, "sqli") // triggers exhaustion

	suggestion := mgr.GetPivotSuggestion()
	if suggestion == nil {
		t.Fatal("expected non-nil pivot suggestion")
	}
	if suggestion.ExhaustedVector != "sqli" {
		t.Errorf("expected exhausted vector 'sqli', got '%s'", suggestion.ExhaustedVector)
	}
	if len(suggestion.NextVectors) == 0 {
		t.Error("expected at least one suggested next vector")
	}
}

func TestAttackBudgetManager_MultipleVectors(t *testing.T) {
	cfg := AttackBudgetConfig{
		ReconMinutes:       30,
		AttackMinutes:      45,
		PostExploitMinutes: 20,
		FailureLimit:       2,
	}
	mgr := NewAttackBudgetManager(cfg)

	// Track two different vectors
	mgr.RecordAttempt(AttackPhaseAttack, "xss", true)
	mgr.RecordAttempt(AttackPhaseAttack, "sqli", false)
	mgr.RecordAttempt(AttackPhaseAttack, "sqli", false)

	// xss should be fine
	result := mgr.CheckBudget(AttackPhaseAttack, "xss")
	if !result.OK {
		t.Error("expected xss budget to be OK")
	}

	// sqli should be exhausted
	result = mgr.CheckBudget(AttackPhaseAttack, "sqli")
	if result.OK {
		t.Error("expected sqli budget to be exhausted")
	}
}

func TestAttackBudgetManager_ExhaustedStaysExhausted(t *testing.T) {
	cfg := AttackBudgetConfig{
		ReconMinutes:       30,
		AttackMinutes:      45,
		PostExploitMinutes: 20,
		FailureLimit:       2,
	}
	mgr := NewAttackBudgetManager(cfg)

	mgr.RecordAttempt(AttackPhaseAttack, "ssrf", false)
	mgr.RecordAttempt(AttackPhaseAttack, "ssrf", false)

	// First check marks as exhausted
	result1 := mgr.CheckBudget(AttackPhaseAttack, "ssrf")
	if result1.OK {
		t.Error("expected first check to be exhausted")
	}

	// Second check should also be exhausted (cached)
	result2 := mgr.CheckBudget(AttackPhaseAttack, "ssrf")
	if result2.OK {
		t.Error("expected second check to also be exhausted")
	}
}

func TestAttackBudgetManager_GetBudgetSummary(t *testing.T) {
	cfg := DefaultAttackBudgetConfig()
	mgr := NewAttackBudgetManager(cfg)

	mgr.RecordAttempt(AttackPhaseRecon, "nmap", true)
	mgr.RecordAttempt(AttackPhaseAttack, "sqli", false)

	summary := mgr.GetBudgetSummary()
	if summary == "" {
		t.Error("expected non-empty budget summary")
	}
}

func TestAttackBudgetManager_GetActiveBudgets(t *testing.T) {
	cfg := AttackBudgetConfig{
		ReconMinutes:       30,
		AttackMinutes:      45,
		PostExploitMinutes: 20,
		FailureLimit:       1,
	}
	mgr := NewAttackBudgetManager(cfg)

	mgr.RecordAttempt(AttackPhaseRecon, "scan1", true)
	mgr.RecordAttempt(AttackPhaseAttack, "vuln1", false) // will be exhausted

	mgr.CheckBudget(AttackPhaseAttack, "vuln1") // trigger exhaustion

	active := mgr.GetActiveBudgets()
	if len(active) != 1 {
		t.Errorf("expected 1 active budget, got %d", len(active))
	}
}

func TestWithAttackBudget_Context(t *testing.T) {
	ctx := context.Background()

	// No budget initially
	if m := GetAttackBudget(ctx); m != nil {
		t.Error("expected nil budget manager from empty context")
	}

	mgr := NewAttackBudgetManager(DefaultAttackBudgetConfig())
	ctx = WithAttackBudget(ctx, mgr)

	if m := GetAttackBudget(ctx); m == nil {
		t.Error("expected non-nil budget manager from context")
	} else if m != mgr {
		t.Error("expected same budget manager instance from context")
	}
}

func TestClassifyToolPhase(t *testing.T) {
	tests := []struct {
		tool     string
		expected AttackPhase
	}{
		{"search", AttackPhaseRecon},
		{"browser", AttackPhaseRecon},
		{"duckduckgo", AttackPhaseRecon},
		{"store_guide", AttackPhasePostExploit},
		{"store_answer", AttackPhasePostExploit},
		{"pentester", AttackPhaseAttack},
		{"coder", AttackPhaseAttack},
		{"terminal", AttackPhaseAttack},
		{"unknown_tool", AttackPhaseAttack},
	}

	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			phase := ClassifyToolPhase(tt.tool)
			if phase != tt.expected {
				t.Errorf("ClassifyToolPhase(%s) = %s, want %s", tt.tool, phase, tt.expected)
			}
		})
	}
}

func TestIsToolCallSuccess(t *testing.T) {
	tests := []struct {
		name        string
		response    string
		isRepeating bool
		expected    bool
	}{
		{"success response", "Found 3 open ports: 22, 80, 443", false, true},
		{"error response", "Error: connection refused", false, false},
		{"timeout response", "Request timed out after 30s", false, false},
		{"repeating call", "some result", true, false},
		{"permission denied", "Permission denied: insufficient privileges", false, false},
		{"normal result", "Scan completed successfully", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsToolCallSuccess(tt.response, tt.isRepeating)
			if result != tt.expected {
				t.Errorf("IsToolCallSuccess(%q, %v) = %v, want %v",
					tt.response, tt.isRepeating, result, tt.expected)
			}
		})
	}
}

func TestFormatPivotContext(t *testing.T) {
	cfg := DefaultAttackBudgetConfig()
	mgr := NewAttackBudgetManager(cfg)

	suggestion := &PivotSuggestion{
		ExhaustedPhase:  AttackPhaseAttack,
		ExhaustedVector: "sqli",
		Reason:          "5 consecutive failures",
		TimeSpent:       10 * time.Minute,
		Attempts:        15,
		Failures:        5,
		NextVectors:     []string{"xss_stored", "ssrf", "auth_bypass"},
	}

	result := mgr.FormatPivotContext(suggestion)
	if result == "" {
		t.Error("expected non-empty pivot context")
	}
}

func TestLoadAttackBudgetConfigFromEnv(t *testing.T) {
	// Should return defaults when no env vars set
	cfg := LoadAttackBudgetConfigFromEnv()
	if cfg.ReconMinutes != DefaultReconMinutes {
		t.Errorf("expected ReconMinutes=%d, got %d", DefaultReconMinutes, cfg.ReconMinutes)
	}
	if cfg.AttackMinutes != DefaultAttackMinutes {
		t.Errorf("expected AttackMinutes=%d, got %d", DefaultAttackMinutes, cfg.AttackMinutes)
	}
	if cfg.PostExploitMinutes != DefaultPostExploitMinutes {
		t.Errorf("expected PostExploitMinutes=%d, got %d", DefaultPostExploitMinutes, cfg.PostExploitMinutes)
	}
	if cfg.FailureLimit != DefaultFailureLimit {
		t.Errorf("expected FailureLimit=%d, got %d", DefaultFailureLimit, cfg.FailureLimit)
	}
}
