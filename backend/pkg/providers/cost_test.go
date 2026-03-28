package providers

import (
	"context"
	"testing"

	"pentagi/pkg/providers/pconfig"
)

func TestLookupDefaultPricing_ExactMatch(t *testing.T) {
	price := LookupDefaultPricing("gpt-4o")
	if price == nil {
		t.Fatal("expected non-nil price for gpt-4o")
	}
	if price.Input != 2.5 {
		t.Errorf("expected input=2.5, got %f", price.Input)
	}
	if price.Output != 10.0 {
		t.Errorf("expected output=10.0, got %f", price.Output)
	}
}

func TestLookupDefaultPricing_PrefixMatch(t *testing.T) {
	// "claude-sonnet-4-20250514" should match "claude-sonnet-4"
	price := LookupDefaultPricing("claude-sonnet-4-custom-suffix")
	if price == nil {
		t.Fatal("expected non-nil price for claude-sonnet-4 prefix match")
	}
	if price.Input != 3.0 {
		t.Errorf("expected input=3.0, got %f", price.Input)
	}
}

func TestLookupDefaultPricing_NotFound(t *testing.T) {
	price := LookupDefaultPricing("totally-unknown-model")
	if price != nil {
		t.Errorf("expected nil for unknown model, got %+v", price)
	}
}

func TestLookupDefaultPricing_Empty(t *testing.T) {
	price := LookupDefaultPricing("")
	if price != nil {
		t.Errorf("expected nil for empty model, got %+v", price)
	}
}

func TestCostTracker_AddUsage(t *testing.T) {
	ct := NewCostTracker("gpt-4o")

	usage1 := pconfig.CallUsage{
		Input:     1000,
		Output:    500,
		CostInput: 0.0025,
		CostOutput: 0.005,
	}
	ct.AddUsage("primary_agent", usage1)

	usage2 := pconfig.CallUsage{
		Input:     2000,
		Output:    1000,
		CostInput: 0.005,
		CostOutput: 0.01,
	}
	ct.AddUsage("pentester", usage2)

	total := ct.GetTotalCost()
	expected := 0.0025 + 0.005 + 0.005 + 0.01
	if abs(total-expected) > 1e-9 {
		t.Errorf("expected total cost %f, got %f", expected, total)
	}

	totalUsage := ct.GetTotalUsage()
	if totalUsage.Input != 3000 {
		t.Errorf("expected input=3000, got %d", totalUsage.Input)
	}
	if totalUsage.Output != 1500 {
		t.Errorf("expected output=1500, got %d", totalUsage.Output)
	}
}

func TestCostTracker_GetCostBreakdown(t *testing.T) {
	ct := NewCostTracker("claude-sonnet-4")

	ct.AddUsage("primary_agent", pconfig.CallUsage{
		Input: 1000, Output: 500, CostInput: 0.003, CostOutput: 0.0075,
	})
	ct.AddUsage("pentester", pconfig.CallUsage{
		Input: 5000, Output: 2000, CostInput: 0.015, CostOutput: 0.03,
	})
	ct.AddUsage("primary_agent", pconfig.CallUsage{
		Input: 1000, Output: 500, CostInput: 0.003, CostOutput: 0.0075,
	})

	breakdown := ct.GetCostBreakdown()

	if len(breakdown.ByAgentType) != 2 {
		t.Errorf("expected 2 agent types, got %d", len(breakdown.ByAgentType))
	}

	pa, ok := breakdown.ByAgentType["primary_agent"]
	if !ok {
		t.Fatal("missing primary_agent in breakdown")
	}
	if pa.CallCount != 2 {
		t.Errorf("expected 2 calls for primary_agent, got %d", pa.CallCount)
	}
	if pa.InputTokens != 2000 {
		t.Errorf("expected 2000 input tokens for primary_agent, got %d", pa.InputTokens)
	}

	pt, ok := breakdown.ByAgentType["pentester"]
	if !ok {
		t.Fatal("missing pentester in breakdown")
	}
	if pt.CallCount != 1 {
		t.Errorf("expected 1 call for pentester, got %d", pt.CallCount)
	}
}

func TestCostTracker_GetCostPerFinding(t *testing.T) {
	ct := NewCostTracker("gpt-4o")
	ct.AddUsage("agent", pconfig.CallUsage{
		Input: 10000, Output: 5000, CostInput: 0.025, CostOutput: 0.05,
	})

	cpf := ct.GetCostPerFinding(5)
	expected := 0.075 / 5.0
	if abs(cpf-expected) > 1e-9 {
		t.Errorf("expected cost per finding %f, got %f", expected, cpf)
	}

	// Zero findings
	cpf = ct.GetCostPerFinding(0)
	if cpf != 0 {
		t.Errorf("expected 0 for zero findings, got %f", cpf)
	}
}

func TestCostTracker_FormatCostSummary(t *testing.T) {
	ct := NewCostTracker("gpt-4o")
	ct.AddUsage("primary_agent", pconfig.CallUsage{
		Input: 10000, Output: 5000, CacheRead: 2000,
		CostInput: 0.025, CostOutput: 0.05,
	})

	formatted := ct.FormatCostSummary(3)
	if formatted == "" {
		t.Fatal("expected non-empty formatted summary")
	}

	// Should contain key metrics
	if !contains(formatted, "LLM Cost Summary") {
		t.Error("missing header in formatted summary")
	}
	if !contains(formatted, "Cost per Finding") {
		t.Error("missing cost per finding in formatted summary")
	}
}

func TestCostTracker_Context(t *testing.T) {
	ct := NewCostTracker("test-model")
	ctx := context.Background()

	// Initially nil
	if GetCostTracker(ctx) != nil {
		t.Error("expected nil cost tracker from empty context")
	}

	// After setting
	ctx = WithCostTracker(ctx, ct)
	retrieved := GetCostTracker(ctx)
	if retrieved != ct {
		t.Error("expected same cost tracker from context")
	}
}

func TestCostTracker_EmptyAgentType(t *testing.T) {
	ct := NewCostTracker("test")
	ct.AddUsage("", pconfig.CallUsage{Input: 100, Output: 50, CostInput: 0.001, CostOutput: 0.002})

	breakdown := ct.GetCostBreakdown()
	if _, ok := breakdown.ByAgentType["unknown"]; !ok {
		t.Error("empty agent type should be recorded as 'unknown'")
	}
}

func TestCostTracker_ConcurrentSafety(t *testing.T) {
	ct := NewCostTracker("gpt-4o")
	done := make(chan struct{})

	for i := 0; i < 100; i++ {
		go func() {
			ct.AddUsage("agent", pconfig.CallUsage{
				Input: 100, Output: 50, CostInput: 0.001, CostOutput: 0.002,
			})
			_ = ct.GetTotalCost()
			_ = ct.GetCostBreakdown()
			_ = ct.GetCostPerFinding(5)
			done <- struct{}{}
		}()
	}

	for i := 0; i < 100; i++ {
		<-done
	}

	usage := ct.GetTotalUsage()
	if usage.Input != 10000 {
		t.Errorf("expected input=10000 after 100 concurrent adds, got %d", usage.Input)
	}
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || len(s) >= len(substr) && containsCheck(s, substr))
}

func containsCheck(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
