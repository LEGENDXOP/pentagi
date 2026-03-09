package providers

import (
	"fmt"
	"sync"
	"testing"
)

func TestGeneralizeEndpoint(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/api/users/123", "/api/users/{id}"},
		{"/api/users/456", "/api/users/{id}"},
		{"/api/users/123/posts/45", "/api/users/{id}/posts/{id}"},
		{"/api/items", "/api/items"},
		{"", ""},
		{"/api/users/550e8400-e29b-41d4-a716-446655440000", "/api/users/{id}"},
		{"/api/users/123?page=1&size=10", "/api/users/{id}"},
		{"/api/v2/orders/99/items/42", "/api/v2/orders/{id}/items/{id}"},
		{"/api/objects/5f3e8b1a2c4d6e7f8a9b0c1d", "/api/objects/{id}"}, // MongoDB ObjectID-like
	}

	for _, tt := range tests {
		result := generalizeEndpoint(tt.input)
		if result != tt.expected {
			t.Errorf("generalizeEndpoint(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestHighestSeverity(t *testing.T) {
	tests := []struct {
		a, b     string
		expected string
	}{
		{"HIGH", "CRITICAL", "CRITICAL"},
		{"CRITICAL", "LOW", "CRITICAL"},
		{"MEDIUM", "HIGH", "HIGH"},
		{"LOW", "LOW", "LOW"},
		{"", "MEDIUM", "MEDIUM"},
	}

	for _, tt := range tests {
		result := highestSeverity(tt.a, tt.b)
		if result != tt.expected {
			t.Errorf("highestSeverity(%q, %q) = %q, want %q", tt.a, tt.b, result, tt.expected)
		}
	}
}

func TestDedupEngine_SameEndpointPattern(t *testing.T) {
	engine := NewDedupEngine()

	// Two IDOR findings on the same endpoint pattern, different IDs.
	rc1 := engine.AddFinding(Finding{
		VulnType:    "idor",
		Endpoint:    "/api/users/1",
		Method:      "GET",
		Severity:    "HIGH",
		Description: "IDOR on user 1",
	})
	rc2 := engine.AddFinding(Finding{
		VulnType:    "idor",
		Endpoint:    "/api/users/2",
		Method:      "GET",
		Severity:    "HIGH",
		Description: "IDOR on user 2",
	})

	if rc1 != rc2 {
		t.Errorf("Expected same root cause for IDOR on /api/users/1 and /api/users/2, got %s and %s", rc1, rc2)
	}
	if engine.GetUniqueCount() != 1 {
		t.Errorf("Expected 1 unique root cause, got %d", engine.GetUniqueCount())
	}
	if engine.GetDuplicateCount() != 1 {
		t.Errorf("Expected 1 duplicate, got %d", engine.GetDuplicateCount())
	}
	if engine.GetTotalFindings() != 2 {
		t.Errorf("Expected 2 total findings, got %d", engine.GetTotalFindings())
	}
}

func TestDedupEngine_SameParamDifferentEndpoint(t *testing.T) {
	engine := NewDedupEngine()

	// Two SQLi findings on different endpoints but same parameter.
	rc1 := engine.AddFinding(Finding{
		VulnType:    "sqli",
		Endpoint:    "/api/users",
		Parameter:   "id",
		Method:      "GET",
		Severity:    "CRITICAL",
		Description: "SQLi in users endpoint",
	})
	rc2 := engine.AddFinding(Finding{
		VulnType:    "sqli",
		Endpoint:    "/api/orders",
		Parameter:   "id",
		Method:      "GET",
		Severity:    "HIGH",
		Description: "SQLi in orders endpoint",
	})

	if rc1 != rc2 {
		t.Errorf("Expected same root cause for SQLi on same param 'id', got %s and %s", rc1, rc2)
	}
	if engine.GetUniqueCount() != 1 {
		t.Errorf("Expected 1 unique root cause, got %d", engine.GetUniqueCount())
	}

	// Severity should be promoted to CRITICAL (the highest).
	rcs := engine.GetRootCauses()
	if rcs[0].Severity != "CRITICAL" {
		t.Errorf("Expected severity CRITICAL, got %s", rcs[0].Severity)
	}
}

func TestDedupEngine_DifferentVulnTypesNeverGrouped(t *testing.T) {
	engine := NewDedupEngine()

	// IDOR and SQLi on the same endpoint should NOT be grouped.
	rc1 := engine.AddFinding(Finding{
		VulnType: "idor",
		Endpoint: "/api/users/1",
		Severity: "HIGH",
	})
	rc2 := engine.AddFinding(Finding{
		VulnType: "sqli",
		Endpoint: "/api/users/1",
		Severity: "CRITICAL",
	})

	if rc1 == rc2 {
		t.Error("Different VulnTypes should NEVER be grouped together")
	}
	if engine.GetUniqueCount() != 2 {
		t.Errorf("Expected 2 unique root causes, got %d", engine.GetUniqueCount())
	}
}

func TestDedupEngine_AliasNormalization(t *testing.T) {
	engine := NewDedupEngine()

	// "sql_injection" is an alias for "sqli".
	rc1 := engine.AddFinding(Finding{
		VulnType: "sql_injection",
		Endpoint: "/api/users/1",
		Severity: "CRITICAL",
	})
	rc2 := engine.AddFinding(Finding{
		VulnType: "sqli",
		Endpoint: "/api/users/2",
		Severity: "CRITICAL",
	})

	if rc1 != rc2 {
		t.Errorf("Alias normalization failed: sql_injection and sqli should group, got %s and %s", rc1, rc2)
	}
}

func TestDedupEngine_TrulyDifferentFindings(t *testing.T) {
	engine := NewDedupEngine()

	// Same VulnType but completely different endpoints and no shared params.
	engine.AddFinding(Finding{
		VulnType:  "xss_reflected",
		Endpoint:  "/search",
		Parameter: "q",
		Severity:  "MEDIUM",
	})
	engine.AddFinding(Finding{
		VulnType:  "xss_reflected",
		Endpoint:  "/profile",
		Parameter: "bio",
		Severity:  "MEDIUM",
	})

	if engine.GetUniqueCount() != 2 {
		t.Errorf("Expected 2 unique root causes for different XSS endpoints/params, got %d", engine.GetUniqueCount())
	}
}

func TestDedupEngine_EmptyEngine(t *testing.T) {
	engine := NewDedupEngine()

	if engine.GetUniqueCount() != 0 {
		t.Errorf("Expected 0, got %d", engine.GetUniqueCount())
	}
	if engine.GetDuplicateCount() != 0 {
		t.Errorf("Expected 0, got %d", engine.GetDuplicateCount())
	}
	if engine.GetTotalFindings() != 0 {
		t.Errorf("Expected 0, got %d", engine.GetTotalFindings())
	}

	rcs := engine.GetRootCauses()
	if len(rcs) != 0 {
		t.Errorf("Expected empty root causes, got %d", len(rcs))
	}
}

func TestDedupEngine_Summary(t *testing.T) {
	engine := NewDedupEngine()
	engine.AddFinding(Finding{VulnType: "idor", Endpoint: "/api/users/1", Severity: "HIGH"})
	engine.AddFinding(Finding{VulnType: "idor", Endpoint: "/api/users/2", Severity: "HIGH"})
	engine.AddFinding(Finding{VulnType: "idor", Endpoint: "/api/users/3", Severity: "HIGH"})
	engine.AddFinding(Finding{VulnType: "sqli", Endpoint: "/login", Parameter: "user", Severity: "CRITICAL"})

	summary := engine.Summary()
	expected := "Dedup Summary: 4 total findings → 2 unique root causes (2 duplicates removed, 50% reduction)"
	if summary != expected {
		t.Errorf("Summary mismatch:\n  got:  %s\n  want: %s", summary, expected)
	}
}

func TestDedupEngine_ThreadSafety(t *testing.T) {
	engine := NewDedupEngine()
	var wg sync.WaitGroup

	// Spawn 100 goroutines adding findings concurrently.
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			engine.AddFinding(Finding{
				VulnType: "idor",
				Endpoint: fmt.Sprintf("/api/users/%d", n),
				Severity: "HIGH",
			})
		}(i)
	}
	wg.Wait()

	// All 100 IDOR findings on /api/users/{id} should be grouped into 1 root cause.
	if engine.GetUniqueCount() != 1 {
		t.Errorf("Thread-safety test: expected 1 root cause, got %d", engine.GetUniqueCount())
	}
	if engine.GetTotalFindings() != 100 {
		t.Errorf("Thread-safety test: expected 100 total findings, got %d", engine.GetTotalFindings())
	}
}

func TestDedupEngine_UUIDEndpoints(t *testing.T) {
	engine := NewDedupEngine()

	rc1 := engine.AddFinding(Finding{
		VulnType: "idor",
		Endpoint: "/api/resources/550e8400-e29b-41d4-a716-446655440000",
		Severity: "HIGH",
	})
	rc2 := engine.AddFinding(Finding{
		VulnType: "idor",
		Endpoint: "/api/resources/660e8400-e29b-41d4-a716-446655440001",
		Severity: "HIGH",
	})

	if rc1 != rc2 {
		t.Errorf("UUID endpoints should be generalized and grouped, got %s and %s", rc1, rc2)
	}
}

func TestDedupEngine_GetRootCausesReturnsCopy(t *testing.T) {
	engine := NewDedupEngine()
	engine.AddFinding(Finding{VulnType: "idor", Endpoint: "/api/users/1", Severity: "HIGH"})

	rcs := engine.GetRootCauses()
	// Mutating the returned slice should not affect the engine.
	rcs[0].Findings = nil
	rcs[0].Severity = "LOW"

	internal := engine.GetRootCauses()
	if len(internal[0].Findings) != 1 {
		t.Error("GetRootCauses should return a defensive copy")
	}
	if internal[0].Severity != "HIGH" {
		t.Error("GetRootCauses should return a defensive copy")
	}
}

func TestDedupEngine_FindingIDAutoAssignment(t *testing.T) {
	engine := NewDedupEngine()

	engine.AddFinding(Finding{VulnType: "sqli", Endpoint: "/login", Severity: "CRITICAL"})
	engine.AddFinding(Finding{ID: "CUSTOM-01", VulnType: "xss_reflected", Endpoint: "/search", Severity: "MEDIUM"})

	rcs := engine.GetRootCauses()
	if rcs[0].Findings[0].ID != "F001" {
		t.Errorf("Expected auto-assigned ID F001, got %s", rcs[0].Findings[0].ID)
	}
	if rcs[1].Findings[0].ID != "CUSTOM-01" {
		t.Errorf("Expected custom ID CUSTOM-01, got %s", rcs[1].Findings[0].ID)
	}
}

func TestDedupEngine_MassiveScenario(t *testing.T) {
	// Simulates the v6 test scenario: 151 findings → ~15 real root causes.
	engine := NewDedupEngine()

	// 10 IDOR findings across /api/users/{id}
	for i := 0; i < 10; i++ {
		engine.AddFinding(Finding{
			VulnType: "idor",
			Endpoint: fmt.Sprintf("/api/users/%d", i+1),
			Severity: "HIGH",
		})
	}
	// 8 IDOR findings across /api/orders/{id}
	for i := 0; i < 8; i++ {
		engine.AddFinding(Finding{
			VulnType: "idor",
			Endpoint: fmt.Sprintf("/api/orders/%d", i+100),
			Severity: "HIGH",
		})
	}
	// 15 SQLi on same param "id"
	for i := 0; i < 15; i++ {
		engine.AddFinding(Finding{
			VulnType:  "sqli",
			Endpoint:  fmt.Sprintf("/api/endpoint%d", i),
			Parameter: "id",
			Severity:  "CRITICAL",
		})
	}
	// 12 XSS reflected on /search with param "q"
	for i := 0; i < 12; i++ {
		engine.AddFinding(Finding{
			VulnType:  "xss_reflected",
			Endpoint:  "/search",
			Parameter: "q",
			Severity:  "MEDIUM",
		})
	}
	// 5 completely unique findings
	uniqueTypes := []string{"ssrf", "csrf", "open_redirect", "broken_auth", "path_traversal"}
	for _, vt := range uniqueTypes {
		engine.AddFinding(Finding{
			VulnType: vt,
			Endpoint: fmt.Sprintf("/unique/%s", vt),
			Severity: "HIGH",
		})
	}

	total := engine.GetTotalFindings()
	unique := engine.GetUniqueCount()
	dupes := engine.GetDuplicateCount()

	if total != 50 {
		t.Errorf("Expected 50 total findings, got %d", total)
	}
	// Expected: IDOR users (1) + IDOR orders (1) + SQLi (1) + XSS (1) + 5 unique = 9
	if unique > 15 {
		t.Errorf("Expected <= 15 unique root causes in mass scenario, got %d", unique)
	}
	if dupes+unique != total {
		t.Errorf("Invariant broken: dupes(%d) + unique(%d) != total(%d)", dupes, unique, total)
	}

	t.Logf("Mass scenario: %s", engine.Summary())
}
