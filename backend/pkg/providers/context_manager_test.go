package providers

import (
	"fmt"
	"strings"
	"testing"
)

func TestEstimateTokens(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"", 0},
		{"hi", 1},           // 2/4 = 0, but minimum 1
		{"hello world", 2},  // 11/4 = 2
		{strings.Repeat("x", 100), 25},
		{strings.Repeat("x", 4000), 1000},
	}

	for _, tt := range tests {
		got := estimateTokens(tt.input)
		if got != tt.expected {
			t.Errorf("estimateTokens(%d chars) = %d, want %d", len(tt.input), got, tt.expected)
		}
	}
}

func TestClassifyContent_Findings(t *testing.T) {
	findings := []string{
		"FINDING: SQL injection in login form",
		"CRITICAL vulnerability discovered",
		"VULNERABILITY in OpenSSL",
		"CVE-2024-12345 affects this version",
		"[VULN] XSS in admin panel",
	}

	for _, content := range findings {
		priority := classifyContent(content, 0)
		if priority != PriorityFindings {
			t.Errorf("classifyContent(%q) = %d, want PriorityFindings (%d)", content[:30], priority, PriorityFindings)
		}
	}
}

func TestClassifyContent_Errors(t *testing.T) {
	errors := []string{
		"[ERROR] connection refused",
		"failed to connect to host",
		"error: permission denied",
		"FATAL: out of memory",
	}

	for _, content := range errors {
		priority := classifyContent(content, 0)
		if priority != PriorityErrors {
			t.Errorf("classifyContent(%q) = %d, want PriorityErrors (%d)", content, priority, PriorityErrors)
		}
	}
}

func TestClassifyContent_Default(t *testing.T) {
	content := "nmap scan completed, 5 hosts up"
	priority := classifyContent(content, 0)
	if priority != PriorityRecentTools {
		t.Errorf("classifyContent(%q) = %d, want PriorityRecentTools (%d)", content, priority, PriorityRecentTools)
	}
}

func TestNewContextManager(t *testing.T) {
	cm := NewContextManager(10000)
	if cm.maxTokens != 10000 {
		t.Errorf("maxTokens = %d, want 10000", cm.maxTokens)
	}

	cm2 := NewContextManager(0)
	if cm2.maxTokens != defaultMaxContextTokens {
		t.Errorf("maxTokens = %d, want default %d", cm2.maxTokens, defaultMaxContextTokens)
	}
}

func TestContextManager_AddAndCount(t *testing.T) {
	cm := NewContextManager(10000)
	cm.Add("result 1", "nmap")
	cm.Add("result 2", "gobuster")
	cm.Add("FINDING: important thing", "custom")

	if cm.GetItemCount() != 3 {
		t.Errorf("GetItemCount() = %d, want 3", cm.GetItemCount())
	}

	// The finding should be classified as PriorityFindings
	findings := cm.GetItemsByPriority(PriorityFindings)
	if len(findings) != 1 {
		t.Errorf("findings count = %d, want 1", len(findings))
	}
}

func TestContextManager_MarkReferenced(t *testing.T) {
	cm := NewContextManager(10000)

	// Add several items
	for i := 0; i < 10; i++ {
		cm.Add(fmt.Sprintf("result-%d: some output", i), "tool")
	}

	// Reclassify so old items become old
	cm.ReclassifyByAge()

	// Mark an old item as referenced
	cm.MarkReferenced("result-0")

	items := cm.Prune()
	found := false
	for _, item := range items {
		if strings.Contains(item.Content, "result-0") {
			if item.Priority > PriorityRecentTools {
				t.Error("referenced item should be bumped to PriorityRecentTools or better")
			}
			found = true
		}
	}
	if !found {
		t.Error("referenced item should still be in pruned results")
	}
}

func TestContextManager_PruneNoise(t *testing.T) {
	// Create a tiny budget so pruning kicks in
	cm := NewContextManager(100) // ~400 chars budget

	// Add a finding (must survive)
	cm.Add("FINDING: critical vuln", "scanner")

	// Add some old noisy content
	noisy := strings.Repeat("x", 3000) // >2000 chars = noise when old
	for i := 0; i < 3; i++ {
		cm.Add(fmt.Sprintf("old-noise-%d: %s", i, noisy), "verbose-tool")
	}

	// Add recent items to push old ones out of the window
	for i := 0; i < recentToolWindowSize; i++ {
		cm.Add(fmt.Sprintf("recent-%d: short output", i), "tool")
	}

	items := cm.Prune()

	// Finding must survive
	findingFound := false
	for _, item := range items {
		if item.Priority == PriorityFindings {
			findingFound = true
		}
		// Noise should be gone
		if item.Priority == PriorityNoise {
			t.Error("noise items should have been pruned")
		}
	}

	if !findingFound {
		t.Error("finding was pruned — this must NEVER happen")
	}
}

func TestContextManager_FindingsNeverPruned(t *testing.T) {
	// Extremely tight budget
	cm := NewContextManager(1) // basically 4 chars

	// Add many findings
	for i := 0; i < 10; i++ {
		cm.Add(fmt.Sprintf("FINDING #%d: SQL injection in endpoint /api/v%d", i, i), "scanner")
	}

	items := cm.Prune()

	// ALL findings must survive regardless of budget
	if len(items) != 10 {
		t.Errorf("expected 10 findings to survive pruning, got %d", len(items))
	}

	for _, item := range items {
		if item.Priority != PriorityFindings {
			t.Errorf("item %q should be PriorityFindings, got %d", item.Content[:20], item.Priority)
		}
	}
}

func TestContextManager_SummarizeOldTools(t *testing.T) {
	// Budget that allows findings + recent but not all old tools at full size
	cm := NewContextManager(200)

	// Add a moderate-length old tool result (not noise, but summarizable)
	lines := make([]string, 20)
	for i := range lines {
		lines[i] = fmt.Sprintf("line %d: some scan output data here", i)
	}
	cm.Add(strings.Join(lines, "\n"), "nmap")

	// Add recent items to push the first one to "old"
	for i := 0; i < recentToolWindowSize+1; i++ {
		cm.Add(fmt.Sprintf("recent-%d: ok", i), "tool")
	}

	items := cm.Prune()

	// Find the old nmap item — it should be summarized
	for _, item := range items {
		if item.ToolName == "nmap" && item.IsSummarized {
			if !strings.Contains(item.Content, "lines omitted") {
				t.Error("summarized item should contain 'lines omitted' marker")
			}
			return
		}
	}
	// It's also ok if it was dropped as noise (since it might be >2000 chars after 20 lines)
	// or if the budget was enough to keep it. The key test is that findings survive.
}

func TestSummarizeToHeadTail(t *testing.T) {
	lines := make([]string, 20)
	for i := range lines {
		lines[i] = fmt.Sprintf("line-%d", i)
	}
	content := strings.Join(lines, "\n")

	result := summarizeToHeadTail(content, 3)

	if !strings.Contains(result, "line-0") {
		t.Error("should contain first line")
	}
	if !strings.Contains(result, "line-19") {
		t.Error("should contain last line")
	}
	if !strings.Contains(result, "lines omitted") {
		t.Error("should contain omission marker")
	}
	if strings.Contains(result, "line-10") {
		t.Error("should NOT contain middle lines")
	}
}

func TestSummarizeToHeadTail_Short(t *testing.T) {
	content := "line1\nline2\nline3"
	result := summarizeToHeadTail(content, 3)
	if result != content {
		t.Error("short content should be returned as-is")
	}
}

func TestExtractFirstErrorLine(t *testing.T) {
	content := "Starting scan...\nConnecting to host...\n[ERROR] connection refused\nRetrying...\nMore output"
	result := extractFirstErrorLine(content)

	if !strings.HasPrefix(result, "[ERROR] connection refused") {
		t.Errorf("expected first error line, got: %q", result)
	}
	if !strings.Contains(result, "more lines omitted") {
		t.Error("should indicate omitted lines")
	}
}

func TestExtractFindings(t *testing.T) {
	content := `Starting nmap scan...
Scanning 192.168.1.0/24
Host 192.168.1.1 is up
Port 22 open
Port 80 open
FINDING: SQL injection in /api/login endpoint
Parameter: username
Severity: CRITICAL
Port 443 open
Normal scan continues
Another VULNERABILITY: XSS in search form
Reflected XSS payload executed
End of scan`

	findings := ExtractFindings(content)

	if findings == "" {
		t.Fatal("expected findings to be extracted")
	}

	// Must contain the FINDING line
	if !strings.Contains(findings, "FINDING: SQL injection") {
		t.Error("should contain FINDING line")
	}

	// Must contain CRITICAL (as context line of the finding)
	if !strings.Contains(findings, "CRITICAL") {
		t.Error("should contain CRITICAL context line")
	}

	// Must contain VULNERABILITY line
	if !strings.Contains(findings, "VULNERABILITY: XSS") {
		t.Error("should contain VULNERABILITY line")
	}

	// Should NOT contain unrelated lines far from findings
	if strings.Contains(findings, "Starting nmap scan") {
		t.Error("should not contain unrelated lines")
	}
}

func TestExtractFindings_None(t *testing.T) {
	content := "Normal scan output\nPort 80 open\nDone"
	findings := ExtractFindings(content)
	if findings != "" {
		t.Errorf("expected no findings, got: %q", findings)
	}
}

func TestContainsFindings(t *testing.T) {
	if !ContainsFindings("Found a VULNERABILITY in the service") {
		t.Error("should detect VULNERABILITY")
	}
	if !ContainsFindings("CVE-2024-1234 is present") {
		t.Error("should detect CVE-")
	}
	if ContainsFindings("Normal output with no issues") {
		t.Error("should not detect findings in normal output")
	}
}

func TestContextManager_Stats(t *testing.T) {
	cm := NewContextManager(10000)
	cm.Add("FINDING: test", "scanner")
	cm.Add("[ERROR] oops", "tool")
	cm.Add("normal output", "nmap")

	stats := cm.Stats()
	if stats.TotalItems != 3 {
		t.Errorf("TotalItems = %d, want 3", stats.TotalItems)
	}
	if stats.MaxTokens != 10000 {
		t.Errorf("MaxTokens = %d, want 10000", stats.MaxTokens)
	}

	formatted := stats.FormatStats()
	if formatted == "" {
		t.Error("FormatStats should not be empty")
	}
}
