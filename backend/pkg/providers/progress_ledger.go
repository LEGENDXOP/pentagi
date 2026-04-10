package providers

import (
	"fmt"
	"strings"
	"sync"
)

// ProgressLedger (Fix 7): A compact structured summary injected into every LLM call's
// system prompt. Tracks phase, counts, findings, and active directives to keep the agent
// oriented even as the context window grows and gets summarized.
//
// Inspired by the Magentic-One progress ledger pattern.
type ProgressLedger struct {
	mu sync.Mutex

	Phase           string // "RECON", "EXPLOITATION", "REPORTING", etc.
	SubtaskCurrent  int
	SubtaskTotal    int
	SubtaskTitle    string
	ReconCalls      int
	ExploitCalls    int
	FindingsCount   int
	ActiveDirective string // current MA steer, if any
	TopFinding      string // most promising finding to chain
}

// NewProgressLedger creates a new empty progress ledger.
func NewProgressLedger() *ProgressLedger {
	return &ProgressLedger{
		Phase: "RECON",
	}
}

// Update refreshes the ledger with current execution state.
func (pl *ProgressLedger) Update(
	reconCalls, exploitCalls, findingsCount int,
	subtaskCurrent, subtaskTotal int,
	subtaskTitle string,
	activeSteer string,
) {
	pl.mu.Lock()
	defer pl.mu.Unlock()

	pl.ReconCalls = reconCalls
	pl.ExploitCalls = exploitCalls
	pl.FindingsCount = findingsCount
	pl.SubtaskCurrent = subtaskCurrent
	pl.SubtaskTotal = subtaskTotal
	pl.SubtaskTitle = subtaskTitle

	if activeSteer != "" {
		pl.ActiveDirective = activeSteer
	}

	// Auto-detect phase from ratio of recon vs exploit calls
	totalCalls := reconCalls + exploitCalls
	if totalCalls == 0 {
		pl.Phase = "RECON"
	} else if float64(exploitCalls)/float64(totalCalls) > 0.3 {
		pl.Phase = "EXPLOITATION"
	} else if reconCalls > 0 && exploitCalls == 0 {
		pl.Phase = "RECON"
	} else {
		pl.Phase = "MIXED"
	}
}

// SetTopFinding records the most promising finding for chain injection.
func (pl *ProgressLedger) SetTopFinding(finding string) {
	pl.mu.Lock()
	defer pl.mu.Unlock()
	pl.TopFinding = finding
}

// Format returns the ledger as a compact string block for system prompt injection.
// Kept under 100 tokens for efficiency.
func (pl *ProgressLedger) Format() string {
	pl.mu.Lock()
	defer pl.mu.Unlock()

	var b strings.Builder
	b.WriteString("=== PROGRESS LEDGER ===\n")
	b.WriteString(fmt.Sprintf("Phase: %s\n", pl.Phase))
	if pl.SubtaskTotal > 0 {
		b.WriteString(fmt.Sprintf("Subtask: %d/%d — %q\n", pl.SubtaskCurrent, pl.SubtaskTotal, pl.SubtaskTitle))
	}
	b.WriteString(fmt.Sprintf("Recon: %d | Exploit: %d | Findings: %d\n",
		pl.ReconCalls, pl.ExploitCalls, pl.FindingsCount))
	if pl.ActiveDirective != "" {
		directive := pl.ActiveDirective
		if len(directive) > 120 {
			directive = directive[:117] + "..."
		}
		b.WriteString(fmt.Sprintf("Active directive: %s\n", directive))
	}
	if pl.TopFinding != "" {
		finding := pl.TopFinding
		if len(finding) > 100 {
			finding = finding[:97] + "..."
		}
		b.WriteString(fmt.Sprintf("Top finding to chain: %s\n", finding))
	}
	b.WriteString("===")
	return b.String()
}

// injectProgressLedger replaces or inserts the progress ledger block in the system prompt.
func injectProgressLedger(systemPrompt string, ledger string) string {
	startTag := "=== PROGRESS LEDGER ==="
	endTag := "==="

	startIdx := strings.Index(systemPrompt, startTag)
	if startIdx >= 0 {
		// Find the closing === after the start tag
		rest := systemPrompt[startIdx+len(startTag):]
		endIdx := strings.Index(rest, endTag)
		if endIdx >= 0 {
			systemPrompt = systemPrompt[:startIdx] + ledger + systemPrompt[startIdx+len(startTag)+endIdx+len(endTag):]
			return systemPrompt
		}
	}

	// Insert before </execution_metrics> if present, otherwise append
	insertPoint := strings.Index(systemPrompt, "<execution_metrics>")
	if insertPoint >= 0 {
		systemPrompt = systemPrompt[:insertPoint] + ledger + "\n" + systemPrompt[insertPoint:]
	} else {
		systemPrompt = systemPrompt + "\n" + ledger
	}
	return systemPrompt
}
