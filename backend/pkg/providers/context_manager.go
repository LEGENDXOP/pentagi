package providers

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// ContextPriority defines how important a context item is for pruning decisions.
// Lower values = higher importance = pruned last (or never).
type ContextPriority int

const (
	// PriorityFindings — NEVER pruned. Contains security findings, vulnerabilities, critical info.
	PriorityFindings ContextPriority = 0
	// PriorityErrors — keep recent errors for debugging context.
	PriorityErrors ContextPriority = 1
	// PriorityRecentTools — last N tool results, always kept intact.
	PriorityRecentTools ContextPriority = 2
	// PriorityOldTools — older tool results that can be summarized.
	PriorityOldTools ContextPriority = 3
	// PriorityNoise — verbose output from old commands, can be dropped entirely.
	PriorityNoise ContextPriority = 4
)

// Default tuning constants for the ContextManager.
const (
	// recentToolWindowSize is the number of most recent tool results to protect from pruning.
	recentToolWindowSize = 5

	// noiseCharThreshold — tool results longer than this from old commands are classified as noise.
	noiseCharThreshold = 2000

	// defaultMaxContextTokens is the default context budget (in estimated tokens).
	// 32K tokens ≈ 128K chars, a reasonable default for most models.
	defaultMaxContextTokens = 32000

	// summarizedLineCount — when summarizing old tool results, keep this many lines
	// from the head and tail.
	summarizedLineCount = 3
)

// findingsKeywords are substrings whose presence elevates content to PriorityFindings.
var findingsKeywords = []string{
	"FINDING",
	"CRITICAL",
	"VULNERABILITY",
	"CVE-",
	"EXPLOIT",
	"[VULN]",
	"HIGH SEVERITY",
	"MEDIUM SEVERITY",
	"LOW SEVERITY",
}

// errorKeywords are substrings whose presence classifies content as PriorityErrors.
var errorKeywords = []string{
	"[ERROR]",
	"failed",
	"error:",
	"Error:",
	"FATAL",
	"panic:",
	"permission denied",
	"not found",
	"timed out",
	"connection refused",
}

// ContextItem represents a single piece of content tracked by the ContextManager.
type ContextItem struct {
	// Content is the raw text of this item (tool result, finding, etc.)
	Content string

	// Priority determines pruning order. Lower = more important.
	Priority ContextPriority

	// Timestamp records when this item was added.
	Timestamp time.Time

	// TokenEstimate is a rough token count (len(Content)/4).
	TokenEstimate int

	// IsReferenced indicates whether recent tool calls referenced this content.
	// Referenced items get bumped to PriorityRecentTools regardless of age.
	IsReferenced bool

	// OriginalPriority preserves the classified priority before any reference bumps.
	OriginalPriority ContextPriority

	// Index is the insertion order (monotonically increasing) for stable age comparisons.
	Index int

	// ToolName records which tool produced this content (empty for non-tool items).
	ToolName string

	// IsSummarized indicates this item has already been summarized (don't re-summarize).
	IsSummarized bool
}

// ContextManager performs intelligent pruning of context items based on priority,
// age, and relevance. It is designed to be used within a single performAgentChain
// invocation — one manager per subtask execution.
type ContextManager struct {
	mu        sync.RWMutex
	items     []ContextItem
	maxTokens int
	nextIndex int
}

// NewContextManager creates a context manager with the given token budget.
// If maxTokens <= 0, defaultMaxContextTokens is used.
func NewContextManager(maxTokens int) *ContextManager {
	if maxTokens <= 0 {
		maxTokens = defaultMaxContextTokens
	}
	return &ContextManager{
		items:     make([]ContextItem, 0, 64),
		maxTokens: maxTokens,
	}
}

// Add classifies content and adds it to the managed context.
// The priority is auto-detected from content keywords unless overridden
// by passing an explicit priority via AddWithPriority.
func (cm *ContextManager) Add(content string, toolName string) {
	priority := classifyContent(content, cm.recentToolCutoff())
	cm.addItem(content, priority, toolName)
}

// AddWithPriority adds content with an explicit priority (skipping auto-classification).
func (cm *ContextManager) AddWithPriority(content string, priority ContextPriority, toolName string) {
	cm.addItem(content, priority, toolName)
}

func (cm *ContextManager) addItem(content string, priority ContextPriority, toolName string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	item := ContextItem{
		Content:          content,
		Priority:         priority,
		OriginalPriority: priority,
		Timestamp:        time.Now(),
		TokenEstimate:    estimateTokens(content),
		ToolName:         toolName,
		Index:            cm.nextIndex,
	}
	cm.nextIndex++
	cm.items = append(cm.items, item)
}

// MarkReferenced scans all items and marks those whose content contains the given
// substring. Marked items are bumped to PriorityRecentTools to protect them from pruning.
func (cm *ContextManager) MarkReferenced(contentSubstring string) {
	if contentSubstring == "" {
		return
	}
	cm.mu.Lock()
	defer cm.mu.Unlock()

	for i := range cm.items {
		if strings.Contains(cm.items[i].Content, contentSubstring) {
			cm.items[i].IsReferenced = true
			// Bump priority but never lower it (findings stay as findings)
			if cm.items[i].Priority > PriorityRecentTools {
				cm.items[i].Priority = PriorityRecentTools
			}
		}
	}
}

// ReclassifyByAge re-evaluates priorities based on the current item count.
// Recent tool results (last recentToolWindowSize items) stay as PriorityRecentTools;
// older ones may be downgraded to PriorityOldTools or PriorityNoise.
// Items that were bumped via MarkReferenced keep their bump.
// PriorityFindings items are NEVER reclassified.
func (cm *ContextManager) ReclassifyByAge() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	n := len(cm.items)
	if n == 0 {
		return
	}

	cutoff := cm.recentToolCutoffLocked()

	for i := range cm.items {
		item := &cm.items[i]

		// Findings are sacred — never touch.
		if item.OriginalPriority == PriorityFindings {
			item.Priority = PriorityFindings
			continue
		}

		// Referenced items stay protected.
		if item.IsReferenced {
			if item.Priority > PriorityRecentTools {
				item.Priority = PriorityRecentTools
			}
			continue
		}

		// Recent items (by insertion order) stay as recent tools.
		if item.Index >= cutoff {
			if item.OriginalPriority != PriorityErrors {
				item.Priority = PriorityRecentTools
			}
			continue
		}

		// Old items: classify based on size.
		if item.OriginalPriority == PriorityErrors {
			// Errors stay as errors unless very old — let pruning handle them.
			item.Priority = PriorityErrors
			continue
		}

		if len(item.Content) > noiseCharThreshold {
			item.Priority = PriorityNoise
		} else {
			item.Priority = PriorityOldTools
		}
	}
}

// Prune removes or summarizes items to bring total tokens under maxTokens.
// Returns the surviving items (in insertion order).
// Pruning order:
//  1. Drop PriorityNoise entirely
//  2. Summarize PriorityOldTools (keep first+last N lines)
//  3. Summarize PriorityErrors (keep first error line only)
//  4. NEVER touch PriorityFindings or PriorityRecentTools
func (cm *ContextManager) Prune() []ContextItem {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Step 0: Reclassify before pruning.
	cm.reclassifyByAgeLocked()

	total := cm.getTotalTokensLocked()
	if total <= cm.maxTokens {
		// Under budget — return everything.
		result := make([]ContextItem, len(cm.items))
		copy(result, cm.items)
		return result
	}

	// Step 1: Drop PriorityNoise entirely.
	cm.items = cm.pruneByPriority(cm.items, PriorityNoise, func(_ *ContextItem) {
		// Drop entirely — no replacement.
	})
	total = cm.getTotalTokensLocked()
	if total <= cm.maxTokens {
		return cm.copyItems()
	}

	// Step 2: Summarize PriorityOldTools — keep first+last N lines.
	for i := range cm.items {
		if total <= cm.maxTokens {
			break
		}
		item := &cm.items[i]
		if item.Priority != PriorityOldTools || item.IsSummarized {
			continue
		}
		oldTokens := item.TokenEstimate
		item.Content = summarizeToHeadTail(item.Content, summarizedLineCount)
		item.TokenEstimate = estimateTokens(item.Content)
		item.IsSummarized = true
		total -= (oldTokens - item.TokenEstimate)
	}
	if total <= cm.maxTokens {
		return cm.copyItems()
	}

	// Step 3: Summarize PriorityErrors — keep first error line only.
	for i := range cm.items {
		if total <= cm.maxTokens {
			break
		}
		item := &cm.items[i]
		if item.Priority != PriorityErrors || item.IsSummarized {
			continue
		}
		oldTokens := item.TokenEstimate
		item.Content = extractFirstErrorLine(item.Content)
		item.TokenEstimate = estimateTokens(item.Content)
		item.IsSummarized = true
		total -= (oldTokens - item.TokenEstimate)
	}

	// Steps 4+: If STILL over budget after all pruning, we do NOT touch
	// PriorityFindings or PriorityRecentTools. The caller must deal with it
	// (e.g., by increasing maxTokens or reducing tool output upstream).

	return cm.copyItems()
}

// GetTotalTokens returns the sum of estimated tokens across all items.
func (cm *ContextManager) GetTotalTokens() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.getTotalTokensLocked()
}

// GetItemCount returns the number of tracked items.
func (cm *ContextManager) GetItemCount() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return len(cm.items)
}

// GetItemsByPriority returns items filtered by the given priority.
func (cm *ContextManager) GetItemsByPriority(priority ContextPriority) []ContextItem {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	var result []ContextItem
	for _, item := range cm.items {
		if item.Priority == priority {
			result = append(result, item)
		}
	}
	return result
}

// Stats returns a snapshot of context manager statistics.
func (cm *ContextManager) Stats() ContextManagerStats {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	stats := ContextManagerStats{
		TotalItems:    len(cm.items),
		TotalTokens:   cm.getTotalTokensLocked(),
		MaxTokens:     cm.maxTokens,
		OverBudget:    cm.getTotalTokensLocked() > cm.maxTokens,
		PriorityCounts: make(map[ContextPriority]int),
		PriorityTokens: make(map[ContextPriority]int),
	}

	for _, item := range cm.items {
		stats.PriorityCounts[item.Priority]++
		stats.PriorityTokens[item.Priority] += item.TokenEstimate
	}

	return stats
}

// ContextManagerStats holds a point-in-time snapshot of the manager's state.
type ContextManagerStats struct {
	TotalItems     int                        `json:"total_items"`
	TotalTokens    int                        `json:"total_tokens"`
	MaxTokens      int                        `json:"max_tokens"`
	OverBudget     bool                       `json:"over_budget"`
	PriorityCounts map[ContextPriority]int    `json:"priority_counts"`
	PriorityTokens map[ContextPriority]int    `json:"priority_tokens"`
}

// FormatStats returns a human-readable summary for logging.
func (s ContextManagerStats) FormatStats() string {
	priorityNames := map[ContextPriority]string{
		PriorityFindings:    "findings",
		PriorityErrors:      "errors",
		PriorityRecentTools: "recent_tools",
		PriorityOldTools:    "old_tools",
		PriorityNoise:       "noise",
	}

	var parts []string
	for p := PriorityFindings; p <= PriorityNoise; p++ {
		count := s.PriorityCounts[p]
		tokens := s.PriorityTokens[p]
		if count > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d(%dtok)", priorityNames[p], count, tokens))
		}
	}

	return fmt.Sprintf("items=%d tokens=%d/%d over=%v [%s]",
		s.TotalItems, s.TotalTokens, s.MaxTokens, s.OverBudget,
		strings.Join(parts, " "))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func (cm *ContextManager) getTotalTokensLocked() int {
	total := 0
	for _, item := range cm.items {
		total += item.TokenEstimate
	}
	return total
}

func (cm *ContextManager) copyItems() []ContextItem {
	result := make([]ContextItem, len(cm.items))
	copy(result, cm.items)
	return result
}

// recentToolCutoff returns the insertion index threshold: items with Index >= this
// are considered "recent". Must be called WITHOUT lock.
func (cm *ContextManager) recentToolCutoff() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.recentToolCutoffLocked()
}

func (cm *ContextManager) recentToolCutoffLocked() int {
	if cm.nextIndex <= recentToolWindowSize {
		return 0
	}
	return cm.nextIndex - recentToolWindowSize
}

// reclassifyByAgeLocked is the lock-held variant of ReclassifyByAge.
func (cm *ContextManager) reclassifyByAgeLocked() {
	n := len(cm.items)
	if n == 0 {
		return
	}

	cutoff := cm.recentToolCutoffLocked()

	for i := range cm.items {
		item := &cm.items[i]

		// Findings are sacred.
		if item.OriginalPriority == PriorityFindings {
			item.Priority = PriorityFindings
			continue
		}

		// Referenced items stay protected.
		if item.IsReferenced {
			if item.Priority > PriorityRecentTools {
				item.Priority = PriorityRecentTools
			}
			continue
		}

		// Recent items stay protected.
		if item.Index >= cutoff {
			if item.OriginalPriority == PriorityErrors {
				item.Priority = PriorityErrors
			} else {
				item.Priority = PriorityRecentTools
			}
			continue
		}

		// Old items.
		if item.OriginalPriority == PriorityErrors {
			item.Priority = PriorityErrors
			continue
		}

		if len(item.Content) > noiseCharThreshold {
			item.Priority = PriorityNoise
		} else {
			item.Priority = PriorityOldTools
		}
	}
}

// pruneByPriority removes items matching the given priority. The onPrune callback
// can optionally transform the item before removal (e.g., summarize it). If the
// callback sets Content to "", the item is dropped; otherwise it's kept as-is.
func (cm *ContextManager) pruneByPriority(items []ContextItem, priority ContextPriority, onPrune func(*ContextItem)) []ContextItem {
	result := make([]ContextItem, 0, len(items))
	for i := range items {
		if items[i].Priority == priority {
			onPrune(&items[i])
			// Drop the item entirely (onPrune for Noise is a no-op).
			continue
		}
		result = append(result, items[i])
	}
	return result
}

// classifyContent determines the priority of a piece of content based on keyword matching.
func classifyContent(content string, recentCutoffIndex int) ContextPriority {
	upper := strings.ToUpper(content)

	// Check for findings keywords first (highest priority).
	for _, kw := range findingsKeywords {
		if strings.Contains(upper, strings.ToUpper(kw)) {
			return PriorityFindings
		}
	}

	// Check for error keywords.
	for _, kw := range errorKeywords {
		if strings.Contains(content, kw) {
			return PriorityErrors
		}
	}

	// Default: will be classified as recent/old based on age during reclassification.
	return PriorityRecentTools
}

// estimateTokens provides a rough token count using the char/4 heuristic.
func estimateTokens(content string) int {
	n := len(content) / 4
	if n == 0 && len(content) > 0 {
		n = 1
	}
	return n
}

// summarizeToHeadTail keeps the first and last N lines of content, replacing
// the middle with a marker. If content has fewer than 2*N+1 lines, it's returned as-is.
func summarizeToHeadTail(content string, n int) string {
	lines := strings.Split(content, "\n")
	if len(lines) <= 2*n+1 {
		return content
	}

	head := lines[:n]
	tail := lines[len(lines)-n:]
	omitted := len(lines) - 2*n

	var b strings.Builder
	for _, line := range head {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	b.WriteString(fmt.Sprintf("\n[... %d lines omitted ...]\n\n", omitted))
	for i, line := range tail {
		b.WriteString(line)
		if i < len(tail)-1 {
			b.WriteByte('\n')
		}
	}

	return b.String()
}

// ExtractFindings scans content line by line and extracts all lines (plus their
// immediate context — 1 line before and after) that contain findings keywords.
// Returns the concatenated findings block, or "" if none found.
// This is used by the summarizer to ensure findings are never lost during truncation.
func ExtractFindings(content string) string {
	lines := strings.Split(content, "\n")
	if len(lines) == 0 {
		return ""
	}

	// Mark lines that contain findings keywords
	marked := make([]bool, len(lines))
	for i, line := range lines {
		upper := strings.ToUpper(line)
		for _, kw := range findingsKeywords {
			if strings.Contains(upper, strings.ToUpper(kw)) {
				marked[i] = true
				// Also mark context lines (1 before, 1 after)
				if i > 0 {
					marked[i-1] = true
				}
				if i < len(lines)-1 {
					marked[i+1] = true
				}
				break
			}
		}
	}

	var findings []string
	inBlock := false
	for i, line := range lines {
		if marked[i] {
			if !inBlock && len(findings) > 0 {
				findings = append(findings, "---")
			}
			findings = append(findings, line)
			inBlock = true
		} else {
			inBlock = false
		}
	}

	if len(findings) == 0 {
		return ""
	}

	return strings.Join(findings, "\n")
}

// ContainsFindings checks whether content contains any findings keywords.
func ContainsFindings(content string) bool {
	upper := strings.ToUpper(content)
	for _, kw := range findingsKeywords {
		if strings.Contains(upper, strings.ToUpper(kw)) {
			return true
		}
	}
	return false
}

// extractFirstErrorLine returns just the first line that looks like an error,
// or the first line if no error-like line is found.
func extractFirstErrorLine(content string) string {
	lines := strings.Split(content, "\n")

	// Try to find the first line containing an error keyword.
	for _, line := range lines {
		for _, kw := range errorKeywords {
			if strings.Contains(line, kw) {
				omitted := len(lines) - 1
				if omitted > 0 {
					return fmt.Sprintf("%s\n[... %d more lines omitted ...]", strings.TrimSpace(line), omitted)
				}
				return strings.TrimSpace(line)
			}
		}
	}

	// Fallback: return the first non-empty line.
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			omitted := len(lines) - 1
			if omitted > 0 {
				return fmt.Sprintf("%s\n[... %d more lines omitted ...]", trimmed, omitted)
			}
			return trimmed
		}
	}

	return content
}
