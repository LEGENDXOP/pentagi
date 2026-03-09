package providers

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"pentagi/pkg/providers/pconfig"
)

// DefaultModelPricing contains default pricing per 1M tokens for known models.
// These serve as a fallback when the provider/config doesn't supply PriceInfo.
// Prices reflect 2025-2026 published API rates (USD per 1M tokens).
var DefaultModelPricing = map[string]pconfig.PriceInfo{
	// Anthropic — Claude 4 family
	"claude-opus-4-20250514":    {Input: 15.0, Output: 75.0, CacheRead: 1.5, CacheWrite: 18.75},
	"claude-opus-4":             {Input: 15.0, Output: 75.0, CacheRead: 1.5, CacheWrite: 18.75},
	"claude-sonnet-4-20250514":  {Input: 3.0, Output: 15.0, CacheRead: 0.3, CacheWrite: 3.75},
	"claude-sonnet-4":           {Input: 3.0, Output: 15.0, CacheRead: 0.3, CacheWrite: 3.75},
	// Anthropic — Claude 3.5 family
	"claude-3-5-sonnet-20241022": {Input: 3.0, Output: 15.0, CacheRead: 0.3, CacheWrite: 3.75},
	"claude-3-5-haiku-20241022":  {Input: 0.8, Output: 4.0, CacheRead: 0.08, CacheWrite: 1.0},
	// Anthropic — Claude 3 family
	"claude-3-opus-20240229":  {Input: 15.0, Output: 75.0, CacheRead: 1.5, CacheWrite: 18.75},
	"claude-3-sonnet-20240229": {Input: 3.0, Output: 15.0},
	"claude-3-haiku-20240307":  {Input: 0.25, Output: 1.25, CacheRead: 0.03, CacheWrite: 0.30},

	// OpenAI — GPT-4o family
	"gpt-4o":            {Input: 2.5, Output: 10.0, CacheRead: 1.25},
	"gpt-4o-2024-11-20": {Input: 2.5, Output: 10.0, CacheRead: 1.25},
	"gpt-4o-mini":       {Input: 0.15, Output: 0.60, CacheRead: 0.075},
	// OpenAI — GPT-4 Turbo
	"gpt-4-turbo":          {Input: 10.0, Output: 30.0},
	"gpt-4-turbo-2024-04-09": {Input: 10.0, Output: 30.0},
	// OpenAI — o-series reasoning
	"o1":         {Input: 15.0, Output: 60.0, CacheRead: 7.5},
	"o1-mini":    {Input: 1.1, Output: 4.4, CacheRead: 0.55},
	"o1-preview": {Input: 15.0, Output: 60.0, CacheRead: 7.5},
	"o3":         {Input: 10.0, Output: 40.0, CacheRead: 2.5},
	"o3-mini":    {Input: 1.1, Output: 4.4, CacheRead: 0.55},
	"o4-mini":    {Input: 1.1, Output: 4.4, CacheRead: 0.275},

	// Google — Gemini family
	"gemini-2.5-pro":   {Input: 1.25, Output: 10.0},
	"gemini-2.5-flash": {Input: 0.15, Output: 0.60},
	"gemini-2.0-flash": {Input: 0.10, Output: 0.40},
	"gemini-1.5-pro":   {Input: 1.25, Output: 5.0},
	"gemini-1.5-flash": {Input: 0.075, Output: 0.30},

	// AWS Bedrock — Claude models (same pricing as direct Anthropic)
	"anthropic.claude-3-opus-20240229-v1:0":   {Input: 15.0, Output: 75.0},
	"anthropic.claude-3-sonnet-20240229-v1:0":  {Input: 3.0, Output: 15.0},
	"anthropic.claude-3-haiku-20240307-v1:0":   {Input: 0.25, Output: 1.25},
	"anthropic.claude-3-5-sonnet-20241022-v2:0": {Input: 3.0, Output: 15.0},
}

// LookupDefaultPricing returns the default PriceInfo for a model name.
// It performs exact match first, then tries prefix matching for versioned model names.
// Returns nil if no pricing is found.
func LookupDefaultPricing(model string) *pconfig.PriceInfo {
	model = strings.TrimSpace(model)
	if model == "" {
		return nil
	}

	// Exact match
	if price, ok := DefaultModelPricing[model]; ok {
		return &price
	}

	// Prefix match: "claude-sonnet-4-20250514" should match "claude-sonnet-4"
	// Try progressively shorter prefixes
	bestKey := ""
	for key := range DefaultModelPricing {
		if strings.HasPrefix(model, key) && len(key) > len(bestKey) {
			bestKey = key
		}
	}
	if bestKey != "" {
		price := DefaultModelPricing[bestKey]
		return &price
	}

	return nil
}

// CostBreakdown provides a detailed view of costs by agent type.
type CostBreakdown struct {
	ByAgentType map[string]AgentTypeCost `json:"by_agent_type"`
	TotalInput  int64                    `json:"total_input_tokens"`
	TotalOutput int64                    `json:"total_output_tokens"`
	TotalCache  int64                    `json:"total_cache_tokens"`
	TotalCost   float64                  `json:"total_cost_usd"`
}

// AgentTypeCost tracks cost for a single agent type.
type AgentTypeCost struct {
	InputTokens  int64   `json:"input_tokens"`
	OutputTokens int64   `json:"output_tokens"`
	CacheTokens  int64   `json:"cache_tokens"`
	CostInput    float64 `json:"cost_input_usd"`
	CostOutput   float64 `json:"cost_output_usd"`
	TotalCost    float64 `json:"total_cost_usd"`
	CallCount    int     `json:"call_count"`
}

// CostSummary provides a formatted summary suitable for inclusion in reports.
type CostSummary struct {
	TotalInputTokens  int64   `json:"total_input_tokens"`
	TotalOutputTokens int64   `json:"total_output_tokens"`
	TotalCacheTokens  int64   `json:"total_cache_tokens"`
	TotalCostUSD      float64 `json:"total_cost_usd"`
	CostPerFinding    float64 `json:"cost_per_finding_usd,omitempty"`
	FindingsCount     int     `json:"findings_count,omitempty"`
	BreakdownByType   []TypeCostEntry `json:"breakdown_by_type,omitempty"`
}

// TypeCostEntry is a single row in the type-level cost breakdown.
type TypeCostEntry struct {
	AgentType    string  `json:"agent_type"`
	InputTokens  int64   `json:"input_tokens"`
	OutputTokens int64   `json:"output_tokens"`
	CostUSD      float64 `json:"cost_usd"`
}

// CostTracker accumulates token usage and cost across multiple LLM calls
// within a single flow. It is goroutine-safe.
type CostTracker struct {
	mu          sync.Mutex
	model       string
	byAgent     map[string]*AgentTypeCost
	totalUsage  pconfig.CallUsage
	callCount   int
}

// NewCostTracker creates a tracker for the given primary model name.
// The model name is used for fallback pricing lookup when PriceInfo is not
// available from the provider config.
func NewCostTracker(model string) *CostTracker {
	return &CostTracker{
		model:   model,
		byAgent: make(map[string]*AgentTypeCost),
	}
}

// AddUsage records a single LLM call's usage, categorized by agent type.
// If agentType is empty, it defaults to "unknown".
func (ct *CostTracker) AddUsage(agentType string, usage pconfig.CallUsage) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if agentType == "" {
		agentType = "unknown"
	}

	ct.totalUsage.Merge(usage)
	ct.callCount++

	entry, ok := ct.byAgent[agentType]
	if !ok {
		entry = &AgentTypeCost{}
		ct.byAgent[agentType] = entry
	}

	entry.InputTokens += usage.Input
	entry.OutputTokens += usage.Output
	entry.CacheTokens += usage.CacheRead + usage.CacheWrite
	entry.CostInput += usage.CostInput
	entry.CostOutput += usage.CostOutput
	entry.TotalCost += usage.CostInput + usage.CostOutput
	entry.CallCount++
}

// GetTotalCost returns the accumulated total cost in USD.
func (ct *CostTracker) GetTotalCost() float64 {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	return ct.totalUsage.CostInput + ct.totalUsage.CostOutput
}

// GetTotalUsage returns the accumulated CallUsage across all calls.
func (ct *CostTracker) GetTotalUsage() pconfig.CallUsage {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	return ct.totalUsage
}

// GetCostBreakdown returns a detailed breakdown by agent type.
func (ct *CostTracker) GetCostBreakdown() CostBreakdown {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	breakdown := CostBreakdown{
		ByAgentType: make(map[string]AgentTypeCost, len(ct.byAgent)),
		TotalInput:  ct.totalUsage.Input,
		TotalOutput: ct.totalUsage.Output,
		TotalCache:  ct.totalUsage.CacheRead + ct.totalUsage.CacheWrite,
		TotalCost:   ct.totalUsage.CostInput + ct.totalUsage.CostOutput,
	}

	for agentType, cost := range ct.byAgent {
		breakdown.ByAgentType[agentType] = *cost
	}

	return breakdown
}

// GetCostPerFinding calculates cost per finding. Returns 0 if findingsCount <= 0.
func (ct *CostTracker) GetCostPerFinding(findingsCount int) float64 {
	if findingsCount <= 0 {
		return 0
	}

	totalCost := ct.GetTotalCost()
	return totalCost / float64(findingsCount)
}

// GetCostSummary produces a CostSummary suitable for report inclusion.
func (ct *CostTracker) GetCostSummary(findingsCount int) CostSummary {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	totalCost := ct.totalUsage.CostInput + ct.totalUsage.CostOutput

	summary := CostSummary{
		TotalInputTokens:  ct.totalUsage.Input,
		TotalOutputTokens: ct.totalUsage.Output,
		TotalCacheTokens:  ct.totalUsage.CacheRead + ct.totalUsage.CacheWrite,
		TotalCostUSD:      totalCost,
		FindingsCount:     findingsCount,
	}

	if findingsCount > 0 {
		summary.CostPerFinding = totalCost / float64(findingsCount)
	}

	for agentType, cost := range ct.byAgent {
		summary.BreakdownByType = append(summary.BreakdownByType, TypeCostEntry{
			AgentType:    agentType,
			InputTokens:  cost.InputTokens,
			OutputTokens: cost.OutputTokens,
			CostUSD:      cost.TotalCost,
		})
	}

	return summary
}

// FormatCostSummary returns a human-readable cost summary string.
func (ct *CostTracker) FormatCostSummary(findingsCount int) string {
	summary := ct.GetCostSummary(findingsCount)

	var sb strings.Builder
	sb.WriteString("=== LLM Cost Summary ===\n")
	sb.WriteString(fmt.Sprintf("Total Input Tokens:  %d\n", summary.TotalInputTokens))
	sb.WriteString(fmt.Sprintf("Total Output Tokens: %d\n", summary.TotalOutputTokens))
	if summary.TotalCacheTokens > 0 {
		sb.WriteString(fmt.Sprintf("Total Cache Tokens:  %d\n", summary.TotalCacheTokens))
	}
	sb.WriteString(fmt.Sprintf("Total Cost:          $%.4f USD\n", summary.TotalCostUSD))

	if summary.FindingsCount > 0 {
		sb.WriteString(fmt.Sprintf("Findings:            %d\n", summary.FindingsCount))
		sb.WriteString(fmt.Sprintf("Cost per Finding:    $%.4f USD\n", summary.CostPerFinding))
	}

	if len(summary.BreakdownByType) > 0 {
		sb.WriteString("\nBreakdown by Agent Type:\n")
		for _, entry := range summary.BreakdownByType {
			sb.WriteString(fmt.Sprintf("  %-20s  in: %-10d  out: %-10d  cost: $%.4f\n",
				entry.AgentType, entry.InputTokens, entry.OutputTokens, entry.CostUSD))
		}
	}

	return sb.String()
}

// --- Context-based CostTracker propagation ---

type costTrackerKey struct{}

// WithCostTracker attaches a CostTracker to a context.
func WithCostTracker(ctx context.Context, ct *CostTracker) context.Context {
	return context.WithValue(ctx, costTrackerKey{}, ct)
}

// GetCostTracker retrieves the CostTracker from a context, or nil if none is set.
func GetCostTracker(ctx context.Context) *CostTracker {
	if ct, ok := ctx.Value(costTrackerKey{}).(*CostTracker); ok {
		return ct
	}
	return nil
}
