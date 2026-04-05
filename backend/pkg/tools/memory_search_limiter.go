package tools

import (
	"fmt"
	"os"
	"strconv"
	"sync"

	"github.com/sirupsen/logrus"
)

// MemorySearchLimiter enforces hard limits on memory/vector-DB search tool calls
// to prevent agents from obsessively querying memory after every subtask.
//
// Three independent limiters work together:
//
// 1. Per-Subtask Consecutive Search Counter:
//    Tracks consecutive memory search calls. After maxConsecutiveSearches (default 3),
//    further searches are BLOCKED until a non-memory tool call is made.
//
// 2. Low-Relevance Auto-Stop:
//    If lowRelevanceThreshold consecutive memory searches return low relevance
//    (score < 0.75), further searches are blocked until a non-memory tool is called.
//    NOTE: This is tracked via RecordRelevanceScore() which must be called by the
//    search handlers AFTER results are available.
//
// 3. Per-Flow Memory Search Budget:
//    Total memory searches must not exceed memoryBudgetPercent (default 15%) of
//    total tool calls across the entire flow. Once exhausted, ALL further memory
//    searches are blocked for the rest of the flow.
//
// The limiter is designed to be shared across all customExecutor instances
// within a single flow (attached to flowToolsExecutor).
type MemorySearchLimiter struct {
	mu sync.Mutex

	// Configuration
	maxConsecutiveSearches int     // max consecutive memory searches before block (default: 3)
	lowRelevanceThreshold  int     // consecutive low-relevance results before block (default: 2)
	lowRelevanceScore      float64 // score threshold for "low relevance" (default: 0.75)
	memoryBudgetPercent    float64 // max % of total tool calls that can be memory searches (default: 0.15)

	// State: per-subtask consecutive search tracking
	// Reset when a non-memory tool is called OR when subtask changes
	consecutiveSearches int
	currentSubtaskID    *int64

	// State: low-relevance tracking
	// Reset when a non-memory tool is called
	consecutiveLowRelevance int

	// State: per-flow budget tracking
	totalToolCalls        int
	totalMemorySearches   int

	// State: whether we are in a blocked state
	consecutiveBlocked    bool // blocked due to consecutive limit
	lowRelevanceBlocked   bool // blocked due to low-relevance auto-stop
}

// MemorySearchLimiterConfig holds configuration for the limiter.
type MemorySearchLimiterConfig struct {
	MaxConsecutiveSearches int
	LowRelevanceThreshold  int
	LowRelevanceScore      float64
	MemoryBudgetPercent    float64
}

// DefaultMemorySearchLimiterConfig returns defaults, overridable by env vars.
func DefaultMemorySearchLimiterConfig() MemorySearchLimiterConfig {
	cfg := MemorySearchLimiterConfig{
		MaxConsecutiveSearches: 3,
		LowRelevanceThreshold:  2,
		LowRelevanceScore:      0.75,
		MemoryBudgetPercent:    0.15,
	}

	if v := os.Getenv("MEMORY_SEARCH_MAX_CONSECUTIVE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			cfg.MaxConsecutiveSearches = n
		}
	}
	if v := os.Getenv("MEMORY_SEARCH_LOW_RELEVANCE_THRESHOLD"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			cfg.LowRelevanceThreshold = n
		}
	}
	if v := os.Getenv("MEMORY_SEARCH_LOW_RELEVANCE_SCORE"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 && f < 1 {
			cfg.LowRelevanceScore = f
		}
	}
	if v := os.Getenv("MEMORY_SEARCH_BUDGET_PERCENT"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 && f <= 1 {
			cfg.MemoryBudgetPercent = f
		}
	}

	return cfg
}

// NewMemorySearchLimiter creates a new limiter with the given configuration.
func NewMemorySearchLimiter(cfg MemorySearchLimiterConfig) *MemorySearchLimiter {
	return &MemorySearchLimiter{
		maxConsecutiveSearches: cfg.MaxConsecutiveSearches,
		lowRelevanceThreshold:  cfg.LowRelevanceThreshold,
		lowRelevanceScore:      cfg.LowRelevanceScore,
		memoryBudgetPercent:    cfg.MemoryBudgetPercent,
	}
}

// NewDefaultMemorySearchLimiter creates a limiter with default/env-configured settings.
func NewDefaultMemorySearchLimiter() *MemorySearchLimiter {
	return NewMemorySearchLimiter(DefaultMemorySearchLimiterConfig())
}

// memorySearchToolNames contains all tool names classified as memory/vector-DB searches.
// These are the tools subject to rate limiting by this limiter.
var memorySearchToolNames = map[string]bool{
	SearchInMemoryToolName: true,
	SearchGuideToolName:    true,
	SearchAnswerToolName:   true,
	SearchCodeToolName:     true,
	GraphitiSearchToolName: true,
}

// IsMemorySearchTool returns true if the given tool name is a memory/vector-DB search.
func IsMemorySearchTool(name string) bool {
	return memorySearchToolNames[name]
}

// CheckAndRecord checks whether a tool call should be allowed and records it.
// Returns (blocked bool, message string).
// If blocked=true, the caller should return `message` instead of executing the tool.
//
// This method MUST be called for EVERY tool call (memory or not) to accurately
// track the consecutive counter and budget ratio.
func (msl *MemorySearchLimiter) CheckAndRecord(name string, subtaskID *int64) (bool, string) {
	msl.mu.Lock()
	defer msl.mu.Unlock()

	isMemorySearch := memorySearchToolNames[name]

	// Always increment total tool calls for budget tracking
	msl.totalToolCalls++

	// Check if subtask changed — reset consecutive counters
	if subtaskChanged(msl.currentSubtaskID, subtaskID) {
		msl.currentSubtaskID = subtaskID
		msl.consecutiveSearches = 0
		msl.consecutiveLowRelevance = 0
		msl.consecutiveBlocked = false
		msl.lowRelevanceBlocked = false
	}

	if !isMemorySearch {
		// Non-memory tool call: reset all consecutive counters
		msl.consecutiveSearches = 0
		msl.consecutiveLowRelevance = 0
		msl.consecutiveBlocked = false
		msl.lowRelevanceBlocked = false
		return false, ""
	}

	// --- This is a memory search tool call ---

	// Check 1: Per-flow budget (hardest limit, cannot be reset)
	if msl.totalToolCalls > 10 { // only enforce after warm-up period of 10 total calls
		budgetUsed := float64(msl.totalMemorySearches) / float64(msl.totalToolCalls)
		if budgetUsed >= msl.memoryBudgetPercent {
			logrus.WithFields(logrus.Fields{
				"tool":              name,
				"total_tool_calls":  msl.totalToolCalls,
				"memory_searches":   msl.totalMemorySearches,
				"budget_percent":    fmt.Sprintf("%.1f%%", budgetUsed*100),
				"limit_percent":     fmt.Sprintf("%.1f%%", msl.memoryBudgetPercent*100),
			}).Warn("memory search limiter: per-flow budget exhausted")

			return true, fmt.Sprintf(
				"Memory search budget exhausted for this flow (%d/%d tool calls = %.0f%% memory searches, limit: %.0f%%). "+
					"Continue with direct testing and exploitation. Use on-disk evidence files if you need prior results.",
				msl.totalMemorySearches, msl.totalToolCalls, budgetUsed*100, msl.memoryBudgetPercent*100,
			)
		}
	}

	// Check 2: Consecutive search limit
	if msl.consecutiveBlocked {
		logrus.WithFields(logrus.Fields{
			"tool":                 name,
			"consecutive_searches": msl.consecutiveSearches,
		}).Warn("memory search limiter: still blocked (consecutive limit)")

		return true, fmt.Sprintf(
			"Memory search limit reached (%d/%d consecutive searches). "+
				"Use evidence files on disk instead. Proceed with your next action — "+
				"use terminal, browser, file write, or any non-memory tool to reset this limit.",
			msl.consecutiveSearches, msl.maxConsecutiveSearches,
		)
	}

	if msl.consecutiveSearches >= msl.maxConsecutiveSearches {
		msl.consecutiveBlocked = true
		logrus.WithFields(logrus.Fields{
			"tool":                 name,
			"consecutive_searches": msl.consecutiveSearches,
			"max_consecutive":      msl.maxConsecutiveSearches,
		}).Warn("memory search limiter: consecutive search limit hit")

		return true, fmt.Sprintf(
			"Memory search limit reached (%d/%d consecutive searches). "+
				"Use evidence files on disk instead. Proceed with your next action — "+
				"use terminal, browser, file write, or any non-memory tool to reset this limit.",
			msl.maxConsecutiveSearches, msl.maxConsecutiveSearches,
		)
	}

	// Check 3: Low-relevance auto-stop
	if msl.lowRelevanceBlocked {
		logrus.WithFields(logrus.Fields{
			"tool":                     name,
			"consecutive_low_relevance": msl.consecutiveLowRelevance,
		}).Warn("memory search limiter: still blocked (low relevance)")

		return true, fmt.Sprintf(
			"Memory searches returning low relevance (<%.2f) for %d consecutive searches. "+
				"Memory system doesn't have what you need. Use on-disk evidence files. "+
				"Use a non-memory tool (terminal, browser, etc.) to reset this limit.",
			msl.lowRelevanceScore, msl.consecutiveLowRelevance,
		)
	}

	// Allowed — record the search
	msl.consecutiveSearches++
	msl.totalMemorySearches++

	return false, ""
}

// RecordRelevanceScore records the highest relevance score from a memory search result.
// Should be called AFTER the search handler returns successfully.
// Pass the maximum score found in the search results, or 0.0 if no results.
func (msl *MemorySearchLimiter) RecordRelevanceScore(score float64) {
	msl.mu.Lock()
	defer msl.mu.Unlock()

	if score < msl.lowRelevanceScore {
		msl.consecutiveLowRelevance++
		if msl.consecutiveLowRelevance >= msl.lowRelevanceThreshold {
			msl.lowRelevanceBlocked = true
			logrus.WithFields(logrus.Fields{
				"score":                     score,
				"consecutive_low_relevance": msl.consecutiveLowRelevance,
				"threshold":                 msl.lowRelevanceThreshold,
			}).Warn("memory search limiter: low-relevance auto-stop triggered")
		}
	} else {
		// Good relevance — reset the low-relevance counter
		msl.consecutiveLowRelevance = 0
	}
}

// GetStats returns current limiter state for debugging/logging.
func (msl *MemorySearchLimiter) GetStats() (consecutiveSearches, totalMemory, totalTools int) {
	msl.mu.Lock()
	defer msl.mu.Unlock()
	return msl.consecutiveSearches, msl.totalMemorySearches, msl.totalToolCalls
}

// subtaskChanged checks if the subtask ID has changed.
func subtaskChanged(current, incoming *int64) bool {
	if current == nil && incoming == nil {
		return false
	}
	if current == nil || incoming == nil {
		return true
	}
	return *current != *incoming
}
