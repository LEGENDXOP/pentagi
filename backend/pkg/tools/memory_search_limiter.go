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

	// FIX Issue-8: Absolute hard cap on memory searches per flow.
	// Prevents unbounded memory search accumulation even within budget ratio.
	absoluteSearchCap int // hard cap on total memory searches (default: 20)

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

	// State: consecutive empty result tracking
	consecutiveEmptyResults int
	emptyResultBlocked      bool

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
	AbsoluteSearchCap      int // FIX Issue-8: hard cap on total searches per flow
}

// DefaultMemorySearchLimiterConfig returns defaults, overridable by env vars.
func DefaultMemorySearchLimiterConfig() MemorySearchLimiterConfig {
	cfg := MemorySearchLimiterConfig{
		MaxConsecutiveSearches: 2,
		LowRelevanceThreshold:  2,
		LowRelevanceScore:      0.75,
		MemoryBudgetPercent:    0.12,
		AbsoluteSearchCap:      15, // FIX Issue-4: tightened from 20→15, ~3 per subtask in 5-subtask flows
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
	if v := os.Getenv("MEMORY_SEARCH_ABSOLUTE_CAP"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 5 {
			cfg.AbsoluteSearchCap = n
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
		absoluteSearchCap:      cfg.AbsoluteSearchCap,
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

	// Check if subtask changed — reset consecutive counters.
	// Deep-copy the value to avoid pointer aliasing: if the caller reuses
	// the same *int64 and mutates it, we'd miss future transitions.
	if subtaskChanged(msl.currentSubtaskID, subtaskID) {
		if subtaskID != nil {
			id := *subtaskID
			msl.currentSubtaskID = &id
		} else {
			msl.currentSubtaskID = nil
		}
		msl.consecutiveSearches = 0
		msl.consecutiveLowRelevance = 0
		msl.consecutiveEmptyResults = 0
		msl.consecutiveBlocked = false
		msl.lowRelevanceBlocked = false
		msl.emptyResultBlocked = false
	}

	if !isMemorySearch {
		// FIX Issue-8: Decay consecutive counter by 1 instead of full reset.
		if msl.consecutiveSearches > 0 {
			msl.consecutiveSearches--
		}
		if msl.consecutiveSearches == 0 {
			msl.consecutiveBlocked = false
		}
		msl.consecutiveLowRelevance = 0
		msl.lowRelevanceBlocked = false
		msl.consecutiveEmptyResults = 0
		msl.emptyResultBlocked = false
		return false, ""
	}

	// --- This is a memory search tool call ---

	// FIX Issue-8: Absolute hard cap on total memory searches across the flow.
	// This is a safety net that fires regardless of budget ratio or warm-up.
	// Set to 20 to allow multi-task flows with ~5 subtasks to average 4 searches each.
	if msl.absoluteSearchCap > 0 && msl.totalMemorySearches >= msl.absoluteSearchCap {
		logrus.WithFields(logrus.Fields{
			"tool":               name,
			"total_searches":     msl.totalMemorySearches,
			"absolute_cap":       msl.absoluteSearchCap,
		}).Warn("memory search limiter: absolute search cap reached")

		return true, fmt.Sprintf(
			"Memory search absolute limit reached (%d/%d total searches this flow). "+
				"No more memory searches are allowed. "+
				"ALTERNATIVE: Use files on disk — `cat /work/HANDOFF.md`, `cat /work/FINDINGS.md`, `ls /work/`. "+
				"Or use terminal/browser tools directly to continue testing.",
			msl.totalMemorySearches, msl.absoluteSearchCap,
		)
	}

	// Check 1: Per-flow budget (hardest limit, cannot be reset)
	// FIX Issue-8: Reduced warm-up from 10 to 5 total tool calls.
	// The consecutive limit of 3 still applies during warm-up, so
	// the agent can do at most 3 searches in the first 5 calls.
	if msl.totalToolCalls > 5 { // only enforce after warm-up period of 5 total calls
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
					"ALTERNATIVE: Use files on disk instead — `cat /work/HANDOFF.md`, `cat /work/FINDINGS.md`, `ls /work/`. "+
					"Or use terminal/browser tools directly to continue testing.",
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
				"ALTERNATIVE: Use files on disk instead — `cat /work/HANDOFF.md`, `cat /work/FINDINGS.md`, `ls /work/`. "+
				"Or use terminal, browser, or any non-memory tool directly to continue. "+
				"Using a non-memory tool resets this limit.",
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
				"ALTERNATIVE: Use files on disk instead — `cat /work/HANDOFF.md`, `cat /work/FINDINGS.md`, `ls /work/`. "+
				"Or use terminal, browser, or any non-memory tool directly to continue. "+
				"Using a non-memory tool resets this limit.",
			msl.maxConsecutiveSearches, msl.maxConsecutiveSearches,
		)
	}

	// Check 3: Consecutive empty results — if 3+ searches returned nothing, block
	if msl.emptyResultBlocked {
		logrus.WithFields(logrus.Fields{
			"tool":                    name,
			"consecutive_empty":       msl.consecutiveEmptyResults,
		}).Warn("memory search limiter: still blocked (consecutive empty results)")

		return true, fmt.Sprintf(
			"Memory searches returning empty results for %d consecutive searches. "+
				"The data does NOT exist in memory. Searching more will NOT help. "+
				"ALTERNATIVE: Use files on disk — `cat /work/HANDOFF.md`, `cat /work/FINDINGS.md`, `ls /work/`. "+
				"Or use terminal/browser tools directly to continue testing.",
			msl.consecutiveEmptyResults,
		)
	}

	// Check 4: Low-relevance auto-stop
	if msl.lowRelevanceBlocked {
		logrus.WithFields(logrus.Fields{
			"tool":                     name,
			"consecutive_low_relevance": msl.consecutiveLowRelevance,
		}).Warn("memory search limiter: still blocked (low relevance)")

		return true, fmt.Sprintf(
			"Memory searches returning low relevance (<%.2f) for %d consecutive searches. "+
				"The data does NOT exist in memory. Searching more will NOT help. "+
				"ALTERNATIVE: Use files on disk — `cat /work/HANDOFF.md`, `cat /work/FINDINGS.md`, `ls /work/`. "+
				"Or use terminal/browser directly to continue testing.",
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

// RecordEmptyResult records that a memory search returned no results.
// After 3 consecutive empty results, further searches are blocked until
// a non-memory tool call is made.
func (msl *MemorySearchLimiter) RecordEmptyResult() {
	msl.mu.Lock()
	defer msl.mu.Unlock()

	msl.consecutiveEmptyResults++
	if msl.consecutiveEmptyResults >= 3 {
		msl.emptyResultBlocked = true
		logrus.WithFields(logrus.Fields{
			"consecutive_empty": msl.consecutiveEmptyResults,
		}).Warn("memory search limiter: consecutive empty results block triggered")
	}
}

// RecordNonEmptyResult resets the empty result counter on a successful search.
func (msl *MemorySearchLimiter) RecordNonEmptyResult() {
	msl.mu.Lock()
	defer msl.mu.Unlock()

	msl.consecutiveEmptyResults = 0
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
