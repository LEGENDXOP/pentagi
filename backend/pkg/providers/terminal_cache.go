package providers

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// TerminalOutputCache caches terminal command outputs within a single subtask
// to prevent redundant re-execution of identical read-only commands.
//
// The Problem:
// Within a single subtask (no context loss), the agent re-extracts JWT tokens
// 15-20x and re-introspects GraphQL schemas 4x. ~40% of tool calls are
// redundant. Chain summarization strips literal values from earlier results,
// so the LLM rationally re-extracts — it genuinely can't see the data anymore.
// The repeat detector doesn't catch these because isReadOnlyCall() exempts ALL
// reads from detection (to allow cross-subtask bootstrap reads).
//
// The Fix:
// Cache outputs for commands whose results are provably idempotent within a
// subtask window (token file reads, schema introspection, jq on stored files).
// Return cached result with a "[CACHED]" prefix so the LLM knows it's seeing
// saved data and should move on instead of re-executing.
//
// Scope: Per-subtask (created as a local variable in performAgentChain).
// New subtask = new cache. No cross-subtask leakage.
type TerminalOutputCache struct {
	mu      sync.Mutex
	entries map[string]*cacheEntry
	ttl     time.Duration
	hits    int
	misses  int
}

// cacheEntry stores a single cached command output with metadata.
type cacheEntry struct {
	command   string    // original command (for debugging/logging)
	output    string    // the terminal output
	timestamp time.Time // when the output was captured
	hitCount  int       // how many times this entry has been served from cache
}

const (
	// defaultCacheTTL is 15 minutes — long enough to cover a typical subtask's
	// execution window, short enough that if data genuinely changes (unlikely
	// within a pentest subtask), the stale entry expires naturally.
	defaultCacheTTL = 15 * time.Minute

	// maxCacheEntries caps memory usage. 200 entries × 32KB max = ~6.4MB worst case.
	// In practice, most cached outputs are <1KB (token values, schema fragments).
	maxCacheEntries = 200

	// maxCachedOutputSize prevents caching huge outputs that would bloat memory.
	// Full GraphQL introspection responses can be 50KB+; we only cache outputs
	// that are small enough to be useful as inline context.
	maxCachedOutputSize = 32 * 1024 // 32 KB
)

// NewTerminalOutputCache creates a new cache scoped to a single subtask execution.
// Callers should create one per performAgentChain invocation and let it be
// garbage collected when the chain completes.
func NewTerminalOutputCache() *TerminalOutputCache {
	return &TerminalOutputCache{
		entries: make(map[string]*cacheEntry),
		ttl:     defaultCacheTTL,
	}
}

// --- Cacheable/Non-cacheable Pattern Definitions ---
//
// Design principle: whitelist idempotent commands, blacklist everything with
// side effects or time-dependent output. When in doubt, don't cache.

// cacheablePatterns are command patterns whose output is idempotent within a
// subtask. These commands produce the same output unless the underlying data
// changes (which we handle via TTL expiration).
//
// Categories:
// 1. Token/credential file reads — the agent extracts these once, they don't change
// 2. GraphQL introspection — schema is static during a pentest
// 3. Static file reads in /tmp and /work — captured data, not live state
// 4. JWT decode/base64 operations — deterministic transforms
// 5. jq parsing of stored files — deterministic
var cacheablePatterns = []*regexp.Regexp{
	// --- Token/credential file reads ---
	// The #1 offender: agent reads token files 15-20x per subtask.
	// Tightened from original `/tmp/.*token` to require the keyword as a
	// meaningful path component (after / _ - .) to avoid false positives like
	// `cat /tmp/monkey_data.txt` matching "key".
	regexp.MustCompile(`(?i)cat\s+/tmp/\S*(?:^|[/_.-])token(?:[s._-]|\s|$)`),
	regexp.MustCompile(`(?i)cat\s+/tmp/\S*(?:^|[/_.-])jwt(?:[._-]|\s|$)`),
	regexp.MustCompile(`(?i)cat\s+/tmp/\S*(?:^|[/_.-])cookie(?:[s._-]|\s|$)`),
	regexp.MustCompile(`(?i)cat\s+/tmp/\S*(?:^|[/_.-])auth(?:[._-]|\s|$)`),
	regexp.MustCompile(`(?i)cat\s+/tmp/\S*(?:^|[/_.-])access(?:[._-]|\s|$)`),
	regexp.MustCompile(`(?i)cat\s+/tmp/\S*(?:^|[/_.-])session(?:[._-]|\s|$)`),
	regexp.MustCompile(`(?i)cat\s+/tmp/\S*(?:^|[/_.-])cred(?:[s._-]|\s|$)`),
	regexp.MustCompile(`(?i)cat\s+/tmp/\S*(?:^|[/_.-])secret(?:[._-]|\s|$)`),
	regexp.MustCompile(`(?i)cat\s+/tmp/\S*(?:^|[/_.-])(?:api[_-]?)?key(?:[._-]|\s|$)`),

	// --- GraphQL introspection queries ---
	// The #2 offender: agent introspects schema 4x per subtask.
	// Introspection is idempotent — schema doesn't change during a pentest.
	regexp.MustCompile(`(?i)__schema\s*\{`),
	regexp.MustCompile(`(?i)__type\s*\(`),
	regexp.MustCompile(`(?i)IntrospectionQuery`),

	// --- Static file reads ---
	// Simple `cat /tmp/something` or `cat /work/something.ext`
	// These are files the agent wrote earlier; re-reading is pure waste.
	regexp.MustCompile(`(?i)^\s*cat\s+/tmp/\S+\s*$`),
	regexp.MustCompile(`(?i)^\s*cat\s+/work/\S+\.(txt|json|csv|xml|html|md)\s*$`),

	// --- JWT decode / base64 decode ---
	// Deterministic transforms — same input always produces same output.
	regexp.MustCompile(`(?i)jwt.*decode`),
	regexp.MustCompile(`(?i)base64\s+(-d|--decode)`),

	// --- jq parsing of stored files ---
	// Deterministic: same jq filter + same file = same output.
	regexp.MustCompile(`(?i)jq\s+.*\s+/tmp/\S+`),
	regexp.MustCompile(`(?i)jq\s+.*\s+/work/\S+`),
}

// nonCacheablePatterns override cacheablePatterns. Commands matching these are
// NEVER cached because their output changes between invocations or they have
// side effects on remote targets.
//
// The check order is:
// 1. Special case: curl with introspection → cacheable (handled separately)
// 2. nonCacheablePatterns → reject
// 3. cacheablePatterns → accept
// 4. Default → reject (conservative: if we don't know, don't cache)
var nonCacheablePatterns = []*regexp.Regexp{
	// --- Network operations to live targets ---
	// curl/wget responses change over time; nmap results vary with network state.
	// NOTE: curl to GraphQL with __schema is handled as a special case BEFORE
	// these patterns are checked, so introspection caching still works.
	regexp.MustCompile(`(?i)^\s*(curl|wget)\s`),
	regexp.MustCompile(`(?i)^\s*(nmap|nc|netcat|masscan)\s`),

	// --- Offensive tools ---
	// These have side effects and non-deterministic output. Never cache.
	regexp.MustCompile(`(?i)(nuclei|ffuf|gobuster|dirb|nikto|sqlmap|hydra|wfuzz)\b`),

	// --- Process/system state ---
	// Output changes between invocations.
	regexp.MustCompile(`(?i)^\s*(ps|top|date|uptime|free|df|w|id|whoami)\b`),

	// --- Random/time-dependent ---
	regexp.MustCompile(`(?i)\$RANDOM|/dev/urandom|mktemp`),

	// --- Commands with output redirects (side effects) ---
	// A command that writes to a file isn't a pure read.
	regexp.MustCompile(`[>]\s*/`),

	// --- ls is non-deterministic (directory contents can change) ---
	regexp.MustCompile(`(?i)^\s*ls\b`),
}

// isCacheable determines if a terminal command's output should be cached.
// Uses a two-pass approach:
//   1. Special case: curl with GraphQL introspection → YES (idempotent)
//   2. Check nonCacheablePatterns → NO (fast rejection for side-effect commands)
//   3. Check cacheablePatterns → YES (whitelisted idempotent patterns)
//   4. Default → NO (conservative: unknown commands are not cached)
//
// This ensures we never accidentally cache offensive tool output or live
// network requests, while still catching the high-frequency token reads
// and schema introspections that burn 40% of the tool call budget.
func (tc *TerminalOutputCache) isCacheable(command string) bool {
	command = strings.TrimSpace(command)
	if command == "" {
		return false
	}

	// Special case: curl with GraphQL introspection IS cacheable.
	// This must be checked BEFORE nonCacheablePatterns because bare `curl`
	// matches the non-cacheable network operations pattern.
	// Introspection is idempotent — schema doesn't change during a pentest.
	cmdLower := strings.ToLower(command)
	if strings.Contains(cmdLower, "curl") &&
		(strings.Contains(command, "__schema") ||
			strings.Contains(command, "__type") ||
			strings.Contains(cmdLower, "introspectionquery")) {
		return true
	}

	// Check non-cacheable patterns (fast rejection path).
	for _, pattern := range nonCacheablePatterns {
		if pattern.MatchString(command) {
			return false
		}
	}

	// Check cacheable patterns (whitelist).
	for _, pattern := range cacheablePatterns {
		if pattern.MatchString(command) {
			return true
		}
	}

	// Default: don't cache unknown commands. Better to re-execute than serve
	// stale/wrong output. The whitelist grows as we identify more patterns.
	return false
}

// fingerprintWhitespaceRe is pre-compiled for use in fingerprint().
// Avoids recompiling on every call (hot path: every terminal command execution).
var fingerprintWhitespaceRe = regexp.MustCompile(`\s+`)

// fingerprint generates a stable 128-bit hash for a terminal command.
// Normalization: trim leading/trailing whitespace, collapse internal whitespace
// to single spaces. This makes "cat  /tmp/token.txt" and "cat /tmp/token.txt"
// hash to the same fingerprint.
//
// We intentionally do NOT lowercase the command because file paths and
// arguments can be case-sensitive on Linux.
func fingerprint(command string) string {
	normalized := strings.TrimSpace(command)
	normalized = fingerprintWhitespaceRe.ReplaceAllString(normalized, " ")

	hash := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(hash[:16]) // 128-bit — collision probability negligible for <200 entries
}

// Check looks up a command in the cache. Returns (cached_output, hit).
// If hit is true, the caller should return cached_output to the LLM instead
// of executing the command. The output is prefixed with a CACHED notice that
// explicitly tells the LLM to stop re-extracting and move on.
//
// Thread-safe: holds tc.mu for the duration of the lookup.
func (tc *TerminalOutputCache) Check(command string) (string, bool) {
	if !tc.isCacheable(command) {
		return "", false
	}

	fp := fingerprint(command)

	tc.mu.Lock()
	defer tc.mu.Unlock()

	entry, exists := tc.entries[fp]
	if !exists {
		tc.misses++
		return "", false
	}

	// Check TTL — expired entries are evicted on access.
	if time.Since(entry.timestamp) > tc.ttl {
		delete(tc.entries, fp)
		tc.misses++
		return "", false
	}

	tc.hits++
	entry.hitCount++

	agoSeconds := int(time.Since(entry.timestamp).Seconds())
	// The prefix is crafted to be maximally directive to the LLM:
	// 1. States the data is cached (explains why it appeared without execution)
	// 2. Shows timing (so the LLM can assess freshness)
	// 3. Explicitly tells the LLM NOT to re-run the command
	// 4. Tells the LLM to proceed to the next action
	prefix := fmt.Sprintf(
		"[CACHED — identical command ran %ds ago, returning saved output (hit #%d). "+
			"You already have this data. DO NOT re-run this command. "+
			"Use the output below and proceed to your next action.]\n\n",
		agoSeconds, entry.hitCount,
	)

	return prefix + entry.output, true
}

// Store records a command's output in the cache. Only stores if the command
// matches cacheable patterns and the output isn't too large.
//
// Called after successful terminal command execution. The cache automatically
// handles deduplication via fingerprinting — storing the same command twice
// just updates the timestamp and resets the hit count.
//
// Thread-safe: holds tc.mu for the duration of the store.
func (tc *TerminalOutputCache) Store(command, output string) {
	if !tc.isCacheable(command) {
		return
	}

	// Don't cache empty outputs — they're usually errors or no-ops.
	if strings.TrimSpace(output) == "" {
		return
	}

	// Don't cache huge outputs — they'd bloat memory and likely contain
	// more data than the LLM can usefully process from a cached prefix.
	if len(output) > maxCachedOutputSize {
		return
	}

	fp := fingerprint(command)

	tc.mu.Lock()
	defer tc.mu.Unlock()

	// Evict oldest entries if at capacity.
	if len(tc.entries) >= maxCacheEntries {
		tc.evictOldest()
	}

	tc.entries[fp] = &cacheEntry{
		command:   command,
		output:    output,
		timestamp: time.Now(),
		hitCount:  0,
	}
}

// evictOldest removes the oldest cache entry by timestamp.
// Must be called with tc.mu held.
func (tc *TerminalOutputCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time
	first := true

	for key, entry := range tc.entries {
		if first || entry.timestamp.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.timestamp
			first = false
		}
	}

	if oldestKey != "" {
		delete(tc.entries, oldestKey)
	}
}

// Stats returns cache hit/miss statistics for logging and diagnostics.
// Thread-safe.
func (tc *TerminalOutputCache) Stats() (hits, misses int) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return tc.hits, tc.misses
}

// Reset clears all cache entries and resets statistics.
// Used when the subtask scope changes (though typically a new cache
// is created per subtask rather than resetting an existing one).
// Thread-safe.
func (tc *TerminalOutputCache) Reset() {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.entries = make(map[string]*cacheEntry)
	tc.hits = 0
	tc.misses = 0
}
