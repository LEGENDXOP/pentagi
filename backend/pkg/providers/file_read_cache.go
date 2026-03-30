package providers

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FileReadCache v2 — Semantic file-read deduplication with terminal interception.
//
// Changes from v1:
//   - Relative path support: `cat STATE.json` resolves to `/work/STATE.json`
//   - Broader regex patterns: jq, relative cat/head/tail, compound commands
//   - Escalating cache hit responses: soft → warning → hard block
//   - InterceptTerminalRead(): dedicated method for terminal tool pre-execution check
//   - Configurable thresholds via env vars
//   - Cross-format dedup: all path variants normalize to the same cache key
//
// Configuration (env vars):
//   - FILE_READ_CACHE_TTL_MINUTES: cache entry TTL in minutes (default: 8)
//   - TERMINAL_READ_CACHE_THRESHOLD: reads before soft interception (default: 3)
//   - TERMINAL_READ_CACHE_HARD_BLOCK: reads before hard block (default: 6)
//   - FILE_READ_CACHE_WORKDIR: working directory for relative path resolution (default: /work)
type FileReadCache struct {
	mu      sync.Mutex
	entries map[string]*fileReadEntry // keyed by normalized filepath
	ttl     time.Duration
	hits    int
	misses  int

	// v2: configurable thresholds
	softThreshold int    // reads before cache starts returning warnings (default: 3)
	hardThreshold int    // reads before cache blocks execution entirely (default: 6)
	workDir       string // default working directory for resolving relative paths
}

type fileReadEntry struct {
	filepath    string
	content     string
	contentHash string
	readAt      time.Time
	modifiedAt  time.Time
	hitCount    int
}

const (
	defaultFileReadCacheTTL  = 8 * time.Minute
	maxFileReadEntries       = 100
	maxFileReadCacheSize     = 64 * 1024 // 64 KB
	defaultSoftThreshold     = 3
	defaultHardThreshold     = 6
	defaultWorkDir           = "/work"
)

// ─── v2 Read Command Detection ──────────────────────────────────────────────
//
// v2 patterns support BOTH absolute and relative paths.
// Each pattern has a named capture group "path" for the filepath.

var fileReadPatternsV2 = []*regexp.Regexp{
	// cat with absolute or relative path
	regexp.MustCompile(`^\s*cat\s+(?P<path>\S+)`),
	// head with flags, absolute or relative
	regexp.MustCompile(`^\s*head\s+(?:-\d+\s+|-n\s*\d+\s+)?(?P<path>\S+)`),
	// tail with flags, absolute or relative
	regexp.MustCompile(`^\s*tail\s+(?:-\d+\s+|-n\s*\d+\s+|-f\s+)?(?P<path>\S+)`),
	// less/more
	regexp.MustCompile(`^\s*(?:less|more)\s+(?P<path>\S+)`),
	// bat (cat alternative)
	regexp.MustCompile(`^\s*bat\s+(?:--\S+\s+)*(?P<path>\S+)`),
	// Piped cat: `cat /path | head -80` or `cat file.txt | grep foo`
	regexp.MustCompile(`^\s*cat\s+(?P<path>\S+)\s*\|`),
	// jq with file argument: `jq '.key' STATE.json` or `jq . /work/STATE.json`
	regexp.MustCompile(`^\s*jq\s+(?:-[a-zA-Z]+\s+)*(?:'[^']*'|"[^"]*"|[.\w]+)\s+(?P<path>\S+)`),
	// python/python3 reading a file: `python3 -c "print(open('/path').read())"`
	regexp.MustCompile(`open\(\s*['"](?P<path>[^'"]+)['"]\s*\)`),
	// grep reading a specific file (not recursive)
	regexp.MustCompile(`^\s*grep\s+(?:-[a-zA-Z]+\s+)*(?:'[^']*'|"[^"]*"|[^\s-]\S*)\s+(?P<path>\S+)\s*$`),
	// wc on a file
	regexp.MustCompile(`^\s*wc\s+(?:-[lwc]+\s+)?(?P<path>\S+)`),
}

var fileWritePatternsV2 = []*regexp.Regexp{
	// Output redirect
	regexp.MustCompile(`(?:>|>>)\s*(?P<path>\S+)`),
	// tee
	regexp.MustCompile(`\|\s*tee\s+(?:-a\s+)?(?P<path>\S+)`),
	// cp/mv destination
	regexp.MustCompile(`^\s*(?:cp|mv)\s+\S+\s+(?P<path>\S+)`),
	// sed in-place
	regexp.MustCompile(`^\s*sed\s+-i\s+.*\s+(?P<path>\S+)`),
	// python writing
	regexp.MustCompile(`open\(\s*['"](?P<path>[^'"]+)['"]\s*,\s*['"][wa]['"]`),
	// echo/printf to file
	regexp.MustCompile(`^\s*(?:echo|printf)\s+.*>\s*(?P<path>\S+)`),
}

// NewFileReadCache creates a cache scoped to a single subtask execution.
func NewFileReadCache() *FileReadCache {
	ttl := defaultFileReadCacheTTL
	if v := os.Getenv("FILE_READ_CACHE_TTL_MINUTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			ttl = time.Duration(n) * time.Minute
		}
	}

	soft := defaultSoftThreshold
	if v := os.Getenv("TERMINAL_READ_CACHE_THRESHOLD"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			soft = n
		}
	}

	hard := defaultHardThreshold
	if v := os.Getenv("TERMINAL_READ_CACHE_HARD_BLOCK"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 2 {
			hard = n
		}
	}

	wd := defaultWorkDir
	if v := os.Getenv("FILE_READ_CACHE_WORKDIR"); v != "" {
		wd = v
	}

	return &FileReadCache{
		entries:       make(map[string]*fileReadEntry),
		ttl:           ttl,
		softThreshold: soft,
		hardThreshold: hard,
		workDir:       wd,
	}
}

// ─── Path Extraction ────────────────────────────────────────────────────────

// extractReadPathV2 extracts a filepath from a read command.
// v2: supports both absolute and relative paths.
// Returns (normalized_filepath, true) if the command is a file read.
func (fc *FileReadCache) extractReadPath(command string) (string, bool) {
	cmd := strings.TrimSpace(command)
	if cmd == "" {
		return "", false
	}

	// v2: For compound commands (cmd1 && cmd2), only check the primary command
	// unless the primary is a write/offensive command.
	primaryCmd := extractPrimaryCommandForCache(cmd)

	for _, pattern := range fileReadPatternsV2 {
		match := pattern.FindStringSubmatch(primaryCmd)
		if match == nil {
			continue
		}
		for i, name := range pattern.SubexpNames() {
			if name == "path" && i < len(match) && match[i] != "" {
				path := normalizePathV2(match[i])
				// v2: Resolve relative paths using workDir
				resolved := fc.resolvePath(path)
				return resolved, true
			}
		}
	}

	// v2: Also try the full command for compound patterns like python open()
	if primaryCmd != cmd {
		for _, pattern := range fileReadPatternsV2 {
			match := pattern.FindStringSubmatch(cmd)
			if match == nil {
				continue
			}
			for i, name := range pattern.SubexpNames() {
				if name == "path" && i < len(match) && match[i] != "" {
					path := normalizePathV2(match[i])
					resolved := fc.resolvePath(path)
					return resolved, true
				}
			}
		}
	}

	return "", false
}

// extractWritePath extracts a filepath from a write command.
func (fc *FileReadCache) extractWritePath(command string) (string, bool) {
	cmd := strings.TrimSpace(command)
	if cmd == "" {
		return "", false
	}

	for _, pattern := range fileWritePatternsV2 {
		match := pattern.FindStringSubmatch(cmd)
		if match == nil {
			continue
		}
		for i, name := range pattern.SubexpNames() {
			if name == "path" && i < len(match) && match[i] != "" {
				path := normalizePathV2(match[i])
				resolved := fc.resolvePath(path)
				return resolved, true
			}
		}
	}
	return "", false
}

// resolvePath resolves a path to an absolute path.
// v2: Relative paths are resolved against fc.workDir.
func (fc *FileReadCache) resolvePath(path string) string {
	if path == "" {
		return ""
	}
	// Already absolute
	if strings.HasPrefix(path, "/") {
		return path
	}
	// Strip ./ prefix
	path = strings.TrimPrefix(path, "./")
	// Resolve relative to workDir
	return fc.workDir + "/" + path
}

// normalizePathV2 cleans up a filepath for consistent cache keying.
// v2: Also strips surrounding quotes and trailing 2>/dev/null patterns.
func normalizePathV2(path string) string {
	path = strings.TrimSpace(path)
	// Remove trailing pipe chars, semicolons, quotes, redirects
	path = strings.TrimRight(path, "|;&'\"")
	// Remove trailing 2>/dev/null or similar
	if idx := strings.Index(path, " 2>"); idx > 0 {
		path = path[:idx]
	}
	path = strings.TrimSpace(path)
	// Remove surrounding quotes
	if len(path) >= 2 {
		if (path[0] == '\'' && path[len(path)-1] == '\'') ||
			(path[0] == '"' && path[len(path)-1] == '"') {
			path = path[1 : len(path)-1]
		}
	}
	return path
}

// extractPrimaryCommandForCache returns the first command segment (before pipes,
// &&, ||, ;). Similar to extractPrimaryCommand in helpers.go but doesn't skip
// env var prefixes (those are handled by the regex patterns).
func extractPrimaryCommandForCache(input string) string {
	// Split on pipe (but not ||)
	for i := 0; i < len(input); i++ {
		if input[i] == '|' {
			if i+1 < len(input) && input[i+1] == '|' {
				return strings.TrimSpace(input[:i])
			}
			return strings.TrimSpace(input[:i])
		}
	}
	// Split on && and ;
	for _, sep := range []string{"&&", ";"} {
		if idx := strings.Index(input, sep); idx > 0 {
			return strings.TrimSpace(input[:idx])
		}
	}
	return strings.TrimSpace(input)
}

// contentFingerprint generates a hash of file content for staleness detection.
func contentFingerprint(content string) string {
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:16])
}

// ─── Core Cache Operations ──────────────────────────────────────────────────

// CheckFileRead checks if a command is a file read and if we have cached content.
// Returns (cached_output, is_hit).
//
// v2: Escalating responses based on hit count:
//   - Hit 1-2: Soft prefix (informational)
//   - Hit 3-4: Warning (the agent is looping)
//   - Hit 5+: Hard block message (do not re-read)
func (fc *FileReadCache) CheckFileRead(command string) (string, bool) {
	filepath, isRead := fc.extractReadPath(command)
	if !isRead {
		return "", false
	}

	fc.mu.Lock()
	defer fc.mu.Unlock()

	entry, exists := fc.entries[filepath]
	if !exists {
		fc.misses++
		return "", false
	}

	// TTL check
	if time.Since(entry.readAt) > fc.ttl {
		delete(fc.entries, filepath)
		fc.misses++
		return "", false
	}

	// Modified-after-read check
	if !entry.modifiedAt.IsZero() && entry.modifiedAt.After(entry.readAt) {
		delete(fc.entries, filepath)
		fc.misses++
		return "", false
	}

	fc.hits++
	entry.hitCount++

	// v2: Escalating response
	prefix := fc.formatCacheHitPrefix(filepath, entry)
	return prefix + entry.content, true
}

// InterceptTerminalRead is the v2 pre-execution interceptor for terminal commands.
// Called BEFORE the terminal command is executed. Returns:
//   - (cached_output, true) if the read should be intercepted (don't execute)
//   - ("", false) if the command should proceed normally
//
// This method is specifically designed for the performer's terminal execution path.
// It provides a stronger interception than CheckFileRead: after hardThreshold hits,
// it returns a BLOCK message and the cached content, signaling that the command
// should NOT be executed at all.
//
// Unlike CheckFileRead (which returns cached content on any hit), this method
// only intercepts after softThreshold hits — allowing the first few reads to
// execute normally so the cache can be populated with fresh content.
func (fc *FileReadCache) InterceptTerminalRead(command string) (string, bool) {
	filepath, isRead := fc.extractReadPath(command)
	if !isRead {
		return "", false
	}

	fc.mu.Lock()
	defer fc.mu.Unlock()

	entry, exists := fc.entries[filepath]
	if !exists {
		fc.misses++
		return "", false
	}

	// TTL check
	if time.Since(entry.readAt) > fc.ttl {
		delete(fc.entries, filepath)
		fc.misses++
		return "", false
	}

	// Modified check — allow re-read of genuinely changed files
	if !entry.modifiedAt.IsZero() && entry.modifiedAt.After(entry.readAt) {
		delete(fc.entries, filepath)
		fc.misses++
		return "", false
	}

	// v2: Only intercept after threshold hits
	entry.hitCount++ // v8: Count every read attempt, even below threshold
	if entry.hitCount < fc.softThreshold {
		// Below threshold: don't intercept, let it execute
		// (hitCount will be incremented by StoreFileRead on re-store,
		// or by CheckFileRead if called from the standard path)
		return "", false
	}

	fc.hits++
	entry.hitCount++

	prefix := fc.formatCacheHitPrefix(filepath, entry)
	return prefix + entry.content, true
}

// formatCacheHitPrefix generates an escalating prefix for cached file reads.
// v2: escalates based on hit count.
func (fc *FileReadCache) formatCacheHitPrefix(filepath string, entry *fileReadEntry) string {
	agoSeconds := int(time.Since(entry.readAt).Seconds())

	switch {
	case entry.hitCount >= fc.hardThreshold:
		return fmt.Sprintf(
			"🛑 [FILE READ BLOCKED — %s has been read %d times in %ds]\n"+
				"This file has NOT changed. Content is cached from your first read.\n"+
				"STOP re-reading this file. You already have all the data.\n"+
				"Your NEXT action must be: execute an offensive tool, write a report, or call result.\n\n",
			filepath, entry.hitCount, agoSeconds,
		)
	case entry.hitCount >= fc.softThreshold:
		return fmt.Sprintf(
			"⚠️ [CACHED FILE — WARNING: %s read %d times in %ds, content unchanged]\n"+
				"You are re-reading a file you already have. This is wasting tool calls.\n"+
				"DO NOT read this file again. Use the data below and PROCEED to your next action.\n\n",
			filepath, entry.hitCount, agoSeconds,
		)
	default:
		return fmt.Sprintf(
			"[CACHED FILE READ — %s was read %ds ago, content unchanged (hit #%d)]\n"+
				"Returning cached content. Proceed to your NEXT action.\n\n",
			filepath, agoSeconds, entry.hitCount,
		)
	}
}

// StoreFileRead records a file read command's output in the cache.
func (fc *FileReadCache) StoreFileRead(command, output string) {
	filepath, isRead := fc.extractReadPath(command)
	if !isRead {
		return
	}

	if strings.TrimSpace(output) == "" {
		return
	}

	if len(output) > maxFileReadCacheSize {
		return
	}

	fc.mu.Lock()
	defer fc.mu.Unlock()

	// v2: If entry already exists with same content hash, just update timestamp
	// but preserve hitCount (so escalation continues)
	if existing, exists := fc.entries[filepath]; exists {
		newHash := contentFingerprint(output)
		if existing.contentHash == newHash {
			existing.readAt = time.Now()
			// v8: hitCount now incremented in InterceptTerminalRead — skip here to avoid double-counting
			return
		}
		// Content actually changed — reset the entry
	}

	// Evict if at capacity
	if len(fc.entries) >= maxFileReadEntries {
		fc.evictOldest()
	}

	fc.entries[filepath] = &fileReadEntry{
		filepath:    filepath,
		content:     output,
		contentHash: contentFingerprint(output),
		readAt:      time.Now(),
		hitCount:    0,
	}
}

// RecordFileWrite marks a file as modified, invalidating any cached read.
// v2: uses the same improved path extraction as reads.
func (fc *FileReadCache) RecordFileWrite(command string) {
	writePath, isWrite := fc.extractWritePath(command)
	if !isWrite {
		return
	}

	fc.mu.Lock()
	defer fc.mu.Unlock()

	// Direct match
	if entry, exists := fc.entries[writePath]; exists {
		entry.modifiedAt = time.Now()
	}

	// Cross-path invalidation by basename
	writeBase := writePath
	if idx := strings.LastIndex(writePath, "/"); idx >= 0 {
		writeBase = writePath[idx+1:]
	}
	writeBaseLower := strings.ToLower(writeBase)
	if writeBaseLower != "" {
		for key, entry := range fc.entries {
			cachedBase := key
			if idx := strings.LastIndex(key, "/"); idx >= 0 {
				cachedBase = key[idx+1:]
			}
			if strings.ToLower(cachedBase) == writeBaseLower {
				entry.modifiedAt = time.Now()
			}
		}
	}
}

// RecordSystemFileWrite explicitly invalidates cache for a file written by
// the system (e.g., the performer writing STATE.json/RESUME.md periodically).
// v2: Ensures system writes properly invalidate the cache so the agent can
// re-read once after a genuine system write.
func (fc *FileReadCache) RecordSystemFileWrite(filename string) {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	baseLower := strings.ToLower(filename)
	if idx := strings.LastIndex(baseLower, "/"); idx >= 0 {
		baseLower = baseLower[idx+1:]
	}

	for key, entry := range fc.entries {
		cachedBase := key
		if idx := strings.LastIndex(key, "/"); idx >= 0 {
			cachedBase = key[idx+1:]
		}
		if strings.ToLower(cachedBase) == baseLower {
			entry.modifiedAt = time.Now()
		}
	}
}

// evictOldest removes the oldest entry by read timestamp.
func (fc *FileReadCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time
	first := true

	for key, entry := range fc.entries {
		if first || entry.readAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.readAt
			first = false
		}
	}

	if oldestKey != "" {
		delete(fc.entries, oldestKey)
	}
}

// Stats returns cache statistics.
func (fc *FileReadCache) Stats() (hits, misses int) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return fc.hits, fc.misses
}

// Reset clears all entries.
func (fc *FileReadCache) Reset() {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.entries = make(map[string]*fileReadEntry)
	fc.hits = 0
	fc.misses = 0
}

// ─── Backward Compatibility ─────────────────────────────────────────────────
// These package-level functions maintain backward compatibility with v1 callers
// that used the old extractReadPath/extractWritePath as free functions.

// extractReadPath is the backward-compatible free function.
// v2: Creates a temporary cache instance to use the improved path extraction.
// For performance-critical paths, use the method on FileReadCache directly.
func extractReadPath(command string) (string, bool) {
	fc := &FileReadCache{workDir: defaultWorkDir}
	return fc.extractReadPath(command)
}

// extractWritePath is the backward-compatible free function.
func extractWritePath(command string) (string, bool) {
	fc := &FileReadCache{workDir: defaultWorkDir}
	return fc.extractWritePath(command)
}
