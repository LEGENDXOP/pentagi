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

// FileReadCache provides semantic file-read deduplication.
//
// The Problem (Flow 24):
// The agent read summary.md 39 times, FINDINGS.md 27 times, STATE.json 19 times.
// 85 redundant reads out of 204 terminal calls (42% waste).
// The existing TerminalOutputCache uses exact fingerprinting, but the agent
// uses slightly different commands each time:
//   - `cat /work/recon/summary.md`
//   - `cat /work/recon/summary.md | head -80`
//   - `head -200 /work/recon/summary.md`
// All three read the same file but bypass exact-match dedup.
//
// The Fix:
// Extract the target filepath from read commands, track read timestamps +
// content hashes per file. If the same file was read recently and hasn't
// been modified (by a write command), return cached content with a directive
// to use existing data and move on.
//
// Scope: Per-subtask (same as TerminalOutputCache). Created alongside it.
type FileReadCache struct {
	mu      sync.Mutex
	entries map[string]*fileReadEntry // keyed by normalized filepath
	ttl     time.Duration
	hits    int
	misses  int
}

type fileReadEntry struct {
	filepath    string    // normalized absolute path
	content     string    // cached output from the read command
	contentHash string    // sha256 of content (for staleness detection)
	readAt      time.Time // when the file was last read
	modifiedAt  time.Time // when we last saw a write to this file (zero = never)
	hitCount    int       // how many times cache served this file
}

const (
	// fileReadCacheTTL controls how long a cached file read is valid.
	// 5 minutes is conservative — most re-reads happen within 1-2 minutes.
	fileReadCacheTTL = 5 * time.Minute

	// maxFileReadEntries caps memory usage. 100 unique files is more than
	// enough for any single subtask.
	maxFileReadEntries = 100

	// maxFileReadCacheSize prevents caching huge file contents.
	maxFileReadCacheSize = 64 * 1024 // 64 KB
)

// --- Read Command Detection ---
//
// These patterns detect terminal commands that are primarily file reads,
// regardless of the specific invocation style. We extract the filepath
// from any of these patterns.

// fileReadPatterns match commands whose primary purpose is reading a file.
// Each pattern has a named capture group "path" for the filepath.
var fileReadPatterns = []*regexp.Regexp{
	// cat variants
	regexp.MustCompile(`^\s*cat\s+(?P<path>/\S+)`),
	// head variants (with or without -n/-NUM)
	regexp.MustCompile(`^\s*head\s+(?:-\d+\s+|-n\s*\d+\s+)?(?P<path>/\S+)`),
	// tail variants
	regexp.MustCompile(`^\s*tail\s+(?:-\d+\s+|-n\s*\d+\s+)?(?P<path>/\S+)`),
	// less/more
	regexp.MustCompile(`^\s*(?:less|more)\s+(?P<path>/\S+)`),
	// bat (cat alternative)
	regexp.MustCompile(`^\s*bat\s+(?:--\S+\s+)*(?P<path>/\S+)`),
	// Piped cat: `cat /path | head -80` or `cat /path | grep foo`
	regexp.MustCompile(`^\s*cat\s+(?P<path>/\S+)\s*\|`),
	// python/python3 reading a file: `python3 -c "print(open('/path').read())"`
	regexp.MustCompile(`open\(\s*['"](?P<path>/[^'"]+)['"]\s*\)`),
	// grep reading a specific file (not recursive)
	regexp.MustCompile(`^\s*grep\s+(?:-[a-zA-Z]+\s+)*(?:['"][^'"]+['"]\s+|[^\s-]\S*\s+)(?P<path>/\S+)\s*$`),
	// wc (word/line count on a file)
	regexp.MustCompile(`^\s*wc\s+(?:-[lwc]+\s+)?(?P<path>/\S+)`),
}

// fileWritePatterns detect commands that modify files, used to invalidate cache.
var fileWritePatterns = []*regexp.Regexp{
	// Output redirect: echo/printf/cat > /path or >> /path
	regexp.MustCompile(`(?:>|>>)\s*(?P<path>/\S+)`),
	// tee
	regexp.MustCompile(`\|\s*tee\s+(?:-a\s+)?(?P<path>/\S+)`),
	// cp/mv destination
	regexp.MustCompile(`^\s*(?:cp|mv)\s+\S+\s+(?P<path>/\S+)`),
	// sed in-place
	regexp.MustCompile(`^\s*sed\s+-i\s+.*\s+(?P<path>/\S+)`),
	// python writing: open('/path', 'w')
	regexp.MustCompile(`open\(\s*['"](?P<path>/[^'"]+)['"]\s*,\s*['"][wa]['"]`),
	// echo/printf to file
	regexp.MustCompile(`^\s*(?:echo|printf)\s+.*>\s*(?P<path>/\S+)`),
}

// NewFileReadCache creates a cache scoped to a single subtask execution.
func NewFileReadCache() *FileReadCache {
	return &FileReadCache{
		entries: make(map[string]*fileReadEntry),
		ttl:     fileReadCacheTTL,
	}
}

// extractReadPath tries to extract a filepath from a read command.
// Returns (filepath, true) if the command is a file read, ("", false) otherwise.
func extractReadPath(command string) (string, bool) {
	cmd := strings.TrimSpace(command)
	if cmd == "" {
		return "", false
	}

	for _, pattern := range fileReadPatterns {
		match := pattern.FindStringSubmatch(cmd)
		if match == nil {
			continue
		}
		// Find the "path" named group
		for i, name := range pattern.SubexpNames() {
			if name == "path" && i < len(match) && match[i] != "" {
				return normalizePath(match[i]), true
			}
		}
	}
	return "", false
}

// extractWritePath tries to extract a filepath from a write command.
// Returns (filepath, true) if the command writes to a file.
func extractWritePath(command string) (string, bool) {
	cmd := strings.TrimSpace(command)
	if cmd == "" {
		return "", false
	}

	for _, pattern := range fileWritePatterns {
		match := pattern.FindStringSubmatch(cmd)
		if match == nil {
			continue
		}
		for i, name := range pattern.SubexpNames() {
			if name == "path" && i < len(match) && match[i] != "" {
				return normalizePath(match[i]), true
			}
		}
	}
	return "", false
}

// normalizePath cleans up a filepath for consistent cache keying.
// Removes trailing pipes, semicolons, quotes, and whitespace.
func normalizePath(path string) string {
	path = strings.TrimSpace(path)
	// Remove trailing pipe chars, semicolons, quotes that might be captured
	path = strings.TrimRight(path, "|;&'\"")
	path = strings.TrimSpace(path)
	return path
}

// contentFingerprint generates a hash of file content for staleness detection.
func contentFingerprint(content string) string {
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:16])
}

// CheckFileRead checks if a command is a file read and if we have cached content.
// Returns (cached_output, is_hit).
//
// If hit: returns cached content with a directive prefix telling the LLM
// to use this data and move on.
//
// If miss: returns ("", false) — caller should execute the command normally.
func (fc *FileReadCache) CheckFileRead(command string) (string, bool) {
	filepath, isRead := extractReadPath(command)
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

	// Check TTL
	if time.Since(entry.readAt) > fc.ttl {
		delete(fc.entries, filepath)
		fc.misses++
		return "", false
	}

	// Check if file was modified after last read
	if !entry.modifiedAt.IsZero() && entry.modifiedAt.After(entry.readAt) {
		// File was written to since we cached it — invalidate
		delete(fc.entries, filepath)
		fc.misses++
		return "", false
	}

	fc.hits++
	entry.hitCount++

	agoSeconds := int(time.Since(entry.readAt).Seconds())
	prefix := fmt.Sprintf(
		"[CACHED FILE READ — %s was read %ds ago and has not been modified since. "+
			"Returning cached content (hit #%d). "+
			"You already have this data. DO NOT re-read this file. "+
			"Proceed to your NEXT action.]\n\n",
		filepath, agoSeconds, entry.hitCount,
	)

	return prefix + entry.content, true
}

// StoreFileRead records a file read command's output in the cache.
// Called after successful terminal command execution.
func (fc *FileReadCache) StoreFileRead(command, output string) {
	filepath, isRead := extractReadPath(command)
	if !isRead {
		return
	}

	// Don't cache empty outputs
	if strings.TrimSpace(output) == "" {
		return
	}

	// Don't cache huge outputs
	if len(output) > maxFileReadCacheSize {
		return
	}

	fc.mu.Lock()
	defer fc.mu.Unlock()

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
// Called for every terminal command — checks if it's a write operation.
func (fc *FileReadCache) RecordFileWrite(command string) {
	filepath, isWrite := extractWritePath(command)
	if !isWrite {
		return
	}

	fc.mu.Lock()
	defer fc.mu.Unlock()

	entry, exists := fc.entries[filepath]
	if exists {
		entry.modifiedAt = time.Now()
	}
}

// evictOldest removes the oldest entry by read timestamp.
// Must be called with fc.mu held.
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
