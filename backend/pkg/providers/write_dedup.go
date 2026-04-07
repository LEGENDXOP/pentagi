package providers

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// WriteDeduplicator prevents agents from writing identical content to the same
// file repeatedly. This fixes Issue-9 where agents wrote the same FINDINGS.md
// content 7 times because the LLM re-generated the write command in a loop.
//
// Design decisions per VERDICT:
//   - Only blocks exact-content duplicates (same path + same content hash)
//   - Appends (>>) are always allowed (content grows, so hash changes)
//   - Writes with genuinely different content are always allowed
//   - TTL expiry allows re-writes after a reasonable period
//   - Never blocks the FIRST write to any path
//
// IMPORTANT: helpers.go exempts all writes from the repeat detector (isWriteOperation).
// This WriteDeduplicator is complementary — it catches cases where the agent
// writes IDENTICAL content to the same file multiple times.
type WriteDeduplicator struct {
	mu      sync.Mutex
	entries map[string]*writeEntry // key: normalized file path
	ttl     time.Duration
}

type writeEntry struct {
	contentHash string
	writeCount  int
	lastWrite   time.Time
}

const (
	defaultWriteDedupTTL = 5 * time.Minute
	maxWriteDedupEntries = 50
)

// NewWriteDeduplicator creates a new write deduplicator scoped to a subtask.
func NewWriteDeduplicator() *WriteDeduplicator {
	return &WriteDeduplicator{
		entries: make(map[string]*writeEntry),
		ttl:     defaultWriteDedupTTL,
	}
}

// CheckWrite examines a tool call and returns a block message if the write is
// a duplicate (same file path + same content hash). Returns ("", false) if the
// write should proceed normally.
//
// Only examines "file" tool with update_file action and "terminal" tool with
// heredoc/redirect patterns that target known output files.
func (wd *WriteDeduplicator) CheckWrite(funcName, funcArgs string) (string, bool) {
	path, contentHash := wd.extractWriteInfo(funcName, funcArgs)
	if path == "" || contentHash == "" {
		return "", false // Not a detectable write, or can't extract content
	}

	wd.mu.Lock()
	defer wd.mu.Unlock()

	entry, exists := wd.entries[path]
	if !exists {
		// First write to this path — always allow
		wd.entries[path] = &writeEntry{
			contentHash: contentHash,
			writeCount:  1,
			lastWrite:   time.Now(),
		}
		wd.evictIfNeeded()
		return "", false
	}

	// TTL expired — allow the write (content may be stale)
	if time.Since(entry.lastWrite) > wd.ttl {
		entry.contentHash = contentHash
		entry.writeCount = 1
		entry.lastWrite = time.Now()
		return "", false
	}

	// Content actually changed — allow the write
	if entry.contentHash != contentHash {
		entry.contentHash = contentHash
		entry.writeCount++
		entry.lastWrite = time.Now()
		return "", false
	}

	// Same content to same path within TTL — BLOCK
	entry.writeCount++
	logrus.WithFields(logrus.Fields{
		"path":         path,
		"write_count":  entry.writeCount,
		"content_hash": contentHash[:12],
	}).Warn("Issue-9: write dedup blocked identical file write")

	return fmt.Sprintf(
		"⚠️ DUPLICATE WRITE BLOCKED: You already wrote identical content to '%s' "+
			"(%d times in the last %s). The file already contains this exact content. "+
			"DO NOT write to this file again unless you have NEW content. "+
			"Proceed to your next action.",
		path, entry.writeCount, wd.ttl.String(),
	), true
}

// extractWriteInfo extracts the target path and a content hash from a write operation.
// Returns ("", "") if the call is not a write or content can't be extracted.
func (wd *WriteDeduplicator) extractWriteInfo(funcName, funcArgs string) (string, string) {
	switch funcName {
	case "file":
		var args struct {
			Action  string `json:"action"`
			Path    string `json:"path"`
			Content string `json:"content"`
		}
		if err := json.Unmarshal([]byte(funcArgs), &args); err != nil {
			return "", ""
		}
		if args.Action != "update_file" || args.Path == "" || args.Content == "" {
			return "", ""
		}
		hash := sha256.Sum256([]byte(args.Content))
		return writeNormalizePath(args.Path), fmt.Sprintf("%x", hash[:8])

	case "terminal":
		var termArgs struct {
			Input string `json:"input"`
		}
		if err := json.Unmarshal([]byte(funcArgs), &termArgs); err != nil {
			return "", ""
		}
		input := termArgs.Input
		if input == "" {
			return "", ""
		}

		// Skip append (>>) — appends produce different content each time
		if strings.Contains(input, ">>") && !strings.Contains(input, "<<") {
			return "", "" // Append — always allow (but << is heredoc, not append)
		}

		path := extractTerminalWriteTarget(input)
		if path == "" {
			return "", ""
		}

		// For heredoc writes, extract the content body
		content := extractHeredocBodyForDedup(input)
		if content == "" {
			// For redirect writes (echo "x" > file), hash the whole command
			content = input
		}
		hash := sha256.Sum256([]byte(content))
		return writeNormalizePath(path), fmt.Sprintf("%x", hash[:8])
	}

	return "", ""
}

// writeRedirectRegex matches output redirects to file paths.
var writeRedirectRegex = regexp.MustCompile(`[^<]>\s*(\S+)`)

// writeTeeRegex matches tee commands (not tee -a which is append).
var writeTeeRegex = regexp.MustCompile(`\btee\s+(?:-[^a]\S*\s+)?(/?\S+)`)

// extractTerminalWriteTarget extracts the target file path from a terminal write command.
func extractTerminalWriteTarget(input string) string {
	// Try redirect pattern: ... > /path/file
	if matches := writeRedirectRegex.FindStringSubmatch(input); len(matches) >= 2 {
		path := strings.TrimRight(matches[1], ";|&'\"")
		if path != "" && path != "/dev/null" {
			return path
		}
	}

	// Try tee pattern: ... | tee /path/file
	if matches := writeTeeRegex.FindStringSubmatch(input); len(matches) >= 2 {
		return strings.TrimRight(matches[1], ";|&'\"")
	}

	return ""
}

// extractHeredocBodyForDedup extracts content between heredoc delimiters.
// FIX Issue-9 per VERDICT: Handles single-quoted, double-quoted, and unquoted delimiters.
func extractHeredocBodyForDedup(input string) string {
	idx := strings.Index(input, "<<")
	if idx == -1 {
		return ""
	}

	rest := input[idx+2:]
	// Skip optional - (for <<-)
	rest = strings.TrimLeft(rest, "- \t")

	// Find the delimiter — strip surrounding quotes (single, double, or none)
	delimEnd := strings.IndexAny(rest, " \t\n\r")
	if delimEnd == -1 {
		return ""
	}
	delimiter := strings.Trim(rest[:delimEnd], `'"`)
	if delimiter == "" {
		return ""
	}

	// Find content between first newline after delimiter declaration and closing delimiter
	contentStart := strings.IndexByte(rest, '\n')
	if contentStart == -1 {
		return ""
	}
	content := rest[contentStart+1:]

	// Find closing delimiter on its own line
	endIdx := strings.Index(content, "\n"+delimiter)
	if endIdx == -1 {
		// Check if delimiter is at the end
		trimmed := strings.TrimSpace(content)
		if strings.HasSuffix(trimmed, delimiter) {
			endIdx = strings.LastIndex(content, delimiter)
			if endIdx > 0 {
				return content[:endIdx]
			}
		}
		return ""
	}

	return content[:endIdx]
}

// writeNormalizePath normalizes a file path for consistent dedup keying.
func writeNormalizePath(path string) string {
	path = strings.TrimSpace(path)
	if !strings.HasPrefix(path, "/") {
		path = "/work/" + path
	}
	return strings.ToLower(path)
}

func (wd *WriteDeduplicator) evictIfNeeded() {
	if len(wd.entries) <= maxWriteDedupEntries {
		return
	}
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, v := range wd.entries {
		if first || v.lastWrite.Before(oldestTime) {
			oldestKey = k
			oldestTime = v.lastWrite
			first = false
		}
	}
	if oldestKey != "" {
		delete(wd.entries, oldestKey)
	}
}
