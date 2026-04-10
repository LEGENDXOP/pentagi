package providers

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// knownDataTracker tracks key data artifacts extracted during a subtask
// (JWT tokens, GraphQL endpoints, schema availability, credentials) and
// formats them for injection into the system prompt.
//
// Why This Exists:
// Chain summarization strips literal values from tool results. After 3
// summarizations, the JWT token extracted at tool_call #5 is gone — the
// summarizer condenses it to "extracted an access token" without the actual
// value. The LLM genuinely cannot see the token anymore, so it rationally
// decides to re-extract it. This cycle repeats 15-20x per subtask.
//
// The Fix:
// This tracker scans terminal outputs for recognizable data patterns and
// stores them. The stored data is injected into the system prompt (which is
// NEVER summarized), ensuring the LLM always has access to previously
// extracted artifacts regardless of how many summarization cycles occur.
//
// Scope: Per-subtask (created as a local variable in performAgentChain).
type knownDataTracker struct {
	mu    sync.Mutex
	items map[string]string // label → value (e.g., "jwt_token" → "eyJ...")
}

// newKnownDataTracker creates a new empty tracker.
func newKnownDataTracker() *knownDataTracker {
	return &knownDataTracker{
		items: make(map[string]string),
	}
}

// jwtPattern matches JWT-like tokens: base64url header (eyJ...) followed by two
// dot-separated segments. The minimum length check (>50 chars) avoids false
// positives on short base64 strings.
var jwtPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)

// urlPattern matches HTTP/HTTPS URLs in command strings.
var knownDataURLPattern = regexp.MustCompile(`https?://[^\s'"<>]+`)

// Extract scans a terminal command and its output for recognizable data patterns
// and stores them for later injection into the system prompt.
//
// Detected patterns:
// 1. JWT tokens (eyJ... format) — from token extraction commands
// 2. GraphQL schema availability — from introspection commands
// 3. GraphQL endpoints — from commands containing "graphql"
// 4. Access tokens (non-JWT) — from token/auth file reads
// 5. API keys — from commands referencing keys/secrets
//
// Thread-safe: holds kd.mu for the duration of the scan.
func (kd *knownDataTracker) Extract(command, output string) {
	kd.mu.Lock()
	defer kd.mu.Unlock()

	cmdLower := strings.ToLower(command)
	outputTrimmed := strings.TrimSpace(output)

	// --- JWT token detection ---
	// Priority: scan output for JWT pattern regardless of command.
	// Token files can have various names; the JWT format is the reliable signal.
	if match := jwtPattern.FindString(outputTrimmed); match != "" {
		kd.items["jwt_token"] = match
	}

	// --- Token-related command detection ---
	// Even if output isn't JWT-formatted, capture short token values from
	// token-specific commands (API keys, session tokens, bearer tokens).
	tokenCmdKeywords := []string{"token", "jwt", "cookie", "auth", "access", "session", "bearer"}
	isTokenCmd := false
	for _, keyword := range tokenCmdKeywords {
		if strings.Contains(cmdLower, keyword) {
			isTokenCmd = true
			break
		}
	}
	if isTokenCmd && len(outputTrimmed) > 10 && len(outputTrimmed) < 2000 {
		// Store the raw output as an access token if it looks like a single value
		// (no newlines, no JSON structure — just a token string).
		lines := strings.Split(outputTrimmed, "\n")
		if len(lines) == 1 && !strings.HasPrefix(outputTrimmed, "{") {
			// Only store if we don't already have a JWT — JWT takes priority.
			if _, hasJWT := kd.items["jwt_token"]; !hasJWT || !strings.HasPrefix(outputTrimmed, "eyJ") {
				kd.items["access_token"] = outputTrimmed
			}
		}
	}

	// --- GraphQL schema introspection detection ---
	if strings.Contains(cmdLower, "__schema") ||
		strings.Contains(cmdLower, "__type") ||
		strings.Contains(cmdLower, "introspection") {
		if len(outputTrimmed) > 100 {
			kd.items["graphql_schema_available"] = "yes (already introspected — full schema in tool history)"
		}
	}

	// --- GraphQL endpoint detection ---
	if strings.Contains(cmdLower, "graphql") {
		for _, endpoint := range knownDataURLPattern.FindAllString(command, -1) {
			if strings.Contains(strings.ToLower(endpoint), "graphql") {
				kd.items["graphql_endpoint"] = endpoint
			}
		}
	}

	// --- API key / secret detection ---
	secretKeywords := []string{"api_key", "apikey", "secret", "password"}
	for _, keyword := range secretKeywords {
		if strings.Contains(cmdLower, keyword) {
			lines := strings.Split(outputTrimmed, "\n")
			if len(lines) == 1 && len(outputTrimmed) > 5 && len(outputTrimmed) < 500 {
				kd.items[keyword] = outputTrimmed
			}
		}
	}
}

// FormatForInjection returns a formatted XML block suitable for injection into
// the system prompt. The block uses <already_extracted_data> tags to clearly
// delineate agent-extracted data from the rest of the prompt.
//
// Returns "" if nothing has been tracked yet (avoids injecting empty blocks).
//
// The format is designed to:
// 1. Be clearly distinguishable from other prompt sections
// 2. Use imperative language ("DO NOT re-extract") to minimize re-extraction
// 3. Truncate long values to avoid prompt bloat
// 4. Survive any number of summarization cycles (lives in system prompt)
//
// Thread-safe: holds kd.mu for the duration of formatting.
func (kd *knownDataTracker) FormatForInjection() string {
	kd.mu.Lock()
	defer kd.mu.Unlock()

	if len(kd.items) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("<already_extracted_data>\n")
	sb.WriteString("The following data has ALREADY been extracted in this subtask. DO NOT re-extract:\n")

	for label, value := range kd.items {
		displayValue := value
		// Truncate long values to keep the system prompt manageable.
		// 200 chars is enough for the LLM to recognize the value and use it.
		if len(displayValue) > 200 {
			displayValue = displayValue[:200] + "..."
		}
		sb.WriteString(fmt.Sprintf("  - %s: %s\n", label, displayValue))
	}

	sb.WriteString("If you need any of the above values, use them directly — do NOT run commands to re-extract them.\n")
	sb.WriteString("</already_extracted_data>")
	return sb.String()
}

// HasData returns true if any data has been tracked.
// Thread-safe.
func (kd *knownDataTracker) HasData() bool {
	kd.mu.Lock()
	defer kd.mu.Unlock()
	return len(kd.items) > 0
}

// Get returns the value for a tracked label, or "" if not found.
// Thread-safe.
func (kd *knownDataTracker) Get(label string) string {
	kd.mu.Lock()
	defer kd.mu.Unlock()
	return kd.items[label]
}

// RestoreItem adds an item from a sibling's persisted state.
// Does NOT overwrite existing items (current subtask's data takes priority).
// Thread-safe.
func (kd *knownDataTracker) RestoreItem(label, value string) {
	kd.mu.Lock()
	defer kd.mu.Unlock()
	if _, exists := kd.items[label]; !exists {
		kd.items[label] = value
	}
}

// Items returns a copy of all tracked items for serialization.
// Thread-safe.
func (kd *knownDataTracker) Items() map[string]string {
	kd.mu.Lock()
	defer kd.mu.Unlock()
	copy := make(map[string]string, len(kd.items))
	for k, v := range kd.items {
		copy[k] = v
	}
	return copy
}

// injectKnownDataBlock inserts or replaces the <already_extracted_data> block
// in the system prompt. If a block already exists, it's replaced with the new
// version. If not, the block is inserted after </execution_metrics> (or
// appended to the end as a fallback).
//
// This function is called during the system prompt refresh cycle in
// performAgentChain, ensuring the LLM always has up-to-date extracted data
// regardless of chain summarization state.
func injectKnownDataBlock(systemPrompt, knownDataBlock string) string {
	startTag := "<already_extracted_data>"
	endTag := "</already_extracted_data>"

	startIdx := strings.Index(systemPrompt, startTag)
	endIdx := strings.Index(systemPrompt, endTag)

	// Replace existing block if present.
	if startIdx >= 0 && endIdx > startIdx {
		return systemPrompt[:startIdx] + knownDataBlock + systemPrompt[endIdx+len(endTag):]
	}

	// Insert after </execution_metrics> if present — keeps related metadata together.
	metricsEndTag := "</execution_metrics>"
	if insertPoint := strings.Index(systemPrompt, metricsEndTag); insertPoint >= 0 {
		insertAt := insertPoint + len(metricsEndTag)
		return systemPrompt[:insertAt] + "\n" + knownDataBlock + systemPrompt[insertAt:]
	}

	// Insert after </time_remaining> if present.
	timeEndTag := "</time_remaining>"
	if insertPoint := strings.Index(systemPrompt, timeEndTag); insertPoint >= 0 {
		insertAt := insertPoint + len(timeEndTag)
		return systemPrompt[:insertAt] + "\n" + knownDataBlock + systemPrompt[insertAt:]
	}

	// Fallback: append to end of system prompt.
	return systemPrompt + "\n" + knownDataBlock
}
