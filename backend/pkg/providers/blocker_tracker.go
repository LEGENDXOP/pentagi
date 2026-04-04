package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// BlockerType categorizes a detected blocker.
type BlockerType string

const (
	BlockerTypeWAF             BlockerType = "waf_block"
	BlockerTypeAuthGate        BlockerType = "auth_gate"
	BlockerTypeVerification    BlockerType = "verification_required"
	BlockerTypeCAPTCHA         BlockerType = "captcha"
	BlockerTypeRateLimit       BlockerType = "rate_limit"
	BlockerTypeEndpointBlocked BlockerType = "endpoint_blocked"
	BlockerTypeKYC             BlockerType = "kyc_required"
	BlockerTypeGeoBlock        BlockerType = "geo_block"
)

// BlockerSeverity indicates how badly a blocker impacts the test plan.
type BlockerSeverity string

const (
	// BlockerSeverityCritical means the entire auth/attack surface is unusable.
	BlockerSeverityCritical BlockerSeverity = "critical"
	// BlockerSeverityHigh means a major category of attacks is blocked.
	BlockerSeverityHigh BlockerSeverity = "high"
	// BlockerSeverityMedium means specific endpoints are blocked but alternatives exist.
	BlockerSeverityMedium BlockerSeverity = "medium"
)

// Blocker represents a single detected blocker that prevents certain attack paths.
type Blocker struct {
	Type        BlockerType     `json:"type"`
	Severity    BlockerSeverity `json:"severity"`
	Description string          `json:"description"`
	// AffectedCategories lists the attack categories (from P0-P3) that this blocker impacts.
	// Example: ["auth_acquisition", "account_takeover", "business_logic"]
	AffectedCategories []string `json:"affected_categories,omitempty"`
	// DetectedAt records when this blocker was first observed.
	DetectedAt string `json:"detected_at"`
	// DetectedBy records which subtask discovered this blocker.
	DetectedBy string `json:"detected_by,omitempty"`
	// Evidence contains raw evidence (error messages, HTTP status codes, etc.)
	Evidence string `json:"evidence,omitempty"`
}

// BlockerTrackerJSON is the serialized form stored in ExecutionState.
type BlockerTrackerJSON struct {
	Blockers []Blocker `json:"blockers"`
}

// BlockerTracker tracks blockers discovered during a flow's execution.
// It is flow-scoped and goroutine-safe.
type BlockerTracker struct {
	mu       sync.RWMutex
	blockers []Blocker
}

// NewBlockerTracker creates a new empty blocker tracker.
func NewBlockerTracker() *BlockerTracker {
	return &BlockerTracker{
		blockers: make([]Blocker, 0),
	}
}

// AddBlocker registers a new blocker. Deduplicates by type + description.
func (bt *BlockerTracker) AddBlocker(b Blocker) {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	// Deduplicate
	for _, existing := range bt.blockers {
		if existing.Type == b.Type && existing.Description == b.Description {
			return
		}
	}

	if b.DetectedAt == "" {
		b.DetectedAt = time.Now().UTC().Format(time.RFC3339)
	}
	bt.blockers = append(bt.blockers, b)
}

// GetBlockers returns all registered blockers.
func (bt *BlockerTracker) GetBlockers() []Blocker {
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	result := make([]Blocker, len(bt.blockers))
	copy(result, bt.blockers)
	return result
}

// HasBlockers returns true if any blockers have been registered.
func (bt *BlockerTracker) HasBlockers() bool {
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	return len(bt.blockers) > 0
}

// HasCriticalBlockers returns true if any CRITICAL-severity blockers exist.
func (bt *BlockerTracker) HasCriticalBlockers() bool {
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	for _, b := range bt.blockers {
		if b.Severity == BlockerSeverityCritical {
			return true
		}
	}
	return false
}

// IsCategoryBlocked checks if a specific attack category is blocked.
func (bt *BlockerTracker) IsCategoryBlocked(category string) bool {
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	lower := strings.ToLower(category)
	for _, b := range bt.blockers {
		for _, cat := range b.AffectedCategories {
			if strings.ToLower(cat) == lower {
				return true
			}
		}
	}
	return false
}

// GetBlockedCategories returns all unique blocked attack categories.
func (bt *BlockerTracker) GetBlockedCategories() []string {
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	seen := make(map[string]bool)
	var result []string
	for _, b := range bt.blockers {
		for _, cat := range b.AffectedCategories {
			if !seen[cat] {
				seen[cat] = true
				result = append(result, cat)
			}
		}
	}
	return result
}

// ToJSON serializes the tracker state for persistence.
func (bt *BlockerTracker) ToJSON() (json.RawMessage, error) {
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	data := BlockerTrackerJSON{Blockers: bt.blockers}
	return json.Marshal(data)
}

// RestoreFromJSON restores blocker state from a persisted JSON blob.
// It merges restored blockers with any already-tracked blockers using
// AddBlocker, which handles deduplication. This is critical when multiple
// sibling subtasks each discover different blockers.
func (bt *BlockerTracker) RestoreFromJSON(raw json.RawMessage) {
	if raw == nil {
		return
	}
	var data BlockerTrackerJSON
	if err := json.Unmarshal(raw, &data); err != nil {
		return
	}
	// Merge instead of overwrite: call AddBlocker for each restored blocker
	// so that blockers from multiple siblings are preserved and deduplicated.
	for _, b := range data.Blockers {
		bt.AddBlocker(b)
	}
}

// AnalyzeToolOutput scans a tool call response for blocker indicators and
// auto-registers any detected blockers. This runs passively on every tool result.
func (bt *BlockerTracker) AnalyzeToolOutput(toolName, toolArgs, response, subtaskTitle string) {
	if response == "" {
		return
	}

	// First, check for explicit [BLOCKER: xxx] tags from agent output.
	bt.extractExplicitBlockerTags(response, subtaskTitle)

	lower := strings.ToLower(response)

	// WAF / firewall blocks
	if containsAny(lower, []string{
		"datadome", "web application firewall",
		"blocked by security", "request blocked by waf",
		"access denied by firewall",
	}) {
		bt.AddBlocker(Blocker{
			Type:        BlockerTypeWAF,
			Severity:    BlockerSeverityCritical,
			Description: "WAF (likely DataDome) blocking all requests — auth-dependent testing impossible",
			AffectedCategories: []string{
				"auth_acquisition", "account_takeover", "business_logic",
				"payment_manipulation", "race_conditions", "idor",
			},
			DetectedBy: subtaskTitle,
			Evidence:   truncateString(response, 512),
		})
	}

	// PayPal / external verification gates
	if containsAny(lower, []string{
		"paypal verification", "verify your paypal",
		"paypal account required", "connect your paypal",
		"link your paypal",
	}) {
		bt.AddBlocker(Blocker{
			Type:        BlockerTypeVerification,
			Severity:    BlockerSeverityHigh,
			Description: "PayPal account verification required — financial endpoints gated",
			AffectedCategories: []string{
				"business_logic", "payment_manipulation", "race_conditions",
			},
			DetectedBy: subtaskTitle,
			Evidence:   truncateString(response, 512),
		})
	}

	// KYC gates
	if containsAny(lower, []string{
		"kyc required", "identity verification required",
		"verify your identity", "kyc verification",
		"document verification required",
	}) {
		bt.AddBlocker(Blocker{
			Type:        BlockerTypeKYC,
			Severity:    BlockerSeverityHigh,
			Description: "KYC/identity verification required — financial features gated behind document upload",
			AffectedCategories: []string{
				"business_logic", "payment_manipulation", "kyc_bypass",
			},
			DetectedBy: subtaskTitle,
			Evidence:   truncateString(response, 512),
		})
	}

	// Phone verification gates
	if containsAny(lower, []string{
		"phone verification required", "sms verification",
		"enter the code sent to your phone",
		"verify your phone number",
	}) {
		bt.AddBlocker(Blocker{
			Type:        BlockerTypeVerification,
			Severity:    BlockerSeverityHigh,
			Description: "Phone/SMS verification required — account creation gated",
			AffectedCategories: []string{
				"auth_acquisition", "account_takeover",
			},
			DetectedBy: subtaskTitle,
			Evidence:   truncateString(response, 512),
		})
	}

	// CAPTCHA blocks
	if containsAny(lower, []string{
		"captcha required", "recaptcha", "hcaptcha",
		"solve the captcha", "captcha challenge",
		"turnstile",
	}) && containsAny(lower, []string{
		"blocked", "denied", "failed", "cannot",
		"unable", "required",
	}) {
		bt.AddBlocker(Blocker{
			Type:        BlockerTypeCAPTCHA,
			Severity:    BlockerSeverityMedium,
			Description: "CAPTCHA required on critical endpoints",
			AffectedCategories: []string{
				"auth_acquisition",
			},
			DetectedBy: subtaskTitle,
			Evidence:   truncateString(response, 512),
		})
	}

	// Rate limiting (severe)
	if containsAny(lower, []string{
		"rate limit exceeded", "too many requests",
		"429 too many", "rate limited",
	}) {
		// Only critical if it's on auth endpoints
		if containsAny(lower, []string{
			"login", "register", "signup", "auth",
			"password", "account",
		}) {
			bt.AddBlocker(Blocker{
				Type:        BlockerTypeRateLimit,
				Severity:    BlockerSeverityHigh,
				Description: "Severe rate limiting on authentication endpoints",
				AffectedCategories: []string{
					"auth_acquisition",
				},
				DetectedBy: subtaskTitle,
				Evidence:   truncateString(response, 512),
			})
		}
	}

	// Broad 403 pattern — many consecutive 403s suggest everything is blocked
	count403 := strings.Count(lower, "403 forbidden")
	count403 += strings.Count(lower, "403 access denied")
	count403 += strings.Count(lower, "status: 403")
	if count403 >= 3 {
		bt.AddBlocker(Blocker{
			Type:        BlockerTypeEndpointBlocked,
			Severity:    BlockerSeverityHigh,
			Description: fmt.Sprintf("Multiple endpoints returning 403 Forbidden (%d occurrences) — likely WAF or IP block", count403),
			AffectedCategories: []string{
				"auth_acquisition", "sensitive_data_harvest",
			},
			DetectedBy: subtaskTitle,
			Evidence:   truncateString(response, 512),
		})
	}
}

// FormatBlockersForPrompt produces a formatted block suitable for injection
// into the refiner or generator prompts.
func (bt *BlockerTracker) FormatBlockersForPrompt() string {
	bt.mu.RLock()
	defer bt.mu.RUnlock()

	if len(bt.blockers) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("<detected_blockers>\n")
	sb.WriteString("🚫 BLOCKERS DETECTED — The following issues prevent certain attack paths:\n\n")

	for i, b := range bt.blockers {
		sb.WriteString(fmt.Sprintf("Blocker #%d: [%s] (Severity: %s)\n", i+1, b.Type, b.Severity))
		sb.WriteString(fmt.Sprintf("  Description: %s\n", b.Description))
		if len(b.AffectedCategories) > 0 {
			sb.WriteString(fmt.Sprintf("  Blocked categories: %s\n", strings.Join(b.AffectedCategories, ", ")))
		}
		if b.DetectedBy != "" {
			sb.WriteString(fmt.Sprintf("  Detected by: %s\n", b.DetectedBy))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("⚠️ MANDATORY RESPONSE TO BLOCKERS:\n")
	sb.WriteString("1. REMOVE all planned subtasks that depend on blocked categories\n")
	sb.WriteString("2. DO NOT retry blocked paths — the blocker is environmental, not a bug\n")
	sb.WriteString("3. PIVOT to attack categories that are NOT affected by these blockers\n")
	sb.WriteString("4. If auth is completely blocked, focus on: unauthenticated endpoints, data harvest, SSRF, information disclosure\n")
	sb.WriteString("5. If financial endpoints are gated, focus on: auth bypass, data exposure, injection testing, API abuse\n")
	sb.WriteString("6. Report blockers as findings in the final report (they ARE security-relevant observations)\n")
	sb.WriteString("</detected_blockers>\n")

	return sb.String()
}

// FormatBlockersForSubtask produces a shorter block suitable for injection
// into the primary agent's system prompt during subtask execution.
func (bt *BlockerTracker) FormatBlockersForSubtask() string {
	bt.mu.RLock()
	defer bt.mu.RUnlock()

	if len(bt.blockers) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("[KNOWN BLOCKERS — DO NOT ATTEMPT BLOCKED PATHS]\n")
	for _, b := range bt.blockers {
		sb.WriteString(fmt.Sprintf("- %s (%s): %s", b.Severity, b.Type, b.Description))
		if len(b.AffectedCategories) > 0 {
			sb.WriteString(fmt.Sprintf(" → blocked: %s", strings.Join(b.AffectedCategories, ", ")))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// extractExplicitBlockerTags parses [BLOCKER: xxx] tags from agent output.
// These are explicitly reported by the agent following the blocker protocol.
func (bt *BlockerTracker) extractExplicitBlockerTags(response, subtaskTitle string) {
	lines := strings.Split(response, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "[BLOCKER:") {
			continue
		}

		// Extract the type and description from [BLOCKER: TYPE] description
		idx := strings.Index(line, "[BLOCKER:")
		rest := line[idx+9:] // skip "[BLOCKER:"
		closeIdx := strings.Index(rest, "]")
		if closeIdx < 0 {
			continue
		}

		blockerTypeStr := strings.TrimSpace(rest[:closeIdx])
		description := strings.TrimSpace(rest[closeIdx+1:])

		var bType BlockerType
		var severity BlockerSeverity
		var affected []string

		switch strings.ToUpper(blockerTypeStr) {
		case "WAF":
			bType = BlockerTypeWAF
			severity = BlockerSeverityCritical
			affected = []string{"auth_acquisition", "account_takeover", "business_logic", "payment_manipulation"}
		case "VERIFICATION":
			bType = BlockerTypeVerification
			severity = BlockerSeverityHigh
			affected = []string{"business_logic", "payment_manipulation"}
		case "CAPTCHA":
			bType = BlockerTypeCAPTCHA
			severity = BlockerSeverityMedium
			affected = []string{"auth_acquisition"}
		case "RATE_LIMIT":
			bType = BlockerTypeRateLimit
			severity = BlockerSeverityHigh
			affected = []string{"auth_acquisition"}
		case "KYC":
			bType = BlockerTypeKYC
			severity = BlockerSeverityHigh
			affected = []string{"kyc_bypass", "payment_manipulation"}
		case "IP_BLOCK":
			bType = BlockerTypeEndpointBlocked
			severity = BlockerSeverityCritical
			affected = []string{"auth_acquisition", "sensitive_data_harvest", "ssrf"}
		default:
			bType = BlockerTypeEndpointBlocked
			severity = BlockerSeverityMedium
			affected = []string{}
		}

		if description == "" {
			description = fmt.Sprintf("%s blocker detected", blockerTypeStr)
		}

		bt.AddBlocker(Blocker{
			Type:               bType,
			Severity:           severity,
			Description:        description,
			AffectedCategories: affected,
			DetectedBy:         subtaskTitle,
		})
	}
}

// containsAny returns true if s contains any of the given substrings.
func containsAny(s string, substrings []string) bool {
	for _, sub := range substrings {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// ─── Context propagation ─────────────────────────────────────────────────────

type blockerTrackerKey struct{}

// WithBlockerTracker attaches a BlockerTracker to the context.
func WithBlockerTracker(ctx context.Context, bt *BlockerTracker) context.Context {
	return context.WithValue(ctx, blockerTrackerKey{}, bt)
}

// GetBlockerTracker retrieves the BlockerTracker from context.
func GetBlockerTracker(ctx context.Context) *BlockerTracker {
	if bt, ok := ctx.Value(blockerTrackerKey{}).(*BlockerTracker); ok {
		return bt
	}
	return nil
}
