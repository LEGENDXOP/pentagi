package providers

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// WAFProduct identifies a specific WAF product with associated bypass techniques.
type WAFProduct struct {
	Name            string   `json:"name"`
	Confidence      float64  `json:"confidence"`
	HeaderPatterns  []string `json:"header_patterns"`
	BodyPatterns    []string `json:"body_patterns"`
	BypassTechniques []string `json:"bypass_techniques"`
}

// WAFAssessment represents the overall WAF detection result for a target.
type WAFAssessment struct {
	Detected       bool        `json:"detected"`
	Product        *WAFProduct `json:"product,omitempty"`
	Confidence     float64     `json:"confidence"`
	BlockCount     int         `json:"block_count"`
	TotalResponses int         `json:"total_responses"`
	BlockedRoutes  []string    `json:"blocked_routes,omitempty"`
}

// WAFDetector performs passive WAF detection from HTTP response analysis.
// It is flow-scoped and goroutine-safe.
type WAFDetector struct {
	mu sync.RWMutex

	// Per-target assessments.
	assessments map[string]*WAFAssessment

	// Global state across all targets.
	totalAnalyzed int
	blockStreak   int // Consecutive blocks across any target.
}

// NewWAFDetector creates a new WAF detector instance.
func NewWAFDetector() *WAFDetector {
	return &WAFDetector{
		assessments: make(map[string]*WAFAssessment),
	}
}

// knownWAFProducts contains fingerprints for identifying specific WAF products.
var knownWAFProducts = []WAFProduct{
	{
		Name: "DataDome",
		HeaderPatterns: []string{
			"x-datadome", "datadome", "set-cookie: datadome",
			"x-dd-b", "x-dd-type",
		},
		BodyPatterns: []string{
			"datadome", "dd.js", "geo.captcha-delivery.com",
			"interstitial", "blocked", "robot detection",
			"captcha-delivery", "dd_check",
		},
		BypassTechniques: []string{
			"DataDome has aggressive bot detection — standard curl/requests will be blocked immediately",
			"Use a REAL browser (Playwright/Puppeteer with stealth plugins) for ALL requests",
			"DataDome fingerprints TLS — use a browser TLS stack, not a library",
			"Residential proxy rotation may help, but DataDome also checks browser fingerprint",
			"If DataDome blocks auth endpoints, ALL auth-dependent testing is impossible — pivot to unauth vectors",
			"Focus on: unauthenticated endpoints, data exposure (.git/.env), SSRF, information disclosure",
			"DO NOT waste time trying to bypass DataDome on auth — it learns and escalates blocks",
		},
	},
	{
		Name: "Cloudflare",
		HeaderPatterns: []string{
			"cf-ray", "cf-cache-status", "server: cloudflare",
			"cf-mitigated", "__cfduid", "cf-request-id",
		},
		BodyPatterns: []string{
			"cloudflare", "ray id", "cf-browser-verification",
			"attention required", "cloudflare to restrict access",
		},
		BypassTechniques: []string{
			"Try finding origin IP behind Cloudflare (check DNS history, subdomains, SPF records)",
			"Use Unicode normalization bypass: replace ' with ʼ (U+02BC) in injection payloads",
			"Chunk transfer encoding: split payloads across chunked HTTP body",
			"Case variation in SQL keywords: SeLeCt, uNiOn, etc.",
			"HTTP/2 header manipulation: duplicate headers, pseudo-header injection",
			"Comment-based SQL bypass: /*!50000UNION*//*!50000SELECT*/",
			"Double URL encoding: %2527 instead of %27",
		},
	},
	{
		Name: "ModSecurity",
		HeaderPatterns: []string{
			"modsecurity", "mod_security", "server: apache",
		},
		BodyPatterns: []string{
			"modsecurity", "mod_security", "not acceptable",
			"request denied", "rule id",
		},
		BypassTechniques: []string{
			"Check paranoia level (PL1 is default, very permissive)",
			"Use comment-based bypass: /*!UNION*/ /*!SELECT*/",
			"HPP (HTTP Parameter Pollution): ?id=1&id=2' UNION SELECT",
			"Tab/newline as whitespace: UNION%09SELECT, UNION%0ASELECT",
			"Nested encoding: double-encode special chars",
			"Use || (OR) instead of UNION for data extraction",
			"JSON content-type bypass: POST with application/json body",
		},
	},
	{
		Name: "AWS WAF",
		HeaderPatterns: []string{
			"x-amzn-requestid", "x-amz-cf-id", "x-amzn-trace-id",
		},
		BodyPatterns: []string{
			"aws", "waf", "request blocked", "automated request",
			"amazon", "access denied",
		},
		BypassTechniques: []string{
			"AWS WAF has limited regex depth — use deeply nested payloads",
			"Unicode normalization: AWS WAF may not normalize before matching",
			"Chunked transfer encoding with variable chunk sizes",
			"Header case manipulation (x-forwarded-for variants)",
			"Path normalization bypass: /./api/../api/endpoint",
			"Content-Type switching: application/x-www-form-urlencoded → multipart/form-data",
		},
	},
	{
		Name: "Imperva/Incapsula",
		HeaderPatterns: []string{
			"x-cdn", "x-iinfo", "incap_ses", "visid_incap",
			"set-cookie: incap_ses", "set-cookie: visid_incap",
		},
		BodyPatterns: []string{
			"incapsula", "imperva", "access denied", "incident id",
			"powered by incapsula", "request unsuccessful",
		},
		BypassTechniques: []string{
			"Imperva has strong bot detection — reduce request rate significantly",
			"Use browser automation (Puppeteer/Playwright) for JS challenge bypass",
			"Try alternative content encoding: gzip, deflate, br",
			"Obfuscate payloads with HTML entities: &#x27; instead of '",
			"IP rotation through residential proxies may bypass rate-based rules",
			"Time-based attacks with longer sleep() values to avoid detection",
		},
	},
	{
		Name: "Sucuri",
		HeaderPatterns: []string{
			"x-sucuri-id", "x-sucuri-cache", "server: sucuri",
		},
		BodyPatterns: []string{
			"sucuri", "access denied - sucuri", "sucuri website firewall",
			"cloudproxy", "your request was blocked",
		},
		BypassTechniques: []string{
			"Find origin IP: check MX records, old DNS history, subdomains",
			"Sucuri primarily blocks known attack signatures — use custom payloads",
			"URL encoding variations: mix single/double/hex encoding",
			"Null byte injection: %00 in path components",
			"Request method switching: if POST is blocked, try PUT/PATCH",
		},
	},
	{
		Name: "Akamai",
		HeaderPatterns: []string{
			"x-akamai-transformed", "akamai-grn", "x-akamai-session-info",
			"server: akamaighost",
		},
		BodyPatterns: []string{
			"akamai", "access denied", "reference#",
			"your access to this site has been limited",
		},
		BypassTechniques: []string{
			"Akamai has advanced bot detection — use headless browsers with stealth",
			"Slow and low: reduce request frequency significantly",
			"Path traversal with encoded sequences: %252e%252e%252f",
			"HTTP method override: X-HTTP-Method-Override header",
			"Custom User-Agent matching legitimate browser fingerprints",
		},
	},
}

// wafBlockIndicators are strings that indicate a WAF block in HTTP responses.
var wafBlockIndicators = []string{
	"403 forbidden",
	"access denied",
	"request blocked",
	"blocked by",
	"waf",
	"web application firewall",
	"security policy",
	"not acceptable",
	"request rejected",
	"captcha",
	"challenge",
	"rate limit",
	"too many requests",
	"429",
}

// AnalyzeToolResult analyzes a tool call response for WAF indicators.
// It extracts the target domain and updates the per-target assessment.
func (wd *WAFDetector) AnalyzeToolResult(toolName, toolArgs, response string) {
	if response == "" {
		return
	}

	target := extractTargetFromArgs(toolArgs)
	if target == "" {
		target = "_default"
	}

	lower := strings.ToLower(response)

	wd.mu.Lock()
	defer wd.mu.Unlock()

	wd.totalAnalyzed++

	assessment, ok := wd.assessments[target]
	if !ok {
		assessment = &WAFAssessment{}
		wd.assessments[target] = assessment
	}
	assessment.TotalResponses++

	// Check for WAF block indicators.
	isBlock := false
	for _, indicator := range wafBlockIndicators {
		if strings.Contains(lower, indicator) {
			isBlock = true
			break
		}
	}

	if isBlock {
		assessment.BlockCount++
		wd.blockStreak++

		// Track blocked routes.
		route := extractRouteFromArgs(toolArgs)
		if route != "" {
			found := false
			for _, r := range assessment.BlockedRoutes {
				if r == route {
					found = true
					break
				}
			}
			if !found {
				assessment.BlockedRoutes = append(assessment.BlockedRoutes, route)
			}
		}
	} else {
		wd.blockStreak = 0
	}

	// Fingerprint the WAF product.
	if assessment.Product == nil && assessment.BlockCount >= 2 {
		assessment.Product = wd.fingerprintWAF(lower)
	}

	// Update confidence.
	if assessment.TotalResponses > 0 {
		blockRatio := float64(assessment.BlockCount) / float64(assessment.TotalResponses)
		headerBoost := 0.0
		bodyBoost := 0.0
		if assessment.Product != nil {
			headerBoost = 0.3
			bodyBoost = 0.2
		}
		streakBonus := 0.0
		if wd.blockStreak >= 3 {
			streakBonus = 0.15
		}
		assessment.Confidence = blockRatio*0.5 + headerBoost + bodyBoost + streakBonus
		if assessment.Confidence > 1.0 {
			assessment.Confidence = 1.0
		}
	}

	assessment.Detected = assessment.Confidence >= 0.4 && assessment.BlockCount >= 2
}

// GetAssessment returns the WAF assessment for a target domain.
func (wd *WAFDetector) GetAssessment(target string) *WAFAssessment {
	wd.mu.RLock()
	defer wd.mu.RUnlock()

	if a, ok := wd.assessments[target]; ok {
		return a
	}
	if a, ok := wd.assessments["_default"]; ok {
		return a
	}
	return nil
}

// GetGlobalAssessment returns the most significant WAF detection across all targets.
func (wd *WAFDetector) GetGlobalAssessment() *WAFAssessment {
	wd.mu.RLock()
	defer wd.mu.RUnlock()

	var best *WAFAssessment
	for _, a := range wd.assessments {
		if best == nil || a.Confidence > best.Confidence {
			best = a
		}
	}
	return best
}

// IsWAFDetected returns true if a WAF has been confidently detected for any target.
func (wd *WAFDetector) IsWAFDetected() bool {
	wd.mu.RLock()
	defer wd.mu.RUnlock()

	for _, a := range wd.assessments {
		if a.Detected {
			return true
		}
	}
	return false
}

// FormatWAFContextForPrompt produces a WAF awareness block for injection into agent prompts.
func (wd *WAFDetector) FormatWAFContextForPrompt() string {
	wd.mu.RLock()
	defer wd.mu.RUnlock()

	if !wd.hasDetectionLocked() {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("<waf_detection>\n")
	sb.WriteString("⚠️ WAF DETECTED on target — adjust your approach:\n\n")

	for target, assessment := range wd.assessments {
		if !assessment.Detected {
			continue
		}
		if target == "_default" {
			sb.WriteString("Target: (primary)\n")
		} else {
			sb.WriteString(fmt.Sprintf("Target: %s\n", target))
		}
		sb.WriteString(fmt.Sprintf("  Confidence: %.0f%%\n", assessment.Confidence*100))
		sb.WriteString(fmt.Sprintf("  Blocks observed: %d/%d responses\n", assessment.BlockCount, assessment.TotalResponses))

		if assessment.Product != nil {
			sb.WriteString(fmt.Sprintf("  Product: %s\n", assessment.Product.Name))
			sb.WriteString("  Recommended bypass techniques:\n")
			for _, technique := range assessment.Product.BypassTechniques {
				sb.WriteString(fmt.Sprintf("    - %s\n", technique))
			}
		}

		if len(assessment.BlockedRoutes) > 0 {
			sb.WriteString(fmt.Sprintf("  Blocked routes (%d): %s\n",
				len(assessment.BlockedRoutes),
				strings.Join(assessment.BlockedRoutes, ", ")))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("STRATEGY: Use the bypass techniques above. If standard tools fail, delegate to coder for custom exploit code with WAF-specific encoding.\n")
	sb.WriteString("</waf_detection>\n")
	return sb.String()
}

// fingerprintWAF identifies the specific WAF product from response content.
func (wd *WAFDetector) fingerprintWAF(lowerResponse string) *WAFProduct {
	var bestMatch *WAFProduct
	bestScore := 0

	for i := range knownWAFProducts {
		score := 0
		for _, pattern := range knownWAFProducts[i].HeaderPatterns {
			if strings.Contains(lowerResponse, strings.ToLower(pattern)) {
				score += 2 // Header matches are stronger signals
			}
		}
		for _, pattern := range knownWAFProducts[i].BodyPatterns {
			if strings.Contains(lowerResponse, strings.ToLower(pattern)) {
				score++
			}
		}
		if score > bestScore {
			bestScore = score
			product := knownWAFProducts[i] // copy
			product.Confidence = float64(score) / float64(len(knownWAFProducts[i].HeaderPatterns)+len(knownWAFProducts[i].BodyPatterns))
			bestMatch = &product
		}
	}

	if bestScore >= 2 {
		return bestMatch
	}
	return nil
}

func (wd *WAFDetector) hasDetectionLocked() bool {
	for _, a := range wd.assessments {
		if a.Detected {
			return true
		}
	}
	return false
}

// ─── Helper functions ────────────────────────────────────────────────────────

// extractTargetFromArgs extracts a target domain from tool call arguments.
var urlRegex = regexp.MustCompile(`https?://([^/\s"']+)`)

func extractTargetFromArgs(args string) string {
	matches := urlRegex.FindStringSubmatch(args)
	if len(matches) >= 2 {
		// Return just the host portion.
		host := matches[1]
		// Strip port if present.
		if idx := strings.LastIndex(host, ":"); idx > 0 {
			host = host[:idx]
		}
		return host
	}
	return ""
}

// extractRouteFromArgs extracts a URL path from tool call arguments.
var routeRegex = regexp.MustCompile(`https?://[^/\s"']+(\/[^\s"']*)?`)

func extractRouteFromArgs(args string) string {
	matches := routeRegex.FindStringSubmatch(args)
	if len(matches) >= 2 && matches[1] != "" {
		return matches[1]
	}
	return ""
}

// ─── Context propagation ─────────────────────────────────────────────────────

type wafDetectorKey struct{}

// WithWAFDetector attaches a WAFDetector to the context.
func WithWAFDetector(ctx context.Context, wd *WAFDetector) context.Context {
	return context.WithValue(ctx, wafDetectorKey{}, wd)
}

// GetWAFDetector retrieves the WAFDetector from context.
func GetWAFDetector(ctx context.Context) *WAFDetector {
	if wd, ok := ctx.Value(wafDetectorKey{}).(*WAFDetector); ok {
		return wd
	}
	return nil
}
