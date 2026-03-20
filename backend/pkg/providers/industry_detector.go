package providers

import (
	"fmt"
	"strings"
)

// IndustryProfile represents a detected target industry with associated
// testing priorities and special instructions. Used to customize the pentester
// agent's approach based on what kind of application is being tested.
type IndustryProfile struct {
	// Type is the canonical industry identifier.
	// One of: "fintech", "saas", "ecommerce", "crypto", "healthcare",
	// "gaming", "social", "wordpress", "generic".
	Type string

	// Markers lists the keywords that were detected in recon output
	// to arrive at this classification.
	Markers []string

	// PlaybookPriorities lists attack categories in recommended testing order
	// for this industry type. Categories use the same keys as CategoryTracker.
	PlaybookPriorities []string

	// SpecialInstructions contains industry-specific testing guidance that
	// gets injected into the agent system prompt.
	SpecialInstructions string
}

// industryMarkerSet maps industry types to their detection keywords.
// Keywords are matched case-insensitively against recon output.
// A minimum of minMarkersForConfidence matches is required for classification.
type industryMarkerSet struct {
	Type     string
	Markers  []string
	Priority int // lower = checked first (for disambiguation)
}

// minMarkersForConfidence is the minimum number of keyword matches required
// to confidently classify a target into an industry. With fewer matches,
// the classification falls back to "generic".
const minMarkersForConfidence = 2

// industryMarkers defines detection keywords for each industry, ordered by
// specificity (most specific first for tie-breaking).
var industryMarkers = []industryMarkerSet{
	{
		Type:     "fintech",
		Markers:  []string{"razorpay", "stripe", "paypal", "payment", "kyc", "loan", "upi", "mpesa", "fintech", "banking", "wallet", "transaction", "payout", "merchant", "checkout", "refund", "settlement", "ledger"},
		Priority: 1,
	},
	{
		Type:     "crypto",
		Markers:  []string{"trading", "blockchain", "swap", "token", "defi", "web3", "metamask", "ethereum", "bitcoin", "nft", "staking", "mining", "exchange", "airdrop", "smart contract", "solidity"},
		Priority: 2,
	},
	{
		Type:     "healthcare",
		Markers:  []string{"hipaa", "patient", "medical", "health", "ehr", "fhir", "clinical", "prescription", "diagnosis", "telehealth", "pharmacy", "insurance claim", "hl7"},
		Priority: 3,
	},
	{
		Type:     "ecommerce",
		Markers:  []string{"shopify", "woocommerce", "cart", "checkout", "product", "order", "inventory", "catalog", "shipping", "magento", "bigcommerce", "storefront", "add to cart"},
		Priority: 4,
	},
	{
		Type:     "saas",
		Markers:  []string{"graphql", "oauth", "multi-tenant", "saas", "subscription", "webhook", "api-key", "workspace", "organization", "tenant", "onboarding", "billing", "seats"},
		Priority: 5,
	},
	{
		Type:     "gaming",
		Markers:  []string{"game", "player", "leaderboard", "score", "matchmaking", "in-app purchase", "loot", "inventory", "guild", "pvp", "mmorpg"},
		Priority: 6,
	},
	{
		Type:     "social",
		Markers:  []string{"social", "profile", "friend", "follow", "feed", "post", "comment", "like", "share", "messaging", "chat", "community", "forum"},
		Priority: 7,
	},
	{
		Type:     "wordpress",
		Markers:  []string{"wordpress", "wp-content", "wp-admin", "wp-json", "wp-login", "xmlrpc.php", "wp-includes", "woocommerce", "yoast", "elementor"},
		Priority: 8,
	},
}

// industryPlaybooks maps each industry type to its recommended attack category
// priorities and special instructions. Derived from ADVICE_COMBINED.md analysis.
var industryPlaybooks = map[string]struct {
	Priorities          []string
	SpecialInstructions string
}{
	"fintech": {
		Priorities: []string{
			"auth_acquisition",
			"payment_logic",
			"idor",
			"data_harvest",
			"business_logic",
			"race_conditions",
			"sqli",
			"ssrf",
			"ato_chains",
		},
		SpecialInstructions: `FINTECH TARGET DETECTED — Payment logic bugs pay 5-10x more than XSS.
Priority testing:
• Test EVERY step of money flow: deposit → transfer → withdrawal → refund
• Race conditions on payment endpoints (double-spend, balance manipulation)
• IDOR on transaction/account endpoints (horizontal + vertical)
• KYC bypass and verification logic flaws
• Currency conversion rounding errors and precision bugs`,
	},
	"crypto": {
		Priorities: []string{
			"auth_acquisition",
			"payment_logic",
			"race_conditions",
			"business_logic",
			"idor",
			"data_harvest",
			"api_attacks",
			"ssrf",
			"ato_chains",
		},
		SpecialInstructions: `CRYPTO/BLOCKCHAIN TARGET DETECTED — Highest average bounty payouts.
Priority testing:
• Withdrawal/deposit race conditions (double-spend is critical-severity)
• Swap/trading logic manipulation (price oracle, slippage abuse)
• Hot wallet infrastructure via SSRF to cloud metadata
• API key management and trading bot authentication
• Always verify on-chain: did the withdrawal actually execute on blockchain?`,
	},
	"healthcare": {
		Priorities: []string{
			"auth_acquisition",
			"data_harvest",
			"idor",
			"ssrf",
			"sqli",
			"api_attacks",
			"business_logic",
		},
		SpecialInstructions: `HEALTHCARE TARGET DETECTED — HIPAA violations are high-severity.
Priority testing:
• Patient data access controls (IDOR on medical records = critical)
• PHI/PII exposure in API responses, error messages, logs
• Role-based access: nurse vs doctor vs admin privilege boundaries
• Prescription/appointment logic manipulation
• Integration endpoints (FHIR, HL7) for injection vulnerabilities`,
	},
	"ecommerce": {
		Priorities: []string{
			"auth_acquisition",
			"payment_logic",
			"business_logic",
			"idor",
			"race_conditions",
			"data_harvest",
			"sqli",
			"ssrf",
		},
		SpecialInstructions: `ECOMMERCE TARGET DETECTED — Business logic bugs on purchase flow are high-value.
Priority testing:
• Price manipulation (cart tampering, coupon stacking, negative quantities)
• Race conditions on inventory/discount redemption
• IDOR on order management (view/modify other users' orders)
• Payment gateway integration flaws
• Shipping address/billing manipulation`,
	},
	"saas": {
		Priorities: []string{
			"auth_acquisition",
			"idor",
			"data_harvest",
			"api_attacks",
			"business_logic",
			"ssrf",
			"sqli",
			"ato_chains",
		},
		SpecialInstructions: `SaaS TARGET DETECTED — Multi-tenancy bugs are critical-severity.
Priority testing:
• Tenant isolation bypass (access Org B data from Org A account)
• GraphQL introspection → schema exploitation → IDOR/SQLi chains
• Webhook/callback injection and SSRF via integration features
• API key and OAuth scope escalation
• Subscription tier bypass and feature gating logic`,
	},
	"gaming": {
		Priorities: []string{
			"auth_acquisition",
			"business_logic",
			"race_conditions",
			"idor",
			"api_attacks",
			"data_harvest",
		},
		SpecialInstructions: `GAMING TARGET DETECTED — Economy manipulation bugs are high-value.
Priority testing:
• In-game economy manipulation (item duplication, currency generation)
• Race conditions on purchases and trades
• Leaderboard/score manipulation
• Matchmaking and anti-cheat bypass
• In-app purchase receipt validation bypass`,
	},
	"social": {
		Priorities: []string{
			"auth_acquisition",
			"idor",
			"xss",
			"data_harvest",
			"ato_chains",
			"business_logic",
			"api_attacks",
		},
		SpecialInstructions: `SOCIAL PLATFORM DETECTED — Privacy bugs and ATO chains are high-value.
Priority testing:
• Privacy controls bypass (view private profiles/posts)
• IDOR on user content (messages, posts, media)
• Stored XSS in user-generated content → session hijack
• Account takeover chains (password reset, OAuth)
• Content manipulation (edit/delete other users' posts)`,
	},
	"wordpress": {
		Priorities: []string{
			"data_harvest",
			"auth_acquisition",
			"sqli",
			"file_upload",
			"ssrf",
			"rce",
		},
		SpecialInstructions: `WORDPRESS TARGET DETECTED — Plugin vulnerabilities are the #1 attack surface.
Priority testing:
• Enumerate plugins and themes for known CVEs
• wp-json REST API enumeration and IDOR
• xmlrpc.php brute force and SSRF
• wp-config.php exposure via traversal or backup files
• Plugin-specific SQLi (especially custom plugins)
• File upload via media library or plugin editors`,
	},
	"generic": {
		Priorities: []string{
			"auth_acquisition",
			"data_harvest",
			"idor",
			"ssrf",
			"business_logic",
			"sqli",
			"api_attacks",
			"ato_chains",
		},
		SpecialInstructions: "",
	},
}

// DetectIndustry analyzes recon output text (task description, initial tool responses)
// and returns an IndustryProfile indicating the detected target industry type.
//
// Detection uses case-insensitive keyword matching. A minimum of minMarkersForConfidence
// keyword matches is required; otherwise returns a "generic" profile.
//
// This function is designed to be called once or twice per subtask (not per tool call)
// and is safe for concurrent use (stateless).
func DetectIndustry(reconOutput string) IndustryProfile {
	if reconOutput == "" {
		return genericProfile()
	}

	lower := strings.ToLower(reconOutput)

	var bestType string
	var bestMarkers []string
	bestScore := 0

	for _, ims := range industryMarkers {
		var matched []string
		for _, marker := range ims.Markers {
			if strings.Contains(lower, strings.ToLower(marker)) {
				matched = append(matched, marker)
			}
		}
		score := len(matched)
		if score > bestScore {
			bestScore = score
			bestType = ims.Type
			bestMarkers = matched
		}
	}

	// Require minimum confidence threshold.
	if bestScore < minMarkersForConfidence {
		return genericProfile()
	}

	return buildProfile(bestType, bestMarkers)
}

// FormatPlaybookForPrompt converts an IndustryProfile into a formatted string
// suitable for injection into the pentester agent's system prompt.
// Returns empty string for generic profiles with no special instructions.
func FormatPlaybookForPrompt(profile IndustryProfile) string {
	if profile.Type == "generic" && profile.SpecialInstructions == "" {
		return ""
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[SYSTEM-AUTO: TARGET INDUSTRY DETECTED — %s]\n\n",
		strings.ToUpper(profile.Type)))

	if profile.SpecialInstructions != "" {
		sb.WriteString(profile.SpecialInstructions)
		sb.WriteString("\n\n")
	}

	if len(profile.PlaybookPriorities) > 0 {
		sb.WriteString("Recommended testing priority order:\n")
		for i, cat := range profile.PlaybookPriorities {
			sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, cat))
		}
	}

	if len(profile.Markers) > 0 {
		sb.WriteString(fmt.Sprintf("\n(Detected markers: %s)\n", strings.Join(profile.Markers, ", ")))
	}

	return sb.String()
}

// genericProfile returns the default "generic" IndustryProfile.
func genericProfile() IndustryProfile {
	pb := industryPlaybooks["generic"]
	return IndustryProfile{
		Type:                "generic",
		Markers:             nil,
		PlaybookPriorities:  pb.Priorities,
		SpecialInstructions: pb.SpecialInstructions,
	}
}

// buildProfile constructs an IndustryProfile for a detected industry type.
func buildProfile(industryType string, detectedMarkers []string) IndustryProfile {
	pb, ok := industryPlaybooks[industryType]
	if !ok {
		pb = industryPlaybooks["generic"]
	}

	return IndustryProfile{
		Type:                industryType,
		Markers:             detectedMarkers,
		PlaybookPriorities:  pb.Priorities,
		SpecialInstructions: pb.SpecialInstructions,
	}
}
