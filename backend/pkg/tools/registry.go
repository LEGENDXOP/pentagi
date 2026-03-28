package tools

import (
	"maps"
	"pentagi/pkg/database"

	"github.com/invopop/jsonschema"
	"github.com/vxcontrol/langchaingo/llms"
)

const (
	FinalyToolName            = "done"
	AskUserToolName           = "ask"
	MaintenanceToolName       = "maintenance"
	MaintenanceResultToolName = "maintenance_result"
	CoderToolName             = "coder"
	CodeResultToolName        = "code_result"
	PentesterToolName         = "pentester"
	HackResultToolName        = "hack_result"
	AdviceToolName            = "advice"
	MemoristToolName          = "memorist"
	MemoristResultToolName    = "memorist_result"
	BrowserToolName           = "browser"
	GoogleToolName            = "google"
	DuckDuckGoToolName        = "duckduckgo"
	TavilyToolName            = "tavily"
	TraversaalToolName        = "traversaal"
	PerplexityToolName        = "perplexity"
	SearxngToolName           = "searxng"
	SploitusToolName          = "sploitus"
	NucleiToolName            = "nuclei_scan"
	SearchToolName            = "search"
	SearchResultToolName      = "search_result"
	EnricherResultToolName    = "enricher_result"
	SearchInMemoryToolName    = "search_in_memory"
	SearchGuideToolName       = "search_guide"
	StoreGuideToolName        = "store_guide"
	SearchAnswerToolName      = "search_answer"
	StoreAnswerToolName       = "store_answer"
	SearchCodeToolName        = "search_code"
	StoreCodeToolName         = "store_code"
	GraphitiSearchToolName    = "graphiti_search"
	InteractshGetURLToolName  = "interactsh_url"
	InteractshPollToolName    = "interactsh_poll"
	InteractshStatusToolName  = "interactsh_status"
	BrowserNavigateToolName   = "browser_navigate"
	BrowserClickToolName      = "browser_click"
	BrowserFillToolName       = "browser_fill"
	BrowserScreenshotToolName = "browser_screenshot"
	BrowserEvaluateToolName   = "browser_evaluate"
	BrowserCookiesToolName    = "browser_cookies"
	RaceConditionToolName      = "race_condition_test"
	AttackPathAnalyzeToolName  = "attack_path_analyze"
	ReportResultToolName      = "report_result"
	SubtaskListToolName       = "subtask_list"
	SubtaskPatchToolName      = "subtask_patch"
	TerminalToolName          = "terminal"
	FileToolName              = "file"
)

type ToolType int

const (
	NoneToolType ToolType = iota
	EnvironmentToolType
	SearchNetworkToolType
	SearchVectorDbToolType
	AgentToolType
	StoreAgentResultToolType
	StoreVectorDbToolType
	BarrierToolType
)

func (t ToolType) String() string {
	switch t {
	case EnvironmentToolType:
		return "environment"
	case SearchNetworkToolType:
		return "search_network"
	case SearchVectorDbToolType:
		return "search_vector_db"
	case AgentToolType:
		return "agent"
	case StoreAgentResultToolType:
		return "store_agent_result"
	case StoreVectorDbToolType:
		return "store_vector_db"
	case BarrierToolType:
		return "barrier"
	default:
		return "none"
	}
}

// GetToolType returns the tool type for a given tool name
func GetToolType(name string) ToolType {
	if toolType, ok := toolsTypeMapping[name]; ok {
		return toolType
	}
	return NoneToolType
}

var toolsTypeMapping = map[string]ToolType{
	FinalyToolName:            BarrierToolType,
	AskUserToolName:           BarrierToolType,
	MaintenanceToolName:       AgentToolType,
	MaintenanceResultToolName: StoreAgentResultToolType,
	CoderToolName:             AgentToolType,
	CodeResultToolName:        StoreAgentResultToolType,
	PentesterToolName:         AgentToolType,
	HackResultToolName:        StoreAgentResultToolType,
	AdviceToolName:            AgentToolType,
	MemoristToolName:          AgentToolType,
	MemoristResultToolName:    StoreAgentResultToolType,
	BrowserToolName:           SearchNetworkToolType,
	GoogleToolName:            SearchNetworkToolType,
	DuckDuckGoToolName:        SearchNetworkToolType,
	TavilyToolName:            SearchNetworkToolType,
	TraversaalToolName:        SearchNetworkToolType,
	PerplexityToolName:        SearchNetworkToolType,
	SearxngToolName:           SearchNetworkToolType,
	SploitusToolName:          SearchNetworkToolType,
	NucleiToolName:            EnvironmentToolType,
	SearchToolName:            AgentToolType,
	SearchResultToolName:      StoreAgentResultToolType,
	EnricherResultToolName:    StoreAgentResultToolType,
	SearchInMemoryToolName:    SearchVectorDbToolType,
	SearchGuideToolName:       SearchVectorDbToolType,
	StoreGuideToolName:        StoreVectorDbToolType,
	SearchAnswerToolName:      SearchVectorDbToolType,
	StoreAnswerToolName:       StoreVectorDbToolType,
	SearchCodeToolName:        SearchVectorDbToolType,
	StoreCodeToolName:         StoreVectorDbToolType,
	GraphitiSearchToolName:    SearchVectorDbToolType,
	RaceConditionToolName:     EnvironmentToolType,
	AttackPathAnalyzeToolName: EnvironmentToolType,
	InteractshGetURLToolName:  EnvironmentToolType,
	InteractshPollToolName:    EnvironmentToolType,
	InteractshStatusToolName:  EnvironmentToolType,
	BrowserNavigateToolName:   EnvironmentToolType,
	BrowserClickToolName:      EnvironmentToolType,
	BrowserFillToolName:       EnvironmentToolType,
	BrowserScreenshotToolName: EnvironmentToolType,
	BrowserEvaluateToolName:   EnvironmentToolType,
	BrowserCookiesToolName:    EnvironmentToolType,
	AuthLoginToolName:         EnvironmentToolType,
	AuthStatusToolName:        EnvironmentToolType,
	AuthInjectToolName:        EnvironmentToolType,
	AuthRefreshToolName:       EnvironmentToolType,
	AuthLogoutToolName:        EnvironmentToolType,
	ReportResultToolName:      StoreAgentResultToolType,
	SubtaskListToolName:       StoreAgentResultToolType,
	SubtaskPatchToolName:      StoreAgentResultToolType,
	TerminalToolName:          EnvironmentToolType,
	FileToolName:              EnvironmentToolType,
}

var reflector = &jsonschema.Reflector{
	DoNotReference: true,
	ExpandedStruct: true,
}

var allowedSummarizingToolsResult = []string{
	TerminalToolName,
	BrowserToolName,
	NucleiToolName,
	RaceConditionToolName,
	BrowserNavigateToolName,
	BrowserEvaluateToolName,
}

var allowedStoringInMemoryTools = []string{
	TerminalToolName,
	FileToolName,
	SearchToolName,
	GoogleToolName,
	DuckDuckGoToolName,
	TavilyToolName,
	TraversaalToolName,
	PerplexityToolName,
	SearxngToolName,
	SploitusToolName,
	NucleiToolName,
	RaceConditionToolName,
	AuthLoginToolName,
	AuthStatusToolName,
	MaintenanceToolName,
	CoderToolName,
	PentesterToolName,
	AdviceToolName,
	BrowserNavigateToolName,
	BrowserEvaluateToolName,
	BrowserCookiesToolName,
	AttackPathAnalyzeToolName,
}

var registryDefinitions = map[string]llms.FunctionDefinition{
	TerminalToolName: {
		Name: TerminalToolName,
		Description: "Calls a terminal command in blocking mode with hard limit timeout 1200 seconds and " +
			"optimum timeout 60 seconds, only one command can be executed at a time",
		Parameters: reflector.Reflect(&TerminalAction{}),
	},
	FileToolName: {
		Name:        FileToolName,
		Description: "Modifies or reads local files",
		Parameters:  reflector.Reflect(&FileAction{}),
	},
	ReportResultToolName: {
		Name:        ReportResultToolName,
		Description: "Send the report result to the user with execution status and description",
		Parameters:  reflector.Reflect(&TaskResult{}),
	},
	SubtaskListToolName: {
		Name:        SubtaskListToolName,
		Description: "Send new generated subtask list to the user",
		Parameters:  reflector.Reflect(&SubtaskList{}),
	},
	SubtaskPatchToolName: {
		Name: SubtaskPatchToolName,
		Description: "Submit delta operations to modify the current subtask list instead of regenerating all subtasks. " +
			"Supports add (create new subtask at position), remove (delete by ID), modify (update title/description), " +
			"and reorder (move to different position) operations. Use empty operations array if no changes needed.",
		Parameters: reflector.Reflect(&SubtaskPatch{}),
	},
	SearchToolName: {
		Name: SearchToolName,
		Description: "Search in a different search engines in the internet and long-term memory " +
			"by your complex question to the researcher team member, also you can add some instructions to get result " +
			"in a specific format or structure or content type like " +
			"code or command samples, manuals, guides, exploits, vulnerability details, repositories, libraries, etc.",
		Parameters: reflector.Reflect(&ComplexSearch{}),
	},
	SearchResultToolName: {
		Name:        SearchResultToolName,
		Description: "Send the complex search result as a answer for the user question to the user",
		Parameters:  reflector.Reflect(&SearchResult{}),
	},
	BrowserToolName: {
		Name:        BrowserToolName,
		Description: "Opens a browser to look for additional information from the web site",
		Parameters:  reflector.Reflect(&Browser{}),
	},
	GoogleToolName: {
		Name: GoogleToolName,
		Description: "Search in the google search engine, it's a fast query and the shortest content " +
			"to check some information or collect public links by short query",
		Parameters: reflector.Reflect(&SearchAction{}),
	},
	DuckDuckGoToolName: {
		Name: DuckDuckGoToolName,
		Description: "Search in the duckduckgo search engine, it's a anonymous query and returns a small content " +
			"to check some information from different sources or collect public links by short query",
		Parameters: reflector.Reflect(&SearchAction{}),
	},
	TavilyToolName: {
		Name: TavilyToolName,
		Description: "Search in the tavily search engine, it's a more complex query and more detailed content " +
			"with answer by query and detailed information from the web sites",
		Parameters: reflector.Reflect(&SearchAction{}),
	},
	TraversaalToolName: {
		Name: TraversaalToolName,
		Description: "Search in the traversaal search engine, presents you answer and web-links " +
			"by your query according to relevant information from the web sites",
		Parameters: reflector.Reflect(&SearchAction{}),
	},
	PerplexityToolName: {
		Name: PerplexityToolName,
		Description: "Search in the perplexity search engine, it's a fully complex query and detailed research report " +
			"with answer by query and detailed information from the web sites and other sources augmented by the LLM",
		Parameters: reflector.Reflect(&SearchAction{}),
	},
	SearxngToolName: {
		Name: SearxngToolName,
		Description: "Search in the searxng meta search engine, it's a privacy-focused search engine " +
			"that aggregates results from multiple search engines with customizable categories, " +
			"language settings, and safety filters",
		Parameters: reflector.Reflect(&SearchAction{}),
	},
	SploitusToolName: {
		Name: SploitusToolName,
		Description: "Search the Sploitus exploit aggregator (https://sploitus.com) for public exploits, " +
			"proof-of-concept code, and offensive security tools. Sploitus indexes ExploitDB, Packet Storm, " +
			"GitHub Security Advisories, and many other sources. Use this tool to find exploit code and PoCs " +
			"for specific software, services, CVEs, or vulnerability classes (e.g. 'ssh', 'apache log4j', " +
			"'CVE-2021-44228'). Returns exploit URLs, CVSS scores, CVE references, and publication dates.",
		Parameters: reflector.Reflect(&SploitusAction{}),
	},
	NucleiToolName: {
		Name: NucleiToolName,
		Description: "Run ProjectDiscovery's Nuclei vulnerability scanner against a target URL or host. " +
			"Nuclei uses community-maintained templates to detect CVEs, misconfigurations, default credentials, " +
			"exposed panels, and other security issues. Specify template tags (e.g. 'cve,sqli,xss,lfi') and " +
			"severity filters (critical,high,medium,low,info) to focus the scan. Returns structured findings " +
			"with vulnerability type, severity, matched URL, and auto-tagged [VULN_TYPE] for compliance mapping. " +
			"Findings are deduplicated against previously discovered vulnerabilities in the current engagement. " +
			"Use this for broad automated vulnerability detection before deeper manual testing.",
		Parameters: reflector.Reflect(&NucleiScanAction{}),
	},
	RaceConditionToolName: {
		Name: RaceConditionToolName,
		Description: "Execute race condition / TOCTOU (Time-of-Check-to-Time-of-Use) tests by sending concurrent " +
			"HTTP requests to a target endpoint. Tests for duplicate transactions, balance manipulation, " +
			"coupon reuse, double-spend, and other time-of-check-to-time-of-use vulnerabilities. " +
			"Analyses response status codes, timing differences, body length variations, and detects anomalies " +
			"that indicate state inconsistencies under concurrency. Use on state-changing endpoints " +
			"(transfers, purchases, votes, coupon redemptions) that should be idempotent.",
		Parameters: reflector.Reflect(&RaceConditionAction{}),
	},
	EnricherResultToolName: {
		Name:        EnricherResultToolName,
		Description: "Send the enriched user's question with additional information to the user",
		Parameters:  reflector.Reflect(&EnricherResult{}),
	},
	SearchInMemoryToolName: {
		Name: SearchInMemoryToolName,
		Description: "Search in the vector database (long-term memory) for relevant information by providing a semantically rich, " +
			"context-aware natural language query. Formulate queries with sufficient context, intent, and detailed descriptions " +
			"to enhance semantic matching and retrieval accuracy. This function is ideal when you need to retrieve specific information " +
			"to assist in generating accurate and informative responses. If Task ID or Subtask ID are known, " +
			"they can be used as strict filters to further refine the search results and improve relevancy.",
		Parameters: reflector.Reflect(&SearchInMemoryAction{}),
	},
	SearchGuideToolName: {
		Name: SearchGuideToolName,
		Description: "Search in the vector database for relevant guides by providing a semantically rich, context-aware natural language query. " +
			"Formulate your query with sufficient context, intent, and detailed descriptions of the guide you need to enhance semantic matching and " +
			"retrieval accuracy. Specify the type of guide required to further refine the search. This function is ideal " +
			"when you need to retrieve specific guides to assist in accomplishing tasks or solving issues.",
		Parameters: reflector.Reflect(&SearchGuideAction{}),
	},
	StoreGuideToolName: {
		Name:        StoreGuideToolName,
		Description: "Store the guide to the vector database for future use",
		Parameters:  reflector.Reflect(&StoreGuideAction{}),
	},
	SearchAnswerToolName: {
		Name: SearchAnswerToolName,
		Description: "Search in the vector database for relevant answers by providing a semantically rich, context-aware natural language query. " +
			"Formulate your query with sufficient context, intent, and detailed descriptions of what you want to find and why you need it " +
			"to enhance semantic matching and retrieval accuracy. Specify the type of answer required to further refine the search. " +
			"This function is ideal when you need to retrieve specific answers to assist in tasks, solve issues, or answer questions.",
		Parameters: reflector.Reflect(&SearchAnswerAction{}),
	},
	StoreAnswerToolName: {
		Name:        StoreAnswerToolName,
		Description: "Store the question answer to the vector database for future use",
		Parameters:  reflector.Reflect(&StoreAnswerAction{}),
	},
	SearchCodeToolName: {
		Name: SearchCodeToolName,
		Description: "Search in the vector database for relevant code samples by providing a semantically rich, context-aware natural language query. " +
			"Formulate your query with sufficient context, intent, and detailed descriptions of what you want to achieve with the code and what should be included, " +
			"to enhance semantic matching and retrieval accuracy. Specify the programming language to further refine the search. " +
			"This function is ideal when you need to retrieve specific code examples to assist in development tasks or solve programming issues.",
		Parameters: reflector.Reflect(&SearchCodeAction{}),
	},
	StoreCodeToolName: {
		Name:        StoreCodeToolName,
		Description: "Store the code sample to the vector database for future use. It's should be a sample like a one source code file for some question",
		Parameters:  reflector.Reflect(&StoreCodeAction{}),
	},
	GraphitiSearchToolName: {
		Name: GraphitiSearchToolName,
		Description: "Search the Graphiti temporal knowledge graph for historical penetration testing context, " +
			"including previous agent responses, tool execution records, discovered entities, and their relationships. " +
			"Supports 7 search types: temporal_window (time-bounded search), entity_relationships (graph traversal from an entity), " +
			"diverse_results (anti-redundancy search), episode_context (full agent reasoning and tool outputs), " +
			"successful_tools (proven techniques), recent_context (latest findings), and entity_by_label (type-specific entity search). " +
			"Use this to avoid repeating failed approaches, reuse successful exploitation techniques, understand entity relationships, " +
			"and build on previous findings within the same penetration testing engagement.",
		Parameters: reflector.Reflect(&GraphitiSearchAction{}),
	},
	AuthLoginToolName: {
		Name: AuthLoginToolName,
		Description: "Authenticate to a target application or API. Supports form-login (POST credentials), " +
			"oauth2-cc (client_credentials grant), api-key (static key storage), and custom flows. " +
			"Creates a named session that can be referenced by auth_inject to get curl flags for authenticated requests. " +
			"Use this when you need to authenticate before testing protected endpoints.",
		Parameters: reflector.Reflect(&AuthLoginAction{}),
	},
	AuthStatusToolName: {
		Name:        AuthStatusToolName,
		Description: "Check the status of authentication sessions including token expiry, active cookies, and CSRF tokens. Shows all sessions or a specific one by flow_id.",
		Parameters:  reflector.Reflect(&AuthStatusAction{}),
	},
	AuthInjectToolName: {
		Name: AuthInjectToolName,
		Description: "Get curl command-line flags for making authenticated requests using a previously created auth session. " +
			"Returns -H, -b flags ready to paste into curl commands. Automatically refreshes tokens nearing expiry.",
		Parameters: reflector.Reflect(&AuthInjectAction{}),
	},
	AuthRefreshToolName: {
		Name:        AuthRefreshToolName,
		Description: "Force a token refresh for an authenticated session. Use when a token has expired or is about to expire. For oauth2-cc flows, re-executes the client_credentials grant.",
		Parameters:  reflector.Reflect(&AuthRefreshAction{}),
	},
	AuthLogoutToolName: {
		Name:        AuthLogoutToolName,
		Description: "Clear an authentication session, removing all cookies, tokens, and session state. Use when switching users or cleaning up after testing.",
		Parameters:  reflector.Reflect(&AuthLogoutAction{}),
	},
	AttackPathAnalyzeToolName: {
		Name: AttackPathAnalyzeToolName,
		Description: "Analyse all findings discovered in the current flow and compute attack paths. " +
			"Builds a directed graph where nodes represent assets (endpoints, services, credentials, admin access) " +
			"and edges represent attack steps (exploitable vulnerabilities). Uses Dijkstra's algorithm to find " +
			"the shortest/easiest attack paths from external attacker to high-value targets. " +
			"Returns a structured report with computed paths, step counts, feasibility ratings, " +
			"and a full graph (nodes + edges) suitable for visualization. " +
			"Use this AFTER discovery/scanning phases when you have accumulated findings with [FINDING] markers.",
		Parameters: reflector.Reflect(&AttackPathAnalyzeAction{}),
	},
	InteractshGetURLToolName: {
		Name: InteractshGetURLToolName,
		Description: "Get a unique Out-of-Band (OOB) callback URL for detecting blind vulnerabilities. " +
			"Use this when testing for blind SSRF, blind XSS, blind SQLi, blind RCE, blind XXE, or any vulnerability " +
			"where the server makes an external request that you cannot observe directly. " +
			"The generated URL will detect DNS, HTTP, and SMTP callbacks. " +
			"After injecting the URL into your payload, use interactsh_poll to check for received callbacks.",
		Parameters: reflector.Reflect(&InteractshGetURLAction{}),
	},
	InteractshPollToolName: {
		Name: InteractshPollToolName,
		Description: "Check for received OOB (Out-of-Band) interactions/callbacks. " +
			"Use this after injecting OOB URLs (from interactsh_url) into attack payloads. " +
			"Returns any DNS, HTTP, or SMTP callbacks that were received, correlated back to their attack IDs. " +
			"Detected interactions confirm blind vulnerabilities (blind SSRF, blind XSS, blind RCE, etc.).",
		Parameters: reflector.Reflect(&InteractshPollAction{}),
	},
	InteractshStatusToolName: {
		Name: InteractshStatusToolName,
		Description: "Check the status of the OOB (Out-of-Band) detection system, " +
			"including whether interactsh is running, the base URL, and all registered attack probes.",
		Parameters: reflector.Reflect(&InteractshStatusAction{}),
	},
	BrowserNavigateToolName: {
		Name: BrowserNavigateToolName,
		Description: "Navigate the headless Playwright browser to a URL. Use this for JS-heavy SPAs, " +
			"Cloudflare-protected sites, or any page that requires JavaScript execution to render. " +
			"Returns the page title, HTTP status, response headers, and rendered text content. " +
			"The browser uses stealth mode to bypass WAF/bot detection. Browser state (cookies, sessions) " +
			"persists across calls within the same flow.",
		Parameters: reflector.Reflect(&BrowserNavigateAction{}),
	},
	BrowserClickToolName: {
		Name: BrowserClickToolName,
		Description: "Click an element on the current page in the headless Playwright browser. " +
			"Use CSS selectors (e.g., '#submit-btn'), text selectors (e.g., 'button:has-text(\"Login\")'), " +
			"or XPath. Waits for the element to be visible before clicking. " +
			"Must call browser_navigate first to load a page.",
		Parameters: reflector.Reflect(&BrowserClickAction{}),
	},
	BrowserFillToolName: {
		Name: BrowserFillToolName,
		Description: "Fill an input field on the current page in the headless Playwright browser. " +
			"Use CSS selectors to target the input (e.g., '#username', 'input[name=\"email\"]'). " +
			"Clears existing content before typing. Combine with browser_click to submit forms.",
		Parameters: reflector.Reflect(&BrowserFillAction{}),
	},
	BrowserScreenshotToolName: {
		Name: BrowserScreenshotToolName,
		Description: "Take a screenshot of the current page in the headless Playwright browser. " +
			"Screenshots are saved to /work/evidence/screenshots/ with timestamps. " +
			"Use this to capture visual evidence of vulnerabilities, error pages, or application state.",
		Parameters: reflector.Reflect(&BrowserScreenshotAction{}),
	},
	BrowserEvaluateToolName: {
		Name: BrowserEvaluateToolName,
		Description: "Execute JavaScript in the current page context of the headless Playwright browser. " +
			"Use this to extract data from the DOM, read localStorage/sessionStorage tokens, " +
			"check for client-side vulnerabilities, or interact with JavaScript APIs. " +
			"Returns the evaluation result as JSON.",
		Parameters: reflector.Reflect(&BrowserEvaluateAction{}),
	},
	BrowserCookiesToolName: {
		Name: BrowserCookiesToolName,
		Description: "Get all cookies from the current browser session. Returns cookie name, value, domain, " +
			"path, secure flag, httpOnly flag, sameSite policy, and expiration. " +
			"Use this to extract session tokens, analyze cookie security, or verify authentication state.",
		Parameters: reflector.Reflect(&BrowserCookiesAction{}),
	},
	MemoristToolName: {
		Name:        MemoristToolName,
		Description: "Call to Archivist team member who remember all the information about the past work and made tasks and can answer your question about it",
		Parameters:  reflector.Reflect(&MemoristAction{}),
	},
	MemoristResultToolName: {
		Name:        MemoristResultToolName,
		Description: "Send the search in long-term memory result as a answer for the user question to the user",
		Parameters:  reflector.Reflect(&MemoristResult{}),
	},
	MaintenanceToolName: {
		Name:        MaintenanceToolName,
		Description: "Call to DevOps team member to maintain local environment and tools inside the docker container",
		Parameters:  reflector.Reflect(&MaintenanceAction{}),
	},
	MaintenanceResultToolName: {
		Name:        MaintenanceResultToolName,
		Description: "Send the maintenance result to the user with task status and fully detailed report about using the result",
		Parameters:  reflector.Reflect(&TaskResult{}),
	},
	CoderToolName: {
		Name:        CoderToolName,
		Description: "Call to developer team member to write a code for the specific task",
		Parameters:  reflector.Reflect(&CoderAction{}),
	},
	CodeResultToolName: {
		Name:        CodeResultToolName,
		Description: "Send the code result to the user with execution status and fully detailed report about using the result",
		Parameters:  reflector.Reflect(&CodeResult{}),
	},
	PentesterToolName: {
		Name:        PentesterToolName,
		Description: "Call to pentester team member to perform a penetration test or looking for vulnerabilities and weaknesses",
		Parameters:  reflector.Reflect(&PentesterAction{}),
	},
	HackResultToolName: {
		Name:        HackResultToolName,
		Description: "Send the penetration test result to the user with detailed report",
		Parameters:  reflector.Reflect(&HackResult{}),
	},
	AdviceToolName: {
		Name:        AdviceToolName,
		Description: "Get more complex answer from the mentor about some issue or difficult situation",
		Parameters:  reflector.Reflect(&AskAdvice{}),
	},
	AskUserToolName: {
		Name:        AskUserToolName,
		Description: "If you need to ask user for input, use this tool",
		Parameters:  reflector.Reflect(&AskUser{}),
	},
	FinalyToolName: {
		Name:        FinalyToolName,
		Description: "If you need to finish the task with success or failure, use this tool",
		Parameters:  reflector.Reflect(&Done{}),
	},
}

func getMessageType(name string) database.MsglogType {
	switch name {
	case TerminalToolName:
		return database.MsglogTypeTerminal
	case FileToolName:
		return database.MsglogTypeFile
	case BrowserToolName:
		return database.MsglogTypeBrowser
	case BrowserNavigateToolName, BrowserClickToolName, BrowserFillToolName,
		BrowserScreenshotToolName, BrowserEvaluateToolName, BrowserCookiesToolName:
		return database.MsglogTypeBrowser
	case NucleiToolName:
		return database.MsglogTypeTerminal
	case RaceConditionToolName:
		return database.MsglogTypeTerminal
	case InteractshGetURLToolName, InteractshPollToolName, InteractshStatusToolName:
		return database.MsglogTypeTerminal
	case AuthLoginToolName, AuthStatusToolName, AuthInjectToolName, AuthRefreshToolName, AuthLogoutToolName:
		return database.MsglogTypeTerminal
	case AttackPathAnalyzeToolName:
		return database.MsglogTypeSearch
	case MemoristToolName, SearchToolName, GoogleToolName, DuckDuckGoToolName, TavilyToolName, TraversaalToolName,
		PerplexityToolName, SearxngToolName, SploitusToolName,
		SearchGuideToolName, SearchAnswerToolName, SearchCodeToolName, SearchInMemoryToolName, GraphitiSearchToolName:
		return database.MsglogTypeSearch
	case AdviceToolName:
		return database.MsglogTypeAdvice
	case AskUserToolName:
		return database.MsglogTypeAsk
	case FinalyToolName:
		return database.MsglogTypeDone
	default:
		return database.MsglogTypeThoughts
	}
}

func getMessageResultFormat(name string) database.MsglogResultFormat {
	switch name {
	case TerminalToolName:
		return database.MsglogResultFormatTerminal
	case FileToolName, BrowserToolName,
		BrowserNavigateToolName, BrowserClickToolName, BrowserFillToolName,
		BrowserScreenshotToolName, BrowserEvaluateToolName, BrowserCookiesToolName:
		return database.MsglogResultFormatPlain
	default:
		return database.MsglogResultFormatMarkdown
	}
}

// GetRegistryDefinitions returns tool definitions from the tools package
func GetRegistryDefinitions() map[string]llms.FunctionDefinition {
	registry := make(map[string]llms.FunctionDefinition, len(registryDefinitions))
	maps.Copy(registry, registryDefinitions)
	return registry
}

// GetToolTypeMapping returns a mapping from tool names to tool types
func GetToolTypeMapping() map[string]ToolType {
	mapping := make(map[string]ToolType, len(toolsTypeMapping))
	maps.Copy(mapping, toolsTypeMapping)
	return mapping
}

// GetToolsByType returns a mapping from tool types to a list of tool names
func GetToolsByType() map[ToolType][]string {
	result := make(map[ToolType][]string)

	for toolName, toolType := range toolsTypeMapping {
		result[toolType] = append(result[toolType], toolName)
	}

	return result
}
