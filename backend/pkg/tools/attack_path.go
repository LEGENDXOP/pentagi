package tools

import (
	"container/heap"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"

	"pentagi/pkg/database"

	"github.com/sirupsen/logrus"
)

// ──────────────────────────────────────────────────────────────────────────────
// Tool argument schema
// ──────────────────────────────────────────────────────────────────────────────

// AttackPathAnalyzeAction is the JSON-schema input for the attack_path_analyze tool.
type AttackPathAnalyzeAction struct {
	Target  string `json:"target,omitempty" jsonschema_description:"Optional target filter (IP, hostname, or URL prefix). When empty all findings for the current flow are analysed."`
	MaxHops Int64  `json:"max_hops" jsonschema:"type=integer" jsonschema_description:"Maximum number of hops (edges) in any single attack path (minimum 2; maximum 10; default 6)"`
	Message string `json:"message" jsonschema:"required,title=Analysis request message" jsonschema_description:"Short description of what you want to analyse and why, in English"`
}

// ──────────────────────────────────────────────────────────────────────────────
// In-memory graph primitives
// ──────────────────────────────────────────────────────────────────────────────

// AssetType classifies nodes in the attack graph.
type AssetType string

const (
	AssetExternal   AssetType = "external"    // attacker entry point
	AssetEndpoint   AssetType = "endpoint"    // URL / IP:port
	AssetService    AssetType = "service"     // detected service
	AssetCredential AssetType = "credential"  // credential / token
	AssetAdmin      AssetType = "admin"       // admin-level access
	AssetData       AssetType = "data"        // sensitive data store
	AssetUnknown    AssetType = "unknown"
)

// GraphNode represents a single asset in the attack graph.
type GraphNode struct {
	ID    string    `json:"id"`
	Type  AssetType `json:"type"`
	Label string    `json:"label"`
}

// GraphEdge represents an attack step between two assets.
type GraphEdge struct {
	Source      string  `json:"source"`
	Target      string  `json:"target"`
	Label       string  `json:"label"`
	Severity    string  `json:"severity"`
	FindingID   string  `json:"finding_id,omitempty"`
	Weight      float64 `json:"weight"`       // lower = easier to exploit
	Description string  `json:"description"`
}

// AttackPathStep describes a single hop in a computed path.
type AttackPathStep struct {
	From        string  `json:"from"`
	To          string  `json:"to"`
	FindingID   string  `json:"finding_id,omitempty"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	Weight      float64 `json:"weight"`
}

// AttackPath is one computed shortest path from an entry to a target.
type AttackPath struct {
	Steps         []AttackPathStep `json:"steps"`
	TotalWeight   float64          `json:"total_weight"`
	Feasibility   string           `json:"feasibility"` // easy / moderate / hard
	StepsCount    int              `json:"steps_count"`
	Summary       string           `json:"summary"`
}

// AttackGraph holds the full graph + computed paths.
type AttackGraph struct {
	Nodes []GraphNode  `json:"nodes"`
	Edges []GraphEdge  `json:"edges"`
	Paths []AttackPath `json:"paths"`
}

// ──────────────────────────────────────────────────────────────────────────────
// Internal adjacency-list graph used for path computation
// ──────────────────────────────────────────────────────────────────────────────

type adjEdge struct {
	to     string
	weight float64
	edge   GraphEdge
}

type graph struct {
	nodes map[string]GraphNode
	adj   map[string][]adjEdge
}

func newGraph() *graph {
	return &graph{
		nodes: make(map[string]GraphNode),
		adj:   make(map[string][]adjEdge),
	}
}

func (g *graph) addNode(n GraphNode) {
	g.nodes[n.ID] = n
}

func (g *graph) addEdge(e GraphEdge) {
	g.adj[e.Source] = append(g.adj[e.Source], adjEdge{
		to:     e.Target,
		weight: e.Weight,
		edge:   e,
	})
}

// ──────────────────────────────────────────────────────────────────────────────
// Dijkstra implementation
// ──────────────────────────────────────────────────────────────────────────────

type dijkstraItem struct {
	node string
	dist float64
	idx  int
}

type priorityQueue []*dijkstraItem

func (pq priorityQueue) Len() int            { return len(pq) }
func (pq priorityQueue) Less(i, j int) bool  { return pq[i].dist < pq[j].dist }
func (pq priorityQueue) Swap(i, j int)       { pq[i], pq[j] = pq[j], pq[i]; pq[i].idx = i; pq[j].idx = j }
func (pq *priorityQueue) Push(x any)         { item := x.(*dijkstraItem); item.idx = len(*pq); *pq = append(*pq, item) }
func (pq *priorityQueue) Pop() any           { old := *pq; n := len(old); item := old[n-1]; old[n-1] = nil; item.idx = -1; *pq = old[:n-1]; return item }

// dijkstra returns shortest distances and predecessor map from source.
func dijkstra(g *graph, source string, maxHops int) (dist map[string]float64, prev map[string]string, prevEdge map[string]GraphEdge, hops map[string]int) {
	dist = make(map[string]float64)
	prev = make(map[string]string)
	prevEdge = make(map[string]GraphEdge)
	hops = make(map[string]int)

	for id := range g.nodes {
		dist[id] = math.Inf(1)
	}
	dist[source] = 0
	hops[source] = 0

	pq := &priorityQueue{}
	heap.Init(pq)
	heap.Push(pq, &dijkstraItem{node: source, dist: 0})

	for pq.Len() > 0 {
		cur := heap.Pop(pq).(*dijkstraItem)
		if cur.dist > dist[cur.node] {
			continue
		}
		if hops[cur.node] >= maxHops {
			continue
		}
		for _, e := range g.adj[cur.node] {
			alt := dist[cur.node] + e.weight
			if alt < dist[e.to] {
				dist[e.to] = alt
				prev[e.to] = cur.node
				prevEdge[e.to] = e.edge
				hops[e.to] = hops[cur.node] + 1
				heap.Push(pq, &dijkstraItem{node: e.to, dist: alt})
			}
		}
	}
	return
}

// reconstructPath builds an AttackPath from Dijkstra's predecessor map.
func reconstructPath(target string, dist map[string]float64, prev map[string]string, prevEdge map[string]GraphEdge) *AttackPath {
	if math.IsInf(dist[target], 1) {
		return nil
	}
	var steps []AttackPathStep
	cur := target
	for {
		p, ok := prev[cur]
		if !ok {
			break
		}
		edge := prevEdge[cur]
		steps = append(steps, AttackPathStep{
			From:        edge.Source,
			To:          edge.Target,
			FindingID:   edge.FindingID,
			Description: edge.Description,
			Severity:    edge.Severity,
			Weight:      edge.Weight,
		})
		cur = p
	}
	// Reverse to get source → target order.
	for i, j := 0, len(steps)-1; i < j; i, j = i+1, j-1 {
		steps[i], steps[j] = steps[j], steps[i]
	}

	totalWeight := dist[target]
	feasibility := "hard"
	if totalWeight < 3 {
		feasibility = "easy"
	} else if totalWeight < 6 {
		feasibility = "moderate"
	}

	summary := buildPathSummary(steps)
	return &AttackPath{
		Steps:       steps,
		TotalWeight: totalWeight,
		Feasibility: feasibility,
		StepsCount:  len(steps),
		Summary:     summary,
	}
}

func buildPathSummary(steps []AttackPathStep) string {
	if len(steps) == 0 {
		return "empty path"
	}
	parts := make([]string, len(steps))
	for i, s := range steps {
		parts[i] = fmt.Sprintf("Step %d: %s → %s via %s [%s]", i+1, s.From, s.To, s.Description, s.Severity)
	}
	return strings.Join(parts, " | ")
}

// ──────────────────────────────────────────────────────────────────────────────
// Finding → Graph builder
// ──────────────────────────────────────────────────────────────────────────────

var (
	findingRe  = regexp.MustCompile(`(?i)\[FINDING:\s*(\S+)\]`)
	vulnTypeRe = regexp.MustCompile(`(?i)\[VULN_TYPE:\s*([^\]]+)\]`)
	severityRe = regexp.MustCompile(`(?i)Severity:\s*(Critical|High|Medium|Low|Info)`)
	targetRe   = regexp.MustCompile(`(?i)Target:\s*(\S+)`)
	titleRe    = regexp.MustCompile(`(?i)Title:\s*(.+)`)
)

// ParsedFinding holds a single extracted finding from subtask results.
type ParsedFinding struct {
	ID       string
	Title    string
	VulnType string
	Severity string
	Target   string
	RawText  string
}

func severityWeight(sev string) float64 {
	switch strings.ToLower(sev) {
	case "critical":
		return 0.5
	case "high":
		return 1.0
	case "medium":
		return 2.0
	case "low":
		return 3.5
	case "info":
		return 5.0
	default:
		return 3.0
	}
}

func classifyVulnType(vt string) AssetType {
	vt = strings.ToLower(vt)
	switch {
	case strings.Contains(vt, "auth_bypass") || strings.Contains(vt, "broken_auth") || strings.Contains(vt, "session"):
		return AssetCredential
	case strings.Contains(vt, "privilege") || strings.Contains(vt, "idor") || strings.Contains(vt, "admin"):
		return AssetAdmin
	case strings.Contains(vt, "sqli") || strings.Contains(vt, "command") || strings.Contains(vt, "rce") || strings.Contains(vt, "deserialization"):
		return AssetData
	case strings.Contains(vt, "ssrf") || strings.Contains(vt, "xxe"):
		return AssetService
	default:
		return AssetEndpoint
	}
}

func nodeID(label string) string {
	h := sha256.Sum256([]byte(label))
	return fmt.Sprintf("n_%x", h[:8])
}

func parseFindings(results []string) []ParsedFinding {
	var findings []ParsedFinding
	for _, text := range results {
		// Split by [FINDING to handle multiple findings in one result.
		segments := strings.Split(text, "[FINDING")
		for _, seg := range segments[1:] { // skip text before first [FINDING
			seg = "[FINDING" + seg
			f := ParsedFinding{RawText: seg}

			if m := findingRe.FindStringSubmatch(seg); len(m) > 1 {
				f.ID = strings.TrimSuffix(m[1], "]")
			}
			if m := titleRe.FindStringSubmatch(seg); len(m) > 1 {
				f.Title = strings.TrimSpace(m[1])
			}
			if m := vulnTypeRe.FindStringSubmatch(seg); len(m) > 1 {
				f.VulnType = strings.TrimSpace(m[1])
			}
			if m := severityRe.FindStringSubmatch(seg); len(m) > 1 {
				f.Severity = strings.TrimSpace(m[1])
			}
			if m := targetRe.FindStringSubmatch(seg); len(m) > 1 {
				f.Target = strings.TrimSpace(m[1])
			}
			if f.ID == "" && f.VulnType == "" {
				continue // not a real finding
			}
			if f.ID == "" {
				f.ID = fmt.Sprintf("F%03d", len(findings)+1)
			}
			if f.Severity == "" {
				f.Severity = "Medium"
			}
			if f.Title == "" {
				f.Title = f.VulnType
			}
			findings = append(findings, f)
		}
	}
	return findings
}

// BuildAttackGraph constructs the in-memory graph from parsed findings.
func BuildAttackGraph(findings []ParsedFinding, maxHops int) *AttackGraph {
	g := newGraph()

	// Always add a virtual external entry point.
	externalNode := GraphNode{ID: "external", Type: AssetExternal, Label: "Attacker (external)"}
	g.addNode(externalNode)

	// Deduplicate nodes by label.
	nodeByLabel := map[string]string{"Attacker (external)": "external"}

	getOrCreateNode := func(label string, typ AssetType) string {
		if id, ok := nodeByLabel[label]; ok {
			return id
		}
		id := nodeID(label)
		g.addNode(GraphNode{ID: id, Type: typ, Label: label})
		nodeByLabel[label] = id
		return id
	}

	// Build edges from findings.
	var graphEdges []GraphEdge
	for _, f := range findings {
		targetLabel := f.Target
		if targetLabel == "" {
			targetLabel = "unknown-target"
		}

		destinationType := classifyVulnType(f.VulnType)
		targetNodeID := getOrCreateNode(targetLabel, AssetEndpoint)

		// Create an edge from external → target endpoint.
		weight := severityWeight(f.Severity)
		edgeLabel := f.VulnType
		if edgeLabel == "" {
			edgeLabel = f.Title
		}

		edge := GraphEdge{
			Source:      "external",
			Target:      targetNodeID,
			Label:       edgeLabel,
			Severity:    f.Severity,
			FindingID:   f.ID,
			Weight:      weight,
			Description: f.Title,
		}
		g.addEdge(edge)
		graphEdges = append(graphEdges, edge)

		// If the vuln leads to a deeper asset (credential, admin, data), add a second hop.
		if destinationType != AssetEndpoint && destinationType != AssetUnknown {
			deepLabel := fmt.Sprintf("%s (%s)", destinationType, targetLabel)
			deepNodeID := getOrCreateNode(deepLabel, destinationType)
			chainEdge := GraphEdge{
				Source:      targetNodeID,
				Target:      deepNodeID,
				Label:       fmt.Sprintf("exploit_%s", f.VulnType),
				Severity:    f.Severity,
				FindingID:   f.ID,
				Weight:      weight * 0.5, // chaining from discovered vuln is easier
				Description: fmt.Sprintf("Exploit %s to reach %s", f.VulnType, destinationType),
			}
			g.addEdge(chainEdge)
			graphEdges = append(graphEdges, chainEdge)
		}
	}

	// Add a virtual admin target if any admin-type nodes exist.
	adminTargetID := ""
	for _, n := range g.nodes {
		if n.Type == AssetAdmin {
			if adminTargetID == "" {
				adminTargetID = "admin_takeover"
				g.addNode(GraphNode{ID: adminTargetID, Type: AssetAdmin, Label: "Admin Takeover"})
			}
			edge := GraphEdge{
				Source:      n.ID,
				Target:      adminTargetID,
				Label:       "escalate_to_admin",
				Severity:    "Critical",
				Weight:      0.5,
				Description: fmt.Sprintf("Escalate from %s to full admin", n.Label),
			}
			g.addEdge(edge)
			graphEdges = append(graphEdges, edge)
		}
	}

	// Compute shortest paths from external to every reachable node.
	dist, prev, prevEdge, _ := dijkstra(g, "external", maxHops)

	// Collect interesting target nodes (non-external, non-unknown).
	type targetCandidate struct {
		id   string
		node GraphNode
		dist float64
	}
	var candidates []targetCandidate
	for id, n := range g.nodes {
		if id == "external" {
			continue
		}
		if math.IsInf(dist[id], 1) {
			continue
		}
		candidates = append(candidates, targetCandidate{id: id, node: n, dist: dist[id]})
	}

	// Sort by distance (most exploitable first) then by type priority.
	typePriority := map[AssetType]int{
		AssetAdmin:      0,
		AssetData:       1,
		AssetCredential: 2,
		AssetService:    3,
		AssetEndpoint:   4,
	}
	sort.Slice(candidates, func(i, j int) bool {
		pi := typePriority[candidates[i].node.Type]
		pj := typePriority[candidates[j].node.Type]
		if pi != pj {
			return pi < pj
		}
		return candidates[i].dist < candidates[j].dist
	})

	// Take top 10 paths.
	limit := 10
	if len(candidates) < limit {
		limit = len(candidates)
	}

	var paths []AttackPath
	for _, c := range candidates[:limit] {
		path := reconstructPath(c.id, dist, prev, prevEdge)
		if path != nil && len(path.Steps) > 0 {
			paths = append(paths, *path)
		}
	}

	// Build output node list.
	var nodes []GraphNode
	for _, n := range g.nodes {
		nodes = append(nodes, n)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })

	return &AttackGraph{
		Nodes: nodes,
		Edges: graphEdges,
		Paths: paths,
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// AttackPathTool — implements the tool pattern
// ──────────────────────────────────────────────────────────────────────────────

// AttackPathTool analyses findings for a flow and computes attack paths.
type AttackPathTool struct {
	flowID    int64
	taskID    *int64
	subtaskID *int64
	db        database.Querier
}

// NewAttackPathTool creates a new attack-path analysis tool.
func NewAttackPathTool(
	flowID int64,
	taskID, subtaskID *int64,
	db database.Querier,
) *AttackPathTool {
	return &AttackPathTool{
		flowID:    flowID,
		taskID:    taskID,
		subtaskID: subtaskID,
		db:        db,
	}
}

// IsAvailable always returns true — the tool only needs DB access.
func (t *AttackPathTool) IsAvailable() bool {
	return t.db != nil
}

// Handle implements ExecutorHandler.
func (t *AttackPathTool) Handle(ctx context.Context, name string, args json.RawMessage) (string, error) {
	logger := logrus.WithContext(ctx).WithFields(enrichLogrusFields(t.flowID, t.taskID, t.subtaskID, logrus.Fields{
		"tool": name,
		"args": string(args),
	}))

	var action AttackPathAnalyzeAction
	if err := json.Unmarshal(args, &action); err != nil {
		logger.WithError(err).Error("failed to unmarshal attack_path_analyze args")
		return "", fmt.Errorf("failed to unmarshal args: %w", err)
	}

	maxHops := action.MaxHops.Int()
	if maxHops < 2 {
		maxHops = 6
	}
	if maxHops > 10 {
		maxHops = 10
	}

	// Gather all subtask results for this flow.
	results, err := collectFlowResults(ctx, t.db, t.flowID)
	if err != nil {
		logger.WithError(err).Error("failed to collect flow results")
		return "", fmt.Errorf("failed to collect flow results: %w", err)
	}

	if len(results) == 0 {
		return "No findings discovered yet for this flow. Run reconnaissance and vulnerability scanning first.", nil
	}

	// Optionally filter by target.
	target := strings.TrimSpace(action.Target)
	if target != "" {
		var filtered []string
		for _, r := range results {
			if strings.Contains(strings.ToLower(r), strings.ToLower(target)) {
				filtered = append(filtered, r)
			}
		}
		if len(filtered) == 0 {
			return fmt.Sprintf("No findings matching target filter '%s'. Try without a filter.", target), nil
		}
		results = filtered
	}

	findings := parseFindings(results)
	if len(findings) == 0 {
		return "No structured findings (with [FINDING] markers) found in flow results. Ensure findings are tagged with [FINDING: ID] and [VULN_TYPE: tag].", nil
	}

	attackGraph := BuildAttackGraph(findings, maxHops)

	return formatAttackGraphResult(attackGraph, findings), nil
}

// collectFlowResults gathers all subtask results for a flow.
func collectFlowResults(ctx context.Context, db database.Querier, flowID int64) ([]string, error) {
	tasks, err := db.GetFlowTasks(ctx, flowID)
	if err != nil {
		return nil, fmt.Errorf("failed to get flow tasks: %w", err)
	}

	var results []string
	for _, task := range tasks {
		subtasks, err := db.GetTaskSubtasks(ctx, task.ID)
		if err != nil {
			continue
		}
		for _, st := range subtasks {
			if strings.Contains(st.Result, "[FINDING") {
				results = append(results, st.Result)
			}
		}
	}
	return results, nil
}

// formatAttackGraphResult builds a markdown report for agent consumption.
func formatAttackGraphResult(ag *AttackGraph, findings []ParsedFinding) string {
	var b strings.Builder

	b.WriteString("# Attack Path Analysis Report\n\n")
	b.WriteString(fmt.Sprintf("**Findings analysed:** %d\n", len(findings)))
	b.WriteString(fmt.Sprintf("**Graph nodes:** %d | **Edges:** %d\n", len(ag.Nodes), len(ag.Edges)))
	b.WriteString(fmt.Sprintf("**Attack paths found:** %d\n\n", len(ag.Paths)))

	if len(ag.Paths) == 0 {
		b.WriteString("No viable attack paths could be computed from the current findings.\n")
		b.WriteString("This may mean findings are isolated and do not chain together.\n")
		return b.String()
	}

	// Shortest/easiest path first.
	b.WriteString("## Computed Attack Paths (sorted by feasibility)\n\n")
	for i, p := range ag.Paths {
		b.WriteString(fmt.Sprintf("### Path %d — %d steps to %s [%s, weight=%.1f]\n\n",
			i+1, p.StepsCount, p.Steps[len(p.Steps)-1].To, p.Feasibility, p.TotalWeight))
		for j, s := range p.Steps {
			b.WriteString(fmt.Sprintf("%d. **%s** → **%s**\n", j+1, s.From, s.To))
			b.WriteString(fmt.Sprintf("   - Vulnerability: %s (Severity: %s)\n", s.Description, s.Severity))
			if s.FindingID != "" {
				b.WriteString(fmt.Sprintf("   - Finding: %s\n", s.FindingID))
			}
		}
		b.WriteString(fmt.Sprintf("\n**Summary:** %s\n\n", p.Summary))
	}

	// Graph data in JSON for frontend.
	b.WriteString("## Graph Data (JSON)\n\n")
	b.WriteString("```json\n")
	graphJSON, _ := json.MarshalIndent(ag, "", "  ")
	b.Write(graphJSON)
	b.WriteString("\n```\n")

	return b.String()
}

// ──────────────────────────────────────────────────────────────────────────────
// Exported helpers for use by the API service layer
// ──────────────────────────────────────────────────────────────────────────────

// ParseFindingsFromResults extracts structured findings from raw subtask result strings.
// This is an exported wrapper around parseFindings for the API service.
func ParseFindingsFromResults(results []string) []ParsedFinding {
	return parseFindings(results)
}

// BuildAttackGraphFromParsed builds an attack graph from already-parsed findings.
// This is an exported alias of BuildAttackGraph for the API service.
func BuildAttackGraphFromParsed(findings []ParsedFinding, maxHops int) *AttackGraph {
	return BuildAttackGraph(findings, maxHops)
}
