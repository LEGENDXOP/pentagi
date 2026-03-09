package models

// ==================== Attack Path Visualization Models ====================

// AttackPathNode represents a single node (asset) in the attack graph.
// nolint:lll
type AttackPathNode struct {
	ID    string `json:"id"`
	Type  string `json:"type"`  // external, endpoint, service, credential, admin, data
	Label string `json:"label"`
}

// AttackPathEdge represents a directed edge (attack step) in the graph.
// nolint:lll
type AttackPathEdge struct {
	Source      string  `json:"source"`
	Target      string  `json:"target"`
	Label       string  `json:"label"`
	Severity    string  `json:"severity"`
	FindingID   string  `json:"finding_id,omitempty"`
	Weight      float64 `json:"weight"`
	Description string  `json:"description"`
}

// AttackPathStepResponse describes one hop in a computed attack path.
// nolint:lll
type AttackPathStepResponse struct {
	From        string  `json:"from"`
	To          string  `json:"to"`
	FindingID   string  `json:"finding_id,omitempty"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	Weight      float64 `json:"weight"`
}

// AttackPathResponse represents a single computed attack path.
// nolint:lll
type AttackPathResponse struct {
	Steps       []AttackPathStepResponse `json:"steps"`
	TotalWeight float64                  `json:"total_weight"`
	Feasibility string                   `json:"feasibility"` // easy / moderate / hard
	StepsCount  int                      `json:"steps_count"`
	Summary     string                   `json:"summary"`
}

// AttackPathGraphResponse is the full response for the attack paths endpoint.
// nolint:lll
type AttackPathGraphResponse struct {
	FlowID        int64                `json:"flow_id"`
	FindingsCount int                  `json:"findings_count"`
	Nodes         []AttackPathNode     `json:"nodes"`
	Edges         []AttackPathEdge     `json:"edges"`
	Paths         []AttackPathResponse `json:"paths"`
}
