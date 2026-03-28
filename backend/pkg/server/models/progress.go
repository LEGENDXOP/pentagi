package models

import (
	"time"
)

// ==================== Progress Dashboard Models ====================

// FlowProgressResponse represents the real-time execution progress of a flow.
// It aggregates data from the flow controller, execution state, subtask context,
// and database queries to provide a unified progress view.
// nolint:lll
type FlowProgressResponse struct {
	FlowID          int64  `json:"flow_id"`
	Status          string `json:"status"`
	Phase           string `json:"phase"`
	ToolCallCount   int    `json:"tool_call_count"`
	ElapsedSeconds  int    `json:"elapsed_seconds"`
	FindingsCount   int    `json:"findings_count"`
	UniqueFindings  int    `json:"unique_findings"`
	AttacksDone     int    `json:"attacks_done"`
	AttacksTotal    int    `json:"attacks_total"`
	ErrorCount      int    `json:"error_count"`
	CurrentAttack   string `json:"current_attack"`
	TasksCount      int    `json:"tasks_count"`
	SubtasksCount   int    `json:"subtasks_count"`
	SubtasksDone    int    `json:"subtasks_done"`
	SubtasksRunning int    `json:"subtasks_running"`
}

// FlowFinding represents a single vulnerability finding for dashboard display.
// nolint:lll
type FlowFinding struct {
	ID                   string   `json:"id"`
	VulnType             string   `json:"vuln_type"`
	Endpoint             string   `json:"endpoint"`
	Severity             string   `json:"severity"`
	Description          string   `json:"description"`
	RootCauseID          string   `json:"root_cause_id"`
	OWASP                string   `json:"owasp"`
	CWEIDs               []string `json:"cwe_ids"`
	CVSS                 float64  `json:"cvss"`
	EvidenceCount        int      `json:"evidence_count"`
	RemediationAvailable bool     `json:"remediation_available"`
}

// FlowFindingsResponse wraps findings list with metadata.
// nolint:lll
type FlowFindingsResponse struct {
	FlowID         int64         `json:"flow_id"`
	Findings       []FlowFinding `json:"findings"`
	TotalCount     int           `json:"total_count"`
	UniqueCount    int           `json:"unique_count"`
	DuplicateCount int           `json:"duplicate_count"`
}

// FlowCostResponse provides cost tracking data for a flow.
// nolint:lll
type FlowCostResponse struct {
	FlowID          int64              `json:"flow_id"`
	TotalTokensIn   int64              `json:"total_tokens_in"`
	TotalTokensOut  int64              `json:"total_tokens_out"`
	TotalCostUSD    float64            `json:"total_cost_usd"`
	CostPerFinding  float64            `json:"cost_per_finding"`
	BreakdownByType []FlowCostBreakdown `json:"breakdown_by_type"`
}

// FlowCostBreakdown represents cost for a single agent type within a flow.
// nolint:lll
type FlowCostBreakdown struct {
	AgentType    string  `json:"agent_type"`
	InputTokens  int64   `json:"input_tokens"`
	OutputTokens int64   `json:"output_tokens"`
	CostUSD      float64 `json:"cost_usd"`
}

// TimelineEventType enumerates the types of timeline events.
type TimelineEventType string

const (
	TimelineEventFinding     TimelineEventType = "finding"
	TimelineEventAttackStart TimelineEventType = "attack_start"
	TimelineEventAttackEnd   TimelineEventType = "attack_end"
	TimelineEventPhaseChange TimelineEventType = "phase_change"
	TimelineEventError       TimelineEventType = "error"
	TimelineEventTaskCreated TimelineEventType = "task_created"
	TimelineEventSubtask     TimelineEventType = "subtask"
	TimelineEventToolCall    TimelineEventType = "tool_call"
)

// FlowTimelineEvent represents a single event in the flow execution timeline.
// nolint:lll
type FlowTimelineEvent struct {
	Timestamp   time.Time         `json:"timestamp"`
	EventType   TimelineEventType `json:"event_type"`
	Description string            `json:"description"`
}

// FlowTimelineResponse wraps the timeline events list.
// nolint:lll
type FlowTimelineResponse struct {
	FlowID int64                `json:"flow_id"`
	Events []FlowTimelineEvent  `json:"events"`
}

// SSEProgressEvent is the payload sent over SSE for real-time progress updates.
// nolint:lll
type SSEProgressEvent struct {
	EventType string      `json:"event_type"` // "progress", "finding", "cost", "timeline", "error"
	Data      interface{} `json:"data"`
}
