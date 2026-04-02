package providers

import (
	"context"
	"fmt"
	"strings"

	"pentagi/pkg/templates"
	"pentagi/pkg/tools"

	"github.com/sirupsen/logrus"
)

// AttackPhaseClassifier classifies tool calls into attack phases based on tool name patterns.
// This classification drives the budget manager's phase and vector tracking.

// reconTools are tool names associated with the reconnaissance phase.
var reconTools = map[string]bool{
	tools.SearchToolName:          true,
	tools.BrowserToolName:         true,
	tools.SearchGuideToolName:     true,
	tools.SearchAnswerToolName:    true,
	tools.SearchCodeToolName:      true,
	tools.GraphitiSearchToolName:  true,
	tools.DuckDuckGoToolName:      true,
	tools.GoogleToolName:          true,
	tools.TavilyToolName:         true,
	tools.TraversaalToolName:     true,
	tools.PerplexityToolName:     true,
	tools.SearxngToolName:        true,
	tools.SploitusToolName:       true,
	tools.SearchInMemoryToolName: true,
}

// postExploitTools are tool names associated with the post-exploitation phase.
var postExploitTools = map[string]bool{
	tools.StoreGuideToolName:  true,
	tools.StoreAnswerToolName: true,
	tools.StoreCodeToolName:   true,
}

// ClassifyToolPhase determines the attack phase for a given tool call.
// Tool calls that don't match specific patterns default to AttackPhaseAttack.
func ClassifyToolPhase(toolName string) AttackPhase {
	if reconTools[toolName] {
		return AttackPhaseRecon
	}
	if postExploitTools[toolName] {
		return AttackPhasePostExploit
	}
	return AttackPhaseAttack
}

// ClassifyToolVector determines the attack vector name from a tool call.
// The vector is the tool name itself (normalized), which provides granular tracking.
func ClassifyToolVector(toolName string) string {
	// Normalize: strip common suffixes for grouping
	vector := strings.ToLower(toolName)
	return vector
}

// IsToolCallSuccess determines whether a tool call was successful based on the response.
// A tool call is considered failed if the response indicates an error.
func IsToolCallSuccess(response string, isRepeating bool) bool {
	if isRepeating {
		return false
	}

	// Check for common error indicators in the response
	lower := strings.ToLower(response)
	errorIndicators := []string{
		"error:",
		"failed:",
		"not found",
		"permission denied",
		"connection refused",
		"timed out",
		"timeout",
		"command not found",
		"no such file",
		"access denied",
		"403 forbidden",
		"request blocked",
		"blocked by",
		"web application firewall",
		"captcha",
	}

	for _, indicator := range errorIndicators {
		if strings.Contains(lower, indicator) {
			return false
		}
	}

	return true
}

// BudgetPivotAction describes what the agent loop should do when a budget is exhausted.
type BudgetPivotAction struct {
	ShouldPivot  bool
	PivotMessage string // rendered pivot prompt to inject into the chain
	Phase        AttackPhase
	Vector       string
	Reason       string
}

// CheckAndBuildPivot checks the budget for the current tool context and,
// if exhausted, renders a pivot prompt using the template system.
func CheckAndBuildPivot(
	ctx context.Context,
	budgetMgr *AttackBudgetManager,
	prompter templates.Prompter,
	toolName string,
) *BudgetPivotAction {
	if budgetMgr == nil {
		return nil
	}

	phase := ClassifyToolPhase(toolName)
	vector := ClassifyToolVector(toolName)

	result := budgetMgr.CheckBudget(phase, vector)
	if result.OK {
		return nil
	}

	// Budget exhausted — build a pivot instruction
	suggestion := budgetMgr.GetPivotSuggestion()

	pivotContext := map[string]any{
		"ExhaustedVector": fmt.Sprintf("%s/%s", result.Phase, result.Vector),
		"Phase":           string(result.Phase),
		"TimeSpent":       "unknown",
		"Attempts":        0,
		"Failures":        0,
		"Reason":          result.Reason,
		"BudgetSummary":   budgetMgr.GetBudgetSummary(),
	}

	if suggestion != nil {
		pivotContext["TimeSpent"] = suggestion.TimeSpent.String()
		pivotContext["Attempts"] = suggestion.Attempts
		pivotContext["Failures"] = suggestion.Failures
		pivotContext["SuggestedVectors"] = suggestion.NextVectors
	}

	// Render the pivot template
	pivotMessage, err := prompter.RenderTemplate(templates.PromptTypePivot, pivotContext)
	if err != nil {
		logrus.WithContext(ctx).WithError(err).Warn("failed to render pivot template, using fallback message")
		pivotMessage = fmt.Sprintf(
			"[AUTO-PIVOT] Budget exhausted for %s/%s: %s. Switch to a different attack vector immediately.",
			result.Phase, result.Vector, result.Reason,
		)
	}

	return &BudgetPivotAction{
		ShouldPivot:  true,
		PivotMessage: pivotMessage,
		Phase:        result.Phase,
		Vector:       result.Vector,
		Reason:       result.Reason,
	}
}

// RenderStrategyPlanner renders the strategy planner template for injection into
// the subtask generation flow, making the agent aware of budget constraints.
func RenderStrategyPlanner(
	prompter templates.Prompter,
	taskInput string,
	cfg AttackBudgetConfig,
) (string, error) {
	plannerContext := map[string]any{
		"TaskInput":          taskInput,
		"ReconMinutes":       cfg.ReconMinutes,
		"AttackMinutes":      cfg.AttackMinutes,
		"PostExploitMinutes": cfg.PostExploitMinutes,
		"FailureLimit":       cfg.FailureLimit,
	}

	return prompter.RenderTemplate(templates.PromptTypeStrategyPlanner, plannerContext)
}
