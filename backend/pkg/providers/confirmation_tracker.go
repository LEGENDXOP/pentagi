package providers

import (
	"context"
	"fmt"

	"pentagi/pkg/database"

	"github.com/sirupsen/logrus"
)

const maxConfirmationSubtasks = 2

type ConfirmationStats struct {
	Total       int64
	Confirmed   int64
	Unconfirmed int64
	Rate        float64
}

func GetFlowConfirmationStats(ctx context.Context, db database.Querier, flowID int64) ConfirmationStats {
	row, err := db.GetFlowFindingConfirmationStats(ctx, flowID)
	if err != nil {
		logrus.WithError(err).Warn("confirmation tracker: failed to query DB stats, falling back to registry")
		return ConfirmationStats{Rate: 1.0}
	}
	return ConfirmationStats{
		Total:       row.Total,
		Confirmed:   row.Confirmed,
		Unconfirmed: row.Unconfirmed,
		Rate:        row.Rate,
	}
}

func NeedsConfirmationSubtask(stats ConfirmationStats, completedTestingSubtasks int, injectedCount int) bool {
	if injectedCount >= maxConfirmationSubtasks {
		return false
	}
	if stats.Total == 0 {
		return false
	}
	if stats.Unconfirmed >= 5 {
		return true
	}
	if completedTestingSubtasks >= 2 && stats.Unconfirmed > 0 {
		return true
	}
	return false
}

func NeedsQualityGate(stats ConfirmationStats, injectedCount int) bool {
	if injectedCount >= maxConfirmationSubtasks {
		return false
	}
	if stats.Total < 3 {
		return false
	}
	return stats.Rate < 0.30
}

func BuildConfirmationSubtaskDescription(ctx context.Context, db database.Querier, flowID int64) (string, string) {
	findings, err := db.GetFlowFindings(ctx, flowID)
	if err != nil {
		return "Finding Confirmation",
			"Re-test and validate unconfirmed findings from previous subtasks."
	}

	var unconfirmed []database.Finding
	for _, f := range findings {
		if !f.Confirmed && !f.FalsePositive {
			unconfirmed = append(unconfirmed, f)
		}
	}

	if len(unconfirmed) == 0 {
		return "Finding Confirmation",
			"All findings are confirmed. Verify edge cases for highest-severity items."
	}

	desc := "Re-test and validate these unconfirmed findings:\n"
	for i, f := range unconfirmed {
		if i >= 5 {
			desc += fmt.Sprintf("... and %d more\n", len(unconfirmed)-5)
			break
		}
		desc += fmt.Sprintf("- [%s] %s: %s", f.Severity, f.VulnType, f.Endpoint)
		if f.Endpoint == "" {
			desc += " (no endpoint)"
		}
		desc += "\n"
	}
	desc += "\nFor each finding: reproduce the issue, capture HTTP evidence, and mark as confirmed or false positive."

	return "Finding Confirmation & Validation", desc
}

func FormatConfirmationForRefiner(stats ConfirmationStats) string {
	if stats.Total == 0 {
		return ""
	}
	return fmt.Sprintf(
		"FINDING CONFIRMATION STATUS: %d/%d confirmed (%.0f%% rate). %d unconfirmed findings need validation.",
		stats.Confirmed, stats.Total, stats.Rate*100, stats.Unconfirmed,
	)
}
