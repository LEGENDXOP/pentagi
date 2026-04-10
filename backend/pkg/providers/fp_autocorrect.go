package providers

import (
	"context"
	"strings"

	"pentagi/pkg/database"

	"github.com/sirupsen/logrus"
)

// ProcessConfirmationResult scans the result text of a confirmation subtask
// for false positive indicators and automatically updates the findings DB.
//
// Fix SURGEON-C #4: When a confirmation subtask PROVES a finding is false positive,
// the findings DB was never updated. Flow 53 Finding 439 (SQL injection) was proven
// false by subtask 1203 but still showed `critical, false_positive=false`.
//
// This function is called after each subtask completes. It:
// 1. Checks if the subtask is a confirmation/validation subtask (by title keywords)
// 2. Scans the subtask result for FP indicators per-finding
// 3. Updates confirmed/false_positive status in the DB
func ProcessConfirmationResult(
	ctx context.Context,
	db database.Querier,
	flowID int64,
	subtaskTitle string,
	subtaskResult string,
) {
	if subtaskResult == "" {
		return
	}

	// Only process confirmation/validation subtasks
	if !isConfirmationSubtask(subtaskTitle) {
		return
	}

	logger := logrus.WithFields(logrus.Fields{
		"flow_id":        flowID,
		"subtask_title":  subtaskTitle,
	})

	// Get all non-FP findings for this flow
	findings, err := db.GetFlowFindings(ctx, flowID)
	if err != nil {
		logger.WithError(err).Warn("FP auto-correct: failed to load flow findings")
		return
	}

	if len(findings) == 0 {
		return
	}

	resultLower := strings.ToLower(subtaskResult)

	// Check each finding against the confirmation result
	fpUpdated := 0
	confirmedUpdated := 0
	for _, f := range findings {
		// Build search patterns for this finding
		findingIdentifiers := buildFindingIdentifiers(f)

		// Find text sections that reference this finding
		relevantText := extractRelevantText(resultLower, findingIdentifiers)
		if relevantText == "" {
			continue
		}

		// Check for false positive indicators
		if containsFPIndicator(relevantText) {
			err := db.UpdateFindingFalsePositive(ctx, database.UpdateFindingFalsePositiveParams{
				ID:            f.ID,
				FalsePositive: true,
			})
			if err != nil {
				logger.WithError(err).WithField("finding_id", f.ID).
					Warn("FP auto-correct: failed to mark finding as false positive")
				continue
			}
			fpUpdated++
			logger.WithFields(logrus.Fields{
				"finding_id": f.ID,
				"vuln_type":  f.VulnType,
				"endpoint":   f.Endpoint,
			}).Info("FP auto-correct: marked finding as false positive based on confirmation result")
		} else if containsConfirmationIndicator(relevantText) {
			// Confirmed as real vulnerability
			if !f.Confirmed {
				err := db.UpdateFindingConfirmed(ctx, database.UpdateFindingConfirmedParams{
					ID:        f.ID,
					Confirmed: true,
				})
				if err != nil {
					logger.WithError(err).WithField("finding_id", f.ID).
						Warn("FP auto-correct: failed to mark finding as confirmed")
					continue
				}
				confirmedUpdated++
			}
		}
	}

	if fpUpdated > 0 || confirmedUpdated > 0 {
		logger.WithFields(logrus.Fields{
			"fp_marked":    fpUpdated,
			"confirmed":    confirmedUpdated,
			"total_checked": len(findings),
		}).Info("FP auto-correct: processed confirmation subtask results")
	}
}

// isConfirmationSubtask checks if a subtask is a confirmation/validation type.
func isConfirmationSubtask(title string) bool {
	lower := strings.ToLower(title)
	confirmKeywords := []string{
		"confirmation", "validation", "verify", "validate",
		"re-test", "retest", "false positive", "finding review",
		"quality gate", "finding confirmation",
	}
	for _, kw := range confirmKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// buildFindingIdentifiers creates search patterns for locating references
// to a specific finding in confirmation result text.
func buildFindingIdentifiers(f database.Finding) []string {
	var ids []string

	// Vuln type variations
	ids = append(ids, strings.ToLower(f.VulnType))
	ids = append(ids, strings.ReplaceAll(strings.ToLower(f.VulnType), "_", " "))

	// Endpoint if present
	if f.Endpoint != "" {
		ids = append(ids, strings.ToLower(f.Endpoint))
		// Also try just the path portion
		if idx := strings.Index(f.Endpoint, "/"); idx != -1 {
			path := f.Endpoint[idx:]
			if len(path) > 3 {
				ids = append(ids, strings.ToLower(path))
			}
		}
	}

	// Title keywords
	if f.Title != "" {
		ids = append(ids, strings.ToLower(f.Title))
	}

	return ids
}

// extractRelevantText finds sections of the result text that reference a finding.
// Returns a window of text around the reference for FP/confirmation analysis.
func extractRelevantText(resultLower string, identifiers []string) string {
	for _, id := range identifiers {
		if id == "" || len(id) < 3 {
			continue
		}
		idx := strings.Index(resultLower, id)
		if idx >= 0 {
			// Extract a window of 500 chars around the reference
			start := idx - 250
			if start < 0 {
				start = 0
			}
			end := idx + len(id) + 250
			if end > len(resultLower) {
				end = len(resultLower)
			}
			return resultLower[start:end]
		}
	}
	return ""
}

// containsNegation checks if the text before a match index contains negation words.
// It looks at up to 15 characters before the match for common negation patterns.
func containsNegation(text string, matchIdx int) bool {
	start := matchIdx - 15
	if start < 0 {
		start = 0
	}
	prefix := strings.ToLower(text[start:matchIdx])

	negations := []string{"not ", "unable", "un", "no ", "cannot ", "can't ", "never "}
	for _, neg := range negations {
		if strings.Contains(prefix, neg) {
			return true
		}
	}
	return false
}

// containsFPIndicator checks if text contains false positive indicators.
func containsFPIndicator(text string) bool {
	fpPatterns := []string{
		"false positive",
		"not exploitable",
		"not vulnerable",
		"no vulnerability",
		"cannot be exploited",
		"not confirmed",
		"failed to reproduce",
		"could not reproduce",
		"unable to reproduce",
		"not reproducible",
		"does not exist",
		"properly sanitized",
		"properly validated",
		"input is sanitized",
		"input is validated",
		"no injection",
		"not injectable",
		"waf blocking",
		"waf prevented",
		"rate limited",
		"mitigated",
	}
	for _, p := range fpPatterns {
		idx := strings.Index(text, p)
		if idx >= 0 {
			// Negation before an FP indicator cancels it:
			// e.g., "not a false positive" means it IS a real vuln.
			if containsNegation(text, idx) {
				continue
			}
			return true
		}
	}
	return false
}

// containsConfirmationIndicator checks if text contains confirmation indicators.
func containsConfirmationIndicator(text string) bool {
	confirmPatterns := []string{
		"confirmed",
		"verified",
		"successfully exploited",
		"successfully reproduced",
		"vulnerability exists",
		"vulnerability confirmed",
		"exploitable",
		"reproduced",
		"proof of concept",
		"poc successful",
		"injection successful",
	}
	for _, p := range confirmPatterns {
		idx := strings.Index(text, p)
		if idx >= 0 {
			// Negation before a confirmation indicator cancels it:
			// e.g., "not confirmed" means it's NOT confirmed.
			if containsNegation(text, idx) {
				continue
			}
			return true
		}
	}
	return false
}


