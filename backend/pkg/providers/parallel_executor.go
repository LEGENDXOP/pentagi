package providers

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

// ParallelConfig holds configuration for parallel subtask execution.
type ParallelConfig struct {
	Enabled        bool
	MaxConcurrency int
}

// LoadParallelConfigFromEnv loads parallel execution configuration from environment.
func LoadParallelConfigFromEnv() ParallelConfig {
	cfg := ParallelConfig{
		Enabled:        false,
		MaxConcurrency: 3,
	}

	if v := os.Getenv("PARALLEL_SUBTASKS_ENABLED"); v != "" {
		cfg.Enabled = strings.ToLower(v) == "true" || v == "1"
	}

	if v := os.Getenv("PARALLEL_MAX_CONCURRENCY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 10 {
			cfg.MaxConcurrency = n
		}
	}

	return cfg
}

// SubtaskDependencyInfo holds dependency metadata from the LLM's subtask generation.
type SubtaskDependencyInfo struct {
	SubtaskID     int64   `json:"subtask_id"`
	DependsOn     []int64 `json:"depends_on"`      // Subtask IDs this depends on
	ParallelGroup int     `json:"parallel_group"`   // 0-based group number
}

// ValidateDependencyInfo validates LLM-generated dependency metadata.
// Returns cleaned dependencies with invalid references removed.
func ValidateDependencyInfo(deps []SubtaskDependencyInfo, validIDs map[int64]bool) []SubtaskDependencyInfo {
	if len(deps) == 0 {
		return deps
	}

	cleaned := make([]SubtaskDependencyInfo, len(deps))
	for i, d := range deps {
		cleaned[i] = SubtaskDependencyInfo{
			SubtaskID:     d.SubtaskID,
			ParallelGroup: d.ParallelGroup,
		}

		// Only keep valid dependency references.
		for _, depID := range d.DependsOn {
			if depID == d.SubtaskID {
				continue // Remove self-references.
			}
			if !validIDs[depID] {
				continue // Remove references to non-existent subtasks.
			}
			cleaned[i].DependsOn = append(cleaned[i].DependsOn, depID)
		}
	}

	return cleaned
}

// BuildDAGFromDependencies constructs a SubtaskDAG from dependency info.
// Returns the DAG and an error if the dependencies form a cycle.
func BuildDAGFromDependencies(deps []SubtaskDependencyInfo, subtaskTitles map[int64]string) (*SubtaskDAG, error) {
	dag := NewSubtaskDAG()

	for _, d := range deps {
		title := subtaskTitles[d.SubtaskID]
		if title == "" {
			title = fmt.Sprintf("Subtask %d", d.SubtaskID)
		}
		dag.AddNode(d.SubtaskID, title, d.DependsOn, d.ParallelGroup)
	}

	if err := dag.Validate(); err != nil {
		return nil, fmt.Errorf("invalid dependency graph: %w", err)
	}

	return dag, nil
}

// ParallelSubtaskResult holds the result of a single parallel subtask execution.
type ParallelSubtaskResult struct {
	SubtaskID int64
	Result    string
	Error     error
}

// DispatchParallelSubtasks runs subtasks concurrently using the DAG scheduler.
// The executeFn is called for each subtask to perform the actual work.
// This function blocks until all subtasks complete or the context is cancelled.
func DispatchParallelSubtasks(
	ctx context.Context,
	dag *SubtaskDAG,
	config ParallelConfig,
	executeFn func(ctx context.Context, subtaskID int64) (string, error),
) []ParallelSubtaskResult {
	logger := logrus.WithContext(ctx).WithField("component", "parallel_executor")

	var (
		allResults []ParallelSubtaskResult
		resultsMu  sync.Mutex
		wg         sync.WaitGroup
		semaphore  = make(chan struct{}, config.MaxConcurrency)
	)

	for !dag.IsComplete() {
		// Check context cancellation.
		if ctx.Err() != nil {
			logger.WithError(ctx.Err()).Warn("parallel dispatch cancelled")
			break
		}

		ready := dag.GetReady(config.MaxConcurrency)
		if len(ready) == 0 {
			// No ready nodes but DAG not complete — must have in-flight nodes.
			if !dag.HasInFlight() {
				// Deadlock: nothing ready, nothing in-flight, not complete.
				// This shouldn't happen if validation passed, but handle gracefully.
				logger.Error("parallel executor deadlock: no ready or in-flight nodes")
				break
			}
			// Wait for an in-flight node to complete.
			// We use a simple polling approach with the WaitGroup.
			wg.Wait()
			continue
		}

		logger.WithField("ready_count", len(ready)).Debug("dispatching parallel subtasks")

		for _, subtaskID := range ready {
			wg.Add(1)
			semaphore <- struct{}{} // Acquire slot

			go func(id int64) {
				defer wg.Done()
				defer func() { <-semaphore }() // Release slot

				// Create subtask-specific working directory context.
				subtaskCtx := context.WithValue(ctx, subtaskWorkDirKey{}, fmt.Sprintf("/work/subtask-%d", id))

				result, err := executeFn(subtaskCtx, id)

				resultsMu.Lock()
				allResults = append(allResults, ParallelSubtaskResult{
					SubtaskID: id,
					Result:    result,
					Error:     err,
				})
				resultsMu.Unlock()

				if err != nil {
					logger.WithError(err).WithField("subtask_id", id).Warn("parallel subtask failed")
					dag.MarkFailed(id)
				} else {
					dag.MarkCompleted(id)
					logger.WithField("subtask_id", id).Info("parallel subtask completed")
				}
			}(subtaskID)
		}

		// Wait for this batch to complete before checking for newly ready nodes.
		wg.Wait()
	}

	summary := dag.GetCompletionSummary()
	logger.WithFields(logrus.Fields{
		"completed": summary[DAGNodeCompleted],
		"failed":    summary[DAGNodeFailed],
		"blocked":   summary[DAGNodeBlocked],
		"total":     dag.Size(),
	}).Info("parallel execution complete")

	return allResults
}

// subtaskWorkDirKey is a context key for the subtask-specific working directory.
type subtaskWorkDirKey struct{}

// GetSubtaskWorkDir returns the subtask-specific working directory from context.
// Falls back to /work if not set (sequential mode).
func GetSubtaskWorkDir(ctx context.Context) string {
	if dir, ok := ctx.Value(subtaskWorkDirKey{}).(string); ok {
		return dir
	}
	return "/work"
}
