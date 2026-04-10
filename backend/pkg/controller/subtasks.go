package controller

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"pentagi/pkg/database"

	"github.com/sirupsen/logrus"
)

type NewSubtaskInfo struct {
	Title       string
	Description string
}

type SubtaskController interface {
	LoadSubtasks(ctx context.Context, taskID int64, updater TaskUpdater) error
	GenerateSubtasks(ctx context.Context) error
	RefineSubtasks(ctx context.Context) error
	PopSubtask(ctx context.Context, updater TaskUpdater) (SubtaskWorker, error)
	ListSubtasks(ctx context.Context) []SubtaskWorker
	GetSubtask(ctx context.Context, subtaskID int64) (SubtaskWorker, error)
}

type subtaskController struct {
	mx       *sync.Mutex
	taskCtx  *TaskContext
	subtasks map[int64]SubtaskWorker
}

func NewSubtaskController(taskCtx *TaskContext) SubtaskController {
	return &subtaskController{
		mx:       &sync.Mutex{},
		taskCtx:  taskCtx,
		subtasks: make(map[int64]SubtaskWorker),
	}
}

func (stc *subtaskController) LoadSubtasks(ctx context.Context, taskID int64, updater TaskUpdater) error {
	stc.mx.Lock()
	defer stc.mx.Unlock()

	subtasks, err := stc.taskCtx.DB.GetTaskSubtasks(ctx, taskID)
	if err != nil {
		return fmt.Errorf("failed to get subtasks for task %d: %w", taskID, err)
	}

	if len(subtasks) == 0 {
		return fmt.Errorf("no subtasks found for task %d: %w", taskID, ErrNothingToLoad)
	}

	for _, subtask := range subtasks {
		st, err := LoadSubtaskWorker(ctx, subtask, stc.taskCtx, updater)
		if err != nil {
			if errors.Is(err, ErrNothingToLoad) {
				continue
			}

			return fmt.Errorf("failed to create subtask worker: %w", err)
		}

		stc.subtasks[subtask.ID] = st
	}

	return nil
}

// vulnClassKeywords maps vulnerability class names to their identifying keywords.
// Used by warnIfMultiVulnClass to detect subtasks that combine multiple classes.
var vulnClassKeywords = map[string][]string{
	"SSRF":            {"ssrf", "server-side request", "server side request", "cloud metadata", "169.254.169.254", "imds"},
	"IDOR":            {"idor", "bola", "insecure direct object", "broken object level"},
	"SQLi":            {"sqli", "sql injection", "nosql injection", "sql/nosql"},
	"XSS":             {"xss", "cross-site scripting", "cross site scripting"},
	"Auth":            {"auth bypass", "authentication bypass", "jwt", "oauth", "session fixation", "credential"},
	"RCE":             {"rce", "remote code execution", "command injection", "deserialization", "ssti"},
	"Race":            {"race condition", "toctou", "double-spend", "double spend", "single-packet"},
	"BusinessLogic":   {"business logic", "price manipulation", "coupon", "payment manipulation", "amount tampering"},
	"ATO":             {"account takeover", "ato", "password reset poisoning", "mfa bypass"},
	"DataHarvest":     {"data harvest", "sensitive data", ".git", ".env", "swagger", "source map", "s3 enum"},
	"APIAttacks":      {"graphql", "api attack", "batching", "method override", "parameter pollution"},
	"RequestSmuggling":{"smuggling", "cache poisoning", "cache deception", "cl.te", "te.cl"},
}

// warnIfMultiVulnClass logs a warning if a subtask description references
// more than one distinct vulnerability class. This is a safety net — the
// primary enforcement is in the prompt template.
func warnIfMultiVulnClass(taskID int64, title, description string) {
	combined := strings.ToLower(title + " " + description)
	wordCount := len(strings.Fields(description))

	var matched []string
	for class, keywords := range vulnClassKeywords {
		for _, kw := range keywords {
			if strings.Contains(combined, kw) {
				matched = append(matched, class)
				break // one match per class is enough
			}
		}
	}

	logger := logrus.WithFields(logrus.Fields{
		"task_id":        taskID,
		"subtask_title":  title,
		"vuln_classes":   matched,
		"word_count":     wordCount,
	})

	if len(matched) > 1 {
		logger.Warn("[SCOPE_VIOLATION] subtask references >1 vulnerability classes — should be exactly one class per subtask")
	}
	if wordCount > 300 {
		logger.Warn("[SCOPE_VIOLATION] subtask description exceeds 300 words — likely overloaded")
	}
}

func (stc *subtaskController) GenerateSubtasks(ctx context.Context) error {
	plan, err := stc.taskCtx.Provider.GenerateSubtasks(ctx, stc.taskCtx.TaskID)
	if err != nil {
		return fmt.Errorf("failed to generate subtasks for task %d: %w", stc.taskCtx.TaskID, err)
	}

	if len(plan) == 0 {
		return fmt.Errorf("no subtasks generated for task %d", stc.taskCtx.TaskID)
	}

	// Safety-net: warn if any generated subtask spans multiple vulnerability classes.
	for _, info := range plan {
		warnIfMultiVulnClass(stc.taskCtx.TaskID, info.Title, info.Description)
	}

	// TODO: change it to insert subtasks in transaction
	for _, info := range plan {
		_, err := stc.taskCtx.DB.CreateSubtask(ctx, database.CreateSubtaskParams{
			Status:      database.SubtaskStatusCreated,
			TaskID:      stc.taskCtx.TaskID,
			Title:       info.Title,
			Description: info.Description,
		})
		if err != nil {
			return fmt.Errorf("failed to create subtask for task %d: %w", stc.taskCtx.TaskID, err)
		}
	}

	return nil
}

// confirmationSubtaskPrefix is used to mark system-injected confirmation subtasks
// so the refiner cannot delete them.
const confirmationSubtaskPrefix = "[CONFIRMATION] "

func (stc *subtaskController) RefineSubtasks(ctx context.Context) error {
	subtasks, err := stc.taskCtx.DB.GetTaskSubtasks(ctx, stc.taskCtx.TaskID)
	if err != nil {
		return fmt.Errorf("failed to get task %d subtasks: %w", stc.taskCtx.TaskID, err)
	}

	plan, err := stc.taskCtx.Provider.RefineSubtasks(ctx, stc.taskCtx.TaskID)
	if err != nil {
		return fmt.Errorf("failed to refine subtasks for task %d: %w", stc.taskCtx.TaskID, err)
	}

	if len(plan) == 0 {
		return nil // no subtasks refined
	}

	subtaskIDs := make([]int64, 0, len(subtasks))
	for _, subtask := range subtasks {
		if subtask.Status == database.SubtaskStatusCreated {
			// Never delete system-injected confirmation subtasks
			if strings.HasPrefix(subtask.Title, confirmationSubtaskPrefix) {
				logrus.WithFields(logrus.Fields{
					"subtask_id": subtask.ID,
					"title":      subtask.Title,
				}).Info("refiner: preserving system-injected confirmation subtask")
				continue
			}
			subtaskIDs = append(subtaskIDs, subtask.ID)
		}
	}

	// FIX: Prevent the refiner from wiping all planned subtasks.
	// If the refiner returns fewer subtasks than a safety threshold AND the
	// original plan had significantly more, keep the original plan to avoid
	// the premature-finishing bug (Flow 26: 0/9 exploitation subtasks started
	// because refiner returned empty plan after recon).
	if len(subtaskIDs) > 0 && len(plan) == 0 {
		logrus.WithFields(logrus.Fields{
			"task_id":                stc.taskCtx.TaskID,
			"original_planned_count": len(subtaskIDs),
			"refiner_returned_count": 0,
		}).Warn("refiner returned ZERO subtasks — keeping original plan to prevent premature finishing")
		return nil
	}

	// FIX: Also guard against refiner dramatically shrinking the plan.
	// If the original plan has 3+ subtasks and the refiner returns less than
	// 25% of the original, log a warning and keep the original plan.
	if len(subtaskIDs) >= 3 && len(plan)*4 < len(subtaskIDs) {
		logrus.WithFields(logrus.Fields{
			"task_id":                stc.taskCtx.TaskID,
			"original_planned_count": len(subtaskIDs),
			"refiner_returned_count": len(plan),
		}).Warn("refiner dramatically reduced subtask count (>75% reduction) — keeping original plan")
		return nil
	}

	err = stc.taskCtx.DB.DeleteSubtasks(ctx, subtaskIDs)
	if err != nil {
		return fmt.Errorf("failed to delete subtasks for task %d: %w", stc.taskCtx.TaskID, err)
	}

	// TODO: change it to insert subtasks in transaction and union it with delete ones
	for _, info := range plan {
		_, err := stc.taskCtx.DB.CreateSubtask(ctx, database.CreateSubtaskParams{
			Status:      database.SubtaskStatusCreated,
			TaskID:      stc.taskCtx.TaskID,
			Title:       info.Title,
			Description: info.Description,
		})
		if err != nil {
			return fmt.Errorf("failed to create subtask for task %d: %w", stc.taskCtx.TaskID, err)
		}
	}

	return nil
}

func (stc *subtaskController) PopSubtask(ctx context.Context, updater TaskUpdater) (SubtaskWorker, error) {
	stc.mx.Lock()
	defer stc.mx.Unlock()

	subtasks, err := stc.taskCtx.DB.GetTaskPlannedSubtasks(ctx, stc.taskCtx.TaskID)
	if err != nil {
		return nil, fmt.Errorf("failed to get task planned subtasks: %w", err)
	}

	if len(subtasks) == 0 {
		return nil, nil
	}

	stdb := subtasks[0]
	if st, ok := stc.subtasks[stdb.ID]; ok {
		return st, nil
	}

	st, err := NewSubtaskWorker(ctx, stc.taskCtx, stdb.ID, stdb.Title, stdb.Description, updater)
	if err != nil {
		return nil, fmt.Errorf("failed to create subtask worker: %w", err)
	}

	stc.subtasks[stdb.ID] = st

	return st, nil
}

func (stc *subtaskController) ListSubtasks(ctx context.Context) []SubtaskWorker {
	stc.mx.Lock()
	defer stc.mx.Unlock()

	subtasks := make([]SubtaskWorker, 0)
	for _, subtask := range stc.subtasks {
		subtasks = append(subtasks, subtask)
	}

	sort.Slice(subtasks, func(i, j int) bool {
		return subtasks[i].GetSubtaskID() < subtasks[j].GetSubtaskID()
	})

	return subtasks
}

func (stc *subtaskController) GetSubtask(ctx context.Context, subtaskID int64) (SubtaskWorker, error) {
	stc.mx.Lock()
	defer stc.mx.Unlock()

	subtask, ok := stc.subtasks[subtaskID]
	if !ok {
		return nil, fmt.Errorf("subtask not found")
	}

	return subtask, nil
}
