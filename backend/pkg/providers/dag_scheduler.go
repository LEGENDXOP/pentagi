package providers

import (
	"fmt"
	"sync"
)

// DAGNodeStatus represents the execution state of a node in the DAG.
type DAGNodeStatus string

const (
	DAGNodeReady      DAGNodeStatus = "ready"
	DAGNodeWaiting    DAGNodeStatus = "waiting"
	DAGNodeDispatched DAGNodeStatus = "dispatched"
	DAGNodeCompleted  DAGNodeStatus = "completed"
	DAGNodeFailed     DAGNodeStatus = "failed"
	DAGNodeBlocked    DAGNodeStatus = "blocked" // Blocked by a failed dependency.
)

// DAGNode represents a single subtask in the dependency graph.
type DAGNode struct {
	SubtaskID     int64
	Title         string
	DependsOn     []int64       // Subtask IDs this node depends on.
	ParallelGroup int           // Subtasks in the same group can run concurrently.
	Status        DAGNodeStatus
	DepCount      int           // Number of unsatisfied dependencies.
}

// SubtaskDAG represents a directed acyclic graph of subtask dependencies.
// It is goroutine-safe.
type SubtaskDAG struct {
	mu    sync.Mutex
	nodes map[int64]*DAGNode
	order []int64 // Insertion order for deterministic iteration.
}

// NewSubtaskDAG creates a new empty DAG.
func NewSubtaskDAG() *SubtaskDAG {
	return &SubtaskDAG{
		nodes: make(map[int64]*DAGNode),
	}
}

// AddNode adds a subtask to the DAG.
func (d *SubtaskDAG) AddNode(subtaskID int64, title string, dependsOn []int64, parallelGroup int) {
	d.mu.Lock()
	defer d.mu.Unlock()

	depCount := len(dependsOn)
	status := DAGNodeWaiting
	if depCount == 0 {
		status = DAGNodeReady
	}

	d.nodes[subtaskID] = &DAGNode{
		SubtaskID:     subtaskID,
		Title:         title,
		DependsOn:     dependsOn,
		ParallelGroup: parallelGroup,
		Status:        status,
		DepCount:      depCount,
	}
	d.order = append(d.order, subtaskID)
}

// Validate checks the DAG for cycles and invalid references.
// Returns an error if the DAG is invalid.
func (d *SubtaskDAG) Validate() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Check for invalid references.
	for _, node := range d.nodes {
		for _, depID := range node.DependsOn {
			if _, ok := d.nodes[depID]; !ok {
				return fmt.Errorf("subtask %d depends on non-existent subtask %d", node.SubtaskID, depID)
			}
			if depID == node.SubtaskID {
				return fmt.Errorf("subtask %d depends on itself (self-loop)", node.SubtaskID)
			}
		}
	}

	// Cycle detection using Kahn's algorithm (topological sort).
	inDegree := make(map[int64]int)
	for id := range d.nodes {
		inDegree[id] = 0
	}
	for _, node := range d.nodes {
		for _, depID := range node.DependsOn {
			// depID must complete before node can run.
			// In dependency terms: there's an edge FROM depID TO node.SubtaskID.
			_ = depID // inDegree counts how many deps this node has.
		}
		inDegree[node.SubtaskID] = len(node.DependsOn)
	}

	// Build adjacency list: adj[A] = list of nodes that depend on A.
	adj := make(map[int64][]int64)
	for _, node := range d.nodes {
		for _, depID := range node.DependsOn {
			adj[depID] = append(adj[depID], node.SubtaskID)
		}
	}

	// Start with all nodes that have 0 in-degree.
	queue := make([]int64, 0)
	for id, deg := range inDegree {
		if deg == 0 {
			queue = append(queue, id)
		}
	}

	visited := 0
	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]
		visited++

		for _, next := range adj[curr] {
			inDegree[next]--
			if inDegree[next] == 0 {
				queue = append(queue, next)
			}
		}
	}

	if visited != len(d.nodes) {
		return fmt.Errorf("DAG contains a cycle: only %d of %d nodes are reachable via topological sort", visited, len(d.nodes))
	}

	return nil
}

// GetReady returns subtask IDs that are ready to execute, respecting the
// concurrency limit. Returned nodes are marked as dispatched.
func (d *SubtaskDAG) GetReady(maxConcurrent int) []int64 {
	d.mu.Lock()
	defer d.mu.Unlock()

	var ready []int64
	for _, id := range d.order {
		if len(ready) >= maxConcurrent {
			break
		}
		node := d.nodes[id]
		if node.Status == DAGNodeReady {
			ready = append(ready, id)
			node.Status = DAGNodeDispatched
		}
	}
	return ready
}

// MarkCompleted marks a subtask as completed and unblocks dependent nodes.
func (d *SubtaskDAG) MarkCompleted(subtaskID int64) {
	d.mu.Lock()
	defer d.mu.Unlock()

	node, ok := d.nodes[subtaskID]
	if !ok {
		return
	}
	node.Status = DAGNodeCompleted

	// Decrement dependency counts for nodes that depend on this one.
	for _, other := range d.nodes {
		if other.Status != DAGNodeWaiting {
			continue
		}
		for _, depID := range other.DependsOn {
			if depID == subtaskID {
				other.DepCount--
				if other.DepCount <= 0 {
					other.Status = DAGNodeReady
				}
				break
			}
		}
	}
}

// MarkFailed marks a subtask as failed and blocks all transitive dependents.
func (d *SubtaskDAG) MarkFailed(subtaskID int64) {
	d.mu.Lock()
	defer d.mu.Unlock()

	node, ok := d.nodes[subtaskID]
	if !ok {
		return
	}
	node.Status = DAGNodeFailed

	// Block all nodes that transitively depend on the failed node.
	d.blockDependentsLocked(subtaskID)
}

// blockDependentsLocked recursively blocks all nodes that depend on the given subtask.
// Must be called with lock held.
func (d *SubtaskDAG) blockDependentsLocked(subtaskID int64) {
	for _, other := range d.nodes {
		if other.Status == DAGNodeBlocked || other.Status == DAGNodeCompleted {
			continue
		}
		for _, depID := range other.DependsOn {
			if depID == subtaskID {
				other.Status = DAGNodeBlocked
				d.blockDependentsLocked(other.SubtaskID) // Recursive blocking.
				break
			}
		}
	}
}

// IsComplete returns true if all nodes are either completed, failed, or blocked.
func (d *SubtaskDAG) IsComplete() bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, node := range d.nodes {
		switch node.Status {
		case DAGNodeReady, DAGNodeWaiting, DAGNodeDispatched:
			return false
		}
	}
	return true
}

// HasInFlight returns true if any nodes are currently dispatched.
func (d *SubtaskDAG) HasInFlight() bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, node := range d.nodes {
		if node.Status == DAGNodeDispatched {
			return true
		}
	}
	return false
}

// GetCompletionSummary returns a summary of node statuses.
func (d *SubtaskDAG) GetCompletionSummary() map[DAGNodeStatus]int {
	d.mu.Lock()
	defer d.mu.Unlock()

	summary := make(map[DAGNodeStatus]int)
	for _, node := range d.nodes {
		summary[node.Status]++
	}
	return summary
}

// Size returns the total number of nodes in the DAG.
func (d *SubtaskDAG) Size() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.nodes)
}

// AggregateResults concatenates completed subtask results in insertion order.
// The resultFn is called for each completed node to get its result text.
func (d *SubtaskDAG) AggregateResults(resultFn func(subtaskID int64) string) string {
	d.mu.Lock()
	defer d.mu.Unlock()

	var parts []string
	for _, id := range d.order {
		node := d.nodes[id]
		if node.Status == DAGNodeCompleted {
			result := resultFn(id)
			if result != "" {
				parts = append(parts, fmt.Sprintf("## %s (Subtask %d)\n%s", node.Title, id, result))
			}
		}
	}

	if len(parts) == 0 {
		return ""
	}

	return "# Parallel Execution Results\n\n" + joinStrings(parts, "\n\n---\n\n")
}

func joinStrings(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	result := parts[0]
	for i := 1; i < len(parts); i++ {
		result += sep + parts[i]
	}
	return result
}
