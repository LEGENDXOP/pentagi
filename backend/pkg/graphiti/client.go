package graphiti

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	graphiti "github.com/vxcontrol/graphiti-go-client"
	"github.com/vxcontrol/langchaingo/vectorstores/pgvector"
)

// Re-export types from the graphiti-go-client package for convenience
type (
	Observation        = graphiti.Observation
	Message            = graphiti.Message
	AddMessagesRequest = graphiti.AddMessagesRequest

	// Search request/response types
	TemporalSearchRequest            = graphiti.TemporalSearchRequest
	TemporalSearchResponse           = graphiti.TemporalSearchResponse
	EntityRelationshipSearchRequest  = graphiti.EntityRelationshipSearchRequest
	EntityRelationshipSearchResponse = graphiti.EntityRelationshipSearchResponse
	DiverseSearchRequest             = graphiti.DiverseSearchRequest
	DiverseSearchResponse            = graphiti.DiverseSearchResponse
	EpisodeContextSearchRequest      = graphiti.EpisodeContextSearchRequest
	EpisodeContextSearchResponse     = graphiti.EpisodeContextSearchResponse
	SuccessfulToolsSearchRequest     = graphiti.SuccessfulToolsSearchRequest
	SuccessfulToolsSearchResponse    = graphiti.SuccessfulToolsSearchResponse
	RecentContextSearchRequest       = graphiti.RecentContextSearchRequest
	RecentContextSearchResponse      = graphiti.RecentContextSearchResponse
	EntityByLabelSearchRequest       = graphiti.EntityByLabelSearchRequest
	EntityByLabelSearchResponse      = graphiti.EntityByLabelSearchResponse

	// Common types used in search responses
	NodeResult      = graphiti.NodeResult
	EdgeResult      = graphiti.EdgeResult
	EpisodeResult   = graphiti.EpisodeResult
	CommunityResult = graphiti.CommunityResult
	TimeWindow      = graphiti.TimeWindow
)

// Client wraps the Graphiti client with Pentagi-specific functionality
type Client struct {
	client   *graphiti.Client
	enabled  bool
	timeout  time.Duration
	cb       *CircuitBreaker
	fallback *FallbackSearcher
}

// NewClient creates a new Graphiti client wrapper
func NewClient(url string, timeout time.Duration, enabled bool) (*Client, error) {
	if !enabled {
		return &Client{enabled: false}, nil
	}

	client := graphiti.NewClient(url, graphiti.WithTimeout(timeout))

	_, err := client.HealthCheck()
	if err != nil {
		return nil, fmt.Errorf("graphiti health check failed: %w", err)
	}

	return &Client{
		client:  client,
		enabled: true,
		timeout: timeout,
		cb:      NewCircuitBreaker(DefaultCircuitBreakerConfig()),
	}, nil
}

// NewClientWithCircuitBreaker creates a new Graphiti client wrapper with a custom circuit breaker config.
func NewClientWithCircuitBreaker(url string, timeout time.Duration, enabled bool, cbConfig CircuitBreakerConfig) (*Client, error) {
	if !enabled {
		return &Client{enabled: false}, nil
	}

	client := graphiti.NewClient(url, graphiti.WithTimeout(timeout))

	_, err := client.HealthCheck()
	if err != nil {
		return nil, fmt.Errorf("graphiti health check failed: %w", err)
	}

	return &Client{
		client:  client,
		enabled: true,
		timeout: timeout,
		cb:      NewCircuitBreaker(cbConfig),
	}, nil
}

// SetFallbackStore configures the pgvector store used for fallback searches
// when the circuit breaker is open.
func (c *Client) SetFallbackStore(store *pgvector.Store) {
	if c == nil {
		return
	}
	c.fallback = NewFallbackSearcher(store)
}

// GetCircuitBreaker returns the underlying circuit breaker for inspection/testing.
func (c *Client) GetCircuitBreaker() *CircuitBreaker {
	if c == nil {
		return nil
	}
	return c.cb
}

// IsEnabled returns whether Graphiti integration is active
func (c *Client) IsEnabled() bool {
	return c != nil && c.enabled
}

// GetTimeout returns the configured timeout duration
func (c *Client) GetTimeout() time.Duration {
	if c == nil {
		return 0
	}
	return c.timeout
}

// circuitOpen checks if the circuit breaker is open and we should fallback.
func (c *Client) circuitOpen() bool {
	if c.cb == nil {
		return false
	}
	return !c.cb.AllowRequest()
}

// recordSuccess records a successful API call to the circuit breaker.
func (c *Client) recordSuccess() {
	if c.cb != nil {
		c.cb.RecordSuccess()
	}
}

// recordFailure records a failed API call to the circuit breaker.
func (c *Client) recordFailure() {
	if c.cb != nil {
		c.cb.RecordFailure()
	}
}

// FallbackSearch performs a pgvector fallback search when the circuit is open.
// This is exposed so callers (e.g., graphiti search tools) can invoke fallback logic directly.
func (c *Client) FallbackSearch(ctx context.Context, query string, groupID string) (string, error) {
	if c.fallback == nil {
		return "Graphiti knowledge graph is temporarily unavailable (circuit breaker open). No fallback search configured.", nil
	}
	return c.fallback.Search(ctx, query, groupID, fallbackVectorStoreResultLimit)
}

// getGroupID extracts the group ID pointer value, returning empty string for nil.
func getGroupID(gid *string) string {
	if gid == nil {
		return ""
	}
	return *gid
}

// AddMessages adds messages to Graphiti (no-op if disabled)
func (c *Client) AddMessages(ctx context.Context, req graphiti.AddMessagesRequest) error {
	if !c.IsEnabled() {
		return nil
	}

	if c.circuitOpen() {
		logrus.WithFields(logrus.Fields{
			"component": "graphiti_circuit_breaker",
			"group_id":  req.GroupID,
		}).Warn("circuit breaker open: skipping AddMessages")
		return nil
	}

	_, err := c.client.AddMessages(req)
	if err != nil {
		c.recordFailure()
		return err
	}

	c.recordSuccess()
	return nil
}

// TemporalWindowSearch searches within a time window
func (c *Client) TemporalWindowSearch(ctx context.Context, req TemporalSearchRequest) (*TemporalSearchResponse, error) {
	if !c.IsEnabled() {
		return nil, fmt.Errorf("graphiti is not enabled")
	}

	if c.circuitOpen() {
		logrus.WithField("component", "graphiti_circuit_breaker").
			Warn("circuit breaker open: falling back to pgvector for TemporalWindowSearch")
		return nil, fmt.Errorf("graphiti circuit breaker open: %w",
			&CircuitOpenError{Query: req.Query, GroupID: getGroupID(req.GroupID)})
	}

	resp, err := c.client.TemporalWindowSearch(req)
	if err != nil {
		c.recordFailure()
		return nil, err
	}

	c.recordSuccess()
	return resp, nil
}

// EntityRelationshipsSearch finds relationships from a center node
func (c *Client) EntityRelationshipsSearch(ctx context.Context, req EntityRelationshipSearchRequest) (*EntityRelationshipSearchResponse, error) {
	if !c.IsEnabled() {
		return nil, fmt.Errorf("graphiti is not enabled")
	}

	if c.circuitOpen() {
		logrus.WithField("component", "graphiti_circuit_breaker").
			Warn("circuit breaker open: falling back for EntityRelationshipsSearch")
		return nil, fmt.Errorf("graphiti circuit breaker open: %w",
			&CircuitOpenError{Query: req.Query, GroupID: getGroupID(req.GroupID)})
	}

	resp, err := c.client.EntityRelationshipsSearch(req)
	if err != nil {
		c.recordFailure()
		return nil, err
	}

	c.recordSuccess()
	return resp, nil
}

// DiverseResultsSearch gets diverse, non-redundant results
func (c *Client) DiverseResultsSearch(ctx context.Context, req DiverseSearchRequest) (*DiverseSearchResponse, error) {
	if !c.IsEnabled() {
		return nil, fmt.Errorf("graphiti is not enabled")
	}

	if c.circuitOpen() {
		logrus.WithField("component", "graphiti_circuit_breaker").
			Warn("circuit breaker open: falling back for DiverseResultsSearch")
		return nil, fmt.Errorf("graphiti circuit breaker open: %w",
			&CircuitOpenError{Query: req.Query, GroupID: getGroupID(req.GroupID)})
	}

	resp, err := c.client.DiverseResultsSearch(req)
	if err != nil {
		c.recordFailure()
		return nil, err
	}

	c.recordSuccess()
	return resp, nil
}

// EpisodeContextSearch searches through agent responses and tool execution records
func (c *Client) EpisodeContextSearch(ctx context.Context, req EpisodeContextSearchRequest) (*EpisodeContextSearchResponse, error) {
	if !c.IsEnabled() {
		return nil, fmt.Errorf("graphiti is not enabled")
	}

	if c.circuitOpen() {
		logrus.WithField("component", "graphiti_circuit_breaker").
			Warn("circuit breaker open: falling back for EpisodeContextSearch")
		return nil, fmt.Errorf("graphiti circuit breaker open: %w",
			&CircuitOpenError{Query: req.Query, GroupID: getGroupID(req.GroupID)})
	}

	resp, err := c.client.EpisodeContextSearch(req)
	if err != nil {
		c.recordFailure()
		return nil, err
	}

	c.recordSuccess()
	return resp, nil
}

// SuccessfulToolsSearch finds successful tool executions and attack patterns
func (c *Client) SuccessfulToolsSearch(ctx context.Context, req SuccessfulToolsSearchRequest) (*SuccessfulToolsSearchResponse, error) {
	if !c.IsEnabled() {
		return nil, fmt.Errorf("graphiti is not enabled")
	}

	if c.circuitOpen() {
		logrus.WithField("component", "graphiti_circuit_breaker").
			Warn("circuit breaker open: falling back for SuccessfulToolsSearch")
		return nil, fmt.Errorf("graphiti circuit breaker open: %w",
			&CircuitOpenError{Query: req.Query, GroupID: getGroupID(req.GroupID)})
	}

	resp, err := c.client.SuccessfulToolsSearch(req)
	if err != nil {
		c.recordFailure()
		return nil, err
	}

	c.recordSuccess()
	return resp, nil
}

// RecentContextSearch retrieves recent relevant context
func (c *Client) RecentContextSearch(ctx context.Context, req RecentContextSearchRequest) (*RecentContextSearchResponse, error) {
	if !c.IsEnabled() {
		return nil, fmt.Errorf("graphiti is not enabled")
	}

	if c.circuitOpen() {
		logrus.WithField("component", "graphiti_circuit_breaker").
			Warn("circuit breaker open: falling back for RecentContextSearch")
		return nil, fmt.Errorf("graphiti circuit breaker open: %w",
			&CircuitOpenError{Query: req.Query, GroupID: getGroupID(req.GroupID)})
	}

	resp, err := c.client.RecentContextSearch(req)
	if err != nil {
		c.recordFailure()
		return nil, err
	}

	c.recordSuccess()
	return resp, nil
}

// EntityByLabelSearch searches for entities by label/type
func (c *Client) EntityByLabelSearch(ctx context.Context, req EntityByLabelSearchRequest) (*EntityByLabelSearchResponse, error) {
	if !c.IsEnabled() {
		return nil, fmt.Errorf("graphiti is not enabled")
	}

	if c.circuitOpen() {
		logrus.WithField("component", "graphiti_circuit_breaker").
			Warn("circuit breaker open: falling back for EntityByLabelSearch")
		return nil, fmt.Errorf("graphiti circuit breaker open: %w",
			&CircuitOpenError{Query: req.Query, GroupID: getGroupID(req.GroupID)})
	}

	resp, err := c.client.EntityByLabelSearch(req)
	if err != nil {
		c.recordFailure()
		return nil, err
	}

	c.recordSuccess()
	return resp, nil
}

// CircuitOpenError is returned when a search call is rejected because the circuit breaker is open.
// It carries the query and group ID so callers can use them for fallback logic.
type CircuitOpenError struct {
	Query   string
	GroupID string
}

func (e *CircuitOpenError) Error() string {
	return fmt.Sprintf("graphiti circuit breaker is open (query=%q, group=%s)", e.Query, e.GroupID)
}

// IsCircuitOpenError checks if an error is a CircuitOpenError.
func IsCircuitOpenError(err error) (*CircuitOpenError, bool) {
	if err == nil {
		return nil, false
	}
	// Check direct type
	if coe, ok := err.(*CircuitOpenError); ok {
		return coe, true
	}
	// Check wrapped
	type unwrapper interface {
		Unwrap() error
	}
	if uw, ok := err.(unwrapper); ok {
		return IsCircuitOpenError(uw.Unwrap())
	}
	return nil, false
}
