package graphiti

import (
	"context"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/vxcontrol/langchaingo/vectorstores"
	"github.com/vxcontrol/langchaingo/vectorstores/pgvector"
)

const (
	fallbackVectorStoreThreshold   = 0.2
	fallbackVectorStoreResultLimit = 10
	fallbackNotFoundMessage        = "Graphiti is temporarily unavailable. No relevant results found via fallback vector search."
)

// FallbackSearcher performs semantic search directly against pgvector
// when the Graphiti circuit breaker is open.
type FallbackSearcher struct {
	store *pgvector.Store
}

// NewFallbackSearcher creates a new pgvector fallback searcher.
// If store is nil, all fallback searches return a "not available" message.
func NewFallbackSearcher(store *pgvector.Store) *FallbackSearcher {
	return &FallbackSearcher{store: store}
}

// Search performs a semantic similarity search against pgvector as a fallback.
// It returns a formatted string result suitable for agent consumption.
func (f *FallbackSearcher) Search(ctx context.Context, query string, groupID string, maxResults int) (string, error) {
	if f.store == nil {
		return fallbackNotFoundMessage, nil
	}

	logger := logrus.WithContext(ctx).WithFields(logrus.Fields{
		"component": "graphiti_fallback",
		"query":     query[:min(len(query), 200)],
		"group_id":  groupID,
	})

	if maxResults <= 0 {
		maxResults = fallbackVectorStoreResultLimit
	}

	filters := map[string]any{}
	if groupID != "" {
		filters["flow_id"] = groupID
	}

	opts := []vectorstores.Option{
		vectorstores.WithScoreThreshold(fallbackVectorStoreThreshold),
	}
	if len(filters) > 0 {
		opts = append(opts, vectorstores.WithFilters(filters))
	}

	docs, err := f.store.SimilaritySearch(ctx, query, maxResults, opts...)
	if err != nil {
		logger.WithError(err).Error("fallback pgvector search failed")
		return "", fmt.Errorf("fallback pgvector search failed: %w", err)
	}

	if len(docs) == 0 {
		logger.Debug("fallback search returned no results")
		return fallbackNotFoundMessage, nil
	}

	logger.WithField("results", len(docs)).Debug("fallback search returned results")

	var builder strings.Builder
	builder.WriteString("# Fallback Search Results (Graphiti temporarily unavailable)\n\n")
	builder.WriteString(fmt.Sprintf("**Query:** %s\n\n", query))
	builder.WriteString(fmt.Sprintf("*Note: These results come from pgvector semantic search because the Graphiti knowledge graph is temporarily unavailable.*\n\n"))

	for i, doc := range docs {
		builder.WriteString(fmt.Sprintf("## Result %d (score: %.3f)\n\n", i+1, doc.Score))
		if docType, ok := doc.Metadata["doc_type"]; ok {
			builder.WriteString(fmt.Sprintf("**Type:** %s\n", docType))
		}
		if question, ok := doc.Metadata["question"]; ok {
			builder.WriteString(fmt.Sprintf("**Original Query:** %s\n", question))
		}
		builder.WriteString(fmt.Sprintf("\n%s\n\n", doc.PageContent))
	}

	return builder.String(), nil
}


