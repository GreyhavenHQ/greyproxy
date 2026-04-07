package greyproxy

import (
	"net/http"
	"sort"

	"github.com/greyhavenhq/greyproxy/internal/greyproxy/dissector"
)

// ClientAdapter knows how a specific coding tool uses the wire format.
// Each adapter provides client-specific interpretation: session extraction,
// scaffolding filtering, thread classification, and subagent handling.
type ClientAdapter interface {
	// Name returns the client identifier (e.g. "claude-code", "opencode").
	Name() string

	// DetectConfidence returns 0.0-1.0 confidence that this request is from this client.
	DetectConfidence(headers http.Header, result *dissector.ExtractionResult) float64

	// Scaffolding returns the scaffolding config for this client.
	Scaffolding() *ScaffoldingConfig

	// ClassifyThread returns "main", "subagent", "utility", "mcp", "title-gen",
	// or "complexity-scorer" for the given extraction result.
	ClassifyThread(result *dissector.ExtractionResult) string

	// SessionStrategy returns the strategy for extracting/inferring session IDs.
	SessionStrategy() SessionStrategy

	// SubagentStrategy returns the strategy for detecting and linking subagents.
	SubagentStrategy() SubagentStrategyI

	// PairTransactions groups transactions that should be assembled as one turn.
	// Default: each transaction is its own turn (return nil to use default).
	PairTransactions(entries []transactionEntry) [][]int64
}

// --- Adapter registry ---

var clientAdapters []ClientAdapter

// RegisterClientAdapter adds a client adapter to the global registry.
func RegisterClientAdapter(a ClientAdapter) {
	clientAdapters = append(clientAdapters, a)
}

// DetectClient finds the best-matching client adapter for the given request.
// Returns the adapter with the highest confidence score >= 0.7, or the
// generic fallback adapter.
func DetectClient(headers http.Header, result *dissector.ExtractionResult) ClientAdapter {
	type scored struct {
		adapter ClientAdapter
		score   float64
	}
	var candidates []scored
	for _, a := range clientAdapters {
		score := a.DetectConfidence(headers, result)
		if score > 0 {
			candidates = append(candidates, scored{a, score})
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].score > candidates[j].score
	})
	if len(candidates) > 0 && candidates[0].score >= 0.7 {
		return candidates[0].adapter
	}
	return &GenericAdapter{}
}

// DetectClientFromEntries detects the client from the first entry with headers.
func DetectClientFromEntries(entries []transactionEntry) ClientAdapter {
	for _, e := range entries {
		if e.requestHeaders != nil && e.result != nil {
			return DetectClient(e.requestHeaders, e.result)
		}
	}
	// No headers available; try result-only detection
	for _, e := range entries {
		if e.result != nil {
			return DetectClient(nil, e.result)
		}
	}
	return &GenericAdapter{}
}

func init() {
	RegisterClientAdapter(&ClaudeCodeAdapter{})
	RegisterClientAdapter(&OpenCodeAdapter{})
	RegisterClientAdapter(&AiderAdapter{})
	// Codex and Gemini CLI are registered in their respective files
}
