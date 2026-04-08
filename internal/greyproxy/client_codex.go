package greyproxy

import (
	"net/http"
	"strings"

	"github.com/greyhavenhq/greyproxy/internal/greyproxy/dissector"
)

// CodexAdapter handles Codex CLI client detection and behavior.
type CodexAdapter struct{}

func (a *CodexAdapter) Name() string { return "codex" }

func (a *CodexAdapter) DetectConfidence(headers http.Header, result *dissector.ExtractionResult) float64 {
	if headers != nil {
		if headers.Get("Originator") == "codex_exec" {
			return 0.98
		}
		if headers.Get("Version") != "" && result != nil &&
			strings.Contains(result.Model, "codex") {
			return 0.8
		}
	}
	// Detect from WS dissector client hint (no headers for WS frames)
	if result != nil && result.ClientHint == "codex" {
		return 0.95
	}
	return 0.0
}

func (a *CodexAdapter) Scaffolding() *ScaffoldingConfig {
	return CodexScaffolding()
}

func (a *CodexAdapter) ClassifyThread(result *dissector.ExtractionResult) string {
	if result == nil {
		return "main"
	}
	// WS_RESP response.completed frames carry assistant responses (SSEResponse)
	// but no tools or messages. They belong to the main conversation thread.
	if result.SSEResponse != nil {
		return "main"
	}
	// Check for orchestration tools
	for _, t := range result.Tools {
		switch t.Name {
		case "spawn_agent", "wait_agent", "resume_agent", "close_agent":
			return "main"
		}
	}
	if len(result.Tools) > 0 {
		return "subagent"
	}
	return "utility"
}

func (a *CodexAdapter) SessionStrategy() SessionStrategy {
	return &PromptCacheKeyStrategy{}
}

func (a *CodexAdapter) SubagentStrategy() SubagentStrategyI {
	return &CodexSubagentStrategy{}
}

func (a *CodexAdapter) PairTransactions(_ []transactionEntry) [][]int64 {
	return nil // 1:1 (WS unpacker already groups frames per turn)
}

func init() {
	RegisterClientAdapter(&CodexAdapter{})
}
