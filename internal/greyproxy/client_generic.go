package greyproxy

import (
	"net/http"
	"time"

	"github.com/greyhavenhq/greyproxy/internal/greyproxy/dissector"
)

// GenericAdapter is the fallback adapter used when no other adapter matches.
type GenericAdapter struct{}

func (a *GenericAdapter) Name() string { return "generic" }

func (a *GenericAdapter) DetectConfidence(_ http.Header, _ *dissector.ExtractionResult) float64 {
	return 0.1 // Always matches at low confidence
}

func (a *GenericAdapter) Scaffolding() *ScaffoldingConfig {
	// Use Claude Code scaffolding as default for backward compat
	return ClaudeCodeScaffolding()
}

func (a *GenericAdapter) ClassifyThread(result *dissector.ExtractionResult) string {
	if result == nil {
		return "main"
	}
	sysLen := dissector.SystemPromptLength(result.SystemBlocks)
	toolCount := len(result.Tools)

	if toolCount > 0 && sysLen > 5000 {
		return "main"
	}
	if toolCount > 0 {
		return "subagent"
	}
	// Requests with user messages are real conversations, not utility calls.
	if result.MessageCount > 0 {
		return "main"
	}
	return "utility"
}

func (a *GenericAdapter) SessionStrategy() SessionStrategy {
	return &TimingStrategy{Gap: 5 * time.Minute}
}

func (a *GenericAdapter) SubagentStrategy() SubagentStrategyI {
	return &NoSubagentStrategy{}
}

func (a *GenericAdapter) PairTransactions(_ []transactionEntry) [][]int64 {
	return nil
}
