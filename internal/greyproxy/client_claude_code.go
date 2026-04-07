package greyproxy

import (
	"net/http"
	"strings"

	"github.com/greyhavenhq/greyproxy/internal/greyproxy/dissector"
)

// ClaudeCodeAdapter handles Claude Code (claude-cli) client detection and behavior.
type ClaudeCodeAdapter struct{}

func (a *ClaudeCodeAdapter) Name() string { return "claude-code" }

func (a *ClaudeCodeAdapter) DetectConfidence(headers http.Header, result *dissector.ExtractionResult) float64 {
	if headers != nil {
		ua := headers.Get("User-Agent")
		if strings.Contains(ua, "claude-cli/") || strings.Contains(ua, "Claude-Code/") {
			return 0.95
		}
	}
	// Fallback: metadata.user_id + PascalCase tool names
	if result != nil && result.Provider == "anthropic" {
		if result.SessionID != "" {
			hasPascalTools := false
			for _, t := range result.Tools {
				if t.Name == "Read" || t.Name == "Bash" || t.Name == "Agent" {
					hasPascalTools = true
					break
				}
			}
			if hasPascalTools {
				return 0.7
			}
		}
	}
	return 0.0
}

func (a *ClaudeCodeAdapter) Scaffolding() *ScaffoldingConfig {
	return ClaudeCodeScaffolding()
}

func (a *ClaudeCodeAdapter) ClassifyThread(result *dissector.ExtractionResult) string {
	if result == nil {
		return "main"
	}
	sysLen := dissector.SystemPromptLength(result.SystemBlocks)
	toolCount := len(result.Tools)

	if sysLen > 10000 {
		return "main"
	}
	if sysLen > 1000 {
		return "subagent"
	}
	if sysLen > 100 && toolCount <= 2 {
		return "mcp"
	}
	return "utility"
}

func (a *ClaudeCodeAdapter) SessionStrategy() SessionStrategy {
	return &HeaderFieldStrategy{}
}

func (a *ClaudeCodeAdapter) SubagentStrategy() SubagentStrategyI {
	return &ClaudeCodeSubagentStrategy{}
}

func (a *ClaudeCodeAdapter) PairTransactions(_ []transactionEntry) [][]int64 {
	return nil // 1:1 default
}
