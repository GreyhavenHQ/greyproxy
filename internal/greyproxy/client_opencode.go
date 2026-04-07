package greyproxy

import (
	"net/http"
	"strings"

	"github.com/greyhavenhq/greyproxy/internal/greyproxy/dissector"
)

// OpenCodeAdapter handles OpenCode client detection and behavior.
type OpenCodeAdapter struct{}

func (a *OpenCodeAdapter) Name() string { return "opencode" }

func (a *OpenCodeAdapter) DetectConfidence(headers http.Header, result *dissector.ExtractionResult) float64 {
	if headers != nil {
		ua := headers.Get("User-Agent")
		if strings.Contains(ua, "opencode/") {
			return 0.95
		}
		// OpenRouter path
		if headers.Get("X-Title") == "opencode" || headers.Get("Http-Referer") == "https://opencode.ai/" {
			return 0.85
		}
	}
	// Fallback: tool name fingerprint
	if result != nil {
		hasTask := false
		hasQuestion := false
		hasTodowrite := false
		for _, t := range result.Tools {
			switch t.Name {
			case "task":
				hasTask = true
			case "question":
				hasQuestion = true
			case "todowrite":
				hasTodowrite = true
			}
		}
		if hasTask && hasQuestion && hasTodowrite {
			return 0.6
		}
	}
	return 0.0
}

func (a *OpenCodeAdapter) Scaffolding() *ScaffoldingConfig {
	return OpenCodeScaffolding()
}

func (a *OpenCodeAdapter) ClassifyThread(result *dissector.ExtractionResult) string {
	if result == nil {
		return "main"
	}
	toolCount := len(result.Tools)

	if toolCount == 0 {
		// Check for title-gen pattern
		if result.Model == "gpt-5-nano" || result.Model == "claude-haiku-4-5-20251001" {
			return "title-gen"
		}
		return "utility"
	}

	// Check for management tools (main conversation only)
	for _, t := range result.Tools {
		switch t.Name {
		case "task", "question", "todowrite":
			return "main"
		}
	}

	if toolCount > 0 {
		return "subagent"
	}
	return "utility"
}

func (a *OpenCodeAdapter) SessionStrategy() SessionStrategy {
	return &CompositeStrategy{
		Strategies: []SessionStrategy{
			&PromptCacheKeyStrategy{},
			&MessageGrowthStrategy{},
		},
	}
}

func (a *OpenCodeAdapter) SubagentStrategy() SubagentStrategyI {
	return &OpenCodeSubagentStrategy{}
}

func (a *OpenCodeAdapter) PairTransactions(_ []transactionEntry) [][]int64 {
	return nil // 1:1 default
}
