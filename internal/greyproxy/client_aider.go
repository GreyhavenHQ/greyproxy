package greyproxy

import (
	"net/http"
	"strings"
	"time"

	"github.com/greyhavenhq/greyproxy/internal/greyproxy/dissector"
)

// AiderAdapter handles Aider client detection and behavior.
type AiderAdapter struct{}

func (a *AiderAdapter) Name() string { return "aider" }

func (a *AiderAdapter) DetectConfidence(headers http.Header, _ *dissector.ExtractionResult) float64 {
	if headers != nil {
		if headers.Get("Http-Referer") == "https://aider.chat" {
			return 0.95
		}
		if headers.Get("X-Title") == "Aider" {
			return 0.85
		}
		ua := headers.Get("User-Agent")
		if strings.Contains(ua, "litellm/") && headers.Get("X-Title") == "Aider" {
			return 0.8
		}
	}
	return 0.0
}

func (a *AiderAdapter) Scaffolding() *ScaffoldingConfig {
	return GenericScaffolding()
}

func (a *AiderAdapter) ClassifyThread(_ *dissector.ExtractionResult) string {
	return "main" // Aider has no subagents or utility calls
}

func (a *AiderAdapter) SessionStrategy() SessionStrategy {
	return &TimingStrategy{Gap: 5 * time.Minute}
}

func (a *AiderAdapter) SubagentStrategy() SubagentStrategyI {
	return &NoSubagentStrategy{}
}

func (a *AiderAdapter) PairTransactions(_ []transactionEntry) [][]int64 {
	return nil // 1:1 default
}
