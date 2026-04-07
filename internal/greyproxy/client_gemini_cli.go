package greyproxy

import (
	"net/http"
	"strings"
	"time"

	"github.com/greyhavenhq/greyproxy/internal/greyproxy/dissector"
)

// GeminiCLIAdapter handles Gemini CLI client detection and behavior.
type GeminiCLIAdapter struct{}

func (a *GeminiCLIAdapter) Name() string { return "gemini-cli" }

func (a *GeminiCLIAdapter) DetectConfidence(headers http.Header, _ *dissector.ExtractionResult) float64 {
	if headers != nil {
		if strings.Contains(headers.Get("User-Agent"), "GeminiCLI/") {
			return 0.98
		}
	}
	return 0.0
}

func (a *GeminiCLIAdapter) Scaffolding() *ScaffoldingConfig {
	return GeminiCLIScaffolding()
}

func (a *GeminiCLIAdapter) ClassifyThread(result *dissector.ExtractionResult) string {
	if result == nil {
		return "main"
	}
	// Complexity scorer: non-streaming generateContent with flash-lite model
	if strings.Contains(result.Model, "flash-lite") {
		return "complexity-scorer"
	}
	return "main"
}

func (a *GeminiCLIAdapter) SessionStrategy() SessionStrategy {
	return &TimingStrategy{Gap: 5 * time.Minute}
}

func (a *GeminiCLIAdapter) SubagentStrategy() SubagentStrategyI {
	return &GeminiCLISubagentStrategy{}
}

// PairTransactions implements 2:1 turn pairing for Gemini CLI.
// Each user turn pairs a generateContent (complexity scorer) with the
// immediately following streamGenerateContent (main agent).
func (a *GeminiCLIAdapter) PairTransactions(entries []transactionEntry) [][]int64 {
	if len(entries) == 0 {
		return nil
	}

	var groups [][]int64
	i := 0
	for i < len(entries) {
		// Check if this is a complexity scorer followed by a main call
		if i+1 < len(entries) && isComplexityScorer(entries[i]) && !isComplexityScorer(entries[i+1]) {
			groups = append(groups, []int64{entries[i].txnID, entries[i+1].txnID})
			i += 2
		} else {
			groups = append(groups, []int64{entries[i].txnID})
			i++
		}
	}
	return groups
}

func isComplexityScorer(e transactionEntry) bool {
	if e.result == nil {
		return false
	}
	return strings.Contains(e.result.Model, "flash-lite")
}

func init() {
	RegisterClientAdapter(&GeminiCLIAdapter{})
}
