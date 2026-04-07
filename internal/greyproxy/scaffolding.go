package greyproxy

import (
	"regexp"
	"strings"

	"github.com/greyhavenhq/greyproxy/internal/greyproxy/dissector"
)

// ScaffoldingConfig defines client-specific scaffolding patterns to filter
// from conversation messages. Scaffolding is client-injected noise (XML tags,
// status messages, deferred tool lists) that is not part of the actual
// user/assistant conversation.
type ScaffoldingConfig struct {
	// ExactTexts are message texts that should be treated as scaffolding
	// when they appear as the entire content of a user message.
	ExactTexts map[string]bool

	// PrefixPatterns are prefixes that mark a message as scaffolding
	// when the content starts with them.
	PrefixPatterns []string

	// XMLTagPatterns are regex patterns for XML tags to strip from text
	// content (the tags are removed but surrounding text is kept).
	XMLTagPatterns []*regexp.Regexp
}

// IsScaffoldingText returns true if the text is a known scaffolding message.
func (cfg *ScaffoldingConfig) IsScaffoldingText(text string) bool {
	stripped := strings.TrimSpace(text)
	if cfg.ExactTexts[stripped] {
		return true
	}
	for _, prefix := range cfg.PrefixPatterns {
		if strings.HasPrefix(stripped, prefix) {
			return true
		}
	}
	return false
}

// CleanText removes XML tag scaffolding from text content.
func (cfg *ScaffoldingConfig) CleanText(text string) string {
	for _, pat := range cfg.XMLTagPatterns {
		text = pat.ReplaceAllString(text, "")
	}
	return strings.TrimSpace(text)
}

// IsRealUserMessage returns true if the message contains actual user content
// (not pure scaffolding or tool-result-only messages).
func (cfg *ScaffoldingConfig) IsRealUserMessage(msg dissector.Message) bool {
	if msg.RawContent != "" {
		if cfg.IsScaffoldingText(msg.RawContent) {
			return false
		}
		return strings.TrimSpace(msg.RawContent) != ""
	}

	hasToolResult := false
	var realTexts []string
	for _, b := range msg.Content {
		if b.Type == "tool_result" {
			hasToolResult = true
			continue
		}
		if b.Type != "text" {
			continue
		}
		text := strings.TrimSpace(b.Text)
		if text == "" || cfg.IsScaffoldingText(text) {
			continue
		}
		realTexts = append(realTexts, text)
	}
	if hasToolResult && len(realTexts) == 0 {
		return false
	}
	return len(realTexts) > 0
}

// GetUserText extracts cleaned user text from a message, filtering scaffolding.
func (cfg *ScaffoldingConfig) GetUserText(msg dissector.Message) *string {
	if msg.RawContent != "" {
		if cfg.IsScaffoldingText(msg.RawContent) {
			return nil
		}
		cleaned := cfg.CleanText(msg.RawContent)
		if cleaned == "" || cfg.ExactTexts[cleaned] {
			return nil
		}
		return &cleaned
	}

	var texts []string
	for _, b := range msg.Content {
		if b.Type != "text" {
			continue
		}
		text := strings.TrimSpace(b.Text)
		if text == "" || cfg.IsScaffoldingText(text) {
			continue
		}
		cleaned := cfg.CleanText(text)
		if cleaned != "" && !cfg.ExactTexts[cleaned] {
			texts = append(texts, cleaned)
		}
	}
	if len(texts) == 0 {
		return nil
	}
	joined := strings.Join(texts, "\n")
	return &joined
}

// --- Built-in scaffolding configs (singleton instances) ---

var (
	claudeCodeScaffolding = &ScaffoldingConfig{
		ExactTexts: map[string]bool{
			"Tool loaded.":                  true,
			"[Request interrupted by user]": true,
			"clear":                         true,
		},
		PrefixPatterns: []string{
			"<available-deferred-tools>",
			"<system-reminder>",
			"<local-command-caveat>",
		},
		XMLTagPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?s)<local-command-caveat>.*?</local-command-caveat>`),
			regexp.MustCompile(`(?s)<command-name>.*?</command-name>`),
			regexp.MustCompile(`(?s)<command-message>.*?</command-message>`),
			regexp.MustCompile(`(?s)<command-args>.*?</command-args>`),
			regexp.MustCompile(`(?s)<local-command-stdout>.*?</local-command-stdout>`),
		},
	}

	openCodeScaffolding = &ScaffoldingConfig{
		ExactTexts:     map[string]bool{},
		PrefixPatterns: nil,
		XMLTagPatterns: nil,
	}

	codexScaffolding = &ScaffoldingConfig{
		ExactTexts: map[string]bool{},
		PrefixPatterns: []string{
			"<environment_context>",
			"<permissions>",
		},
		XMLTagPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?s)<environment_context>.*?</environment_context>`),
			regexp.MustCompile(`(?s)<permissions>.*?</permissions>`),
		},
	}

	geminiCLIScaffolding = &ScaffoldingConfig{
		ExactTexts: map[string]bool{},
		PrefixPatterns: []string{
			"<session_context>",
		},
		XMLTagPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?s)<session_context>.*?</session_context>`),
			regexp.MustCompile(`(?s)<extension_context>.*?</extension_context>`),
			regexp.MustCompile(`(?s)<loaded_context>.*?</loaded_context>`),
		},
	}

	genericScaffolding = &ScaffoldingConfig{
		ExactTexts:     map[string]bool{},
		PrefixPatterns: nil,
		XMLTagPatterns: nil,
	}
)

// ClaudeCodeScaffolding returns the scaffolding config for Claude Code.
func ClaudeCodeScaffolding() *ScaffoldingConfig { return claudeCodeScaffolding }

// OpenCodeScaffolding returns the scaffolding config for OpenCode.
func OpenCodeScaffolding() *ScaffoldingConfig { return openCodeScaffolding }

// CodexScaffolding returns the scaffolding config for Codex CLI.
func CodexScaffolding() *ScaffoldingConfig { return codexScaffolding }

// GeminiCLIScaffolding returns the scaffolding config for Gemini CLI.
func GeminiCLIScaffolding() *ScaffoldingConfig { return geminiCLIScaffolding }

// GenericScaffolding returns an empty scaffolding config (no filtering).
func GenericScaffolding() *ScaffoldingConfig { return genericScaffolding }

// ScaffoldingForClient returns the scaffolding config for a given client name.
func ScaffoldingForClient(clientName string) *ScaffoldingConfig {
	switch clientName {
	case "claude-code":
		return claudeCodeScaffolding
	case "opencode":
		return openCodeScaffolding
	case "codex":
		return codexScaffolding
	case "gemini-cli":
		return geminiCLIScaffolding
	case "aider":
		return genericScaffolding
	default:
		return claudeCodeScaffolding // default: apply Claude Code filtering for backward compat
	}
}
