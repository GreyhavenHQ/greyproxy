package greyproxy

import (
	"github.com/greyhavenhq/greyproxy/internal/greyproxy/dissector"
)

// SubagentStrategyI defines how a client spawns and links subagent sessions.
type SubagentStrategyI interface {
	// AgentToolNames returns tool names that represent subagent spawning.
	AgentToolNames() []string

	// ExtractReferencedSessions scans messages for cross-session references.
	ExtractReferencedSessions(messages []dissector.Message) []string

	// LinkSubagentID extracts the subagent session ID from a tool result.
	LinkSubagentID(content string) string

	// SplitInvocations detects new subagent starts within a shared session.
	SplitInvocations(entries []transactionEntry) [][]transactionEntry
}

// --- NoSubagentStrategy ---
// For clients with no multi-agent architecture (Aider, generic).

type NoSubagentStrategy struct{}

func (s *NoSubagentStrategy) AgentToolNames() []string              { return nil }
func (s *NoSubagentStrategy) ExtractReferencedSessions(_ []dissector.Message) []string {
	return nil
}
func (s *NoSubagentStrategy) LinkSubagentID(_ string) string        { return "" }
func (s *NoSubagentStrategy) SplitInvocations(entries []transactionEntry) [][]transactionEntry {
	if len(entries) == 0 {
		return nil
	}
	return [][]transactionEntry{entries}
}

// --- ClaudeCodeSubagentStrategy ---
// Claude Code: Tool "Agent", same session ID, split by message count drop.

type ClaudeCodeSubagentStrategy struct{}

func (s *ClaudeCodeSubagentStrategy) AgentToolNames() []string {
	return []string{"Agent"}
}

func (s *ClaudeCodeSubagentStrategy) ExtractReferencedSessions(_ []dissector.Message) []string {
	return nil // Same session ID as parent
}

func (s *ClaudeCodeSubagentStrategy) LinkSubagentID(_ string) string {
	return "" // No cross-session linking needed
}

func (s *ClaudeCodeSubagentStrategy) SplitInvocations(entries []transactionEntry) [][]transactionEntry {
	return splitSubagentInvocations(entries)
}

// --- OpenCodeSubagentStrategy ---
// OpenCode: Tool "task", separate session IDs, cross-session linking via task_id.

type OpenCodeSubagentStrategy struct{}



func (s *OpenCodeSubagentStrategy) AgentToolNames() []string {
	return []string{"task"}
}

func (s *OpenCodeSubagentStrategy) ExtractReferencedSessions(messages []dissector.Message) []string {
	var refs []string
	for _, msg := range messages {
		for _, cb := range msg.Content {
			if cb.Type == "tool_result" && cb.Content != "" {
				if tid := s.LinkSubagentID(cb.Content); tid != "" {
					refs = append(refs, tid)
				}
			}
		}
	}
	return refs
}

func (s *OpenCodeSubagentStrategy) LinkSubagentID(content string) string {
	m := taskIDPattern.FindStringSubmatch(content)
	if len(m) >= 2 {
		return m[1]
	}
	return ""
}

func (s *OpenCodeSubagentStrategy) SplitInvocations(entries []transactionEntry) [][]transactionEntry {
	if len(entries) == 0 {
		return nil
	}
	return [][]transactionEntry{entries}
}

// --- CodexSubagentStrategy ---
// Codex: Tools spawn_agent/wait_agent, separate WS sessions per subagent.

type CodexSubagentStrategy struct{}

func (s *CodexSubagentStrategy) AgentToolNames() []string {
	return []string{"spawn_agent", "wait_agent"}
}

func (s *CodexSubagentStrategy) ExtractReferencedSessions(_ []dissector.Message) []string {
	return nil // Cross-session linking via wait_agent results (future)
}

func (s *CodexSubagentStrategy) LinkSubagentID(_ string) string {
	return "" // Future: parse wait_agent function_call_output
}

func (s *CodexSubagentStrategy) SplitInvocations(entries []transactionEntry) [][]transactionEntry {
	if len(entries) == 0 {
		return nil
	}
	return [][]transactionEntry{entries}
}

// --- GeminiCLISubagentStrategy ---
// Gemini CLI: GSD delegation tools declared but behavior unobserved.

type GeminiCLISubagentStrategy struct{}

func (s *GeminiCLISubagentStrategy) AgentToolNames() []string {
	return []string{"gsd-executor", "gsd-planner", "gsd-debugger", "codebase_investigator", "generalist"}
}

func (s *GeminiCLISubagentStrategy) ExtractReferencedSessions(_ []dissector.Message) []string {
	return nil
}

func (s *GeminiCLISubagentStrategy) LinkSubagentID(_ string) string {
	return ""
}

func (s *GeminiCLISubagentStrategy) SplitInvocations(entries []transactionEntry) [][]transactionEntry {
	if len(entries) == 0 {
		return nil
	}
	return [][]transactionEntry{entries}
}
