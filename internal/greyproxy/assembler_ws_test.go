package greyproxy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/greyhavenhq/greyproxy/internal/greyproxy/dissector"
)

// makeWSReqEntry creates a transactionEntry as the WS dissector would produce
// from a Codex WS_REQ frame.
func makeWSReqEntry(txnID int64, ts string, sessionID string, messages []dissector.Message, sysBlocks []dissector.SystemBlock, tools []dissector.Tool) transactionEntry {
	return transactionEntry{
		txnID:         txnID,
		timestamp:     ts,
		containerName: "codex",
		url:           "wss://api.openai.com:80/v1/responses",
		sessionID:     sessionID,
		model:         "gpt-5.4",
		result: &dissector.ExtractionResult{
			Provider:     "openai",
			SessionID:    sessionID,
			Model:        "gpt-5.4",
			Messages:     messages,
			SystemBlocks: sysBlocks,
			Tools:        tools,
			MessageCount: len(messages),
			ClientHint:   "codex",
		},
	}
}

// makeWSRespEntry creates a transactionEntry as the WS event dissector would
// produce from a response.completed WS_RESP frame.
func makeWSRespEntry(txnID int64, ts string, text string, toolCalls []dissector.ToolCall) transactionEntry {
	sse := &dissector.SSEResponseData{}
	if text != "" {
		sse.Text = text
	}
	if len(toolCalls) > 0 {
		sse.ToolCalls = toolCalls
	}
	return transactionEntry{
		txnID:         txnID,
		timestamp:     ts,
		containerName: "codex",
		url:           "wss://api.openai.com:80/v1/responses",
		model:         "gpt-5.4",
		result: &dissector.ExtractionResult{
			Provider:    "openai",
			Model:       "gpt-5.4",
			SSEResponse: sse,
		},
	}
}

// TestAssembleConversation_CodexWS_TwoTurns verifies that a Codex WebSocket
// session with incremental messages produces the correct multi-turn conversation.
//
// Codex WS is incremental: each response.create only sends NEW input items,
// not the full history. The assembler must aggregate across all WS_REQ entries
// and interleave assistant responses from WS_RESP response.completed events.
func TestAssembleConversation_CodexWS_TwoTurns(t *testing.T) {
	sessionID := "019d6b93-5148-7f41-a054-cacb6be5916e"
	codexTools := []dissector.Tool{
		{Name: "exec_command"},
		{Name: "spawn_agent"},
	}

	entries := []transactionEntry{
		// TX 1: session init (empty input)
		makeWSReqEntry(26768, "2026-04-08T00:00:01Z", sessionID,
			nil, // no messages
			[]dissector.SystemBlock{{Type: "text", Text: "You are Codex."}},
			codexTools,
		),
		// TX 2: first user turn: env_context scaffolding + "hello"
		makeWSReqEntry(26772, "2026-04-08T00:00:02Z", sessionID,
			[]dissector.Message{
				{Role: "user", Content: []dissector.ContentBlock{{Type: "text", Text: "<environment_context>\n  <cwd>/home/tito</cwd>\n</environment_context>"}}},
				{Role: "user", Content: []dissector.ContentBlock{{Type: "text", Text: "hello"}}},
			},
			[]dissector.SystemBlock{{Type: "text", Text: "You are Codex."}},
			codexTools,
		),
		// TX 3: response.completed for turn 1 -> "Hello."
		makeWSRespEntry(26783, "2026-04-08T00:00:03Z", "Hello.", nil),
		// TX 4: second user turn: "what's your name"
		makeWSReqEntry(26784, "2026-04-08T00:00:04Z", sessionID,
			[]dissector.Message{
				{Role: "user", Content: []dissector.ContentBlock{{Type: "text", Text: "what's your name"}}},
			},
			[]dissector.SystemBlock{{Type: "text", Text: "You are Codex."}},
			codexTools,
		),
		// TX 5: response.completed for turn 2 -> "Codex."
		makeWSRespEntry(26795, "2026-04-08T00:00:05Z", "Codex.", nil),
	}

	conv := assembleConversation(sessionID, entries)

	// Basic checks
	if conv.provider != "openai" {
		t.Errorf("provider = %q, want openai", conv.provider)
	}
	if conv.clientName != "codex" {
		t.Errorf("clientName = %q, want codex", conv.clientName)
	}
	if conv.model != "gpt-5.4" {
		t.Errorf("model = %q, want gpt-5.4", conv.model)
	}

	// Must have 2 turns
	if conv.turnCount != 2 {
		t.Fatalf("turnCount = %d, want 2", conv.turnCount)
	}
	if len(conv.turns) != 2 {
		t.Fatalf("len(turns) = %d, want 2", len(conv.turns))
	}

	// Turn 1: user prompt = "hello"
	turn1 := conv.turns[0]
	if turn1.userPrompt == nil || *turn1.userPrompt != "hello" {
		got := "<nil>"
		if turn1.userPrompt != nil {
			got = *turn1.userPrompt
		}
		t.Errorf("turn 1 userPrompt = %q, want 'hello'", got)
	}

	// Turn 1 should have an assistant step with "Hello."
	turn1HasAssistant := false
	for _, step := range turn1.steps {
		if step["type"] == "assistant" {
			if text, ok := step["text"].(string); ok && text == "Hello." {
				turn1HasAssistant = true
			}
		}
	}
	if !turn1HasAssistant {
		t.Errorf("turn 1 missing assistant step with 'Hello.', steps: %v", stepsJSON(turn1.steps))
	}

	// Turn 2: user prompt = "what's your name"
	turn2 := conv.turns[1]
	if turn2.userPrompt == nil || *turn2.userPrompt != "what's your name" {
		got := "<nil>"
		if turn2.userPrompt != nil {
			got = *turn2.userPrompt
		}
		t.Errorf("turn 2 userPrompt = %q, want \"what's your name\"", got)
	}

	// Turn 2 should have an assistant step with "Codex."
	turn2HasAssistant := false
	for _, step := range turn2.steps {
		if step["type"] == "assistant" {
			if text, ok := step["text"].(string); ok && text == "Codex." {
				turn2HasAssistant = true
			}
		}
	}
	if !turn2HasAssistant {
		t.Errorf("turn 2 missing assistant step with 'Codex.', steps: %v", stepsJSON(turn2.steps))
	}

	// System prompt should be set
	if conv.systemPrompt == nil || !strings.Contains(*conv.systemPrompt, "Codex") {
		t.Error("missing system prompt")
	}
}

// TestAssembleConversation_CodexWS_WithToolCalls verifies that tool calls
// from WS_RESP response.completed frames are included in turns.
func TestAssembleConversation_CodexWS_WithToolCalls(t *testing.T) {
	sessionID := "test-tools-session"
	codexTools := []dissector.Tool{
		{Name: "exec_command"},
		{Name: "apply_patch"},
		{Name: "spawn_agent"},
	}

	entries := []transactionEntry{
		// Turn 1: user asks to list files
		makeWSReqEntry(1, "2026-04-08T00:00:01Z", sessionID,
			[]dissector.Message{
				{Role: "user", Content: []dissector.ContentBlock{{Type: "text", Text: "list files"}}},
			},
			[]dissector.SystemBlock{{Type: "text", Text: "You are Codex."}},
			codexTools,
		),
		// Response: assistant calls exec_command
		makeWSRespEntry(2, "2026-04-08T00:00:02Z", "", []dissector.ToolCall{
			{Tool: "exec_command", InputPreview: `{"command":"ls -la"}`, ToolSummary: "ls -la"},
		}),
		// Turn 2: user asks to fix a bug (after tool result was sent)
		makeWSReqEntry(3, "2026-04-08T00:00:03Z", sessionID,
			[]dissector.Message{
				// The tool result from previous turn
				{Role: "user", Content: []dissector.ContentBlock{{Type: "tool_result", ToolUseID: "call_1", Content: "file1.go\nfile2.go"}}},
				// New user message
				{Role: "user", Content: []dissector.ContentBlock{{Type: "text", Text: "fix the bug in file1.go"}}},
			},
			[]dissector.SystemBlock{{Type: "text", Text: "You are Codex."}},
			codexTools,
		),
		// Response: assistant text
		makeWSRespEntry(4, "2026-04-08T00:00:04Z", "I'll fix it.", nil),
	}

	conv := assembleConversation(sessionID, entries)

	if conv.turnCount != 2 {
		t.Fatalf("turnCount = %d, want 2", conv.turnCount)
	}

	// Turn 1: "list files"
	if conv.turns[0].userPrompt == nil || *conv.turns[0].userPrompt != "list files" {
		got := "<nil>"
		if conv.turns[0].userPrompt != nil {
			got = *conv.turns[0].userPrompt
		}
		t.Errorf("turn 1 userPrompt = %q, want 'list files'", got)
	}

	// Turn 2: "fix the bug in file1.go"
	if conv.turns[1].userPrompt == nil || *conv.turns[1].userPrompt != "fix the bug in file1.go" {
		got := "<nil>"
		if conv.turns[1].userPrompt != nil {
			got = *conv.turns[1].userPrompt
		}
		t.Errorf("turn 2 userPrompt = %q, want 'fix the bug in file1.go'", got)
	}
}

// TestAssembleConversation_NonWS_StillUsesBestEntry verifies that the
// existing best-entry logic is preserved for non-WS (HTTP POST) transactions.
func TestAssembleConversation_NonWS_StillUsesBestEntry(t *testing.T) {
	// Simulate Claude Code HTTP POST: cumulative message history
	entries := []transactionEntry{
		{
			txnID:         1,
			timestamp:     "2026-04-08T00:00:01Z",
			containerName: "test",
			url:           "https://api.anthropic.com/v1/messages",
			sessionID:     "sess1",
			model:         "claude-sonnet",
			result: &dissector.ExtractionResult{
				Provider:  "anthropic",
				SessionID: "sess1",
				Model:     "claude-sonnet",
				Messages: []dissector.Message{
					{Role: "user", Content: []dissector.ContentBlock{{Type: "text", Text: "hello"}}},
				},
				MessageCount: 1,
			},
			requestHeaders: map[string][]string{"User-Agent": {"claude-cli/1.0"}},
		},
		{
			txnID:         2,
			timestamp:     "2026-04-08T00:00:02Z",
			containerName: "test",
			url:           "https://api.anthropic.com/v1/messages",
			sessionID:     "sess1",
			model:         "claude-sonnet",
			result: &dissector.ExtractionResult{
				Provider:  "anthropic",
				SessionID: "sess1",
				Model:     "claude-sonnet",
				Messages: []dissector.Message{
					{Role: "user", Content: []dissector.ContentBlock{{Type: "text", Text: "hello"}}},
					{Role: "assistant", Content: []dissector.ContentBlock{{Type: "text", Text: "Hi!"}}},
					{Role: "user", Content: []dissector.ContentBlock{{Type: "text", Text: "what's your name"}}},
				},
				MessageCount: 3,
			},
			requestHeaders: map[string][]string{"User-Agent": {"claude-cli/1.0"}},
		},
	}

	conv := assembleConversation("sess1", entries)

	// Should use cumulative best-entry approach: 2 turns from entry 2
	if conv.turnCount != 2 {
		t.Fatalf("turnCount = %d, want 2", conv.turnCount)
	}
	if conv.turns[0].userPrompt == nil || *conv.turns[0].userPrompt != "hello" {
		t.Error("turn 1 should be 'hello'")
	}
	if conv.turns[1].userPrompt == nil || *conv.turns[1].userPrompt != "what's your name" {
		t.Error("turn 2 should be 'what's your name'")
	}
}

// TestAssignWSResponseSessions verifies that sessionless WS_RESP entries
// get assigned the session of the nearest preceding WS_REQ.
func TestAssignWSResponseSessions(t *testing.T) {
	entries := []transactionEntry{
		{txnID: 1, url: "wss://api.openai.com:80/v1/responses", sessionID: "sess-A"},          // WS_REQ
		{txnID: 2, url: "wss://api.openai.com:80/v1/responses", sessionID: ""},                 // WS_RESP (no session)
		{txnID: 3, url: "wss://api.openai.com:80/v1/responses", sessionID: ""},                 // WS_RESP (no session)
		{txnID: 4, url: "wss://api.openai.com:80/v1/responses", sessionID: "sess-A"},          // WS_REQ
		{txnID: 5, url: "wss://api.openai.com:80/v1/responses", sessionID: ""},                 // WS_RESP (no session)
		{txnID: 6, url: "https://api.anthropic.com/v1/messages", sessionID: ""},                 // non-WS (should not be touched)
		{txnID: 7, url: "wss://api.openai.com:80/v1/responses", sessionID: "sess-B"},          // WS_REQ different session
		{txnID: 8, url: "wss://api.openai.com:80/v1/responses", sessionID: ""},                 // WS_RESP (should get sess-B)
	}

	assignWSResponseSessions(entries)

	expected := []string{"sess-A", "sess-A", "sess-A", "sess-A", "sess-A", "", "sess-B", "sess-B"}
	for i, want := range expected {
		if entries[i].sessionID != want {
			t.Errorf("entries[%d] (txnID=%d) sessionID = %q, want %q", i, entries[i].txnID, entries[i].sessionID, want)
		}
	}
}

func stepsJSON(steps []map[string]any) string {
	b, _ := json.MarshalIndent(steps, "", "  ")
	return string(b)
}
