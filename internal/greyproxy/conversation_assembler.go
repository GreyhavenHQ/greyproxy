package greyproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/greyhavenhq/greyproxy/internal/greyproxy/dissector"
)

// AssemblerVersion is incremented when the assembly logic changes in a way
// that requires reprocessing existing conversations (e.g. new fields, linking).
// When the stored version differs from this constant, the settings page
// offers a "Rebuild conversations" action.
const AssemblerVersion = 3

// ConversationAssembler subscribes to EventTransactionNew and reassembles
// LLM conversations from HTTP transactions using registered dissectors.
type ConversationAssembler struct {
	db  *DB
	bus *EventBus
	mu  sync.Mutex // protects processNewTransactions / RebuildAllConversations
}

// NewConversationAssembler creates a new assembler.
func NewConversationAssembler(db *DB, bus *EventBus) *ConversationAssembler {
	return &ConversationAssembler{db: db, bus: bus}
}

// StoredAssemblerVersion returns the version stored in the DB, or 0 if unset/invalid.
func StoredAssemblerVersion(db *DB) int {
	v, err := GetConversationProcessingState(db, "assembler_version")
	if err != nil {
		slog.Warn("assembler: failed to read assembler_version", "error", err)
		return 0
	}
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		slog.Warn("assembler: invalid assembler_version value", "value", v, "error", err)
		return 0
	}
	return n
}

// RebuildAllConversations resets the processing cursor so the assembler
// reprocesses every transaction from scratch on its next cycle.
func (a *ConversationAssembler) RebuildAllConversations() {
	a.mu.Lock()
	defer a.mu.Unlock()
	slog.Info("assembler: rebuild requested, resetting processing cursor")
	SetConversationProcessingState(a.db, "last_processed_id", "0")
	a.processNewTransactionsLocked()
	SetConversationProcessingState(a.db, "assembler_version", strconv.Itoa(AssemblerVersion))
	slog.Info("assembler: rebuild complete")
}

// Start begins listening for new transactions and processing them.
// On startup it backfills any existing unprocessed transactions (covers
// first run or transactions that arrived while the assembler was stopped).
// Then it debounces rapid-fire transactions (500ms) to batch processing.
func (a *ConversationAssembler) Start(ctx context.Context) {
	// Auto-rebuild if assembler version changed
	if StoredAssemblerVersion(a.db) < AssemblerVersion {
		slog.Info("assembler: version changed, rebuilding all conversations",
			"stored", StoredAssemblerVersion(a.db), "current", AssemblerVersion)
		a.RebuildAllConversations()
	}

	// Backfill: process any transactions already in the DB but not yet assembled
	a.processNewTransactions()

	ch := a.bus.Subscribe(128)
	defer a.bus.Unsubscribe(ch)

	// trigger is a non-blocking signal channel used by the debounce timer
	// to notify the main loop that processing should run.
	trigger := make(chan struct{}, 1)
	var debounceTimer *time.Timer

	for {
		select {
		case <-ctx.Done():
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			return
		case evt := <-ch:
			if evt.Type != EventTransactionNew {
				continue
			}
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			debounceTimer = time.AfterFunc(500*time.Millisecond, func() {
				select {
				case trigger <- struct{}{}:
				default:
				}
			})
		case <-trigger:
			a.processNewTransactions()
		}
	}
}

// processNewTransactions acquires the mutex and runs incremental assembly.
func (a *ConversationAssembler) processNewTransactions() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.processNewTransactionsLocked()
}

// processNewTransactionsLocked runs incremental assembly. Caller must hold a.mu.
func (a *ConversationAssembler) processNewTransactionsLocked() {
	lastIDStr, err := GetConversationProcessingState(a.db, "last_processed_id")
	if err != nil {
		slog.Warn("assembler: failed to get last processed ID", "error", err)
		return
	}
	lastID := int64(0)
	if lastIDStr != "" {
		parsed, err := strconv.ParseInt(lastIDStr, 10, 64)
		if err != nil {
			slog.Warn("assembler: invalid last_processed_id", "value", lastIDStr, "error", err)
		} else {
			lastID = parsed
		}
	}

	// Load new transactions that match any dissector
	newTxns, maxID, err := a.loadNewTransactions(lastID)
	if err != nil {
		slog.Warn("assembler: failed to load transactions", "error", err)
		return
	}
	if len(newTxns) == 0 {
		if maxID > lastID {
			SetConversationProcessingState(a.db, "last_processed_id", strconv.FormatInt(maxID, 10))
		}
		return
	}

	// Find affected session IDs
	affectedSessions := map[string]bool{}
	for _, te := range newTxns {
		if te.sessionID != "" {
			affectedSessions[te.sessionID] = true
		}
	}

	if len(affectedSessions) == 0 {
		SetConversationProcessingState(a.db, "last_processed_id", strconv.FormatInt(maxID, 10))
		return
	}

	// Reload ALL transactions for affected sessions
	allTxns, err := a.loadTransactionsForSessions(affectedSessions)
	if err != nil {
		slog.Warn("assembler: failed to reload sessions", "error", err)
		return
	}

	// Group by session and assemble
	sessions := groupBySession(allTxns)
	var allConversations []assembledConversation

	for sessionID, entries := range sessions {
		conv := assembleConversation(sessionID, entries)
		allConversations = append(allConversations, conv)
	}

	linkSubagentConversations(allConversations)

	// Upsert into database
	for _, conv := range allConversations {
		if err := a.upsertConversation(conv); err != nil {
			slog.Warn("assembler: failed to upsert conversation", "id", conv.conversationID, "error", err)
			continue
		}
		a.bus.Publish(Event{
			Type: EventConversationUpdated,
			Data: map[string]any{"conversation_id": conv.conversationID},
		})
	}

	SetConversationProcessingState(a.db, "last_processed_id", strconv.FormatInt(maxID, 10))
	slog.Info("assembler: processed conversations", "count", len(allConversations), "max_id", maxID)
}

// --- Internal types ---

type transactionEntry struct {
	txnID         int64
	timestamp     string
	containerName string
	url           string
	sessionID     string
	model         string
	body          map[string]any // parsed request body
	msgCount      int
	result        *dissector.ExtractionResult
	durationMs    int64
}

type assembledConversation struct {
	conversationID      string
	model               string
	containerName       string
	provider            string
	requestIDs          []int64
	startedAt           string
	endedAt             string
	turnCount           int
	systemPrompt        *string
	systemPromptSummary *string
	parentConvID        *string
	lastTurnHasResponse bool
	metadata            map[string]any
	linkedSubagents     []map[string]any
	incomplete          bool
	incompleteReason    *string
	turns               []assembledTurn
}

type assembledTurn struct {
	turnNumber     int
	userPrompt     *string
	steps          []map[string]any
	apiCallsInTurn int
	requestIDs     []int64
	timestamp      *string
	timestampEnd   *string
	durationMs     *int64
	model          *string
}

// --- Transaction loading ---

func (a *ConversationAssembler) loadNewTransactions(sinceID int64) ([]transactionEntry, int64, error) {
	rows, err := a.db.ReadDB().Query(`
		SELECT id, timestamp, container_name, url, method, destination_host,
		       request_body, response_body, response_content_type, duration_ms
		FROM http_transactions
		WHERE id > ?
		ORDER BY id`, sinceID)
	if err != nil {
		return nil, sinceID, err
	}
	defer rows.Close()

	var entries []transactionEntry
	maxID := sinceID

	for rows.Next() {
		var (
			id            int64
			ts, container, url, method, host string
			reqBody, respBody []byte
			respCT        string
			durationMs    int64
		)
		if err := rows.Scan(&id, &ts, &container, &url, &method, &host,
			&reqBody, &respBody, &respCT, &durationMs); err != nil {
			slog.Warn("assembler: failed to scan transaction row", "error", err)
			continue
		}
		if id > maxID {
			maxID = id
		}

		d := dissector.FindDissector(url, method, host)
		if d == nil {
			continue
		}

		result, err := d.Extract(dissector.ExtractionInput{
			TransactionID: id,
			URL:           url,
			Method:        method,
			Host:          host,
			RequestBody:   reqBody,
			ResponseBody:  respBody,
			ResponseCT:    respCT,
			ContainerName: container,
			DurationMs:    durationMs,
		})
		if err != nil || result == nil {
			continue
		}

		// Parse body for assembly logic
		var body map[string]any
		if len(reqBody) > 0 {
			if err := json.Unmarshal(reqBody, &body); err != nil {
				slog.Debug("assembler: failed to parse request body JSON", "txn_id", id, "error", err)
			}
		}

		entries = append(entries, transactionEntry{
			txnID:         id,
			timestamp:     ts,
			containerName: container,
			url:           url,
			sessionID:     result.SessionID,
			model:         result.Model,
			body:          body,
			msgCount:      result.MessageCount,
			result:        result,
			durationMs:    durationMs,
		})
	}
	return entries, maxID, nil
}

func (a *ConversationAssembler) loadTransactionsForSessions(sessionIDs map[string]bool) ([]transactionEntry, error) {
	// Build LIKE clauses for session ID filtering
	var likeClauses []string
	var args []any
	for sid := range sessionIDs {
		likeClauses = append(likeClauses, `CAST(request_body AS TEXT) LIKE ? ESCAPE '\'`)
		args = append(args, "%session_"+escapeLikePattern(sid)+"%")
	}

	query := fmt.Sprintf(`
		SELECT id, timestamp, container_name, url, method, destination_host,
		       request_body, response_body, response_content_type, duration_ms
		FROM http_transactions
		WHERE url LIKE '%%api.anthropic.com/v1/messages%%'
		  AND (%s)
		ORDER BY id`, strings.Join(likeClauses, " OR "))

	rows, err := a.db.ReadDB().Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []transactionEntry
	for rows.Next() {
		var (
			id            int64
			ts, container, url, method, host string
			reqBody, respBody []byte
			respCT        string
			durationMs    int64
		)
		if err := rows.Scan(&id, &ts, &container, &url, &method, &host,
			&reqBody, &respBody, &respCT, &durationMs); err != nil {
			slog.Warn("assembler: failed to scan session transaction row", "error", err)
			continue
		}

		d := dissector.FindDissector(url, method, host)
		if d == nil {
			continue
		}

		result, err := d.Extract(dissector.ExtractionInput{
			TransactionID: id,
			URL:           url,
			Method:        method,
			Host:          host,
			RequestBody:   reqBody,
			ResponseBody:  respBody,
			ResponseCT:    respCT,
			ContainerName: container,
			DurationMs:    durationMs,
		})
		if err != nil || result == nil {
			continue
		}

		var body map[string]any
		if len(reqBody) > 0 {
			if err := json.Unmarshal(reqBody, &body); err != nil {
				slog.Debug("assembler: failed to parse request body JSON", "txn_id", id, "error", err)
			}
		}

		entries = append(entries, transactionEntry{
			txnID:         id,
			timestamp:     ts,
			containerName: container,
			url:           url,
			sessionID:     result.SessionID,
			model:         result.Model,
			body:          body,
			msgCount:      result.MessageCount,
			result:        result,
			durationMs:    durationMs,
		})
	}
	return entries, nil
}

// --- Assembly logic (ported from assemble2.py) ---

var (
	scaffoldingTexts = map[string]bool{
		"Tool loaded.":                       true,
		"[Request interrupted by user]":      true,
		"clear":                              true,
	}

	xmlTagPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?s)<local-command-caveat>.*?</local-command-caveat>`),
		regexp.MustCompile(`(?s)<command-name>.*?</command-name>`),
		regexp.MustCompile(`(?s)<command-message>.*?</command-message>`),
		regexp.MustCompile(`(?s)<command-args>.*?</command-args>`),
		regexp.MustCompile(`(?s)<local-command-stdout>.*?</local-command-stdout>`),
	}

	timeGapThreshold = 5 * time.Minute
)

func groupBySession(txns []transactionEntry) map[string][]transactionEntry {
	rawSessions := map[string][]transactionEntry{}
	var unassigned []transactionEntry

	for _, txn := range txns {
		if txn.sessionID != "" {
			rawSessions[txn.sessionID] = append(rawSessions[txn.sessionID], txn)
		} else {
			unassigned = append(unassigned, txn)
		}
	}

	// Heuristic grouping for unassigned
	if len(unassigned) > 0 {
		sort.Slice(unassigned, func(i, j int) bool { return unassigned[i].timestamp < unassigned[j].timestamp })

		var groups [][]transactionEntry
		var current []transactionEntry

		for _, entry := range unassigned {
			if len(current) == 0 {
				current = append(current, entry)
				continue
			}
			prevTs, err1 := time.Parse(time.RFC3339, current[len(current)-1].timestamp)
			currTs, err2 := time.Parse(time.RFC3339, entry.timestamp)
			if err1 != nil || err2 != nil {
				// Cannot determine time gap; keep in same group
				current = append(current, entry)
				continue
			}
			if currTs.Sub(prevTs) > timeGapThreshold {
				groups = append(groups, current)
				current = []transactionEntry{entry}
			} else {
				current = append(current, entry)
			}
		}
		if len(current) > 0 {
			groups = append(groups, current)
		}

		for _, group := range groups {
			groupStart, err1 := time.Parse(time.RFC3339, group[0].timestamp)
			groupEnd, err2 := time.Parse(time.RFC3339, group[len(group)-1].timestamp)

			if err1 != nil || err2 != nil {
				// Cannot determine overlap; assign to heuristic group
				fakeID := fmt.Sprintf("heuristic_%d_%d", group[0].txnID, group[len(group)-1].txnID)
				rawSessions[fakeID] = group
				continue
			}

			var bestSession string
			var bestOverlap time.Duration

			for sid, sentries := range rawSessions {
				sStart, e1 := time.Parse(time.RFC3339, sentries[0].timestamp)
				sEnd, e2 := time.Parse(time.RFC3339, sentries[len(sentries)-1].timestamp)
				if e1 != nil || e2 != nil {
					continue
				}
				overlapStart := maxTime(sStart, groupStart)
				overlapEnd := minTime(sEnd.Add(timeGapThreshold), groupEnd.Add(timeGapThreshold))
				if overlapStart.Before(overlapEnd) || overlapStart.Equal(overlapEnd) {
					overlap := overlapEnd.Sub(overlapStart)
					if overlap > bestOverlap {
						bestOverlap = overlap
						bestSession = sid
					}
				}
			}

			if bestSession != "" {
				rawSessions[bestSession] = append(rawSessions[bestSession], group...)
				sort.Slice(rawSessions[bestSession], func(i, j int) bool {
					return rawSessions[bestSession][i].timestamp < rawSessions[bestSession][j].timestamp
				})
			} else {
				fakeID := fmt.Sprintf("heuristic_%d_%d", group[0].txnID, group[len(group)-1].txnID)
				rawSessions[fakeID] = group
			}
		}
	}

	// Split each session into threads
	sessions := map[string][]transactionEntry{}
	for sid, entries := range rawSessions {
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].timestamp == entries[j].timestamp {
				return entries[i].txnID < entries[j].txnID
			}
			return entries[i].timestamp < entries[j].timestamp
		})

		threads := splitSessionIntoThreads(entries)
		for threadKey, threadEntries := range threads {
			if len(threadEntries) == 0 || threadKey == "utility" || threadKey == "mcp" {
				continue
			}
			if threadKey == "main" {
				sessions[sid] = threadEntries
			} else {
				subConvs := splitSubagentInvocations(threadEntries)
				for i, subEntries := range subConvs {
					sessions[fmt.Sprintf("%s/%s_%d", sid, threadKey, i+1)] = subEntries
				}
			}
		}
	}
	return sessions
}

func splitSessionIntoThreads(entries []transactionEntry) map[string][]transactionEntry {
	threads := map[string][]transactionEntry{}
	for _, entry := range entries {
		if entry.result == nil {
			threads["main"] = append(threads["main"], entry)
			continue
		}
		threadType := dissector.ClassifyThread(entry.result.SystemBlocks, len(entry.result.Tools))
		switch threadType {
		case "main":
			threads["main"] = append(threads["main"], entry)
		case "subagent":
			sysLen := dissector.SystemPromptLength(entry.result.SystemBlocks)
			key := fmt.Sprintf("subagent_%d", sysLen)
			threads[key] = append(threads[key], entry)
		case "mcp", "utility":
			threads[threadType] = append(threads[threadType], entry)
		default:
			threads["main"] = append(threads["main"], entry)
		}
	}
	return threads
}

func splitSubagentInvocations(entries []transactionEntry) [][]transactionEntry {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].timestamp == entries[j].timestamp {
			return entries[i].txnID < entries[j].txnID
		}
		return entries[i].timestamp < entries[j].timestamp
	})

	var invocations [][]transactionEntry
	var current []transactionEntry

	for _, entry := range entries {
		msgCount := entry.msgCount
		if len(current) > 0 && msgCount >= 0 {
			prevCount := -1
			for i := len(current) - 1; i >= 0; i-- {
				if current[i].msgCount >= 0 {
					prevCount = current[i].msgCount
					break
				}
			}
			if prevCount < 0 {
				prevCount = 999
			}
			if msgCount < prevCount-1 {
				invocations = append(invocations, current)
				current = nil
			}
		}
		current = append(current, entry)
	}
	if len(current) > 0 {
		invocations = append(invocations, current)
	}
	return invocations
}

func isRealUserMessage(msg dissector.Message) bool {
	if msg.RawContent != "" {
		if strings.HasPrefix(msg.RawContent, "<available-deferred-tools>") {
			return false
		}
		stripped := strings.TrimSpace(msg.RawContent)
		return stripped != "" && !scaffoldingTexts[stripped]
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
		if text == "" || strings.HasPrefix(text, "<system-reminder>") || strings.HasPrefix(text, "<local-command-caveat>") || scaffoldingTexts[text] {
			continue
		}
		realTexts = append(realTexts, text)
	}
	if hasToolResult && len(realTexts) == 0 {
		return false
	}
	return len(realTexts) > 0
}

func cleanText(text string) string {
	for _, pat := range xmlTagPatterns {
		text = pat.ReplaceAllString(text, "")
	}
	return strings.TrimSpace(text)
}

func getUserText(msg dissector.Message) *string {
	if msg.RawContent != "" {
		if strings.HasPrefix(msg.RawContent, "<available-deferred-tools>") {
			return nil
		}
		cleaned := cleanText(msg.RawContent)
		if cleaned == "" || scaffoldingTexts[cleaned] {
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
		if text == "" || strings.HasPrefix(text, "<system-reminder>") || scaffoldingTexts[text] {
			continue
		}
		cleaned := cleanText(text)
		if cleaned != "" && !scaffoldingTexts[cleaned] {
			texts = append(texts, cleaned)
		}
	}
	if len(texts) == 0 {
		return nil
	}
	joined := strings.Join(texts, "\n")
	return &joined
}

func getAssistantSummary(msg dissector.Message) map[string]any {
	result := map[string]any{"tool_calls": []map[string]any{}}

	if msg.RawContent != "" {
		result["text"] = msg.RawContent
		return result
	}

	var texts []string
	var toolCalls []map[string]any
	var thinking []string

	for _, b := range msg.Content {
		switch b.Type {
		case "text":
			texts = append(texts, b.Text)
		case "tool_use":
			tc := map[string]any{
				"tool":          b.Name,
				"input_preview": b.Input,
			}
			if b.ToolSummary != "" {
				tc["tool_summary"] = b.ToolSummary
			}
			if b.ID != "" {
				tc["tool_use_id"] = b.ID
			}
			toolCalls = append(toolCalls, tc)
		case "thinking":
			if b.Thinking != "" {
				thinking = append(thinking, b.Thinking)
			}
		}
	}

	if len(texts) > 0 {
		result["text"] = strings.Join(texts, "\n")
	}
	if len(toolCalls) > 0 {
		result["tool_calls"] = toolCalls
	}
	if len(thinking) > 0 {
		t := thinking[0]
		if len(t) > 500 {
			t = truncateUTF8(t, 500) + "..."
		}
		result["thinking"] = t
	}
	return result
}

func getToolResults(msg dissector.Message) []map[string]any {
	var results []map[string]any
	for _, b := range msg.Content {
		if b.Type != "tool_result" {
			continue
		}
		results = append(results, map[string]any{
			"tool_use_id":     b.ToolUseID,
			"content_preview": b.Content,
			"is_error":        b.IsError,
		})
	}
	return results
}

func buildRoundsFromMessages(messages []dissector.Message) []assembledTurn {
	// Find indices of real user prompts
	var promptIndices []int
	for i, msg := range messages {
		if msg.Role == "user" && isRealUserMessage(msg) {
			promptIndices = append(promptIndices, i)
		}
	}
	if len(promptIndices) == 0 {
		return nil
	}

	var rounds []assembledTurn
	for ri, startIdx := range promptIndices {
		endIdx := len(messages)
		if ri+1 < len(promptIndices) {
			endIdx = promptIndices[ri+1]
		}

		userText := getUserText(messages[startIdx])

		var steps []map[string]any
		apiCalls := 0
		pendingToolCalls := map[string]map[string]any{}

		for j := startIdx + 1; j < endIdx; j++ {
			msg := messages[j]
			if msg.Role == "assistant" {
				apiCalls++
				summary := getAssistantSummary(msg)
				step := map[string]any{"type": "assistant"}
				if t, ok := summary["thinking"]; ok {
					step["thinking_preview"] = t
				}
				if t, ok := summary["text"]; ok && t != nil {
					step["text"] = t
				}
				if tcs, ok := summary["tool_calls"].([]map[string]any); ok && len(tcs) > 0 {
					step["tool_calls"] = tcs
					for _, tc := range tcs {
						if tid, ok := tc["tool_use_id"].(string); ok && tid != "" {
							pendingToolCalls[tid] = tc
						}
					}
				}
				steps = append(steps, step)
			} else if msg.Role == "user" {
				results := getToolResults(msg)
				for _, r := range results {
					tid, _ := r["tool_use_id"].(string)
					if tc, ok := pendingToolCalls[tid]; ok {
						tc["result_preview"] = r["content_preview"]
						tc["is_error"] = r["is_error"]
					}
				}
			}
		}

		rounds = append(rounds, assembledTurn{
			turnNumber:     ri + 1,
			userPrompt:     userText,
			steps:          steps,
			apiCallsInTurn: apiCalls,
		})
	}
	return rounds
}

func assembleConversation(sessionID string, entries []transactionEntry) assembledConversation {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].timestamp == entries[j].timestamp {
			return entries[i].txnID < entries[j].txnID
		}
		return entries[i].timestamp < entries[j].timestamp
	})

	conv := assembledConversation{
		conversationID: "session_" + sessionID,
		provider:       "anthropic",
		containerName:  entries[0].containerName,
		startedAt:      entries[0].timestamp,
		endedAt:        entries[len(entries)-1].timestamp,
		requestIDs:     make([]int64, 0, len(entries)),
	}
	for _, e := range entries {
		conv.requestIDs = append(conv.requestIDs, e.txnID)
	}

	// Find best entry (last one with parsed body and messages)
	var bestEntry *transactionEntry
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].result != nil && entries[i].result.MessageCount > 0 {
			bestEntry = &entries[i]
			break
		}
	}

	if bestEntry == nil {
		conv.model = entries[0].model
		conv.incomplete = true
		reason := "All request bodies truncated; cannot parse messages"
		conv.incompleteReason = &reason
		conv.metadata = map[string]any{
			"total_requests":     len(entries),
			"truncated_requests": len(entries),
			"parseable_requests": 0,
		}
		return conv
	}

	conv.model = bestEntry.model
	messages := bestEntry.result.Messages
	rounds := buildRoundsFromMessages(messages)
	conv.turnCount = len(rounds)

	// Map requests to turns
	turnEntryMap := mapRequestsToTurns(entries, conv.turnCount)

	for i, rnd := range rounds {
		turnNum := i + 1
		turnReqs := turnEntryMap[turnNum]

		turn := assembledTurn{
			turnNumber:     turnNum,
			userPrompt:     rnd.userPrompt,
			steps:          rnd.steps,
			apiCallsInTurn: rnd.apiCallsInTurn,
		}

		for _, e := range turnReqs {
			turn.requestIDs = append(turn.requestIDs, e.txnID)
		}

		if len(turnReqs) > 0 {
			turn.timestamp = &turnReqs[0].timestamp
			endTs := turnReqs[len(turnReqs)-1].timestamp
			turn.timestampEnd = &endTs
			var totalDur int64
			for _, e := range turnReqs {
				totalDur += e.durationMs
			}
			turn.durationMs = &totalDur
			turn.model = &turnReqs[0].model
		} else if i < len(entries) {
			turn.timestamp = &entries[i].timestamp
			turn.durationMs = &entries[i].durationMs
			turn.model = &entries[i].model
		}

		conv.turns = append(conv.turns, turn)
	}

	// System prompt
	if len(bestEntry.result.SystemBlocks) > 0 {
		var parts []string
		for _, b := range bestEntry.result.SystemBlocks {
			if b.Text != "" {
				parts = append(parts, b.Text)
			}
		}
		if len(parts) > 0 {
			sp := strings.Join(parts, "\n\n---\n\n")
			conv.systemPrompt = &sp
			if len(sp) > 100 {
				summary := sp
				if len(summary) > 500 {
					summary = truncateUTF8(summary, 500) + "..."
				}
				conv.systemPromptSummary = &summary
			}
		}
	}

	// Recover last assistant response from SSE
	if len(conv.turns) > 0 {
		lastTurn := &conv.turns[len(conv.turns)-1]
		existingTexts := map[string]bool{}
		for _, s := range lastTurn.steps {
			if s["type"] == "assistant" {
				if text, ok := s["text"].(string); ok && len(text) > 0 {
					key := text
					if len(key) > 200 {
						key = key[:200]
					}
					existingTexts[key] = true
				}
			}
		}

		for i := len(entries) - 1; i >= 0; i-- {
			sse := entries[i].result.SSEResponse
			if sse == nil {
				continue
			}
			if sse.Text != "" {
				key := sse.Text
				if len(key) > 200 {
					key = key[:200]
				}
				if existingTexts[key] {
					continue
				}
			}
			step := map[string]any{"type": "assistant"}
			if sse.Thinking != "" {
				step["thinking_preview"] = sse.Thinking
			}
			if sse.Text != "" {
				step["text"] = sse.Text
			}
			if len(sse.ToolCalls) > 0 {
				var tcs []map[string]any
				for _, tc := range sse.ToolCalls {
					m := map[string]any{
						"tool":          tc.Tool,
						"input_preview": tc.InputPreview,
					}
					if tc.ToolSummary != "" {
						m["tool_summary"] = tc.ToolSummary
					}
					tcs = append(tcs, m)
				}
				step["tool_calls"] = tcs
			}
			lastTurn.steps = append(lastTurn.steps, step)
			break
		}

		// Check if last turn has a response
		for _, s := range lastTurn.steps {
			if s["type"] == "assistant" {
				if _, ok := s["text"]; ok {
					conv.lastTurnHasResponse = true
					break
				}
			}
		}
	}

	// Parent conversation ID for subagents
	if strings.Contains(sessionID, "/") {
		parts := strings.SplitN(sessionID, "/", 2)
		parentID := "session_" + parts[0]
		conv.parentConvID = &parentID
	}

	// Metadata
	truncated := 0
	parseable := 0
	for _, e := range entries {
		if e.result == nil || e.result.MessageCount == 0 {
			truncated++
		} else {
			parseable++
		}
	}
	conv.metadata = map[string]any{
		"total_requests":              len(entries),
		"truncated_requests":          truncated,
		"parseable_requests":          parseable,
		"messages_in_best_request":    bestEntry.result.MessageCount,
		"best_request_id":             bestEntry.txnID,
	}

	return conv
}

func mapRequestsToTurns(entries []transactionEntry, numTurns int) map[int][]transactionEntry {
	entryTurns := map[int]int{}
	for i, entry := range entries {
		if entry.result != nil && entry.result.MessageCount > 0 {
			// Count real prompts
			prompts := 0
			for _, msg := range entry.result.Messages {
				if msg.Role == "user" && isRealUserMessage(msg) {
					prompts++
				}
			}
			entryTurns[i] = prompts
		}
	}

	// Fill in gaps
	for i := range entries {
		if _, ok := entryTurns[i]; ok {
			continue
		}
		prevTurn := 0
		for j := i - 1; j >= 0; j-- {
			if v, ok := entryTurns[j]; ok {
				prevTurn = v
				break
			}
		}
		nextTurn := numTurns
		for j := i + 1; j < len(entries); j++ {
			if v, ok := entryTurns[j]; ok {
				nextTurn = v
				break
			}
		}
		if prevTurn > nextTurn {
			entryTurns[i] = prevTurn
		} else {
			entryTurns[i] = nextTurn
		}
	}

	result := map[int][]transactionEntry{}
	for i, entry := range entries {
		turnNum := entryTurns[i]
		if turnNum >= 1 && turnNum <= numTurns {
			result[turnNum] = append(result[turnNum], entry)
		}
	}
	return result
}

func linkSubagentConversations(allConvs []assembledConversation) {
	subagentMap := map[string][]assembledConversation{}
	for _, conv := range allConvs {
		if strings.Contains(conv.conversationID, "/") {
			parts := strings.SplitN(conv.conversationID, "/", 2)
			base := parts[0]
			subagentMap[base] = append(subagentMap[base], conv)
		}
	}

	for i, conv := range allConvs {
		if strings.Contains(conv.conversationID, "/") {
			continue
		}
		subs, ok := subagentMap[conv.conversationID]
		if !ok || len(subs) == 0 {
			continue
		}

		var linked []map[string]any
		for _, s := range subs {
			sub := map[string]any{
				"conversation_id": s.conversationID,
				"turn_count":      s.turnCount,
				"started_at":      s.startedAt,
				"ended_at":        s.endedAt,
			}
			if len(s.turns) > 0 && s.turns[0].userPrompt != nil {
				prompt := *s.turns[0].userPrompt
				if len(prompt) > 200 {
					prompt = truncateUTF8(prompt, 200)
				}
				sub["first_prompt"] = prompt
			}
			linked = append(linked, sub)
		}
		allConvs[i].linkedSubagents = linked

		// Link Agent tool calls to subagent conversations by order
		subIdx := 0
		for _, turn := range allConvs[i].turns {
			for _, step := range turn.steps {
				tcs, _ := step["tool_calls"].([]map[string]any)
				for _, tc := range tcs {
					toolName, _ := tc["tool"].(string)
					if toolName == "Agent" && subIdx < len(subs) {
						tc["linked_conversation_id"] = subs[subIdx].conversationID
						subIdx++
					}
				}
			}
		}
	}
}

func (a *ConversationAssembler) upsertConversation(conv assembledConversation) error {
	input := ConversationUpsertInput{
		ID:                  conv.conversationID,
		Model:               conv.model,
		ContainerName:       conv.containerName,
		Provider:            conv.provider,
		StartedAt:           conv.startedAt,
		EndedAt:             conv.endedAt,
		TurnCount:           conv.turnCount,
		SystemPrompt:        conv.systemPrompt,
		SystemPromptSummary: conv.systemPromptSummary,
		ParentConversationID: conv.parentConvID,
		LastTurnHasResponse: conv.lastTurnHasResponse,
		Incomplete:          conv.incomplete,
		IncompleteReason:    conv.incompleteReason,
	}

	input.MetadataJSON = jsonMarshalOrNil(conv.metadata)
	input.LinkedSubagentsJSON = jsonMarshalOrNil(conv.linkedSubagents)
	input.RequestIDsJSON = jsonMarshalOrNil(conv.requestIDs)

	if err := UpsertConversation(a.db, input); err != nil {
		return fmt.Errorf("upsert conversation: %w", err)
	}

	// Upsert turns
	var turns []TurnInput
	for _, t := range conv.turns {
		ti := TurnInput{
			TurnNumber:     t.turnNumber,
			UserPrompt:     t.userPrompt,
			APICallsInTurn: t.apiCallsInTurn,
			Timestamp:      t.timestamp,
			TimestampEnd:   t.timestampEnd,
			DurationMs:     t.durationMs,
			Model:          t.model,
		}
		if len(t.steps) > 0 {
			ti.StepsJSON = jsonMarshalOrNil(t.steps)
		}
		if len(t.requestIDs) > 0 {
			ti.RequestIDsJSON = jsonMarshalOrNil(t.requestIDs)
		}
		turns = append(turns, ti)
	}

	if err := UpsertTurns(a.db, conv.conversationID, turns); err != nil {
		return fmt.Errorf("upsert turns: %w", err)
	}

	// Update http_transactions with conversation_id link
	for _, txnID := range conv.requestIDs {
		UpdateTransactionConversationID(a.db, txnID, conv.conversationID)
	}

	return nil
}

// --- helpers ---

// truncateUTF8 truncates s to at most maxBytes bytes without splitting a
// multi-byte UTF-8 character.
func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	// Back up from maxBytes to avoid splitting a multi-byte rune
	for maxBytes > 0 && maxBytes < len(s) && s[maxBytes]>>6 == 0b10 {
		maxBytes--
	}
	return s[:maxBytes]
}

// escapeLikePattern escapes SQL LIKE special characters (%, _, \) so they
// are matched literally when used with ESCAPE '\'.
func escapeLikePattern(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
