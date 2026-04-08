package greyproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/greyhavenhq/greyproxy/internal/greyproxy/dissector"
)

// AssemblerVersion is changed when the assembly logic changes in a way
// that requires reprocessing existing conversations (e.g. new fields, linking).
// When the stored version differs from this constant, a rebuild is triggered
// automatically on startup and the settings page flags it.
const AssemblerVersion = 7

// ConversationAssembler subscribes to EventTransactionNew and reassembles
// LLM conversations from HTTP transactions using registered dissectors.
type ConversationAssembler struct {
	db       *DB
	bus      *EventBus
	Registry *EndpointRegistry
	mu       sync.Mutex // protects processNewTransactions / RebuildAllConversations
	enabled  atomic.Bool
}

// NewConversationAssembler creates a new assembler.
func NewConversationAssembler(db *DB, bus *EventBus, registry *EndpointRegistry) *ConversationAssembler {
	a := &ConversationAssembler{db: db, bus: bus, Registry: registry}
	a.enabled.Store(true)
	return a
}

// SetEnabled toggles conversation tracking on or off at runtime.
func (a *ConversationAssembler) SetEnabled(enabled bool) {
	a.enabled.Store(enabled)
	if enabled {
		slog.Info("assembler: conversation tracking enabled")
	} else {
		slog.Info("assembler: conversation tracking disabled")
	}
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
	slog.Info("assembler: rebuild requested, clearing old conversations and resetting cursor")
	DeleteAllConversations(a.db)
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
	if StoredAssemblerVersion(a.db) != AssemblerVersion {
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
	if !a.enabled.Load() {
		return
	}
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

	// Find affected session IDs and collect sessionless entries
	affectedSessions := map[string]bool{}
	var sessionlessTxns []transactionEntry
	for _, te := range newTxns {
		if te.sessionID != "" {
			affectedSessions[te.sessionID] = true
		} else {
			sessionlessTxns = append(sessionlessTxns, te)
		}
	}

	if len(affectedSessions) == 0 && len(sessionlessTxns) == 0 {
		SetConversationProcessingState(a.db, "last_processed_id", strconv.FormatInt(maxID, 10))
		return
	}

	var allConversations []assembledConversation

	// Full rebuild (lastID == 0): loadNewTransactions already scanned every
	// transaction in the DB, so the session reload is redundant and extremely
	// expensive on large databases (LIKE scans over multi-GB bodies).
	// Use the already-loaded entries directly.
	fullRebuild := lastID == 0

	// Process session-based transactions
	if len(affectedSessions) > 0 {
		var allTxns []transactionEntry

		if fullRebuild {
			// Already have all transactions from the initial scan
			allTxns = newTxns
			slog.Info("assembler: full rebuild, skipping session reload",
				"sessions", len(affectedSessions), "entries", len(allTxns))
		} else {
			// Incremental: reload ALL transactions for affected sessions
			var err error
			allTxns, err = a.loadTransactionsForSessions(affectedSessions)
			if err != nil {
				slog.Warn("assembler: failed to reload sessions", "error", err)
				return
			}

			// For OpenAI: main sessions may reference subagent sessions via task_id
			// in tool results. Load those referenced sessions too so that
			// remapOpenAISubagents can remap them under their parent.
			if extraSessions := extractReferencedSubagentSessions(allTxns, affectedSessions); len(extraSessions) > 0 {
				extraTxns, err := a.loadTransactionsForSessions(extraSessions)
				if err != nil {
					slog.Warn("assembler: failed to load referenced subagent sessions", "error", err)
				} else {
					allTxns = append(allTxns, extraTxns...)
				}
			}
		}

		// Group by session and assemble
		sessions := groupBySession(allTxns)
		for sessionID, entries := range sessions {
			conv := assembleConversation(sessionID, entries)
			allConversations = append(allConversations, conv)
		}
	}

	// Process sessionless transactions (Gemini, Aider, etc.)
	// These don't have a session to reload; group them directly via adapter strategy.
	if len(sessionlessTxns) > 0 {
		sessions := groupBySession(sessionlessTxns)
		for sessionID, entries := range sessions {
			conv := assembleConversation(sessionID, entries)
			allConversations = append(allConversations, conv)
		}
	}

	linkSubagentConversations(allConversations)

	// Upsert into database
	upserted := 0
	upsertLastLog := time.Now()
	for _, conv := range allConversations {
		if err := a.upsertConversation(conv); err != nil {
			slog.Warn("assembler: failed to upsert conversation", "id", conv.conversationID, "error", err)
			continue
		}
		a.bus.Publish(Event{
			Type: EventConversationUpdated,
			Data: map[string]any{"conversation_id": conv.conversationID},
		})
		upserted++
		if now := time.Now(); now.Sub(upsertLastLog) >= 10*time.Second {
			slog.Info("assembler: upserting conversations", "progress", fmt.Sprintf("%d/%d", upserted, len(allConversations)))
			upsertLastLog = now
		}
	}

	SetConversationProcessingState(a.db, "last_processed_id", strconv.FormatInt(maxID, 10))
	slog.Info("assembler: processed conversations", "count", len(allConversations), "max_id", maxID)
}

// --- Internal types ---

type transactionEntry struct {
	txnID          int64
	timestamp      string
	containerName  string
	url            string
	sessionID      string
	model          string
	body           map[string]any // parsed request body
	msgCount       int
	result         *dissector.ExtractionResult
	durationMs     int64
	requestHeaders http.Header
}

type assembledConversation struct {
	conversationID      string
	model               string
	containerName       string
	provider            string
	clientName          string
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
	var totalRows int
	_ = a.db.ReadDB().QueryRow(`SELECT COUNT(*) FROM http_transactions WHERE id > ?`, sinceID).Scan(&totalRows)
	slog.Info("assembler: starting scan", "transactions_to_scan", totalRows)

	rows, err := a.db.ReadDB().Query(`
		SELECT id, timestamp, container_name, url, method, destination_host,
		       request_body, response_body, response_content_type, duration_ms,
		       request_headers
		FROM http_transactions
		WHERE id > ?
		ORDER BY id`, sinceID)
	if err != nil {
		return nil, sinceID, err
	}
	defer rows.Close()

	var entries []transactionEntry
	maxID := sinceID
	scanned := 0
	matched := 0
	lastLog := time.Now()

	for rows.Next() {
		var (
			id            int64
			ts, container, url, method, host string
			reqBody, respBody []byte
			respCT        *string
			durationMsPtr *int64
			reqHeadersJSON *string
		)
		if err := rows.Scan(&id, &ts, &container, &url, &method, &host,
			&reqBody, &respBody, &respCT, &durationMsPtr, &reqHeadersJSON); err != nil {
			slog.Warn("assembler: failed to scan transaction row", "error", err)
			continue
		}
		var durationMs int64
		if durationMsPtr != nil {
			durationMs = *durationMsPtr
		}
		reqHeaders := parseHeadersJSON(reqHeadersJSON)
		scanned++
		if id > maxID {
			maxID = id
		}
		if now := time.Now(); now.Sub(lastLog) >= 10*time.Second {
			slog.Info("assembler: scanning transactions", "scanned", scanned, "matched", matched, "current_id", id)
			lastLog = now
		}

		d := a.Registry.FindDissector(url, method, host)
		if d == nil {
			// Try auto-detecting OpenAI-compatible endpoints from body shape
			d = a.Registry.AutoDetectAndCreate(url, method, host, reqBody)
			if d == nil {
				continue
			}
		}

		result, err := d.Extract(dissector.ExtractionInput{
			TransactionID:  id,
			URL:            url,
			Method:         method,
			Host:           host,
			RequestBody:    reqBody,
			ResponseBody:   respBody,
			ResponseCT:     derefString(respCT),
			RequestHeaders: reqHeaders,
			ContainerName:  container,
			DurationMs:     durationMs,
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

		matched++
		entries = append(entries, transactionEntry{
			txnID:          id,
			timestamp:      ts,
			containerName:  container,
			url:            url,
			sessionID:      result.SessionID,
			model:          result.Model,
			body:           body,
			msgCount:       result.MessageCount,
			result:         result,
			durationMs:     durationMs,
			requestHeaders: reqHeaders,
		})
	}
	if scanned > 0 {
		slog.Info("assembler: scan complete", "scanned", scanned, "matched", matched)
	}

	// Assign sessionless WS_RESP entries to the session of the nearest
	// preceding WS_REQ. WS_RESP response.completed frames carry the assistant
	// response but have no prompt_cache_key; they belong to whichever WS_REQ
	// was last sent on the same connection. Since entries are ordered by ID
	// (chronological), we track the last-seen WS_REQ session and propagate it.
	assignWSResponseSessions(entries)

	return entries, maxID, nil
}

func (a *ConversationAssembler) loadTransactionsForSessions(sessionIDs map[string]bool) ([]transactionEntry, error) {
	// Build LIKE clauses for session ID filtering.
	// The LIKE query is a pre-filter to avoid scanning all transactions.
	// The actual filtering happens post-extraction: we only keep entries
	// whose dissector-extracted SessionID is in our target set. This prevents
	// cross-contamination when one provider's transactions mention another
	// provider's session IDs (e.g. in tool results or status reports).
	var likeClauses []string
	var args []any
	for sid := range sessionIDs {
		// Match legacy format (session_UUID), JSON format (session_id with UUID value),
		// and WS format (prompt_cache_key with UUID value).
		clause := `(CAST(request_body AS TEXT) LIKE ? ESCAPE '\' OR CAST(request_body AS TEXT) LIKE ? ESCAPE '\' OR CAST(request_body AS TEXT) LIKE ? ESCAPE '\')`
		likeClauses = append(likeClauses, clause)
		args = append(args, "%session_"+escapeLikePattern(sid)+"%")
		args = append(args, "%session_id%"+escapeLikePattern(sid)+"%")
		args = append(args, "%prompt_cache_key%"+escapeLikePattern(sid)+"%")
	}

	// Build URL pattern filter from endpoint registry (replaces hardcoded patterns)
	urlPatterns := a.Registry.AllURLPatterns()
	if len(urlPatterns) == 0 {
		// Fallback to hardcoded patterns if registry is empty (shouldn't happen)
		urlPatterns = []string{
			"%api.anthropic.com/v1/messages%",
			"%api.openai.com/v1/responses%",
		}
	}
	var urlClauses []string
	var urlArgs []any
	for _, pat := range urlPatterns {
		urlClauses = append(urlClauses, "url LIKE ?")
		urlArgs = append(urlArgs, pat)
	}

	// URL args come first, then session LIKE args
	allArgs := append(urlArgs, args...)

	query := fmt.Sprintf(`
		SELECT id, timestamp, container_name, url, method, destination_host,
		       request_body, response_body, response_content_type, duration_ms,
		       request_headers
		FROM http_transactions
		WHERE (%s)
		  AND (%s)
		ORDER BY id`, strings.Join(urlClauses, " OR "), strings.Join(likeClauses, " OR "))

	rows, err := a.db.ReadDB().Query(query, allArgs...)
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
			respCT        *string
			durationMsPtr *int64
			reqHeadersJSON *string
		)
		if err := rows.Scan(&id, &ts, &container, &url, &method, &host,
			&reqBody, &respBody, &respCT, &durationMsPtr, &reqHeadersJSON); err != nil {
			slog.Warn("assembler: failed to scan session transaction row", "error", err)
			continue
		}
		var durationMs int64
		if durationMsPtr != nil {
			durationMs = *durationMsPtr
		}
		reqHeaders := parseHeadersJSON(reqHeadersJSON)

		d := a.Registry.FindDissector(url, method, host)
		if d == nil {
			d = a.Registry.AutoDetectAndCreate(url, method, host, reqBody)
			if d == nil {
				continue
			}
		}

		result, err := d.Extract(dissector.ExtractionInput{
			TransactionID:  id,
			URL:            url,
			Method:         method,
			Host:           host,
			RequestBody:    reqBody,
			ResponseBody:   respBody,
			ResponseCT:     derefString(respCT),
			RequestHeaders: reqHeaders,
			ContainerName:  container,
			DurationMs:     durationMs,
		})
		if err != nil || result == nil {
			continue
		}

		// Only keep entries whose extracted session ID is in our target set.
		// The LIKE query is just a pre-filter; a transaction might match
		// because it *mentions* a session ID (e.g. in a tool result) rather
		// than *belonging* to that session.
		if result.SessionID == "" || !sessionIDs[result.SessionID] {
			continue
		}

		var body map[string]any
		if len(reqBody) > 0 {
			if err := json.Unmarshal(reqBody, &body); err != nil {
				slog.Debug("assembler: failed to parse request body JSON", "txn_id", id, "error", err)
			}
		}

		entries = append(entries, transactionEntry{
			txnID:          id,
			timestamp:      ts,
			containerName:  container,
			url:            url,
			sessionID:      result.SessionID,
			model:          result.Model,
			body:           body,
			msgCount:       result.MessageCount,
			result:         result,
			durationMs:     durationMs,
			requestHeaders: reqHeaders,
		})
	}
	return entries, nil
}

// --- Assembly logic (ported from assemble2.py) ---

var timeGapThreshold = 5 * time.Minute

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

	// Heuristic grouping for unassigned entries.
	// First, try the adapter's SessionStrategy to infer session IDs.
	// Entries that remain unassigned after that fall back to the time-gap + overlap heuristic.
	if len(unassigned) > 0 {
		sort.Slice(unassigned, func(i, j int) bool { return unassigned[i].timestamp < unassigned[j].timestamp })

		// Detect adapter from unassigned entries and use its session strategy
		adapter := DetectClientFromEntries(unassigned)
		inferred := adapter.SessionStrategy().InferSession(unassigned)

		var stillUnassigned []transactionEntry
		if len(inferred) > 0 {
			for _, entry := range unassigned {
				if sid, ok := inferred[entry.txnID]; ok && sid != "" {
					rawSessions[sid] = append(rawSessions[sid], entry)
				} else {
					stillUnassigned = append(stillUnassigned, entry)
				}
			}
		} else {
			stillUnassigned = unassigned
		}

		// Fallback: time-gap + overlap heuristic for entries the strategy did not assign
		if len(stillUnassigned) > 0 {
			var groups [][]transactionEntry
			var current []transactionEntry

			for _, entry := range stillUnassigned {
				if len(current) == 0 {
					current = append(current, entry)
					continue
				}
				prevTs, err1 := time.Parse(time.RFC3339, current[len(current)-1].timestamp)
				currTs, err2 := time.Parse(time.RFC3339, entry.timestamp)
				if err1 != nil || err2 != nil {
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

		adapter := DetectClientFromEntries(entries)
		threads := splitSessionIntoThreads(entries, adapter)
		for threadKey, threadEntries := range threads {
			if len(threadEntries) == 0 || threadKey == "utility" || threadKey == "mcp" || threadKey == "title-gen" || threadKey == "complexity-scorer" {
				continue
			}
			if threadKey == "main" {
				sessions[sid] = threadEntries
			} else {
				subConvs := adapter.SubagentStrategy().SplitInvocations(threadEntries)
				for i, subEntries := range subConvs {
					sessions[fmt.Sprintf("%s/%s_%d", sid, threadKey, i+1)] = subEntries
				}
			}
		}
	}

	// For OpenAI: remap orphan subagent sessions under their parent main session.
	// OpenCode spawns subagents with separate session IDs (prompt_cache_key).
	// The link is in the main session's "task" tool output: "task_id: ses_XXX".
	remapOpenAISubagents(sessions)

	return sessions
}

// remapOpenAISubagents finds OpenAI main sessions that reference subagent
// session IDs via the "task" tool, and remaps those subagent sessions to be
// children of the main session (using the sid/subagent_N convention).
func remapOpenAISubagents(sessions map[string][]transactionEntry) {
	// Find main OpenAI sessions and extract task_id references
	type mainInfo struct {
		sid      string
		taskSIDs []string // subagent session IDs referenced by task tool
	}
	var mains []mainInfo

	for sid, entries := range sessions {
		if strings.Contains(sid, "/") {
			continue // already a subagent key
		}
		// Check if this is an OpenAI main session
		isOpenAI := false
		for _, e := range entries {
			if e.result != nil && e.result.Provider == "openai" {
				isOpenAI = true
				break
			}
		}
		if !isOpenAI {
			continue
		}

		// Scan for task_id references in function_call_output items
		var taskSIDs []string
		for _, e := range entries {
			if e.result == nil {
				continue
			}
			for _, msg := range e.result.Messages {
				for _, cb := range msg.Content {
					if cb.Type == "tool_result" && cb.Content != "" {
						if tid := extractTaskID(cb.Content); tid != "" {
							taskSIDs = append(taskSIDs, tid)
						}
					}
				}
			}
			// Also check SSE response for task tool results
			if e.result.SSEResponse != nil {
				for _, tc := range e.result.SSEResponse.ToolCalls {
					if tc.ResultPreview != "" {
						if tid := extractTaskID(tc.ResultPreview); tid != "" {
							taskSIDs = append(taskSIDs, tid)
						}
					}
				}
			}
		}
		if len(taskSIDs) > 0 {
			mains = append(mains, mainInfo{sid: sid, taskSIDs: taskSIDs})
		}
	}

	// Remap subagent sessions under their parent
	for _, m := range mains {
		subIdx := 0
		for _, taskSID := range m.taskSIDs {
			// Look for sessions keyed by this task session ID (or containing it)
			for existingKey := range sessions {
				// Match: the session key starts with the task session ID
				baseSID := existingKey
				if i := strings.Index(existingKey, "/"); i >= 0 {
					baseSID = existingKey[:i]
				}
				if baseSID != taskSID {
					continue
				}
				subIdx++
				newKey := fmt.Sprintf("%s/subagent_%d", m.sid, subIdx)
				sessions[newKey] = sessions[existingKey]
				delete(sessions, existingKey)
			}
		}
	}
}

// extractReferencedSubagentSessions scans dissected transaction entries for
// cross-session subagent references and returns any that are not already
// in the known set. Uses the adapter's SubagentStrategy when available,
// falling back to OpenAI-specific task_id scanning for backward compatibility.
func extractReferencedSubagentSessions(entries []transactionEntry, known map[string]bool) map[string]bool {
	extra := map[string]bool{}

	// Try adapter-based extraction first
	adapter := DetectClientFromEntries(entries)
	strategy := adapter.SubagentStrategy()

	for _, e := range entries {
		if e.result == nil {
			continue
		}
		refs := strategy.ExtractReferencedSessions(e.result.Messages)
		for _, ref := range refs {
			if ref != "" && !known[ref] {
				extra[ref] = true
			}
		}
		// Also check SSE response for tool results with cross-session refs
		if e.result.SSEResponse != nil {
			for _, tc := range e.result.SSEResponse.ToolCalls {
				if tc.ResultPreview != "" {
					if tid := strategy.LinkSubagentID(tc.ResultPreview); tid != "" && !known[tid] {
						extra[tid] = true
					}
				}
			}
		}
	}
	return extra
}

var taskIDPattern = regexp.MustCompile(`task_id:\s*(ses_[A-Za-z0-9_]+)`)

// extractTaskID finds a "task_id: ses_XXX" pattern in text.
func extractTaskID(text string) string {
	m := taskIDPattern.FindStringSubmatch(text)
	if len(m) >= 2 {
		return m[1]
	}
	return ""
}

func splitSessionIntoThreads(entries []transactionEntry, adapter ClientAdapter) map[string][]transactionEntry {
	threads := map[string][]transactionEntry{}
	for _, entry := range entries {
		if entry.result == nil {
			threads["main"] = append(threads["main"], entry)
			continue
		}
		threadType := adapter.ClassifyThread(entry.result)
		switch threadType {
		case "main":
			threads["main"] = append(threads["main"], entry)
		case "subagent":
			sysLen := dissector.SystemPromptLength(entry.result.SystemBlocks)
			key := fmt.Sprintf("subagent_%d", sysLen)
			threads[key] = append(threads[key], entry)
		case "mcp", "utility", "title-gen", "complexity-scorer":
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
	return defaultScaffolding.IsRealUserMessage(msg)
}

func getUserText(msg dissector.Message) *string {
	return defaultScaffolding.GetUserText(msg)
}

// defaultScaffolding is used by legacy code paths that don't yet have
// a per-client config. Matches the original hardcoded behavior.
var defaultScaffolding = ClaudeCodeScaffolding()

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

func buildRoundsFromMessages(messages []dissector.Message, scaffolding *ScaffoldingConfig) []assembledTurn {
	if scaffolding == nil {
		scaffolding = defaultScaffolding
	}

	// Find indices of real user prompts
	var promptIndices []int
	for i, msg := range messages {
		if msg.Role == "user" && scaffolding.IsRealUserMessage(msg) {
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

		userText := scaffolding.GetUserText(messages[startIdx])

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

// detectProvider infers the LLM provider from dissector-extracted provider
// fields first, then falls back to URL-based detection.
func detectProvider(entries []transactionEntry) string {
	// Prefer the provider set by the dissector (authoritative)
	for _, e := range entries {
		if e.result != nil && e.result.Provider != "" {
			return e.result.Provider
		}
	}
	// Fallback: URL-based detection
	for _, e := range entries {
		if strings.Contains(e.url, "api.openai.com") {
			return "openai"
		}
		if strings.Contains(e.url, "api.anthropic.com") {
			return "anthropic"
		}
		if strings.Contains(e.url, "openrouter.ai") {
			return "openrouter"
		}
		if strings.Contains(e.url, "generativelanguage.googleapis.com") {
			return "google-ai"
		}
	}
	return "unknown"
}

// inferClientName detects the coding tool client from request headers and
// other signals. This is a basic detection; the full ClientAdapter system
// (Phase 2+) provides richer detection with confidence scoring.
// containerToClient maps greywall container names (process identifiers from
// SOCKS5 auth) to client adapter names. This is the most reliable detection
// signal since it comes from the OS-level process name.
var containerToClient = map[string]string{
	"claude":  "claude-code",
	"codex":   "codex",
	"opencode": "opencode",
	"aider":   "aider",
	"gemini":  "gemini-cli",
}

func inferClientName(provider string, entries []transactionEntry) string {
	// 1. Container name from greywall (most reliable: OS-level process ID)
	for _, e := range entries {
		if name, ok := containerToClient[e.containerName]; ok {
			return name
		}
	}

	// 2. Header-based detection (for traffic not routed through greywall)
	for _, e := range entries {
		h := e.requestHeaders
		if h == nil {
			continue
		}
		ua := h.Get("User-Agent")
		if h.Get("Originator") == "codex_exec" {
			return "codex"
		}
		if strings.Contains(ua, "claude-cli/") || strings.Contains(ua, "Claude-Code/") {
			return "claude-code"
		}
		if strings.Contains(ua, "GeminiCLI/") {
			return "gemini-cli"
		}
		if strings.Contains(ua, "opencode/") {
			return "opencode"
		}
		if h.Get("X-Title") == "opencode" || h.Get("Http-Referer") == "https://opencode.ai/" {
			return "opencode"
		}
		if h.Get("Http-Referer") == "https://aider.chat" || h.Get("X-Title") == "Aider" {
			return "aider"
		}
	}

	// 3. Dissector client hints (e.g. from WS metadata)
	for _, e := range entries {
		if e.result != nil && e.result.ClientHint != "" {
			return e.result.ClientHint
		}
	}

	// 4. Adapter detection from request content (system prompt fingerprinting)
	adapter := DetectClientFromEntries(entries)
	if adapter.Name() != "generic" {
		return adapter.Name()
	}

	// 5. Fallback: infer from provider
	switch provider {
	case "anthropic":
		return "claude-code"
	case "openai":
		return "opencode"
	}
	return "generic"
}

func assembleConversation(sessionID string, entries []transactionEntry) assembledConversation {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].timestamp == entries[j].timestamp {
			return entries[i].txnID < entries[j].txnID
		}
		return entries[i].timestamp < entries[j].timestamp
	})

	provider := detectProvider(entries)
	clientName := inferClientName(provider, entries)

	conv := assembledConversation{
		conversationID: "session_" + sessionID,
		provider:       provider,
		clientName:     clientName,
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
	scaffolding := ScaffoldingForClient(clientName)

	// Detect incremental WS sessions (Codex CLI): each WS_REQ only carries
	// NEW messages for that turn, not the full cumulative history. We must
	// aggregate messages across all entries and interleave assistant responses
	// from WS_RESP response.completed frames.
	messages := bestEntry.result.Messages
	if isIncrementalWSSession(entries) {
		messages = aggregateWSMessages(entries)
	}

	rounds := buildRoundsFromMessages(messages, scaffolding)
	conv.turnCount = len(rounds)

	// Map requests to turns
	turnEntryMap := mapRequestsToTurns(entries, conv.turnCount, scaffolding)

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

	// Recover last assistant response from SSE.
	// Skip for incremental WS sessions: aggregateWSMessages already interleaves
	// assistant responses from SSE into the message stream, so this recovery
	// would duplicate earlier-turn responses into the last turn.
	if len(conv.turns) > 0 && !isIncrementalWSSession(entries) {
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

	}

	// Check if last turn has a response
	if len(conv.turns) > 0 {
		for _, s := range conv.turns[len(conv.turns)-1].steps {
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

// assignWSResponseSessions assigns session IDs to sessionless WS_RESP entries
// by propagating the session from the nearest preceding WS_REQ. Entries must
// be sorted by ID (chronological order) before calling this function.
func assignWSResponseSessions(entries []transactionEntry) {
	var lastWSSession string
	for i := range entries {
		if entries[i].sessionID != "" && strings.HasPrefix(entries[i].url, "wss://") {
			lastWSSession = entries[i].sessionID
		} else if entries[i].sessionID == "" && strings.HasPrefix(entries[i].url, "wss://") && lastWSSession != "" {
			entries[i].sessionID = lastWSSession
		}
	}
}

// isIncrementalWSSession returns true if the entries represent a WebSocket
// session with incremental messaging (e.g. Codex CLI). In this mode, each
// WS_REQ only carries new messages for that turn, not the full history.
func isIncrementalWSSession(entries []transactionEntry) bool {
	for _, e := range entries {
		if strings.HasPrefix(e.url, "wss://") {
			return true
		}
	}
	return false
}

// aggregateWSMessages collects messages from all WS_REQ entries in
// chronological order and interleaves assistant responses from WS_RESP
// response.completed frames (via SSEResponse). This reconstructs the
// full conversation from incremental WebSocket frames.
func aggregateWSMessages(entries []transactionEntry) []dissector.Message {
	var messages []dissector.Message

	for _, e := range entries {
		if e.result == nil {
			continue
		}

		// Append user/tool messages from WS_REQ frames
		if len(e.result.Messages) > 0 {
			messages = append(messages, e.result.Messages...)
		}

		// Append assistant response from WS_RESP response.completed frames
		if e.result.SSEResponse != nil {
			sse := e.result.SSEResponse
			var blocks []dissector.ContentBlock

			if sse.Text != "" {
				blocks = append(blocks, dissector.ContentBlock{
					Type: "text",
					Text: sse.Text,
				})
			}
			for _, tc := range sse.ToolCalls {
				blocks = append(blocks, dissector.ContentBlock{
					Type:        "tool_use",
					Name:        tc.Tool,
					ID:          tc.ToolUseID,
					Input:       tc.InputPreview,
					ToolSummary: tc.ToolSummary,
				})
			}

			if len(blocks) > 0 {
				messages = append(messages, dissector.Message{
					Role:    "assistant",
					Content: blocks,
				})
			}
		}
	}

	return messages
}

func mapRequestsToTurns(entries []transactionEntry, numTurns int, scaffolding *ScaffoldingConfig) map[int][]transactionEntry {
	if scaffolding == nil {
		scaffolding = defaultScaffolding
	}
	entryTurns := map[int]int{}
	for i, entry := range entries {
		if entry.result != nil && entry.result.MessageCount > 0 {
			// Count real prompts
			prompts := 0
			for _, msg := range entry.result.Messages {
				if msg.Role == "user" && scaffolding.IsRealUserMessage(msg) {
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

		// Link agent tool calls to subagent conversations by order.
		// Build set of known agent tool names from all registered adapters.
		agentTools := map[string]bool{
			"Agent":       true,
			"task":        true,
			"spawn_agent": true,
		}
		for _, a := range clientAdapters {
			for _, name := range a.SubagentStrategy().AgentToolNames() {
				agentTools[name] = true
			}
		}

		subIdx := 0
		for _, turn := range allConvs[i].turns {
			for _, step := range turn.steps {
				tcs, _ := step["tool_calls"].([]map[string]any)
				for _, tc := range tcs {
					toolName, _ := tc["tool"].(string)
					if agentTools[toolName] && subIdx < len(subs) {
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
		ClientName:          conv.clientName,
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

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// parseHeadersJSON deserializes stored request headers from the JSON column.
// Headers are stored as {"Key": ["val1", "val2"], ...} or {"Key": "val"}.
// Returns nil on NULL or parse errors (callers handle nil gracefully).
func parseHeadersJSON(jsonStr *string) http.Header {
	if jsonStr == nil || *jsonStr == "" {
		return nil
	}
	// Try standard http.Header format: map[string][]string
	var multi map[string][]string
	if json.Unmarshal([]byte(*jsonStr), &multi) == nil && len(multi) > 0 {
		return http.Header(multi)
	}
	// Fallback: map[string]string (single value per key)
	var single map[string]string
	if json.Unmarshal([]byte(*jsonStr), &single) == nil && len(single) > 0 {
		h := http.Header{}
		for k, v := range single {
			h.Set(k, v)
		}
		return h
	}
	return nil
}
