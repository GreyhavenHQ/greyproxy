package greyproxy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/greyhavenhq/greyproxy/internal/greyproxy/dissector"
)

// SessionStrategy extracts or infers session IDs from requests.
type SessionStrategy interface {
	// ExtractSessionID returns the session key from a single request.
	// Returns "" if no session ID is available.
	ExtractSessionID(result *dissector.ExtractionResult, headers http.Header) string

	// InferSession groups requests that lack explicit session IDs.
	// Returns a map of transaction ID -> inferred session key.
	InferSession(entries []transactionEntry) map[int64]string
}

// --- HeaderFieldStrategy ---
// Used by Claude Code: reads X-Claude-Code-Session-Id header,
// falls back to metadata.user_id regex.

type HeaderFieldStrategy struct{}

var sessionIDRe = regexp.MustCompile(`session_([a-f0-9-]{36})`)

func (s *HeaderFieldStrategy) ExtractSessionID(result *dissector.ExtractionResult, headers http.Header) string {
	// Already extracted by dissector
	if result != nil && result.SessionID != "" {
		return result.SessionID
	}
	// Try header
	if headers != nil {
		if sid := headers.Get("X-Claude-Code-Session-Id"); sid != "" {
			return sid
		}
	}
	return ""
}

func (s *HeaderFieldStrategy) InferSession(_ []transactionEntry) map[int64]string {
	return nil // Claude Code always has session IDs
}

// --- PromptCacheKeyStrategy ---
// Used by OpenCode/OpenAI and Codex: reads prompt_cache_key or Session_id header.

type PromptCacheKeyStrategy struct{}

func (s *PromptCacheKeyStrategy) ExtractSessionID(result *dissector.ExtractionResult, headers http.Header) string {
	if result != nil && result.SessionID != "" {
		return result.SessionID
	}
	if headers != nil {
		if sid := headers.Get("Session_id"); sid != "" {
			return sid
		}
	}
	return ""
}

func (s *PromptCacheKeyStrategy) InferSession(_ []transactionEntry) map[int64]string {
	return nil
}

// --- TimingStrategy ---
// Used by Aider and Gemini CLI: groups by time gap within the same container.

type TimingStrategy struct {
	Gap time.Duration
}

func (s *TimingStrategy) ExtractSessionID(_ *dissector.ExtractionResult, _ http.Header) string {
	return "" // no explicit session ID
}

func (s *TimingStrategy) InferSession(entries []transactionEntry) map[int64]string {
	gap := s.Gap
	if gap == 0 {
		gap = 5 * time.Minute
	}

	result := map[int64]string{}
	if len(entries) == 0 {
		return result
	}

	groupIdx := 0
	var prevTs time.Time
	groupKey := fmt.Sprintf("timing_%d", entries[0].txnID)

	for _, e := range entries {
		ts, err := time.Parse(time.RFC3339, e.timestamp)
		if err != nil {
			result[e.txnID] = groupKey
			continue
		}
		if !prevTs.IsZero() && ts.Sub(prevTs) > gap {
			groupIdx++
			groupKey = fmt.Sprintf("timing_%d", e.txnID)
		}
		result[e.txnID] = groupKey
		prevTs = ts
	}
	return result
}

// --- MessageGrowthStrategy ---
// Used by OpenCode/Anthropic and OpenCode/LiteLLM: no session ID field,
// infers by system prompt fingerprint + message array superset growth.

type MessageGrowthStrategy struct{}

func (s *MessageGrowthStrategy) ExtractSessionID(_ *dissector.ExtractionResult, _ http.Header) string {
	return ""
}

func (s *MessageGrowthStrategy) InferSession(entries []transactionEntry) map[int64]string {
	result := map[int64]string{}
	if len(entries) == 0 {
		return result
	}

	// Group by system prompt fingerprint
	type group struct {
		fingerprint string
		entries     []transactionEntry
	}

	fingerprints := map[string]*group{}
	for _, e := range entries {
		fp := systemPromptFingerprint(e.result)
		g, ok := fingerprints[fp]
		if !ok {
			g = &group{fingerprint: fp}
			fingerprints[fp] = g
		}
		g.entries = append(g.entries, e)
	}

	for _, g := range fingerprints {
		// Within each fingerprint group, chain by message count growth
		sessionIdx := 0
		prevCount := -1
		sessionKey := fmt.Sprintf("growth_%s_%d", g.fingerprint[:8], sessionIdx)

		for _, e := range g.entries {
			count := e.msgCount
			if prevCount >= 0 && count < prevCount-1 {
				// Message count dropped; new session
				sessionIdx++
				sessionKey = fmt.Sprintf("growth_%s_%d", g.fingerprint[:8], sessionIdx)
			}
			result[e.txnID] = sessionKey
			prevCount = count
		}
	}
	return result
}

func systemPromptFingerprint(result *dissector.ExtractionResult) string {
	if result == nil || len(result.SystemBlocks) == 0 {
		return "nosystem"
	}
	var text string
	for _, b := range result.SystemBlocks {
		text += b.Text
	}
	if len(text) > 200 {
		text = text[:200]
	}
	h := sha256.Sum256([]byte(text))
	return hex.EncodeToString(h[:16])
}

// --- CompositeStrategy ---
// Tries strategies in order; first non-empty session ID wins.

type CompositeStrategy struct {
	Strategies []SessionStrategy
}

func (s *CompositeStrategy) ExtractSessionID(result *dissector.ExtractionResult, headers http.Header) string {
	for _, strategy := range s.Strategies {
		if sid := strategy.ExtractSessionID(result, headers); sid != "" {
			return sid
		}
	}
	return ""
}

func (s *CompositeStrategy) InferSession(entries []transactionEntry) map[int64]string {
	for _, strategy := range s.Strategies {
		result := strategy.InferSession(entries)
		if len(result) > 0 {
			return result
		}
	}
	return nil
}

