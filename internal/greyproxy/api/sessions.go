package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
)

// SessionsListHandler returns all active sessions (without credential values).
func SessionsListHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		sessions, err := greyproxy.ListSessions(s.DB)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		result := make([]greyproxy.SessionJSON, 0, len(sessions))
		for _, sess := range sessions {
			labels := greyproxy.GetSessionLabels(&sess)
			result = append(result, sess.ToJSON(labels))
		}

		c.JSON(http.StatusOK, result)
	}
}

// SessionsCreateHandler creates or upserts a credential substitution session.
//
// If `global_credentials` is provided (list of labels), the handler resolves
// each label to its stored placeholder and includes it in the response.
// Greywall uses the returned placeholders to set environment variables and
// rewrite .env files in the sandbox. The placeholder-to-real-value mapping
// is merged into the session so the proxy can substitute on the wire.
func SessionsCreateHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		var input greyproxy.SessionCreateInput
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if input.SessionID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "session_id is required"})
			return
		}
		if input.ContainerName == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "container_name is required"})
			return
		}

		// Resolve global credentials: validate they exist and merge labels for dashboard display.
		// Global credential values are NOT duplicated into session mappings; the proxy
		// loads them separately from the global_credentials table at startup and when
		// credentials are created/deleted. This ensures deleting a global credential
		// immediately stops substitution for all sessions.
		var resolvedGlobals map[string]string // label -> placeholder
		if len(input.GlobalCredentials) > 0 {
			found, missing, err := greyproxy.GetGlobalCredentialsByLabels(s.DB, input.GlobalCredentials)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			if len(missing) > 0 {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": fmt.Sprintf("unknown global credentials: %s", strings.Join(missing, ", ")),
				})
				return
			}

			if input.Labels == nil {
				input.Labels = make(map[string]string)
			}
			resolvedGlobals = make(map[string]string, len(found))

			for label, cred := range found {
				// Only store the label mapping (for dashboard), not the real value
				input.Labels[cred.Placeholder] = label
				resolvedGlobals[label] = cred.Placeholder
			}
		}

		if len(input.Mappings) == 0 && len(resolvedGlobals) == 0 && len(input.NetworkRules) == 0 && !input.AllowAll {
			c.JSON(http.StatusBadRequest, gin.H{"error": "no credentials or network rules provided"})
			return
		}

		// Cap TTL at 1 hour
		maxTTL := 3600
		if input.TTLSeconds > maxTTL {
			input.TTLSeconds = maxTTL
		}

		session, err := greyproxy.CreateOrUpdateSession(s.DB, input, s.EncryptionKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Update in-memory store
		if s.CredentialStore != nil {
			s.CredentialStore.RegisterSession(session, input.Mappings)
		}

		rulesCreated := greyproxy.GetSessionRuleCount(s.DB, session.SessionID)

		resp := gin.H{
			"session_id":       session.SessionID,
			"expires_at":       session.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
			"credential_count": len(input.Mappings) + len(resolvedGlobals),
			"rules_created":    rulesCreated,
		}
		if resolvedGlobals != nil {
			resp["global_credentials"] = resolvedGlobals
		}

		c.JSON(http.StatusOK, resp)
	}
}

// SessionsHeartbeatHandler resets the TTL for an active session and, when
// the request carries a JSON body, ingests filesystem events shipped by
// greywall's --record-fs tracer. The body is optional: empty/no body is the
// pre-fs-events behavior and must keep working.
func SessionsHeartbeatHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionID := c.Param("id")

		// Parse optional FsEvents payload. greywall posts either an empty
		// body (no events queued) or a JSON object. We tolerate both and a
		// malformed body without failing the TTL refresh — losing events is
		// recoverable, losing the heartbeat is not.
		var payload greyproxy.FsEventsPayload
		raw, _ := io.ReadAll(c.Request.Body)
		if len(raw) > 0 {
			// Malformed bodies are tolerated: heartbeat must still refresh
			// the TTL even if greywall ships a payload we cannot parse.
			_ = json.Unmarshal(raw, &payload)
		}

		session, err := greyproxy.HeartbeatSession(s.DB, sessionID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if session == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "session not found or expired"})
			return
		}

		ingested := 0
		if s.FsEvents != nil && (len(payload.Events) > 0 || payload.Dropped > 0) {
			s.FsEvents.Ingest(sessionID, payload.Events, payload.Dropped)
			ingested = len(payload.Events)

			if s.Bus != nil && (len(payload.Events) > 0 || payload.Dropped > 0) {
				s.Bus.Publish(greyproxy.Event{
					Type: greyproxy.EventSessionFsEvents,
					Data: greyproxy.FsEventsBatch{
						SessionID: sessionID,
						Events:    payload.Events,
						Dropped:   payload.Dropped,
					},
				})
			}
		}

		if s.Bus != nil {
			s.Bus.Publish(greyproxy.Event{
				Type: greyproxy.EventSessionHeartbeat,
				Data: sessionID,
			})
		}

		resp := gin.H{
			"session_id": session.SessionID,
			"expires_at": session.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
		}
		if ingested > 0 || payload.Dropped > 0 {
			resp["fs_events_ingested"] = ingested
			resp["fs_events_dropped"] = payload.Dropped
		}
		c.JSON(http.StatusOK, resp)
	}
}

// SessionsFsEventsHandler returns the buffered filesystem events for a
// session. The buffer is in-memory and FIFO; older entries are evicted
// once the per-session ring fills up (reflected by truncated=true).
func SessionsFsEventsHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionID := c.Param("id")
		if s.FsEvents == nil {
			c.JSON(http.StatusOK, greyproxy.FsEventsSnapshot{SessionID: sessionID})
			return
		}
		c.JSON(http.StatusOK, s.FsEvents.Snapshot(sessionID))
	}
}


// SessionsDeleteHandler removes a session and wipes credentials from DB and memory.
func SessionsDeleteHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionID := c.Param("id")

		deleted, err := greyproxy.DeleteSession(s.DB, sessionID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		if deleted && s.CredentialStore != nil {
			s.CredentialStore.UnregisterSession(sessionID)
		}
		if deleted && s.FsEvents != nil {
			s.FsEvents.Forget(sessionID)
		}

		c.JSON(http.StatusOK, gin.H{
			"session_id": sessionID,
			"deleted":    deleted,
		})
	}
}
