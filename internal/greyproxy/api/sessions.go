package api

import (
	"fmt"
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

		if len(input.Mappings) == 0 && len(resolvedGlobals) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "no credentials provided (mappings or global_credentials required)"})
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

		resp := gin.H{
			"session_id":       session.SessionID,
			"expires_at":       session.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
			"credential_count": len(input.Mappings) + len(resolvedGlobals),
		}
		if resolvedGlobals != nil {
			resp["global_credentials"] = resolvedGlobals
		}

		c.JSON(http.StatusOK, resp)
	}
}

// SessionsHeartbeatHandler resets the TTL for an active session.
func SessionsHeartbeatHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionID := c.Param("id")

		session, err := greyproxy.HeartbeatSession(s.DB, sessionID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if session == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "session not found or expired"})
			return
		}

		if s.Bus != nil {
			s.Bus.Publish(greyproxy.Event{
				Type: greyproxy.EventSessionHeartbeat,
				Data: sessionID,
			})
		}

		c.JSON(http.StatusOK, gin.H{
			"session_id": session.SessionID,
			"expires_at": session.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
		})
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

		c.JSON(http.StatusOK, gin.H{
			"session_id": sessionID,
			"deleted":    deleted,
		})
	}
}
