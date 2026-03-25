package api

import (
	"net/http"

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
		if len(input.Mappings) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "mappings is required and must not be empty"})
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

		c.JSON(http.StatusOK, gin.H{
			"session_id":       session.SessionID,
			"expires_at":       session.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
			"credential_count": len(input.Mappings),
		})
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
