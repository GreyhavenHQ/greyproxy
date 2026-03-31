package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
)

// CredentialsListHandler returns all global credentials (labels + previews only).
func CredentialsListHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		creds, err := greyproxy.ListGlobalCredentials(s.DB)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		result := make([]greyproxy.GlobalCredentialJSON, 0, len(creds))
		for _, cred := range creds {
			result = append(result, cred.ToJSON())
		}

		c.JSON(http.StatusOK, result)
	}
}

// CredentialsCreateHandler registers a new global credential.
func CredentialsCreateHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		var input greyproxy.GlobalCredentialCreateInput
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if input.Label == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "label is required"})
			return
		}
		if input.Value == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "value is required"})
			return
		}

		cred, err := greyproxy.CreateGlobalCredential(s.DB, input, s.EncryptionKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Update in-memory store
		if s.CredentialStore != nil {
			s.CredentialStore.RegisterGlobalCredential(cred.Placeholder, input.Value, input.Label)
		}

		c.JSON(http.StatusOK, gin.H{
			"id":            cred.ID,
			"label":         cred.Label,
			"placeholder":   cred.Placeholder,
			"value_preview": cred.ValuePreview,
			"created_at":    cred.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		})
	}
}

// CredentialsDeleteHandler removes a global credential.
func CredentialsDeleteHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")

		// Get the credential first to know its placeholder for memory cleanup
		cred, err := greyproxy.GetGlobalCredential(s.DB, id)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "credential not found"})
			return
		}

		deleted, err := greyproxy.DeleteGlobalCredential(s.DB, id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		if deleted && s.CredentialStore != nil && cred != nil {
			s.CredentialStore.UnregisterGlobalCredential(cred.Placeholder)
		}

		c.JSON(http.StatusOK, gin.H{
			"id":      id,
			"deleted": deleted,
		})
	}
}
