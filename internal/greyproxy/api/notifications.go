package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
)

func NotificationsStatusHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.Settings == nil {
			c.JSON(http.StatusOK, gin.H{"enabled": false, "active_claims": 0})
			return
		}
		resolved := s.Settings.Get()
		activeClaims := 0
		if s.Notifier != nil {
			activeClaims = s.Notifier.ActiveClaims()
		}
		c.JSON(http.StatusOK, gin.H{
			"enabled":       resolved.NotificationsEnabled,
			"active_claims": activeClaims,
		})
	}
}

func NotificationsToggleHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.Settings == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "settings not initialized"})
			return
		}
		var body struct {
			Enabled bool `json:"enabled"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		patch := greyproxy.UserSettings{NotificationsEnabled: &body.Enabled}
		resolved, err := s.Settings.Update(patch)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"enabled": resolved.NotificationsEnabled})
	}
}
