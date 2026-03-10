package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func NotificationsStatusHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.Notifier == nil {
			c.JSON(http.StatusOK, gin.H{"enabled": false})
			return
		}
		c.JSON(http.StatusOK, gin.H{"enabled": s.Notifier.Enabled()})
	}
}

func NotificationsToggleHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.Notifier == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "notifier not initialized"})
			return
		}
		var body struct {
			Enabled bool `json:"enabled"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		s.Notifier.SetEnabled(body.Enabled)
		c.JSON(http.StatusOK, gin.H{"enabled": s.Notifier.Enabled()})
	}
}
