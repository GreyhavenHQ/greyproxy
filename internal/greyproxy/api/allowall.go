package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
)

const maxSilentModeDuration = 8 * time.Hour

func AllowAllStatusHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, s.AllowAll.Status())
	}
}

func AllowAllEnableHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		var body struct {
			Duration string `json:"duration"` // Go duration string, or "restart"
			Mode     string `json:"mode"`     // "allow" or "deny"
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if body.Mode != greyproxy.SilentModeAllow && body.Mode != greyproxy.SilentModeDeny {
			c.JSON(http.StatusBadRequest, gin.H{"error": `mode must be "allow" or "deny"`})
			return
		}

		// "restart" is a special sentinel meaning "until the proxy is restarted".
		var duration time.Duration
		if body.Duration != "restart" {
			d, err := time.ParseDuration(body.Duration)
			if err != nil || d <= 0 {
				c.JSON(http.StatusBadRequest, gin.H{"error": `invalid duration; use a Go duration (e.g. "5m", "1h") or "restart"`})
				return
			}
			if d > maxSilentModeDuration {
				c.JSON(http.StatusBadRequest, gin.H{"error": "duration exceeds maximum of 8h"})
				return
			}
			duration = d
		}
		// duration=0 → Enable treats it as "until restart"

		s.AllowAll.Enable(duration, body.Mode)
		c.JSON(http.StatusOK, s.AllowAll.Status())
	}
}

func AllowAllDisableHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		s.AllowAll.Disable()
		c.JSON(http.StatusOK, s.AllowAll.Status())
	}
}
