package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
)

// PIIStatsHandler returns PII redaction statistics.
func PIIStatsHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		now := time.Now()
		var from time.Time
		switch c.DefaultQuery("period", "today") {
		case "7d":
			from = now.AddDate(0, 0, -7)
		case "30d":
			from = now.AddDate(0, 0, -30)
		default:
			from = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.Local)
		}
		total, byType, err := greyproxy.GetPIIStats(s.DB, from, now)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"total":   total,
			"by_type": byType,
		})
	}
}
