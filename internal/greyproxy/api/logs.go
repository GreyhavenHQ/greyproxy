package api

import (
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
)

func LogsListHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
		offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

		f := greyproxy.LogFilter{
			Container:   c.Query("container"),
			Destination: c.Query("destination"),
			Result:      c.Query("result"),
			Limit:       limit,
			Offset:      offset,
		}

		if v := c.Query("from_date"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				f.FromDate = &t
			} else if t, err := time.Parse("2006-01-02T15:04", v); err == nil {
				f.FromDate = &t
			}
		}
		if v := c.Query("to_date"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				f.ToDate = &t
			} else if t, err := time.Parse("2006-01-02T15:04", v); err == nil {
				f.ToDate = &t
			}
		}

		items, total, err := greyproxy.QueryLogs(s.DB, f)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		jsonItems := make([]greyproxy.RequestLogJSON, len(items))
		for i, item := range items {
			jsonItems[i] = item.ToJSON()
		}

		page := 1
		if limit > 0 && offset > 0 {
			page = offset/limit + 1
		}
		pages := 1
		if limit > 0 && total > 0 {
			pages = int(math.Ceil(float64(total) / float64(limit)))
		}

		c.JSON(http.StatusOK, gin.H{
			"items": jsonItems,
			"total": total,
			"page":  page,
			"pages": pages,
		})
	}
}

func LogsStatsHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		now := time.Now().UTC()
		fromDate := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		toDate := now

		if v := c.Query("from_date"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				fromDate = t
			}
		}
		if v := c.Query("to_date"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				toDate = t
			}
		}

		stats, err := greyproxy.GetDashboardStats(s.DB, fromDate, toDate, "hour", 0)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"period":           stats.Period,
			"total_requests":   stats.TotalRequests,
			"allowed":          stats.Allowed,
			"blocked":          stats.Blocked,
			"top_containers":   stats.ByContainer,
			"top_destinations": stats.TopBlocked,
			"timeline":         stats.Timeline,
		})
	}
}
