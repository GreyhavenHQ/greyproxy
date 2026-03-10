package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
)

func PendingHttpCountHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		count, err := greyproxy.GetPendingHttpCount(s.DB)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"count": count})
	}
}

func PendingHttpListHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
		offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

		items, total, err := greyproxy.GetPendingHttpRequests(s.DB, greyproxy.PendingHttpFilter{
			Container:   c.Query("container"),
			Destination: c.Query("destination"),
			Method:      c.Query("method"),
			Status:      c.DefaultQuery("status", "pending"),
			Limit:       limit,
			Offset:      offset,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		jsonItems := make([]greyproxy.PendingHttpRequestJSON, len(items))
		for i, item := range items {
			jsonItems[i] = item.ToJSON(false)
		}

		c.JSON(http.StatusOK, gin.H{
			"items": jsonItems,
			"total": total,
		})
	}
}

func PendingHttpDetailHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}

		p, err := greyproxy.GetPendingHttpRequest(s.DB, id)
		if err != nil || p == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}

		c.JSON(http.StatusOK, p.ToJSON(true))
	}
}

func PendingHttpAllowHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}

		p, err := greyproxy.ResolvePendingHttpRequest(s.DB, id, "allowed")
		if err != nil || p == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found or already resolved"})
			return
		}

		s.Bus.Publish(greyproxy.Event{
			Type: greyproxy.EventHttpPendingAllowed,
			Data: map[string]any{"pending_id": id},
		})

		c.JSON(http.StatusOK, gin.H{"status": "allowed", "pending": p.ToJSON(false)})
	}
}

func PendingHttpDenyHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}

		p, err := greyproxy.ResolvePendingHttpRequest(s.DB, id, "denied")
		if err != nil || p == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found or already resolved"})
			return
		}

		s.Bus.Publish(greyproxy.Event{
			Type: greyproxy.EventHttpPendingDenied,
			Data: map[string]any{"pending_id": id},
		})

		c.JSON(http.StatusOK, gin.H{"status": "denied", "pending": p.ToJSON(false)})
	}
}
