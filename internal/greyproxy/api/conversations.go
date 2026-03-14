package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
)

// ConversationsListHandler returns paginated conversation list (top-level only).
func ConversationsListHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
		offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

		f := greyproxy.ConversationFilter{
			Container: c.Query("container"),
			Model:     c.Query("model"),
			Provider:  c.Query("provider"),
			Limit:     limit,
			Offset:    offset,
		}

		convs, total, err := greyproxy.QueryConversations(s.DB, f)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		var items []greyproxy.ConversationJSON
		for _, conv := range convs {
			items = append(items, conv.ToJSON(false))
		}

		c.JSON(http.StatusOK, gin.H{
			"items": items,
			"total": total,
		})
	}
}

// ConversationsDetailHandler returns a single conversation with turns.
func ConversationsDetailHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		conv, err := greyproxy.GetConversation(s.DB, id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if conv == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusOK, conv.ToJSON(true))
	}
}

// ConversationsSubagentsHandler returns subagents of a conversation.
func ConversationsSubagentsHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		subs, err := greyproxy.GetSubagents(s.DB, id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		var items []greyproxy.ConversationJSON
		for _, sub := range subs {
			items = append(items, sub.ToJSON(false))
		}

		c.JSON(http.StatusOK, gin.H{"items": items})
	}
}
