package api

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
)

func RulesListHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
		offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
		includeExpired := c.Query("include_expired") == "true"

		items, total, err := greyproxy.GetRules(s.DB, greyproxy.RuleFilter{
			Container:      c.Query("container"),
			Destination:    c.Query("destination"),
			Action:         c.Query("action"),
			IncludeExpired: includeExpired,
			Limit:          limit,
			Offset:         offset,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		jsonItems := make([]greyproxy.RuleJSON, len(items))
		for i, item := range items {
			jsonItems[i] = item.ToJSON()
		}

		c.JSON(http.StatusOK, gin.H{
			"items": jsonItems,
			"total": total,
		})
	}
}

func RulesCreateHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		var input greyproxy.RuleCreateInput
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		rule, err := greyproxy.CreateRule(s.DB, input)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusCreated, rule.ToJSON())
	}
}

func RulesUpdateHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}

		var input greyproxy.RuleUpdateInput
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		rule, err := greyproxy.UpdateRule(s.DB, id, input)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if rule == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
			return
		}

		// If the rule was changed to deny, cancel connections that relied on it.
		if rule.Action == "deny" && s.ConnTracker != nil {
			s.ConnTracker.CancelByRule(id)
		}

		c.JSON(http.StatusOK, rule.ToJSON())
	}
}

func RulesIngestHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		var input []greyproxy.IngestRuleInput
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		result, err := greyproxy.IngestRules(s.DB, input)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, result)
	}
}

func RulesDeleteHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}

		slog.Info("api: deleting rule", "rule_id", id)

		deleted, err := greyproxy.DeleteRule(s.DB, id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		slog.Info("api: rule deleted, cancelling connections", "rule_id", id, "deleted", deleted)
		if deleted && s.ConnTracker != nil {
			s.ConnTracker.CancelByRule(id)
		}

		c.JSON(http.StatusOK, gin.H{"status": "ok", "deleted": deleted})
	}
}
