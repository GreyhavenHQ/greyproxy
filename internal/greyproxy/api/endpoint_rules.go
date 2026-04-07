package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
)

// EndpointRulesListHandler returns all endpoint rules.
func EndpointRulesListHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.Assembler == nil || s.Assembler.Registry == nil {
			c.JSON(http.StatusOK, gin.H{"rules": []any{}})
			return
		}
		rules := s.Assembler.Registry.ListRules()
		c.JSON(http.StatusOK, gin.H{"rules": rules})
	}
}

// EndpointRulesCreateHandler creates a user-defined endpoint rule.
func EndpointRulesCreateHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		var input struct {
			HostPattern string `json:"host_pattern" binding:"required"`
			PathPattern string `json:"path_pattern" binding:"required"`
			Method      string `json:"method"`
			DecoderName string `json:"decoder_name" binding:"required"`
			Priority    int    `json:"priority"`
			Enabled     *bool  `json:"enabled"`
		}
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if input.Method == "" {
			input.Method = "POST"
		}
		enabled := true
		if input.Enabled != nil {
			enabled = *input.Enabled
		}

		rule := greyproxy.EndpointRule{
			HostPattern: input.HostPattern,
			PathPattern: input.PathPattern,
			Method:      input.Method,
			DecoderName: input.DecoderName,
			Priority:    input.Priority,
			Enabled:     enabled,
		}
		id, err := s.Assembler.Registry.CreateRule(rule)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		rule.ID = id
		rule.UserDefined = true
		c.JSON(http.StatusCreated, rule)
	}
}

// EndpointRulesUpdateHandler updates a user-defined endpoint rule.
func EndpointRulesUpdateHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		var input struct {
			HostPattern string `json:"host_pattern" binding:"required"`
			PathPattern string `json:"path_pattern" binding:"required"`
			Method      string `json:"method"`
			DecoderName string `json:"decoder_name" binding:"required"`
			Priority    int    `json:"priority"`
			Enabled     *bool  `json:"enabled"`
		}
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if input.Method == "" {
			input.Method = "POST"
		}
		enabled := true
		if input.Enabled != nil {
			enabled = *input.Enabled
		}

		rule := greyproxy.EndpointRule{
			HostPattern: input.HostPattern,
			PathPattern: input.PathPattern,
			Method:      input.Method,
			DecoderName: input.DecoderName,
			Priority:    input.Priority,
			Enabled:     enabled,
		}
		if err := s.Assembler.Registry.UpdateRule(id, rule); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}

// EndpointRulesDeleteHandler deletes a user-defined endpoint rule.
func EndpointRulesDeleteHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		if err := s.Assembler.Registry.DeleteRule(id); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}
