package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
	"github.com/greyhavenhq/greyproxy/internal/greyproxy/dissector"
)

// validMethods lists the accepted HTTP methods, WebSocket pseudo-methods, and wildcard.
var validMethods = map[string]bool{
	"GET": true, "HEAD": true, "POST": true, "PUT": true,
	"PATCH": true, "DELETE": true, "OPTIONS": true, "TRACE": true,
	"WS_REQ": true, "WS_RESP": true, "*": true,
}

// validateEndpointRule checks user input for an endpoint rule.
// Returns an error message or empty string if valid.
func validateEndpointRule(hostPattern, pathPattern, method, decoderName string) string {
	// Validate decoder_name exists
	if dissector.FindDissectorByName(decoderName) == nil {
		return "unknown decoder_name: " + decoderName
	}
	// Validate path_pattern starts with /
	if !strings.HasPrefix(pathPattern, "/") {
		return "path_pattern must start with /"
	}
	// Validate host_pattern is not just a bare wildcard or empty
	trimmed := strings.TrimSpace(hostPattern)
	if trimmed == "" || trimmed == "%" || trimmed == "*" {
		return "host_pattern must not be empty or a bare wildcard"
	}
	// Validate method
	if !validMethods[strings.ToUpper(method)] {
		return "invalid method: " + method + "; expected a standard HTTP method or *"
	}
	return ""
}

// endpointRuleInput is the shared JSON input for create/update handlers.
type endpointRuleInput struct {
	HostPattern string `json:"host_pattern" binding:"required"`
	PathPattern string `json:"path_pattern" binding:"required"`
	Method      string `json:"method"`
	DecoderName string `json:"decoder_name" binding:"required"`
	Priority    int    `json:"priority"`
	Enabled     *bool  `json:"enabled"`
}

func (in *endpointRuleInput) toRule() (greyproxy.EndpointRule, string) {
	if in.Method == "" {
		in.Method = "POST"
	}
	if errMsg := validateEndpointRule(in.HostPattern, in.PathPattern, in.Method, in.DecoderName); errMsg != "" {
		return greyproxy.EndpointRule{}, errMsg
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	return greyproxy.EndpointRule{
		HostPattern: in.HostPattern,
		PathPattern: in.PathPattern,
		Method:      in.Method,
		DecoderName: in.DecoderName,
		Priority:    in.Priority,
		Enabled:     enabled,
	}, ""
}

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
		var input endpointRuleInput
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		rule, errMsg := input.toRule()
		if errMsg != "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": errMsg})
			return
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
		var input endpointRuleInput
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		rule, errMsg := input.toRule()
		if errMsg != "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": errMsg})
			return
		}
		if err := s.Assembler.Registry.UpdateRule(id, rule); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}

// DissectorsListHandler returns metadata about all registered dissectors.
func DissectorsListHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"dissectors": dissector.RegisteredDissectors()})
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
