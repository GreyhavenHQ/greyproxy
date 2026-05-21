package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/greyhavenhq/greyproxy/internal/greyproxy/llmproxy"
)

// LLMProvidersListHandler — GET /api/llm/providers.
// Returns every provider row, with api_key replaced by a masked preview.
func LLMProvidersListHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.LLMStore == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "llm proxy disabled"})
			return
		}
		items, err := s.LLMStore.ListProviders()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"items": items})
	}
}

// LLMProvidersGetHandler — GET /api/llm/providers/:id.
func LLMProvidersGetHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.LLMStore == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "llm proxy disabled"})
			return
		}
		id, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		p, err := s.LLMStore.GetProvider(id)
		if err != nil {
			c.JSON(statusForLLMErr(err), gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, p)
	}
}

// LLMProvidersCreateHandler — POST /api/llm/providers.
func LLMProvidersCreateHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.LLMStore == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "llm proxy disabled"})
			return
		}
		var input llmproxy.ProviderInput
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		p, err := s.LLMStore.CreateProvider(input)
		if err != nil {
			c.JSON(statusForLLMErr(err), gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusCreated, p)
	}
}

// LLMProvidersUpdateHandler — PUT /api/llm/providers/:id.
func LLMProvidersUpdateHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.LLMStore == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "llm proxy disabled"})
			return
		}
		id, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		var input llmproxy.ProviderInput
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		p, err := s.LLMStore.UpdateProvider(id, input)
		if err != nil {
			c.JSON(statusForLLMErr(err), gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, p)
	}
}

// LLMProvidersDeleteHandler — DELETE /api/llm/providers/:id.
// Rejects with 409 when any alias references the provider.
func LLMProvidersDeleteHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.LLMStore == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "llm proxy disabled"})
			return
		}
		id, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		if err := s.LLMStore.DeleteProvider(id); err != nil {
			c.JSON(statusForLLMErr(err), gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}
}

// statusForLLMErr maps llmproxy sentinel errors to HTTP statuses. Keeps
// the handlers concise — all of them funnel error replies through here.
func statusForLLMErr(err error) int {
	switch {
	case errors.Is(err, llmproxy.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, llmproxy.ErrDisabled):
		return http.StatusUnprocessableEntity
	case errors.Is(err, llmproxy.ErrInUse):
		return http.StatusConflict
	case errors.Is(err, llmproxy.ErrBadInput):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}
