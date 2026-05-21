package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/greyhavenhq/greyproxy/internal/greyproxy/llmproxy"
)

// LLMAliasesListHandler — GET /api/llm/aliases.
func LLMAliasesListHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.LLMStore == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "llm proxy disabled"})
			return
		}
		items, err := s.LLMStore.ListAliases()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"items": items})
	}
}

// LLMAliasesGetHandler — GET /api/llm/aliases/:id.
func LLMAliasesGetHandler(s *Shared) gin.HandlerFunc {
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
		a, err := s.LLMStore.GetAlias(id)
		if err != nil {
			c.JSON(statusForLLMErr(err), gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, a)
	}
}

// LLMAliasesCreateHandler — POST /api/llm/aliases.
func LLMAliasesCreateHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.LLMStore == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "llm proxy disabled"})
			return
		}
		var input llmproxy.AliasInput
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		a, err := s.LLMStore.CreateAlias(input)
		if err != nil {
			c.JSON(statusForLLMErr(err), gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusCreated, a)
	}
}

// LLMAliasesUpdateHandler — PUT /api/llm/aliases/:id.
func LLMAliasesUpdateHandler(s *Shared) gin.HandlerFunc {
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
		var input llmproxy.AliasInput
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		a, err := s.LLMStore.UpdateAlias(id, input)
		if err != nil {
			c.JSON(statusForLLMErr(err), gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, a)
	}
}

// LLMAliasesDeleteHandler — DELETE /api/llm/aliases/:id.
func LLMAliasesDeleteHandler(s *Shared) gin.HandlerFunc {
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
		if err := s.LLMStore.DeleteAlias(id); err != nil {
			c.JSON(statusForLLMErr(err), gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}
}
