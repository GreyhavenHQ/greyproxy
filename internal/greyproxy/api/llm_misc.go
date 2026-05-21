package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/greyhavenhq/greyproxy/internal/greyproxy/llmproxy"
)

// LLMProviderTypesHandler — GET /api/llm/provider-types.
// Returns the static list of backend implementations compiled into the
// binary (e.g. "openai", "openai-compat", "openrouter"). Driven off the
// in-memory registry, so adding a new provider type is a matter of
// dropping a file in llmproxy and re-running the binary.
func LLMProviderTypesHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"items": llmproxy.BackendTypes()})
	}
}
