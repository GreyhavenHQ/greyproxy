package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
)

// MiddlewaresListHandler returns the live status of every configured
// middleware client (connection state, hooks, agreed protocol version,
// timeout / on_disconnect policy). Read-only; no mutation endpoints here
// because middleware configuration is owned by CLI flags and greyproxy.yml,
// not the runtime store.
//
// If no middlewares are configured, returns an empty list rather than 404 —
// the UI uses the empty case to render a "no middlewares configured" hint.
func MiddlewaresListHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		var statuses []greyproxy.MiddlewareStatus
		if s.MiddlewareStatusesFn != nil {
			statuses = s.MiddlewareStatusesFn()
		}
		if statuses == nil {
			statuses = []greyproxy.MiddlewareStatus{}
		}
		c.JSON(http.StatusOK, gin.H{"middlewares": statuses})
	}
}
