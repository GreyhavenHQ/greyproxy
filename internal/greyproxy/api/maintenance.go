package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
)

func MaintenanceStatusHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		stored := greyproxy.StoredAssemblerVersion(s.DB)
		c.JSON(http.StatusOK, gin.H{
			"assembler_version_current": greyproxy.AssemblerVersion,
			"assembler_version_stored":  stored,
			"needs_rebuild":             stored < greyproxy.AssemblerVersion,
		})
	}
}

func RebuildConversationsHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.Assembler == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "assembler not available"})
			return
		}
		go s.Assembler.RebuildAllConversations()
		c.JSON(http.StatusOK, gin.H{"status": "rebuild started"})
	}
}
