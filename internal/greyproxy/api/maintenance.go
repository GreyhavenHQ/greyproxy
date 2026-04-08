package api

import (
	"log/slog"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
)

func MaintenanceStatusHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		stored := greyproxy.StoredAssemblerVersion(s.DB)
		c.JSON(http.StatusOK, gin.H{
			"assembler_version_current": greyproxy.AssemblerVersion,
			"assembler_version_stored":  stored,
			"needs_rebuild":             stored != greyproxy.AssemblerVersion,
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

// redactHeadersState tracks the background redaction job.
var redactHeadersState struct {
	mu      sync.Mutex
	running bool
}

func RedactHeadersHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		redactHeadersState.mu.Lock()
		if redactHeadersState.running {
			redactHeadersState.mu.Unlock()
			c.JSON(http.StatusConflict, gin.H{"error": "redaction already in progress"})
			return
		}
		redactHeadersState.running = true
		redactHeadersState.mu.Unlock()

		redactor := s.Settings.HeaderRedactor()
		go func() {
			defer func() {
				redactHeadersState.mu.Lock()
				redactHeadersState.running = false
				redactHeadersState.mu.Unlock()
			}()

			count, err := greyproxy.RedactExistingTransactionHeaders(s.DB, redactor, func(p greyproxy.MaintenanceProgress) {
				s.Bus.Publish(greyproxy.Event{
					Type: greyproxy.EventMaintenanceProgress,
					Data: p,
				})
			})
			if err != nil {
				slog.Error("maintenance: redact headers failed", "error", err, "processed", count)
				s.Bus.Publish(greyproxy.Event{
					Type: greyproxy.EventMaintenanceProgress,
					Data: greyproxy.MaintenanceProgress{
						Task:      "redact_headers",
						Processed: count,
						Done:      true,
						Error:     err.Error(),
					},
				})
				return
			}
			slog.Info("maintenance: redact headers completed", "processed", count)
		}()

		c.JSON(http.StatusOK, gin.H{"status": "redaction started"})
	}
}
