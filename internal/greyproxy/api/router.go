package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
)

// Shared holds shared state passed to all handlers.
type Shared struct {
	DB          *greyproxy.DB
	Cache       *greyproxy.DNSCache
	Bus         *greyproxy.EventBus
	Waiters     *greyproxy.WaiterTracker
	ConnTracker *greyproxy.ConnTracker
	Notifier    *greyproxy.Notifier
	Settings    *greyproxy.SettingsManager
	Assembler   *greyproxy.ConversationAssembler
	Version     string
	Ports       map[string]int
	DataHome    string // Path to greyproxy data directory (contains CA cert/key)
}

// NewRouter creates the Gin router with all routes.
// It returns the engine and the router group for the given pathPrefix,
// so callers can register additional routes under the same group
// without double-nesting the prefix.
func NewRouter(s *Shared, pathPrefix string) (*gin.Engine, *gin.RouterGroup) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	// Normalize pathPrefix
	if pathPrefix == "" {
		pathPrefix = "/"
	}

	// Redirect engine root to dashboard when pathPrefix is not "/"
	if pathPrefix != "/" {
		dest := strings.TrimRight(pathPrefix, "/") + "/dashboard"
		r.GET("/", func(c *gin.Context) {
			c.Redirect(http.StatusFound, dest)
		})
	}

	g := r.Group(pathPrefix)

	// REST API
	api := g.Group("/api")
	{
		api.GET("/health", HealthHandler(s))

		api.GET("/dashboard", DashboardHandler(s))

		api.GET("/pending/count", PendingCountHandler(s))
		api.GET("/pending", PendingListHandler(s))
		api.POST("/pending/:id/allow", PendingAllowHandler(s))
		api.POST("/pending/:id/deny", PendingDenyHandler(s))
		api.DELETE("/pending/:id", PendingDeleteHandler(s))
		api.POST("/pending/bulk-allow", PendingBulkAllowHandler(s))
		api.POST("/pending/bulk-dismiss", PendingBulkDismissHandler(s))

		api.GET("/rules", RulesListHandler(s))
		api.POST("/rules", RulesCreateHandler(s))
		api.POST("/rules/ingest", RulesIngestHandler(s))
		api.PUT("/rules/:id", RulesUpdateHandler(s))
		api.DELETE("/rules/:id", RulesDeleteHandler(s))

		api.GET("/logs", LogsListHandler(s))
		api.GET("/logs/stats", LogsStatsHandler(s))

		api.GET("/notifications", NotificationsStatusHandler(s))
		api.PUT("/notifications", NotificationsToggleHandler(s))

		api.GET("/settings", SettingsGetHandler(s))
		api.PUT("/settings", SettingsUpdateHandler(s))

		api.GET("/transactions", TransactionsListHandler(s))
		api.GET("/transactions/:id", TransactionsDetailHandler(s))

		// Conversations (LLM conversation dissection)
		api.GET("/conversations", ConversationsListHandler(s))
		api.GET("/conversations/:id", ConversationsDetailHandler(s))
		api.GET("/conversations/:id/subagents", ConversationsSubagentsHandler(s))

		// Certificate management
		api.GET("/cert/status", CertStatusHandler(s))
		api.POST("/cert/generate", CertGenerateHandler(s))
		api.GET("/cert/download", CertDownloadHandler(s))

		// Maintenance
		api.POST("/maintenance/rebuild-conversations", RebuildConversationsHandler(s))
		api.GET("/maintenance/status", MaintenanceStatusHandler(s))
	}

	// WebSocket
	g.GET("/ws", WebSocketHandler(s))

	// Static files (embedded) with cache headers
	g.GET("/static/*filepath", func(c *gin.Context) {
		filepath := c.Param("filepath")
		// Cache fonts and icons for 1 year (immutable embedded assets)
		if strings.HasPrefix(filepath, "/fonts/") || strings.HasPrefix(filepath, "/icons/") {
			c.Header("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			c.Header("Cache-Control", "public, max-age=3600")
		}
		c.FileFromFS("static"+filepath, http.FS(greyproxy.StaticFS))
	})

	return r, g
}
