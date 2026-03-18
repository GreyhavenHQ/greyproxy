package ui

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"math"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"log/slog"

	"github.com/gin-gonic/gin"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
)

//go:embed templates/*
var templatesFS embed.FS

// Note: Static files are served from the greyproxy package, not embedded here.
// The router in api/router.go will set up static file serving.

var funcMap = template.FuncMap{
	"timeAgo": func(t time.Time) string {
		d := time.Since(t)
		switch {
		case d < time.Minute:
			return "just now"
		case d < time.Hour:
			return fmt.Sprintf("%dm ago", int(d.Minutes()))
		case d < 24*time.Hour:
			return fmt.Sprintf("%dh ago", int(d.Hours()))
		default:
			return fmt.Sprintf("%dd ago", int(d.Hours()/24))
		}
	},
	"formatTime": func(t time.Time) string {
		return t.Format("2006-01-02 15:04:05")
	},
	"formatTimeShort": func(t time.Time) string {
		return t.Format("01-02 15:04")
	},
	"formatHMS": func(t time.Time) string {
		return t.Format("15:04:05")
	},
	"formatTimeOnly": func(s string) string {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return t.Format("15:04:05")
		}
		// Fallback: try to extract time portion
		if len(s) >= 19 {
			return s[11:19]
		}
		return s
	},
	"formatDate": func(t time.Time) string {
		return t.Format("2006-01-02 15:04")
	},
	"contains": strings.Contains,
	"join":     strings.Join,
	"add": func(a, b int) int {
		return a + b
	},
	"sub": func(a, b int) int {
		return a - b
	},
	"formatFloat": func(f float64) string {
		return fmt.Sprintf("%.1f", f)
	},
	"formatNumber": func(n int) string {
		if n < 1000 {
			return fmt.Sprintf("%d", n)
		}
		// Simple comma formatting
		s := fmt.Sprintf("%d", n)
		result := make([]byte, 0, len(s)+(len(s)-1)/3)
		for i, c := range s {
			if i > 0 && (len(s)-i)%3 == 0 {
				result = append(result, ',')
			}
			result = append(result, byte(c))
		}
		return string(result)
	},
	"percent": func(part, total int) float64 {
		if total == 0 {
			return 0
		}
		return float64(part) / float64(total) * 100
	},
	"baseDomain": func(host string) string {
		parts := strings.Split(host, ".")
		if len(parts) >= 2 {
			return strings.Join(parts[len(parts)-2:], ".")
		}
		return host
	},
	"pluralize": func(count int, singular, plural string) string {
		if count == 1 {
			return singular
		}
		return plural
	},
	"truncate": func(v any, n int) string {
		s := fmt.Sprintf("%v", v)
		if len(s) <= n {
			return s
		}
		return s[:n]
	},
	"mitmSkipReasonLabel": func(reason string) string {
		switch reason {
		case "no_cert":
			return "CA certificate not configured"
		case "mitm_bypass":
			return "Host is in MITM bypass list"
		case "sniffing_disabled":
			return "Traffic sniffing is disabled"
		case "non_tls":
			return "Protocol is not TLS"
		case "mitm_disabled":
			return "MITM is globally disabled"
		case "non_http_after_tls":
			return "Decrypted stream is not HTTP"
		case "mitm_error":
			return "TLS interception failed (client may reject forged certificate)"
		default:
			return reason
		}
	},
	"strLen": func(v any) int {
		if v == nil {
			return 0
		}
		return len(fmt.Sprintf("%v", v))
	},
	"cleanToolOutput": func(v any) string {
		s := fmt.Sprintf("%v", v)
		lines := strings.Split(s, "\n")
		for i, line := range lines {
			// Strip line number prefixes like "     1→" or "   42→"
			for j := 0; j < len(line); j++ {
				if line[j] == '\xe2' && j+2 < len(line) && line[j+1] == '\x86' && line[j+2] == '\x92' {
					// Found → (U+2192), strip everything before and including it
					lines[i] = line[j+3:]
					break
				}
				if line[j] != ' ' && (line[j] < '0' || line[j] > '9') {
					break
				}
			}
		}
		return strings.Join(lines, "\n")
	},
	"expiresIn": func(t time.Time) string {
		d := time.Until(t)
		if d <= 0 {
			return "Expired"
		}
		hours := int(d.Hours())
		if hours > 0 {
			return fmt.Sprintf("Expires in %dh", hours)
		}
		mins := int(d.Minutes())
		return fmt.Sprintf("Expires in %dm", mins)
	},
	"isExpired": func(t time.Time) bool {
		return time.Now().After(t)
	},
	"credLabels": func(raw string) []string {
		var labels []string
		json.Unmarshal([]byte(raw), &labels)
		return labels
	},
	"derefStr": func(s *string) string {
		if s == nil {
			return ""
		}
		return *s
	},
	"derefInt": func(i *int64) int64 {
		if i == nil {
			return 0
		}
		return *i
	},
	"hasValue": func(s *string) bool {
		return s != nil && *s != ""
	},
	"hasIntValue": func(i *int64) bool {
		return i != nil
	},
	"seq": func(start, end int) []int {
		var result []int
		for i := start; i <= end; i++ {
			result = append(result, i)
		}
		return result
	},
	// Conversation detail template helpers
	"isStep": func(step any, stepType string) bool {
		if m, ok := step.(map[string]any); ok {
			return m["type"] == stepType
		}
		return false
	},
	// toolIconCategory normalizes tool names across providers (Anthropic PascalCase,
	// OpenAI lowercase) and returns a category string for icon rendering.
	"toolIconCategory": func(tool string) string {
		switch strings.ToLower(tool) {
		case "read":
			return "read"
		case "edit", "apply_patch":
			return "edit"
		case "write", "notebookedit":
			return "write"
		case "bash":
			return "bash"
		case "grep", "glob":
			return "search"
		case "agent", "task":
			return "agent"
		case "webfetch", "websearch":
			return "web"
		case "skill":
			return "skill"
		case "toolsearch":
			return "toolsearch"
		case "askuserquestion", "question":
			return "question"
		case "todowrite", "todoread":
			return "todo"
		default:
			return "generic"
		}
	},
	"hasStepField": func(step any, field string) bool {
		if m, ok := step.(map[string]any); ok {
			v, exists := m[field]
			if !exists {
				return false
			}
			if s, ok := v.(string); ok {
				return s != ""
			}
			return v != nil
		}
		return false
	},
	"stepField": func(step any, field string) string {
		if m, ok := step.(map[string]any); ok {
			if v, ok := m[field]; ok {
				if s, ok := v.(string); ok {
					return s
				}
				return fmt.Sprintf("%v", v)
			}
		}
		return ""
	},
	"stepToolCalls": func(step any) []map[string]any {
		if m, ok := step.(map[string]any); ok {
			if tcs, ok := m["tool_calls"].([]any); ok {
				var result []map[string]any
				for _, tc := range tcs {
					if tcMap, ok := tc.(map[string]any); ok {
						result = append(result, tcMap)
					}
				}
				return result
			}
		}
		return nil
	},
	"stepID": func(step any) string {
		if m, ok := step.(map[string]any); ok {
			if id, ok := m["tool_use_id"].(string); ok {
				return id
			}
		}
		return fmt.Sprintf("%p", step)
	},
	// toolSummary returns a compact one-line summary for a tool call.
	// It parses the input_preview JSON and extracts the most relevant field.
	"toolSummary": func(tc map[string]any) string {
		// Prefer pre-computed summary (available for new data)
		if summary, ok := tc["tool_summary"].(string); ok && summary != "" {
			return summary
		}
		// Fallback: parse input_preview JSON (may fail on truncated data)
		toolName, _ := tc["tool"].(string)
		inputRaw, _ := tc["input_preview"].(string)
		if inputRaw == "" {
			return ""
		}
		var input map[string]any
		if err := json.Unmarshal([]byte(inputRaw), &input); err != nil {
			// Not valid JSON, return truncated raw
			if len(inputRaw) > 80 {
				return inputRaw[:80] + "..."
			}
			return inputRaw
		}
		switch toolName {
		case "Read", "Edit", "Write":
			if fp, ok := input["file_path"].(string); ok {
				short := filepath.Base(fp)
				dir := filepath.Dir(fp)
				// Show last 2 path components for context
				parent := filepath.Base(dir)
				if parent != "." && parent != "/" {
					short = parent + "/" + short
				}
				return short
			}
		case "Bash":
			if desc, ok := input["description"].(string); ok && desc != "" {
				return desc
			}
			if cmd, ok := input["command"].(string); ok {
				if len(cmd) > 80 {
					return cmd[:80] + "..."
				}
				return cmd
			}
		case "Grep":
			if pat, ok := input["pattern"].(string); ok {
				summary := "pattern: " + pat
				if p, ok := input["path"].(string); ok {
					summary += " in " + filepath.Base(p)
				}
				return summary
			}
		case "Glob":
			if pat, ok := input["pattern"].(string); ok {
				return pat
			}
		case "Agent":
			if desc, ok := input["description"].(string); ok && desc != "" {
				return desc
			}
		case "ToolSearch":
			if q, ok := input["query"].(string); ok {
				return q
			}
		case "WebFetch", "WebSearch":
			if u, ok := input["url"].(string); ok {
				return u
			}
			if q, ok := input["query"].(string); ok {
				return q
			}
		}
		// Fallback: show truncated JSON
		if len(inputRaw) > 80 {
			return inputRaw[:80] + "..."
		}
		return inputRaw
	},
	// toolIcon returns an SVG icon name hint for a tool (used as CSS class).
	"toolIcon": func(toolName string) string {
		switch toolName {
		case "Read":
			return "tool-icon-read"
		case "Edit":
			return "tool-icon-edit"
		case "Write":
			return "tool-icon-write"
		case "Bash":
			return "tool-icon-bash"
		case "Grep", "Glob":
			return "tool-icon-search"
		case "Agent":
			return "tool-icon-agent"
		default:
			return "tool-icon-default"
		}
	},
	// toolResultSummary returns a short result summary for collapsed view.
	"toolResultSummary": func(tc map[string]any) string {
		result, _ := tc["result_preview"].(string)
		if result == "" {
			return ""
		}
		// Clean tool output (strip line number prefixes)
		lines := strings.Split(result, "\n")
		for i, line := range lines {
			for j := 0; j < len(line); j++ {
				if line[j] == '\xe2' && j+2 < len(line) && line[j+1] == '\x86' && line[j+2] == '\x92' {
					lines[i] = line[j+3:]
					break
				}
				if line[j] != ' ' && (line[j] < '0' || line[j] > '9') {
					break
				}
			}
		}
		cleaned := strings.Join(lines, "\n")
		isError, _ := tc["is_error"].(bool)
		if isError {
			first := strings.SplitN(cleaned, "\n", 2)[0]
			if len(first) > 60 {
				first = first[:60] + "..."
			}
			return "Error: " + first
		}
		first := strings.SplitN(cleaned, "\n", 2)[0]
		if len(first) > 60 {
			first = first[:60] + "..."
		}
		return first
	},
	// truncateLines returns the first N lines of a string.
	"truncateLines": func(s string, n int) string {
		lines := strings.SplitN(s, "\n", n+1)
		if len(lines) <= n {
			return s
		}
		return strings.Join(lines[:n], "\n") + "\n..."
	},
	// countToolResultLines counts the lines in a tool result.
	"countToolResultLines": func(s string) int {
		if s == "" {
			return 0
		}
		return strings.Count(s, "\n") + 1
	},
}

func parseTemplate(name string, files ...string) *template.Template {
	paths := make([]string, len(files))
	for i, f := range files {
		paths[i] = "templates/" + f
	}
	t, err := template.New(name).Funcs(funcMap).ParseFS(templatesFS, paths...)
	if err != nil {
		panic(fmt.Sprintf("parse template %s: %v", name, err))
	}
	return t
}

var (
	dashboardTmpl = parseTemplate("base.html", "base.html", "dashboard.html")
	pendingTmpl   = parseTemplate("base.html", "base.html", "pending.html")
	rulesTmpl     = parseTemplate("base.html", "base.html", "rules.html")
	logsTmpl      = parseTemplate("base.html", "base.html", "logs.html")
	settingsTmpl  = parseTemplate("base.html", "base.html", "settings.html")

	trafficTmpl       = parseTemplate("base.html", "base.html", "traffic.html")
	activityTmpl      = parseTemplate("base.html", "base.html", "activity.html")
	conversationsTmpl = parseTemplate("base.html", "base.html", "conversations.html")

	dashboardStatsTmpl    = parseTemplate("dashboard_stats.html", "partials/dashboard_stats.html")
	pendingListTmpl       = parseTemplate("pending_list.html", "partials/pending_list.html")
	rulesListTmpl         = parseTemplate("rules_list.html", "partials/rules_list.html")
	logsTableTmpl         = parseTemplate("logs_table.html", "partials/logs_table.html")
	trafficTableTmpl      = parseTemplate("traffic_table.html", "partials/traffic_table.html")
	activityTableTmpl     = parseTemplate("activity_table.html", "partials/activity_table.html")
	convListTmpl          = parseTemplate("conversation_list.html", "partials/conversation_list.html")
	convDetailTmpl        = parseTemplate("conversation_detail.html", "partials/conversation_detail.html")
)

// cacheBuster is set once at startup for static asset cache busting.
var cacheBuster = strconv.FormatInt(time.Now().Unix(), 36)

type PageData struct {
	CurrentPath string
	Prefix      string // URL path prefix (e.g., "" for root, "/proxy" for sub-path)
	CacheBuster string
	Title       string
	Containers  []string
	Data        any
}

func getContainers(db *greyproxy.DB) []string {
	rows, err := db.ReadDB().Query(
		`SELECT DISTINCT container_name FROM pending_requests
		 UNION SELECT DISTINCT container_name FROM request_logs
		 UNION SELECT DISTINCT container_name FROM http_transactions
		 ORDER BY container_name`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var containers []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err == nil {
			containers = append(containers, c)
		}
	}
	return containers
}

// RegisterPageRoutes registers the full-page HTML routes.
func RegisterPageRoutes(r *gin.RouterGroup, db *greyproxy.DB, bus *greyproxy.EventBus) {
	// Compute prefix once: strip trailing slash, so "/" becomes "" and "/proxy" stays "/proxy"
	prefix := strings.TrimRight(r.BasePath(), "/")

	r.GET("/dashboard", func(c *gin.Context) {
		dashboardTmpl.Execute(c.Writer, PageData{
			CurrentPath: c.Request.URL.Path,
			Prefix:      prefix,
			CacheBuster: cacheBuster,
			Title:       "Dashboard - Greyproxy",
			Containers:  getContainers(db),
		})
	})

	r.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusFound, prefix+"/dashboard")
	})

	r.GET("/pending", func(c *gin.Context) {
		pendingTmpl.Execute(c.Writer, PageData{
			CurrentPath: c.Request.URL.Path,
			Prefix:      prefix,
			CacheBuster: cacheBuster,
			Title:       "Pending Requests - Greyproxy",
			Containers:  getContainers(db),
		})
	})

	r.GET("/rules", func(c *gin.Context) {
		rulesTmpl.Execute(c.Writer, PageData{
			CurrentPath: c.Request.URL.Path,
			Prefix:      prefix,
			CacheBuster: cacheBuster,
			Title:       "Rules - Greyproxy",
			Containers:  getContainers(db),
		})
	})

	r.GET("/logs", func(c *gin.Context) {
		c.Redirect(http.StatusFound, prefix+"/activity?kind=connection")
	})

	r.GET("/settings", func(c *gin.Context) {
		settingsTmpl.Execute(c.Writer, PageData{
			CurrentPath: c.Request.URL.Path,
			Prefix:      prefix,
			CacheBuster: cacheBuster,
			Title:       "Settings - Greyproxy",
			Containers:  getContainers(db),
		})
	})

	r.GET("/traffic", func(c *gin.Context) {
		c.Redirect(http.StatusFound, prefix+"/activity?kind=http")
	})

	r.GET("/activity", func(c *gin.Context) {
		activityTmpl.Execute(c.Writer, PageData{
			CurrentPath: c.Request.URL.Path,
			Prefix:      prefix,
			CacheBuster: cacheBuster,
			Title:       "Activity - Greyproxy",
			Containers:  getContainers(db),
		})
	})

	r.GET("/conversations", func(c *gin.Context) {
		conversationsTmpl.Execute(c.Writer, PageData{
			CurrentPath: c.Request.URL.Path,
			Prefix:      prefix,
			CacheBuster: cacheBuster,
			Title:       "Conversations - Greyproxy",
			Containers:  getContainers(db),
		})
	})
}

// RegisterHTMXRoutes registers the HTMX partial routes.
func RegisterHTMXRoutes(r *gin.RouterGroup, db *greyproxy.DB, bus *greyproxy.EventBus, waiters *greyproxy.WaiterTracker, connTracker *greyproxy.ConnTracker) {
	prefix := strings.TrimRight(r.BasePath(), "/")
	htmx := r.Group("/htmx")

	htmx.GET("/dashboard-stats", func(c *gin.Context) {
		now := time.Now()
		var fromDate, toDate time.Time

		period := c.DefaultQuery("period", "today")
		switch period {
		case "7d":
			fromDate = now.AddDate(0, 0, -7)
		case "30d":
			fromDate = now.AddDate(0, 0, -30)
		default:
			fromDate = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.Local)
		}
		toDate = now

		groupBy := "hour"
		diff := toDate.Sub(fromDate)
		if diff > 48*time.Hour {
			groupBy = "day"
		}

		stats, err := greyproxy.GetDashboardStats(db, fromDate, toDate, groupBy, 10)
		if err != nil {
			c.String(http.StatusInternalServerError, "Error: %v", err)
			return
		}

		c.Writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		dashboardStatsTmpl.Execute(c.Writer, gin.H{
			"Prefix": prefix,
			"Stats":  stats,
			"Period": period,
		})
	})

	htmx.GET("/pending-list", func(c *gin.Context) {
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
		offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

		container := c.Query("container")
		destination := c.Query("destination")

		items, total, err := greyproxy.GetPendingRequests(db, greyproxy.PendingFilter{
			Container:   container,
			Destination: destination,
			Limit:       limit,
			Offset:      offset,
		})
		if err != nil {
			c.String(http.StatusInternalServerError, "Error: %v", err)
			return
		}

		enrichWaitingCounts(items, waiters)

		hasFilters := container != "" || destination != ""

		c.Writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		pendingListTmpl.Execute(c.Writer, gin.H{
			"Prefix":     prefix,
			"Items":      items,
			"Total":      total,
			"HasFilters": hasFilters,
		})
	})

	// Allow pending via HTMX
	htmx.POST("/pending/:id/allow", func(c *gin.Context) {
		id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
		scope := c.DefaultPostForm("scope", "exact")
		duration := c.DefaultPostForm("duration", "permanent")

		rule, err := greyproxy.AllowPending(db, id, scope, duration, nil)
		if err != nil {
			c.String(http.StatusInternalServerError, "Error: %v", err)
			return
		}

		bus.Publish(greyproxy.Event{
			Type: greyproxy.EventPendingAllowed,
			Data: map[string]any{"pending_id": id, "rule": rule.ToJSON()},
		})

		// Re-render pending list
		renderPendingList(c, db, prefix, waiters)
	})

	// Deny pending via HTMX
	htmx.POST("/pending/:id/deny", func(c *gin.Context) {
		id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
		scope := c.DefaultPostForm("scope", "exact")
		duration := c.DefaultPostForm("duration", "permanent")

		rule, err := greyproxy.DenyPending(db, id, scope, duration, nil)
		if err != nil {
			c.String(http.StatusInternalServerError, "Error: %v", err)
			return
		}

		bus.Publish(greyproxy.Event{
			Type: greyproxy.EventPendingDismissed,
			Data: map[string]any{"pending_id": id, "rule": rule.ToJSON()},
		})

		renderPendingList(c, db, prefix, waiters)
	})

	// Dismiss pending via HTMX
	htmx.DELETE("/pending/:id", func(c *gin.Context) {
		id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
		ok, _ := greyproxy.DeletePending(db, id)
		if ok {
			bus.Publish(greyproxy.Event{
				Type: greyproxy.EventPendingDismissed,
				Data: map[string]any{"pending_id": id},
			})
		}
		renderPendingList(c, db, prefix, waiters)
	})

	// Bulk allow via HTMX
	htmx.POST("/pending/bulk-allow", func(c *gin.Context) {
		ids := c.PostFormArray("selected")
		for _, idStr := range ids {
			id, err := strconv.ParseInt(idStr, 10, 64)
			if err != nil {
				continue
			}
			rule, err := greyproxy.AllowPending(db, id, "exact", "permanent", nil)
			if err == nil {
				bus.Publish(greyproxy.Event{
					Type: greyproxy.EventPendingAllowed,
					Data: map[string]any{"pending_id": id, "rule": rule.ToJSON()},
				})
			}
		}
		renderPendingList(c, db, prefix, waiters)
	})

	// Bulk dismiss via HTMX
	htmx.POST("/pending/bulk-dismiss", func(c *gin.Context) {
		ids := c.PostFormArray("selected")
		for _, idStr := range ids {
			id, err := strconv.ParseInt(idStr, 10, 64)
			if err != nil {
				continue
			}
			ok, _ := greyproxy.DeletePending(db, id)
			if ok {
				bus.Publish(greyproxy.Event{
					Type: greyproxy.EventPendingDismissed,
					Data: map[string]any{"pending_id": id},
				})
			}
		}
		renderPendingList(c, db, prefix, waiters)
	})

	// Rules HTMX
	htmx.GET("/rules-list", func(c *gin.Context) {
		renderRulesList(c, db, prefix)
	})

	htmx.POST("/rules", func(c *gin.Context) {
		portPattern := c.DefaultPostForm("port_pattern", "*")
		ruleType := c.DefaultPostForm("rule_type", "permanent")
		action := c.DefaultPostForm("action", "allow")
		notes := c.PostForm("notes")

		var expiresIn *int64
		if ruleType == "temporary" {
			v := int64(86400)
			expiresIn = &v
		}
		var notesPtr *string
		if notes != "" {
			notesPtr = &notes
		}

		_, err := greyproxy.CreateRule(db, greyproxy.RuleCreateInput{
			ContainerPattern:   c.PostForm("container_pattern"),
			DestinationPattern: c.PostForm("destination_pattern"),
			PortPattern:        portPattern,
			RuleType:           ruleType,
			Action:             action,
			ExpiresInSeconds:   expiresIn,
			Notes:              notesPtr,
		})
		if err != nil {
			c.String(http.StatusInternalServerError, "Error: %v", err)
			return
		}

		renderRulesList(c, db, prefix)
	})

	htmx.PUT("/rules/:id", func(c *gin.Context) {
		id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
		cp := c.PostForm("container_pattern")
		dp := c.PostForm("destination_pattern")
		pp := c.PostForm("port_pattern")
		action := c.PostForm("action")
		notes := c.PostForm("notes")

		input := greyproxy.RuleUpdateInput{}
		if cp != "" {
			input.ContainerPattern = &cp
		}
		if dp != "" {
			input.DestinationPattern = &dp
		}
		if pp != "" {
			input.PortPattern = &pp
		}
		if action != "" {
			input.Action = &action
		}
		if notes != "" {
			input.Notes = &notes
		}

		rule, _ := greyproxy.UpdateRule(db, id, input)
		if rule != nil && rule.Action == "deny" && connTracker != nil {
			connTracker.CancelByRule(id)
		}
		renderRulesList(c, db, prefix)
	})

	htmx.DELETE("/rules/:id", func(c *gin.Context) {
		id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
		slog.Info("htmx: deleting rule", "rule_id", id)
		deleted, _ := greyproxy.DeleteRule(db, id)
		slog.Info("htmx: rule deleted, cancelling connections", "rule_id", id, "deleted", deleted)
		if deleted && connTracker != nil {
			connTracker.CancelByRule(id)
		}
		c.Status(http.StatusOK)
	})

	// Logs HTMX
	htmx.GET("/logs-table", func(c *gin.Context) {
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
		offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

		if page, err := strconv.Atoi(c.Query("page")); err == nil && page > 1 {
			offset = (page - 1) * limit
		}

		container := c.Query("container")
		destination := c.Query("destination")
		result := c.Query("result")
		fromDateStr := c.Query("from_date")
		toDateStr := c.Query("to_date")

		f := greyproxy.LogFilter{
			Container:   container,
			Destination: destination,
			Result:      result,
			Limit:       limit,
			Offset:      offset,
		}

		if fromDateStr != "" {
			if t, err := time.Parse("2006-01-02T15:04", fromDateStr); err == nil {
				f.FromDate = &t
			}
		}
		if toDateStr != "" {
			if t, err := time.Parse("2006-01-02T15:04", toDateStr); err == nil {
				f.ToDate = &t
			}
		}

		items, total, err := greyproxy.QueryLogs(db, f)
		if err != nil {
			c.String(http.StatusInternalServerError, "Error: %v", err)
			return
		}

		page := 1
		if limit > 0 && offset > 0 {
			page = offset/limit + 1
		}
		pages := 1
		if limit > 0 && total > 0 {
			pages = int(math.Ceil(float64(total) / float64(limit)))
		}

		hasFilters := container != "" || destination != "" || result != "" || fromDateStr != "" || toDateStr != ""

		c.Writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		logsTableTmpl.Execute(c.Writer, gin.H{
			"Prefix":     prefix,
			"Items":      items,
			"Total":      total,
			"Page":       page,
			"Pages":      pages,
			"HasFilters": hasFilters,
		})
	})

	htmx.GET("/traffic-table", func(c *gin.Context) {
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
		offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

		if page, err := strconv.Atoi(c.Query("page")); err == nil && page > 1 {
			offset = (page - 1) * limit
		}

		container := c.Query("container")
		destination := c.Query("destination")
		method := c.Query("method")
		sessionID := c.Query("session_id")

		f := greyproxy.TransactionFilter{
			Container:   container,
			Destination: destination,
			Method:      method,
			SessionID:   sessionID,
			Limit:       limit,
			Offset:      offset,
		}

		items, total, err := greyproxy.QueryHttpTransactions(db, f)
		if err != nil {
			c.String(http.StatusInternalServerError, "Error: %v", err)
			return
		}

		page := 1
		if limit > 0 && offset > 0 {
			page = offset/limit + 1
		}
		pages := 1
		if limit > 0 && total > 0 {
			pages = int(math.Ceil(float64(total) / float64(limit)))
		}

		hasFilters := container != "" || destination != "" || method != ""

		c.Writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		trafficTableTmpl.Execute(c.Writer, gin.H{
			"Prefix":     prefix,
			"Items":      items,
			"Total":      total,
			"Page":       page,
			"Pages":      pages,
			"HasFilters": hasFilters,
		})
	})

	// Activity HTMX route (unified logs + traffic)
	htmx.GET("/activity-table", func(c *gin.Context) {
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
		offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

		if page, err := strconv.Atoi(c.Query("page")); err == nil && page > 1 {
			offset = (page - 1) * limit
		}

		container := c.Query("container")
		destination := c.Query("destination")
		kind := c.Query("kind")
		result := c.Query("result")

		f := greyproxy.ActivityFilter{
			Container:   container,
			Destination: destination,
			Kind:        kind,
			Result:      result,
			Limit:       limit,
			Offset:      offset,
		}

		items, total, err := greyproxy.QueryActivity(db, f)
		if err != nil {
			c.String(http.StatusInternalServerError, "Error: %v", err)
			return
		}

		page := 1
		if limit > 0 && offset > 0 {
			page = offset/limit + 1
		}
		pages := 1
		if limit > 0 && total > 0 {
			pages = int(math.Ceil(float64(total) / float64(limit)))
		}

		hasFilters := container != "" || destination != "" || kind != "" || result != ""

		c.Writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		activityTableTmpl.Execute(c.Writer, gin.H{
			"Prefix":     prefix,
			"Items":      items,
			"Total":      total,
			"Page":       page,
			"Pages":      pages,
			"HasFilters": hasFilters,
		})
	})

	// Conversation HTMX routes
	htmx.GET("/conversation-list", func(c *gin.Context) {
		container := c.Query("container")
		f := greyproxy.ConversationFilter{
			Container: container,
			Limit:     50,
		}
		convs, total, err := greyproxy.QueryConversations(db, f)
		if err != nil {
			c.String(http.StatusInternalServerError, "Error: %v", err)
			return
		}
		var items []greyproxy.ConversationJSON
		for _, conv := range convs {
			items = append(items, conv.ToJSON(false))
		}
		c.Writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		convListTmpl.Execute(c.Writer, gin.H{
			"Prefix": prefix,
			"Items":  items,
			"Total":  total,
		})
	})

	htmx.GET("/conversation-detail", func(c *gin.Context) {
		id := c.Query("id")
		if id == "" {
			c.String(http.StatusBadRequest, "Missing id")
			return
		}
		conv, err := greyproxy.GetConversation(db, id)
		if err != nil {
			c.String(http.StatusInternalServerError, "Error: %v", err)
			return
		}

		var convJSON *greyproxy.ConversationJSON
		var subagents []greyproxy.ConversationJSON
		var txnIDs []int64
		if conv != nil {
			j := conv.ToJSON(true)
			convJSON = &j

			// Load subagents
			subs, _ := greyproxy.GetSubagents(db, id)
			for _, s := range subs {
				subagents = append(subagents, s.ToJSON(false))
			}

			// Get transaction IDs
			txnIDs, _ = greyproxy.GetTransactionsByConversationID(db, id)
		}

		c.Writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		c.Writer.Header().Set("Cache-Control", "no-store")
		convDetailTmpl.Execute(c.Writer, gin.H{
			"Prefix":    prefix,
			"Conv":      convJSON,
			"Subagents": subagents,
			"TxnIDs":    txnIDs,
		})
	})
}

func enrichWaitingCounts(items []greyproxy.PendingRequest, waiters *greyproxy.WaiterTracker) {
	if waiters == nil {
		return
	}
	for i := range items {
		items[i].WaitingCount = waiters.Get(items[i].ContainerName, items[i].DestinationHost, items[i].DestinationPort)
	}
}

func renderPendingList(c *gin.Context, db *greyproxy.DB, prefix string, waiters *greyproxy.WaiterTracker) {
	container := c.Query("container")
	destination := c.Query("destination")

	items, total, _ := greyproxy.GetPendingRequests(db, greyproxy.PendingFilter{
		Container:   container,
		Destination: destination,
		Limit:       100,
	})

	enrichWaitingCounts(items, waiters)

	hasFilters := container != "" || destination != ""

	c.Writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	pendingListTmpl.Execute(c.Writer, gin.H{
		"Prefix":     prefix,
		"Items":      items,
		"Total":      total,
		"HasFilters": hasFilters,
	})
}

func renderRulesList(c *gin.Context, db *greyproxy.DB, prefix string) {
	container := c.Query("container")
	destination := c.Query("destination")
	action := c.Query("action")
	includeExpired := c.Query("include_expired") == "true"

	items, total, _ := greyproxy.GetRules(db, greyproxy.RuleFilter{
		Container:      container,
		Destination:    destination,
		Action:         action,
		IncludeExpired: includeExpired,
		Limit:          100,
	})

	hasFilters := container != "" || destination != "" || action != "" || includeExpired

	c.Writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	rulesListTmpl.Execute(c.Writer, gin.H{
		"Prefix":     prefix,
		"Items":      items,
		"Total":      total,
		"HasFilters": hasFilters,
	})
}
