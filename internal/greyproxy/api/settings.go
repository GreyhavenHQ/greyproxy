package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
)

type settingsResponse struct {
	Theme           string                        `json:"theme"`
	Notifications   notificationSettingsResp      `json:"notifications"`
	Mitm            mitmSettingsResp              `json:"mitm"`
	Conversations   conversationsSettingsResp     `json:"conversations"`
	RedactedHeaders []string                      `json:"redactedHeaders"`
}

type conversationsSettingsResp struct {
	Enabled bool `json:"enabled"`
}

type mitmSettingsResp struct {
	Enabled       bool   `json:"enabled"`
	CertGenerated bool   `json:"certGenerated"`
	CertExpiry    string `json:"certExpiry,omitempty"`
	CertPath      string `json:"certPath"`
	Installed     bool   `json:"installed"`
}

type notificationSettingsResp struct {
	Enabled         bool   `json:"enabled"`
	Available       bool   `json:"available"`
	Backend         string `json:"backend"`
	InstallHint     string `json:"installHint,omitempty"`
	SupportsActions bool   `json:"supportsActions"`
}

func buildSettingsResponse(s *Shared) settingsResponse {
	resolved := s.Settings.Get()

	var info greyproxy.NotificationBackendInfo
	if s.Notifier != nil {
		info = s.Notifier.BackendInfo()
	}

	certStatus := buildCertStatus(s.DataHome)
	mitm := mitmSettingsResp{
		Enabled:       resolved.MitmEnabled,
		CertGenerated: certStatus.Generated,
		CertPath:      certStatus.CertPath,
		Installed:     certStatus.Installed,
	}
	if certStatus.ExpiresAt != nil {
		mitm.CertExpiry = certStatus.ExpiresAt.Format("2006-01-02")
	}

	return settingsResponse{
		Theme:           resolved.Theme,
		RedactedHeaders: resolved.RedactedHeaders,
		Conversations:   conversationsSettingsResp{Enabled: resolved.ConversationsEnabled},
		Notifications: notificationSettingsResp{
			Enabled:         resolved.NotificationsEnabled,
			Available:       info.Available,
			Backend:         info.Backend,
			InstallHint:     info.InstallHint,
			SupportsActions: info.SupportsActions,
		},
		Mitm: mitm,
	}
}

func SettingsGetHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, buildSettingsResponse(s))
	}
}

func SettingsUpdateHandler(s *Shared) gin.HandlerFunc {
	return func(c *gin.Context) {
		var body struct {
			Theme         *string `json:"theme"`
			Notifications *struct {
				Enabled *bool `json:"enabled"`
			} `json:"notifications"`
			Mitm *struct {
				Enabled *bool `json:"enabled"`
			} `json:"mitm"`
			Conversations *struct {
				Enabled *bool `json:"enabled"`
			} `json:"conversations"`
			RedactedHeaders []string `json:"redactedHeaders"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		patch := greyproxy.UserSettings{}
		if body.Theme != nil {
			t := *body.Theme
			if t != "system" && t != "light" && t != "dark" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "theme must be system, light, or dark"})
				return
			}
			patch.Theme = &t
		}
		if body.Notifications != nil && body.Notifications.Enabled != nil {
			patch.NotificationsEnabled = body.Notifications.Enabled
		}
		if body.Mitm != nil && body.Mitm.Enabled != nil {
			patch.MitmEnabled = body.Mitm.Enabled
		}
		if body.Conversations != nil && body.Conversations.Enabled != nil {
			patch.ConversationsEnabled = body.Conversations.Enabled
		}
		if body.RedactedHeaders != nil {
			patch.RedactedHeaders = body.RedactedHeaders
		}

		if _, err := s.Settings.Update(patch); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, buildSettingsResponse(s))
	}
}
