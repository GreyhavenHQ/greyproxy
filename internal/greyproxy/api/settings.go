package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
)

type settingsResponse struct {
	Theme         string                   `json:"theme"`
	Notifications notificationSettingsResp `json:"notifications"`
}

type notificationSettingsResp struct {
	Enabled     bool   `json:"enabled"`
	Available   bool   `json:"available"`
	Backend     string `json:"backend"`
	InstallHint string `json:"installHint,omitempty"`
}

func buildSettingsResponse(s *Shared) settingsResponse {
	resolved := s.Settings.Get()

	var info greyproxy.NotificationBackendInfo
	if s.Notifier != nil {
		info = s.Notifier.BackendInfo()
	}

	return settingsResponse{
		Theme: resolved.Theme,
		Notifications: notificationSettingsResp{
			Enabled:     resolved.NotificationsEnabled,
			Available:   info.Available,
			Backend:     info.Backend,
			InstallHint: info.InstallHint,
		},
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

		if _, err := s.Settings.Update(patch); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, buildSettingsResponse(s))
	}
}
