package greyproxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// UserSettings stores user-overridden settings. Only non-nil fields
// have been explicitly set by the user and will be persisted to disk.
type UserSettings struct {
	Theme                *string `json:"theme,omitempty"`
	NotificationsEnabled *bool   `json:"notificationsEnabled,omitempty"`
	MitmEnabled          *bool   `json:"mitmEnabled,omitempty"`
}

// ResolvedSettings is the fully resolved settings with defaults applied.
type ResolvedSettings struct {
	Theme                string `json:"theme"`
	NotificationsEnabled bool   `json:"notificationsEnabled"`
	MitmEnabled          bool   `json:"mitmEnabled"`
}

// SettingsManager handles loading and saving user settings, merging
// with defaults. The settings file is only created when the user
// explicitly changes a setting.
type SettingsManager struct {
	path string
	mu   sync.RWMutex
	user UserSettings

	defaultNotificationsEnabled bool

	onNotificationsChanged func(bool)
	onMitmChanged          func(bool)
}

func NewSettingsManager(path string, defaultNotificationsEnabled bool) *SettingsManager {
	return &SettingsManager{
		path:                        path,
		defaultNotificationsEnabled: defaultNotificationsEnabled,
	}
}

// OnNotificationsChanged sets a callback invoked when the notifications
// enabled state changes.
func (m *SettingsManager) OnNotificationsChanged(fn func(bool)) {
	m.onNotificationsChanged = fn
}

// OnMitmChanged sets a callback invoked when the MITM enabled state changes.
func (m *SettingsManager) OnMitmChanged(fn func(bool)) {
	m.onMitmChanged = fn
}

// Load reads user settings from disk. If the file doesn't exist,
// defaults are used (no error).
func (m *SettingsManager) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(m.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	return json.Unmarshal(data, &m.user)
}

// Get returns the fully resolved settings (defaults + user overrides).
func (m *SettingsManager) Get() ResolvedSettings {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.resolve()
}

func (m *SettingsManager) resolve() ResolvedSettings {
	s := ResolvedSettings{
		Theme:                "system",
		NotificationsEnabled: m.defaultNotificationsEnabled,
		MitmEnabled:          true, // MITM enabled by default
	}
	if m.user.Theme != nil {
		s.Theme = *m.user.Theme
	}
	if m.user.NotificationsEnabled != nil {
		s.NotificationsEnabled = *m.user.NotificationsEnabled
	}
	if m.user.MitmEnabled != nil {
		s.MitmEnabled = *m.user.MitmEnabled
	}
	return s
}

// Update applies a partial settings update. Only non-nil fields in
// the patch are applied. Returns the resolved settings after the update.
func (m *SettingsManager) Update(patch UserSettings) (ResolvedSettings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if patch.Theme != nil {
		m.user.Theme = patch.Theme
	}

	var notifChanged bool
	if patch.NotificationsEnabled != nil {
		old := m.resolve().NotificationsEnabled
		m.user.NotificationsEnabled = patch.NotificationsEnabled
		notifChanged = old != *patch.NotificationsEnabled
	}

	var mitmChanged bool
	if patch.MitmEnabled != nil {
		old := m.resolve().MitmEnabled
		m.user.MitmEnabled = patch.MitmEnabled
		mitmChanged = old != *patch.MitmEnabled
	}

	if err := m.save(); err != nil {
		return ResolvedSettings{}, err
	}

	resolved := m.resolve()

	if notifChanged && m.onNotificationsChanged != nil {
		m.onNotificationsChanged(resolved.NotificationsEnabled)
	}
	if mitmChanged && m.onMitmChanged != nil {
		m.onMitmChanged(resolved.MitmEnabled)
	}

	return resolved, nil
}

func (m *SettingsManager) save() error {
	if m.user.Theme == nil && m.user.NotificationsEnabled == nil && m.user.MitmEnabled == nil {
		return nil
	}

	if dir := filepath.Dir(m.path); dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}

	data, err := json.MarshalIndent(m.user, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(m.path, data, 0o644)
}
