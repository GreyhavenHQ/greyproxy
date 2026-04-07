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
	Theme                *string  `json:"theme,omitempty"`
	NotificationsEnabled *bool    `json:"notificationsEnabled,omitempty"`
	MitmEnabled          *bool    `json:"mitmEnabled,omitempty"`
	RedactedHeaders      []string         `json:"redactedHeaders,omitempty"`
	PIIEnabled           *bool            `json:"piiEnabled,omitempty"`
	PIIAction            *string          `json:"piiAction,omitempty"`
	PIITypes             map[string]*bool `json:"piiTypes,omitempty"`
	PIIAllowlist         []string         `json:"piiAllowlist,omitempty"`
}

// ResolvedSettings is the fully resolved settings with defaults applied.
type ResolvedSettings struct {
	Theme                string   `json:"theme"`
	NotificationsEnabled bool     `json:"notificationsEnabled"`
	MitmEnabled          bool     `json:"mitmEnabled"`
	RedactedHeaders      []string        `json:"redactedHeaders"`
	PIIEnabled           bool            `json:"piiEnabled"`
	PIIAction            string          `json:"piiAction"`
	PIITypes             map[string]bool `json:"piiTypes"`
	PIIAllowlist         []string        `json:"piiAllowlist"`
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
	onPIIChanged           func(ResolvedSettings)

	redactor *HeaderRedactor
}

func NewSettingsManager(path string, defaultNotificationsEnabled bool) *SettingsManager {
	m := &SettingsManager{
		path:                        path,
		defaultNotificationsEnabled: defaultNotificationsEnabled,
	}
	m.redactor = NewHeaderRedactor(nil)
	return m
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

// OnPIIChanged sets a callback invoked when PII settings change.
func (m *SettingsManager) OnPIIChanged(fn func(ResolvedSettings)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onPIIChanged = fn
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

	if err := json.Unmarshal(data, &m.user); err != nil {
		return err
	}
	m.rebuildRedactor()
	return nil
}

func (m *SettingsManager) rebuildRedactor() {
	m.redactor = NewHeaderRedactor(m.user.RedactedHeaders)
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
		RedactedHeaders:      DefaultRedactedHeaders,
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
	if m.user.RedactedHeaders != nil {
		s.RedactedHeaders = append(DefaultRedactedHeaders, m.user.RedactedHeaders...)
	}

	s.PIIAction = "redact"
	s.PIITypes = map[string]bool{
		"email":       true,
		"phone":       true,
		"ssn":         true,
		"credit_card": true,
		"ip_address":  true,
	}

	if m.user.PIIEnabled != nil {
		s.PIIEnabled = *m.user.PIIEnabled
	}
	if m.user.PIIAction != nil {
		s.PIIAction = *m.user.PIIAction
	}
	if m.user.PIITypes != nil {
		for k, v := range m.user.PIITypes {
			if v != nil {
				s.PIITypes[k] = *v
			}
		}
	}
	if m.user.PIIAllowlist != nil {
		s.PIIAllowlist = m.user.PIIAllowlist
	}

	return s
}

// HeaderRedactor returns the current header redactor, which includes
// both default and user-configured patterns.
func (m *SettingsManager) HeaderRedactor() *HeaderRedactor {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.redactor
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

	if patch.RedactedHeaders != nil {
		m.user.RedactedHeaders = patch.RedactedHeaders
		m.rebuildRedactor()
	}

	oldResolved := m.resolve()

	if patch.PIIEnabled != nil {
		m.user.PIIEnabled = patch.PIIEnabled
	}
	if patch.PIIAction != nil {
		m.user.PIIAction = patch.PIIAction
	}
	if patch.PIITypes != nil {
		if m.user.PIITypes == nil {
			m.user.PIITypes = make(map[string]*bool)
		}
		for k, v := range patch.PIITypes {
			m.user.PIITypes[k] = v
		}
	}
	if patch.PIIAllowlist != nil {
		m.user.PIIAllowlist = patch.PIIAllowlist
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

	piiChanged := (oldResolved.PIIEnabled != resolved.PIIEnabled ||
		oldResolved.PIIAction != resolved.PIIAction)
	if piiChanged && m.onPIIChanged != nil {
		go m.onPIIChanged(resolved)
	}

	return resolved, nil
}

func (m *SettingsManager) save() error {
	if m.user.Theme == nil && m.user.NotificationsEnabled == nil && m.user.MitmEnabled == nil && m.user.RedactedHeaders == nil &&
		m.user.PIIEnabled == nil && m.user.PIIAction == nil && m.user.PIITypes == nil && m.user.PIIAllowlist == nil {
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
