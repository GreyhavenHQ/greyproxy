package plugins

import (
	"testing"
)

func TestParseClientID(t *testing.T) {
	tests := []struct {
		name     string
		clientID string
		wantIP   string
		wantUser string
	}{
		{"ip|user", "192.168.1.1|john", "192.168.1.1", "john"},
		{"ip only", "192.168.1.1", "192.168.1.1", ""},
		{"ip|empty user", "192.168.1.1|", "192.168.1.1", ""},
		{"empty", "", "", ""},
		{"pipe in user", "192.168.1.1|user|extra", "192.168.1.1", "user|extra"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, user := ParseClientID(tt.clientID)
			if ip != tt.wantIP {
				t.Errorf("ip: got %q, want %q", ip, tt.wantIP)
			}
			if user != tt.wantUser {
				t.Errorf("user: got %q, want %q", user, tt.wantUser)
			}
		})
	}
}

func TestResolveIdentity(t *testing.T) {
	tests := []struct {
		name          string
		clientID      string
		wantContainer string
	}{
		{"user with ip", "192.168.1.1|john", "john"},
		{"proxy user defaults to unknown", "192.168.1.1|proxy", "unknown-192.168.1.1"},
		{"no user defaults to unknown", "192.168.1.1", "unknown-192.168.1.1"},
		{"empty client id", "", "unknown-"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			container, _ := ResolveIdentity(tt.clientID)
			if container != tt.wantContainer {
				t.Errorf("got %q, want %q", container, tt.wantContainer)
			}
		})
	}
}
