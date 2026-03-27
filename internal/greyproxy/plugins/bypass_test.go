package plugins

import (
	"testing"
)

type mockDockerResolver struct {
	names map[string]string
	ids   map[string]string
}

func (m *mockDockerResolver) ResolveIP(ip string) (string, string) {
	return m.names[ip], m.ids[ip]
}

// TestResolveIdentityWithDocker verifies that resolveIdentity behaves correctly
// even when a Docker resolver is wired in. Docker resolution happens upstream in
// Contains(), not inside resolveIdentity(), so the expected values here are the
// pure IP/username fallback results.
func TestResolveIdentityWithDocker(t *testing.T) {
	mockResolver := &mockDockerResolver{
		names: map[string]string{"172.17.0.2": "my-container"},
		ids:   map[string]string{"172.17.0.2": "abc123456789"},
	}

	b := &Bypass{docker: mockResolver}

	tests := []struct {
		name          string
		clientID      string
		wantContainer string
		wantID        string
	}{
		{
			// No username → falls back to "unknown-<ip>"; Docker resolver is NOT called here.
			name:          "IP only falls back to unknown",
			clientID:      "172.17.0.2",
			wantContainer: "unknown-172.17.0.2",
			wantID:        "",
		},
		{
			// Username present → returns username regardless of Docker.
			name:          "IP with user returns username",
			clientID:      "172.17.0.2|alice",
			wantContainer: "alice",
			wantID:        "",
		},
		{
			name:          "Unknown IP",
			clientID:      "192.168.1.1",
			wantContainer: "unknown-192.168.1.1",
			wantID:        "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotContainer, gotID := b.resolveIdentity(tt.clientID)
			if gotContainer != tt.wantContainer {
				t.Errorf("container: got %q, want %q", gotContainer, tt.wantContainer)
			}
			if gotID != tt.wantID {
				t.Errorf("id: got %q, want %q", gotID, tt.wantID)
			}
		})
	}
}

func TestResolveIdentityNoDocker(t *testing.T) {
	b := &Bypass{}

	tests := []struct {
		name          string
		clientID      string
		wantContainer string
		wantID        string
	}{
		{
			name:          "IP",
			clientID:      "192.168.1.1",
			wantContainer: "unknown-192.168.1.1",
			wantID:        "",
		},
		{
			name:          "User with IP",
			clientID:      "192.168.1.1|alice",
			wantContainer: "alice",
			wantID:        "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotContainer, gotID := b.resolveIdentity(tt.clientID)
			if gotContainer != tt.wantContainer {
				t.Errorf("container: got %q, want %q", gotContainer, tt.wantContainer)
			}
			if gotID != tt.wantID {
				t.Errorf("id: got %q, want %q", gotID, tt.wantID)
			}
		})
	}
}
