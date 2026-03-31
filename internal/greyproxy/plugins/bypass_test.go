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
	// Docker resolution happens upstream in Contains(), not inside ResolveIdentity(),
	// so the mock resolver is not used here — only the pure IP/username fallback is tested.
	_ = &mockDockerResolver{
		names: map[string]string{"172.17.0.2": "my-container"},
		ids:   map[string]string{"172.17.0.2": "abc123456789"},
	}

	tests := []struct {
		name          string
		clientID      string
		srcIP         string
		wantContainer string
		wantID        string
	}{
		{
			// No username → falls back to "unknown-<srcIP>"; Docker resolver is NOT called here.
			name:          "srcIP used when clientID has no username",
			clientID:      "unknown",
			srcIP:         "172.17.0.2",
			wantContainer: "unknown-172.17.0.2",
			wantID:        "",
		},
		{
			// Username present → returns username regardless of Docker.
			name:          "IP with user returns username",
			clientID:      "172.17.0.2|alice",
			srcIP:         "172.17.0.2",
			wantContainer: "alice",
			wantID:        "",
		},
		{
			name:          "srcIP used when clientID is unknown",
			clientID:      "unknown",
			srcIP:         "192.168.1.1",
			wantContainer: "unknown-192.168.1.1",
			wantID:        "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotContainer, gotID := ResolveIdentity(tt.clientID, tt.srcIP)
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
	tests := []struct {
		name          string
		clientID      string
		srcIP         string
		wantContainer string
		wantID        string
	}{
		{
			name:          "srcIP available",
			clientID:      "unknown",
			srcIP:         "192.168.1.1",
			wantContainer: "unknown-192.168.1.1",
			wantID:        "",
		},
		{
			name:          "srcIP empty falls back to clientID",
			clientID:      "192.168.1.1",
			srcIP:         "",
			wantContainer: "unknown-192.168.1.1",
			wantID:        "",
		},
		{
			name:          "username takes priority over srcIP",
			clientID:      "192.168.1.1|alice",
			srcIP:         "192.168.1.1",
			wantContainer: "alice",
			wantID:        "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotContainer, gotID := ResolveIdentity(tt.clientID, tt.srcIP)
			if gotContainer != tt.wantContainer {
				t.Errorf("container: got %q, want %q", gotContainer, tt.wantContainer)
			}
			if gotID != tt.wantID {
				t.Errorf("id: got %q, want %q", gotID, tt.wantID)
			}
		})
	}
}
