package greyproxy

import "testing"

func TestParseVersion(t *testing.T) {
	tests := []struct {
		input     string
		wantMajor int
		wantMinor int
	}{
		{"0.7.9", 0, 7},
		{"0.8.3", 0, 8},
		{"0.8.6", 0, 8},
		{"0.8.8", 0, 8},
		{"1.0.0", 1, 0},
		{"0.8", 0, 8},
		{"2", 2, 0},
		{"", 0, 0},
		{"abc", 0, 0},
	}

	for _, tt := range tests {
		major, minor := parseVersion(tt.input)
		if major != tt.wantMajor || minor != tt.wantMinor {
			t.Errorf("parseVersion(%q) = (%d, %d), want (%d, %d)",
				tt.input, major, minor, tt.wantMajor, tt.wantMinor)
		}
	}
}

func TestDetectNotifySendCaps(t *testing.T) {
	// detectNotifySendCaps calls the real notify-send binary, so we
	// can only run a meaningful assertion when it is installed. When
	// it is not installed the function returns the zero-value caps,
	// which is still a valid (and safe) result.
	caps := detectNotifySendCaps()

	// wait and actions are always set together.
	if caps.wait != caps.actions {
		t.Errorf("expected wait and actions to match, got wait=%v actions=%v",
			caps.wait, caps.actions)
	}
}

// TestNotifySendCapsFromVersion verifies the version-to-capability logic
// by exercising parseVersion against the thresholds used in detectNotifySendCaps.
func TestNotifySendCapsFromVersion(t *testing.T) {
	tests := []struct {
		version     string
		wantAdvanced bool
	}{
		{"0.7.9", false},
		{"0.7.0", false},
		{"0.6.1", false},
		{"0.8.0", true},
		{"0.8.3", true},
		{"0.8.6", true},
		{"0.8.8", true},
		{"1.0.0", true},
		{"2.1.3", true},
	}

	for _, tt := range tests {
		major, minor := parseVersion(tt.version)
		advanced := major > 0 || (major == 0 && minor >= 8)
		if advanced != tt.wantAdvanced {
			t.Errorf("version %q: advanced=%v, want %v", tt.version, advanced, tt.wantAdvanced)
		}
	}
}
