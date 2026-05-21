package parser

import (
	"testing"

	"github.com/greyhavenhq/greyproxy/internal/gostx/config"
)

func TestApplyDefaultHost(t *testing.T) {
	tests := []struct {
		name string
		addr string
		host string
		want string
	}{
		{"bare colon port", ":43080", "127.0.0.1", "127.0.0.1:43080"},
		{"bare numeric", "43080", "127.0.0.1", "127.0.0.1:43080"},
		{"explicit ipv4 unspecified", "0.0.0.0:43080", "127.0.0.1", "0.0.0.0:43080"},
		{"explicit ipv4 loopback", "127.0.0.1:43080", "127.0.0.1", "127.0.0.1:43080"},
		{"explicit ipv4 lan", "192.168.1.5:43080", "127.0.0.1", "192.168.1.5:43080"},
		{"explicit ipv6 unspecified", "[::]:43080", "127.0.0.1", "[::]:43080"},
		{"explicit ipv6 loopback", "[::1]:43080", "127.0.0.1", "[::1]:43080"},
		{"unix socket left alone", "unix:///tmp/foo.sock", "127.0.0.1", "unix:///tmp/foo.sock"},
		{"empty left alone", "", "127.0.0.1", ""},
		{"host overrides to unspecified", ":43080", "0.0.0.0", "0.0.0.0:43080"},
		{"ipv6 host with brackets", ":43080", "::1", "[::1]:43080"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := applyDefaultHost(tc.addr, tc.host)
			if got != tc.want {
				t.Errorf("applyDefaultHost(%q, %q) = %q, want %q", tc.addr, tc.host, got, tc.want)
			}
		})
	}
}

func TestWalkAddresses(t *testing.T) {
	cfg := &config.Config{
		Services: []*config.ServiceConfig{
			{Name: "bare", Addr: ":43051"},
			{Name: "explicit", Addr: "0.0.0.0:43052"},
			{Name: "lan", Addr: "192.168.1.5:43053"},
		},
		Metrics:   &config.MetricsConfig{Addr: ":9100"},
		Profiling: &config.ProfilingConfig{Addr: ":6060"},
	}
	walkAddresses(cfg, "127.0.0.1")

	if cfg.Services[0].Addr != "127.0.0.1:43051" {
		t.Errorf("bare service: got %q", cfg.Services[0].Addr)
	}
	if cfg.Services[1].Addr != "0.0.0.0:43052" {
		t.Errorf("explicit service rewritten: got %q", cfg.Services[1].Addr)
	}
	if cfg.Services[2].Addr != "192.168.1.5:43053" {
		t.Errorf("lan service rewritten: got %q", cfg.Services[2].Addr)
	}
	if cfg.Metrics.Addr != "127.0.0.1:9100" {
		t.Errorf("metrics: got %q", cfg.Metrics.Addr)
	}
	if cfg.Profiling.Addr != "127.0.0.1:6060" {
		t.Errorf("profiling: got %q", cfg.Profiling.Addr)
	}
}

func TestWalkAddressesNilSections(t *testing.T) {
	cfg := &config.Config{}
	walkAddresses(cfg, "127.0.0.1")
	if cfg.Metrics != nil || cfg.Profiling != nil {
		t.Errorf("walkAddresses should not create empty Metrics/Profiling sections")
	}
}

func TestParseHostFlag(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"empty allowed", "", "", false},
		{"ipv4 loopback", "127.0.0.1", "127.0.0.1", false},
		{"ipv4 unspecified", "0.0.0.0", "0.0.0.0", false},
		{"ipv4 lan", "192.168.1.10", "192.168.1.10", false},
		{"ipv6 loopback", "::1", "::1", false},
		{"ipv6 unspecified", "::", "::", false},
		{"hostname rejected", "my-laptop.local", "", true},
		{"garbage rejected", "not-an-ip", "", true},
		{"host:port rejected", "127.0.0.1:43080", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseHostFlag(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("ParseHostFlag(%q): expected error, got nil", tc.input)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseHostFlag(%q): unexpected error %v", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("ParseHostFlag(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
