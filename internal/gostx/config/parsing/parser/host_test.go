package parser

import (
	"net"
	"testing"

	"github.com/greyhavenhq/greyproxy/internal/gostx/config"
)

// TestNetListenWithDefault verifies the OS actually treats the normalized
// address as loopback-only on the test platform. Runs on every supported
// OS in CI (linux, darwin) and guards against the normalization output
// being syntactically right but semantically wrong (e.g. a typo that
// makes net.Listen bind everywhere).
func TestNetListenWithDefault(t *testing.T) {
	addr := ApplyDefaultHost(":0", DefaultHost)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("net.Listen(%q): %v", addr, err)
	}
	defer ln.Close()

	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener addr %T not *net.TCPAddr", ln.Addr())
	}
	if !tcpAddr.IP.IsLoopback() {
		t.Errorf("listener IP %v is not loopback", tcpAddr.IP)
	}
}

// TestNetListenWithUnspecified verifies --host 0.0.0.0 actually produces
// an unspecified bind so the WARN log corresponds to reality.
func TestNetListenWithUnspecified(t *testing.T) {
	addr := ApplyDefaultHost(":0", "0.0.0.0")
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("net.Listen(%q): %v", addr, err)
	}
	defer ln.Close()

	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener addr %T not *net.TCPAddr", ln.Addr())
	}
	if !tcpAddr.IP.IsUnspecified() {
		t.Errorf("listener IP %v is not unspecified", tcpAddr.IP)
	}
}

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
			got := ApplyDefaultHost(tc.addr, tc.host)
			if got != tc.want {
				t.Errorf("ApplyDefaultHost(%q, %q) = %q, want %q", tc.addr, tc.host, got, tc.want)
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

// TestParseAppliesDefaultHost walks a full YAML config through Parse() to
// confirm bare ":PORT" addrs get rewritten end-to-end. This catches wiring
// regressions that the standalone walkAddresses test wouldn't.
func TestParseAppliesDefaultHost(t *testing.T) {
	yaml := []byte(`
host: 127.0.0.1
services:
  - name: http-proxy
    addr: ":43051"
  - name: explicit
    addr: "0.0.0.0:43052"
metrics:
  addr: ":9100"
profiling:
  addr: ":6060"
`)

	Init(Args{DefaultConfig: yaml})
	cfg, err := Parse()
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	want := map[string]string{
		"http-proxy": "127.0.0.1:43051",
		"explicit":   "0.0.0.0:43052",
	}
	for _, svc := range cfg.Services {
		if got := want[svc.Name]; got != svc.Addr {
			t.Errorf("service %q: addr = %q, want %q", svc.Name, svc.Addr, got)
		}
	}
	if cfg.Metrics.Addr != "127.0.0.1:9100" {
		t.Errorf("metrics addr = %q, want 127.0.0.1:9100", cfg.Metrics.Addr)
	}
	if cfg.Profiling.Addr != "127.0.0.1:6060" {
		t.Errorf("profiling addr = %q, want 127.0.0.1:6060", cfg.Profiling.Addr)
	}
}

// TestParseFlagOverridesYAMLHost confirms CLI --host wins over the YAML field.
func TestParseFlagOverridesYAMLHost(t *testing.T) {
	yaml := []byte(`
host: 127.0.0.1
services:
  - name: http-proxy
    addr: ":43051"
`)

	Init(Args{DefaultConfig: yaml, Host: "0.0.0.0"})
	cfg, err := Parse()
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Services[0].Addr != "0.0.0.0:43051" {
		t.Errorf("flag override: got %q, want 0.0.0.0:43051", cfg.Services[0].Addr)
	}
}

// TestParseDefaultsToLoopback confirms the built-in default when neither
// the flag nor the YAML field set a host.
func TestParseDefaultsToLoopback(t *testing.T) {
	yaml := []byte(`
services:
  - name: http-proxy
    addr: ":43051"
`)

	Init(Args{DefaultConfig: yaml})
	cfg, err := Parse()
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Services[0].Addr != "127.0.0.1:43051" {
		t.Errorf("default: got %q, want 127.0.0.1:43051", cfg.Services[0].Addr)
	}
}

func TestDashboardHost(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want string
	}{
		{"loopback ipv4", "127.0.0.1:43080", "localhost"},
		{"unnamed bare port", ":43080", "localhost"},
		{"unspecified ipv4", "0.0.0.0:43080", "localhost"},
		{"unspecified ipv6", "[::]:43080", "localhost"},
		{"loopback ipv6", "[::1]:43080", "localhost"},
		{"explicit lan ipv4", "100.64.0.1:43080", "100.64.0.1"},
		{"explicit lan ipv6 bracketed", "[2001:db8::1]:43080", "[2001:db8::1]"},
		{"empty addr", "", "localhost"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := DashboardHost(tc.addr); got != tc.want {
				t.Errorf("DashboardHost(%q) = %q, want %q", tc.addr, got, tc.want)
			}
		})
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
