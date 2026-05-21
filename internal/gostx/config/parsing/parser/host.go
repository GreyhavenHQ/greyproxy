package parser

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/greyhavenhq/greyproxy/internal/gostx/config"
)

// DefaultHost is the address greyproxy binds to when no host is specified
// in the config or on the command line. Loopback is the safe default — see
// SECURITY.md for the rationale.
const DefaultHost = "127.0.0.1"

// ParseHostFlag validates the value of the --host CLI flag and the top-level
// `host:` YAML field. It accepts IP literals only (IPv4 or IPv6); hostnames
// are rejected so that operators don't have to wonder which resolved address
// the listener picked.
func ParseHostFlag(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	if net.ParseIP(s) == nil {
		return "", fmt.Errorf("host requires a literal IP address, got %q", s)
	}
	return s, nil
}

// applyDefaultHost prepends host to addr when addr is a bare port form like
// ":43080" or "43080". Addresses that already carry a host part (explicit
// 0.0.0.0, 127.0.0.1, a LAN IP, [::]/[::1], etc.) are returned unchanged so
// operator overrides win. Non-TCP URI forms ("unix://...") and the empty
// string are also returned unchanged.
func applyDefaultHost(addr, host string) string {
	if addr == "" {
		return ""
	}
	if strings.Contains(addr, "://") {
		return addr
	}
	h, port, err := net.SplitHostPort(addr)
	if err != nil {
		if _, perr := strconv.Atoi(addr); perr == nil {
			return net.JoinHostPort(host, addr)
		}
		return addr
	}
	if h != "" {
		return addr
	}
	return net.JoinHostPort(host, port)
}

// walkAddresses applies applyDefaultHost to every listener address in cfg:
// each service, the metrics endpoint, and the pprof endpoint. The greyproxy
// dashboard address lives under the `greyproxy:` viper subtree and is
// normalized separately in cmd/greyproxy/program.go.
func walkAddresses(cfg *config.Config, host string) {
	if cfg == nil {
		return
	}
	for _, svc := range cfg.Services {
		if svc == nil {
			continue
		}
		svc.Addr = applyDefaultHost(svc.Addr, host)
	}
	if cfg.Metrics != nil {
		cfg.Metrics.Addr = applyDefaultHost(cfg.Metrics.Addr, host)
	}
	if cfg.Profiling != nil {
		cfg.Profiling.Addr = applyDefaultHost(cfg.Profiling.Addr, host)
	}
}

// IsUnspecifiedBind returns true when addr binds to all interfaces
// (0.0.0.0 / ::), so callers can warn the operator at startup.
func IsUnspecifiedBind(addr string) bool {
	if addr == "" {
		return false
	}
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsUnspecified()
}
