package main

import (
	"bufio"
	"net"
	"os"
	"runtime"
	"strings"
)

// systemDNSServers returns the host's configured DNS resolver addresses in
// "host:53" form. Falls back to ["8.8.8.8:53"] when detection fails so the
// DNS proxy always has a working upstream.
func systemDNSServers() []string {
	var servers []string
	if runtime.GOOS == "windows" {
		servers = windowsDNSServers()
	} else {
		servers = linuxMacDNSServers()
	}
	if len(servers) == 0 {
		return []string{"1.1.1.1:53"}
	}
	return servers
}

// linuxMacDNSServers reads DNS servers from /etc/resolv.conf.
//
// systemd-resolved typically sets /etc/resolv.conf to contain only
// "nameserver 127.0.0.53" (its stub listener). That address is reachable on
// the host, but NOT inside containers (127.x.x.x is the container's own
// loopback, not the host's). In that case we fall back to
// /run/systemd/resolve/resolv.conf which systemd-resolved writes with the
// real upstream nameservers.
func linuxMacDNSServers() []string {
	servers := resolvConfServers("/etc/resolv.conf")

	// If every server is the systemd stub (127.0.0.53) try to get the real
	// upstreams. Other loopback resolvers (dnsmasq on 127.0.0.1, etc.) are
	// left alone because they are intentionally local.
	if allSystemdStub(servers) {
		if real := resolvConfServers("/run/systemd/resolve/resolv.conf"); len(real) > 0 {
			return real
		}
	}

	return servers
}

// allSystemdStub reports whether every server address is the systemd-resolved
// stub listener (127.0.0.53). A single non-stub address makes this false.
func allSystemdStub(servers []string) bool {
	if len(servers) == 0 {
		return false
	}
	for _, s := range servers {
		host, _, _ := net.SplitHostPort(s)
		if host != "127.0.0.53" {
			return false
		}
	}
	return true
}

// resolvConfServers parses nameserver lines from a resolv.conf-style file.
func resolvConfServers(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close() //nolint:errcheck // read-only file, close error is not actionable

	var servers []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "nameserver") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		addr := fields[1]
		if net.ParseIP(addr) != nil {
			servers = append(servers, net.JoinHostPort(addr, "53"))
		}
	}
	return servers
}
