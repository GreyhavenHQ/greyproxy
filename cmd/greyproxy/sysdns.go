package main

import (
	"bufio"
	"net"
	"os"
	"runtime"
	"strings"
)

// stubResolvConfPath is the file systemd-resolved writes with its stub
// listener (127.0.0.53) as the only nameserver. We read it when
// /etc/resolv.conf is missing so queries still go through resolved and
// benefit from its DoT/DNSSEC/split-DNS handling.
//
// We deliberately never read /run/systemd/resolve/resolv.conf: that file
// contains the raw upstream nameservers and using it bypasses
// systemd-resolved entirely, breaking DoT-only setups (see issue #47).
const stubResolvConfPath = "/run/systemd/resolve/stub-resolv.conf"

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

// linuxMacDNSServers reads DNS servers from /etc/resolv.conf verbatim.
//
// On systemd-resolved hosts /etc/resolv.conf usually contains only
// "nameserver 127.0.0.53" (the stub listener). We keep that address as-is
// so queries are handled by resolved and go through whatever DoT/DNSSEC/
// split-DNS config the user has set up. Bypassing the stub would drop all
// of that (see issue #47).
//
// If /etc/resolv.conf is missing (rare, but possible on minimal images) we
// fall back to /run/systemd/resolve/stub-resolv.conf, which also points at
// the stub listener and keeps queries flowing through resolved.
func linuxMacDNSServers() []string {
	if servers := resolvConfServers("/etc/resolv.conf"); len(servers) > 0 {
		return servers
	}
	return resolvConfServers(stubResolvConfPath)
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
