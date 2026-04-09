package main

import (
	"net"

	"golang.org/x/sys/windows/registry"
)

// windowsDNSServers reads DNS servers from the Windows registry.
// It checks both per-interface and global TCP/IP parameters.
func windowsDNSServers() []string {
	const tcpipKey = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`
	const interfacesKey = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`

	var servers []string

	// Per-interface DNS servers (preferred; these are the ones actually in use).
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, interfacesKey, registry.READ)
	if err == nil {
		defer k.Close()
		subkeys, _ := k.ReadSubKeyNames(-1)
		for _, sub := range subkeys {
			ik, err := registry.OpenKey(k, sub, registry.READ)
			if err != nil {
				continue
			}
			for _, valueName := range []string{"NameServer", "DhcpNameServer"} {
				val, _, err := ik.GetStringValue(valueName)
				if err != nil || val == "" {
					continue
				}
				for _, addr := range splitDNSList(val) {
					if ip := net.ParseIP(addr); ip != nil {
						servers = append(servers, net.JoinHostPort(addr, "53"))
					}
				}
			}
			ik.Close()
		}
	}

	if len(servers) > 0 {
		return servers
	}

	// Global fallback.
	gk, err := registry.OpenKey(registry.LOCAL_MACHINE, tcpipKey, registry.READ)
	if err != nil {
		return nil
	}
	defer gk.Close()
	for _, valueName := range []string{"NameServer", "DhcpNameServer"} {
		val, _, err := gk.GetStringValue(valueName)
		if err != nil || val == "" {
			continue
		}
		for _, addr := range splitDNSList(val) {
			if ip := net.ParseIP(addr); ip != nil {
				servers = append(servers, net.JoinHostPort(addr, "53"))
			}
		}
	}
	return servers
}

// splitDNSList splits a Windows DNS server string which may use spaces or commas.
func splitDNSList(s string) []string {
	// Windows stores servers as space- or comma-separated.
	var parts []string
	for _, part := range splitAny(s, " ,") {
		if part != "" {
			parts = append(parts, part)
		}
	}
	return parts
}

func splitAny(s, sep string) []string {
	// Replace all separators with a single one, then split.
	result := make([]string, 0)
	current := ""
	for _, c := range s {
		if containsRune(sep, c) {
			if current != "" {
				result = append(result, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}
