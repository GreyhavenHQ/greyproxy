//go:build !windows

package main

// windowsDNSServers is a no-op stub on non-Windows platforms.
// The actual implementation lives in sysdns_windows.go.
func windowsDNSServers() []string { return nil }
