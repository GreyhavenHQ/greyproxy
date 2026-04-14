package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeResolvConf(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write temp resolv.conf: %v", err)
	}
	return path
}

func TestResolvConfServers(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []string
	}{
		{
			name: "systemd stub is returned verbatim, not bypassed",
			// Regression for issue #47: 0.4.1 replaced 127.0.0.53 with the
			// raw upstream from /run/systemd/resolve/resolv.conf, breaking
			// hosts whose resolved is configured with DoT-only upstreams.
			content: "# comment\nnameserver 127.0.0.53\noptions edns0 trust-ad\n",
			want:    []string{"127.0.0.53:53"},
		},
		{
			name:    "multiple ipv4 nameservers preserved in order",
			content: "nameserver 1.1.1.1\nnameserver 8.8.8.8\n",
			want:    []string{"1.1.1.1:53", "8.8.8.8:53"},
		},
		{
			name:    "ipv6 nameserver is bracketed",
			content: "nameserver 2001:4860:4860::8888\n",
			want:    []string{"[2001:4860:4860::8888]:53"},
		},
		{
			name:    "malformed and blank lines are skipped",
			content: "\nnameserver\nnameserver notanip\nnameserver 9.9.9.9\n",
			want:    []string{"9.9.9.9:53"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeResolvConf(t, tc.content)
			got := resolvConfServers(path)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("resolvConfServers() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestResolvConfServersMissingFile(t *testing.T) {
	got := resolvConfServers(filepath.Join(t.TempDir(), "does-not-exist"))
	if got != nil {
		t.Fatalf("expected nil for missing file, got %v", got)
	}
}
