package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/greyhavenhq/greyproxy/internal/gostx/config"
)

// =============================================================================
// splitCommand
// =============================================================================

func TestSplitCommand(t *testing.T) {
	cases := []struct {
		in      string
		want    []string
		wantErr bool
	}{
		{"uv run mw.py", []string{"uv", "run", "mw.py"}, false},
		{`"uv" "run" "mw.py"`, []string{"uv", "run", "mw.py"}, false},
		{`uv run "path with spaces/mw.py"`, []string{"uv", "run", "path with spaces/mw.py"}, false},
		{`python -c 'print("hi")'`, []string{"python", "-c", `print("hi")`}, false},
		{`echo hello\ world`, []string{"echo", "hello world"}, false},
		{`  leading   and   trailing  `, []string{"leading", "and", "trailing"}, false},

		// Errors: shell escape / empty input
		{`"unterminated`, nil, true},
		{`trailing\`, nil, true},
		{``, nil, true},
		{`   `, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := splitCommand(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}

// writePEM writes a minimal placeholder file (not a real cert, just for Stat checks).
func writePlaceholder(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("placeholder"), 0600); err != nil {
		t.Fatal(err)
	}
}

// =============================================================================
// injectCertPaths
// =============================================================================

func TestInjectCertPaths_neitherFileExists_noInjection(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		Services: []*config.ServiceConfig{
			{Handler: &config.HandlerConfig{Type: "http"}},
		},
	}

	injectCertPaths(cfg, dir)

	if cfg.Services[0].Handler.Metadata != nil {
		t.Error("expected no metadata to be set when cert files are absent")
	}
}

func TestInjectCertPaths_onlyCertExists_noInjection(t *testing.T) {
	dir := t.TempDir()
	writePlaceholder(t, filepath.Join(dir, "ca-cert.pem"))
	// no ca-key.pem

	cfg := &config.Config{
		Services: []*config.ServiceConfig{
			{Handler: &config.HandlerConfig{Type: "http"}},
		},
	}

	injectCertPaths(cfg, dir)

	if cfg.Services[0].Handler.Metadata != nil {
		t.Error("expected no metadata when key file is absent")
	}
}

func TestInjectCertPaths_bothFilesExist_injectsHTTPAndSOCKS5(t *testing.T) {
	dir := t.TempDir()
	writePlaceholder(t, filepath.Join(dir, "ca-cert.pem"))
	writePlaceholder(t, filepath.Join(dir, "ca-key.pem"))

	cfg := &config.Config{
		Services: []*config.ServiceConfig{
			{Handler: &config.HandlerConfig{Type: "http"}},
			{Handler: &config.HandlerConfig{Type: "socks5"}},
		},
	}

	injectCertPaths(cfg, dir)

	for _, svc := range cfg.Services {
		if svc.Handler.Metadata == nil {
			t.Fatalf("expected metadata on %s handler", svc.Handler.Type)
		}
		if svc.Handler.Metadata["mitm.certFile"] != filepath.Join(dir, "ca-cert.pem") {
			t.Errorf("unexpected certFile: %v", svc.Handler.Metadata["mitm.certFile"])
		}
		if svc.Handler.Metadata["mitm.keyFile"] != filepath.Join(dir, "ca-key.pem") {
			t.Errorf("unexpected keyFile: %v", svc.Handler.Metadata["mitm.keyFile"])
		}
	}
}

func TestInjectCertPaths_skipsNonHTTPHandlers(t *testing.T) {
	dir := t.TempDir()
	writePlaceholder(t, filepath.Join(dir, "ca-cert.pem"))
	writePlaceholder(t, filepath.Join(dir, "ca-key.pem"))

	cfg := &config.Config{
		Services: []*config.ServiceConfig{
			{Handler: &config.HandlerConfig{Type: "tcp"}},
			{Handler: &config.HandlerConfig{Type: "udp"}},
		},
	}

	injectCertPaths(cfg, dir)

	for _, svc := range cfg.Services {
		if svc.Handler.Metadata != nil {
			t.Errorf("expected no metadata on %s handler", svc.Handler.Type)
		}
	}
}

func TestInjectCertPaths_nilHandler_doesNotPanic(t *testing.T) {
	dir := t.TempDir()
	writePlaceholder(t, filepath.Join(dir, "ca-cert.pem"))
	writePlaceholder(t, filepath.Join(dir, "ca-key.pem"))

	cfg := &config.Config{
		Services: []*config.ServiceConfig{
			{Handler: nil},
		},
	}

	// should not panic
	injectCertPaths(cfg, dir)
}

func TestInjectCertPaths_doesNotOverwriteExistingCertFile(t *testing.T) {
	dir := t.TempDir()
	writePlaceholder(t, filepath.Join(dir, "ca-cert.pem"))
	writePlaceholder(t, filepath.Join(dir, "ca-key.pem"))

	existing := "already-set"
	cfg := &config.Config{
		Services: []*config.ServiceConfig{
			{Handler: &config.HandlerConfig{
				Type:     "http",
				Metadata: map[string]any{"mitm.certFile": existing},
			}},
		},
	}

	injectCertPaths(cfg, dir)

	if cfg.Services[0].Handler.Metadata["mitm.certFile"] != existing {
		t.Error("injectCertPaths should not overwrite an existing mitm.certFile")
	}
}
