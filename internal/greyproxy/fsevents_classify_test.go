package greyproxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClassifier_Credentials(t *testing.T) {
	c, err := NewFsEventClassifier("")
	if err != nil {
		t.Fatal(err)
	}
	home, _ := os.UserHomeDir()

	cases := []struct {
		path     string
		op       string
		wantSev  string
		wantHas  string // one tag we expect to be present
	}{
		{filepath.Join(home, ".ssh/id_rsa"), "open_read", SeverityCritical, "credentials"},
		{filepath.Join(home, ".ssh/id_ed25519"), "open_read", SeverityCritical, "credentials"},
		{filepath.Join(home, ".aws/credentials"), "open_read", SeverityCritical, "aws"},
		{filepath.Join(home, ".kube/config"), "open_read", SeverityCritical, "kube"},
		{"/etc/shadow", "open_read", SeverityCritical, "credentials"},
		{"/Users/anyone/project/.env", "open_read", SeverityCritical, "dotenv"},
		{"/Users/anyone/project/.env.local", "open_read", SeverityCritical, "dotenv"},
	}
	for _, tc := range cases {
		got := c.Classify(FsEvent{Path: tc.path, Op: tc.op})
		if got.Severity != tc.wantSev {
			t.Errorf("%s %s: severity = %q, want %q", tc.op, tc.path, got.Severity, tc.wantSev)
		}
		if !contains(got.Tags, tc.wantHas) {
			t.Errorf("%s %s: tags = %v, missing %q", tc.op, tc.path, got.Tags, tc.wantHas)
		}
	}
}

func TestClassifier_Kernel(t *testing.T) {
	c, _ := NewFsEventClassifier("")
	for _, p := range []string{"/dev/kmem", "/dev/mem", "/proc/kcore", "/proc/kallsyms", "/sys/kernel/debug/foo", "/System/Library/Kernels/kernel"} {
		got := c.Classify(FsEvent{Path: p, Op: "open_read"})
		if got.Severity != SeverityCritical {
			t.Errorf("%s: severity = %q, want critical", p, got.Severity)
		}
		if !contains(got.Tags, "kernel") {
			t.Errorf("%s: tags = %v, want kernel", p, got.Tags)
		}
	}
}

func TestClassifier_ShellInitWriteVsRead(t *testing.T) {
	c, _ := NewFsEventClassifier("")
	home, _ := os.UserHomeDir()

	write := c.Classify(FsEvent{Path: filepath.Join(home, ".zshrc"), Op: "open_write"})
	if write.Severity != SeverityWarn {
		t.Errorf("write .zshrc severity = %q, want warn", write.Severity)
	}
	read := c.Classify(FsEvent{Path: filepath.Join(home, ".zshrc"), Op: "open_read"})
	if read.Severity != SeverityInfo {
		t.Errorf("read .zshrc severity = %q, want info (shell init read is benign)", read.Severity)
	}
}

func TestClassifier_GitHooksOnlyOnWrite(t *testing.T) {
	c, _ := NewFsEventClassifier("")
	// Read of a git hook should NOT trigger (the rule is Ops-scoped to writes).
	r := c.Classify(FsEvent{Path: "/Users/foo/project/.git/hooks/pre-commit", Op: "open_read"})
	if r.Severity != SeverityInfo || len(r.Tags) != 0 {
		t.Errorf("read of .git/hooks tagged unexpectedly: %+v", r)
	}
	// Write should trigger warn + git-hooks tag.
	w := c.Classify(FsEvent{Path: "/Users/foo/project/.git/hooks/pre-commit", Op: "open_write"})
	if w.Severity != SeverityWarn || !contains(w.Tags, "git-hooks") {
		t.Errorf("write of .git/hooks not flagged: %+v", w)
	}
}

func TestClassifier_BenignPathStaysInfo(t *testing.T) {
	c, _ := NewFsEventClassifier("")
	got := c.Classify(FsEvent{Path: "/Users/foo/project/main.go", Op: "open_read"})
	if got.Severity != SeverityInfo || len(got.Tags) != 0 {
		t.Errorf("benign path classified: %+v", got)
	}
}

func TestClassifier_OverrideFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yml")
	yaml := `
rules:
  - pattern: "/var/log/secret-app/**"
    tags: ["custom", "credentials"]
    severity: "critical"
`
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := NewFsEventClassifier(path)
	if err != nil {
		t.Fatal(err)
	}
	got := c.Classify(FsEvent{Path: "/var/log/secret-app/auth.log", Op: "open_read"})
	if got.Severity != SeverityCritical {
		t.Errorf("override severity = %q, want critical", got.Severity)
	}
	if !contains(got.Tags, "custom") {
		t.Errorf("override tags = %v, want 'custom'", got.Tags)
	}
}

func TestClassifier_MissingOverrideFileIsFine(t *testing.T) {
	c, err := NewFsEventClassifier(filepath.Join(t.TempDir(), "does-not-exist.yml"))
	if err != nil {
		t.Fatalf("missing override should not error: %v", err)
	}
	// Baseline still works.
	got := c.Classify(FsEvent{Path: "/dev/kmem", Op: "open_read"})
	if got.Severity != SeverityCritical {
		t.Errorf("baseline lost when override missing: %+v", got)
	}
}

func TestClassifier_RejectsMalformedPattern(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yml")
	if err := os.WriteFile(path, []byte("rules:\n  - pattern: \"[\"\n    tags: [bad]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := NewFsEventClassifier(path)
	if err == nil || !strings.Contains(err.Error(), "compile pattern") {
		t.Fatalf("expected compile error, got %v", err)
	}
}

func TestStore_IngestClassifies(t *testing.T) {
	classifier, _ := NewFsEventClassifier("")
	store := NewFsEventStore(8)
	store.SetClassifier(classifier)

	home, _ := os.UserHomeDir()
	res := store.Ingest("s1", []FsEvent{
		{Op: "open_read", Path: filepath.Join(home, ".aws/credentials")}, // critical
		{Op: "open_write", Path: filepath.Join(home, ".zshrc")},          // warn
		{Op: "open_read", Path: "/Users/foo/main.go"},                    // info
	}, 0)

	if res.MaxSeverity != SeverityCritical {
		t.Errorf("MaxSeverity = %q, want critical", res.MaxSeverity)
	}
	if len(res.AlertEvents) != 2 {
		t.Errorf("AlertEvents = %d, want 2 (critical + warn)", len(res.AlertEvents))
	}
	snap := store.Snapshot("s1")
	if snap.CriticalCount != 1 || snap.WarnCount != 1 {
		t.Errorf("counts = critical:%d warn:%d, want 1/1", snap.CriticalCount, snap.WarnCount)
	}
	// Stored events should carry severity/tags inline.
	gotInfo := false
	for _, e := range snap.Events {
		if e.Op == "open_read" && strings.HasSuffix(e.Path, ".aws/credentials") {
			if e.Severity != SeverityCritical || !contains(e.Tags, "aws") {
				t.Errorf("aws credentials event not classified inline: %+v", e)
			}
		}
		if e.Path == "/Users/foo/main.go" {
			gotInfo = true
			if e.Severity != SeverityInfo {
				t.Errorf("benign event severity = %q, want info", e.Severity)
			}
		}
	}
	if !gotInfo {
		t.Error("benign event missing from snapshot")
	}
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
