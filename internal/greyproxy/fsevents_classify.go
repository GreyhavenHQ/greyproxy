package greyproxy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gobwas/glob"
	"gopkg.in/yaml.v3"
)

// Severity levels for classified filesystem events.
const (
	SeverityInfo     = "info"
	SeverityWarn     = "warn"
	SeverityCritical = "critical"
)

// FsEventRule is one path pattern plus the tags it applies and the op-class
// it cares about. Empty Ops applies to every op.
type FsEventRule struct {
	Pattern  string   `yaml:"pattern"`
	Tags     []string `yaml:"tags"`
	Ops      []string `yaml:"ops,omitempty"`
	Severity string   `yaml:"severity,omitempty"` // optional override; otherwise derived
}

// compiledRule is the runtime form of an FsEventRule.
type compiledRule struct {
	pattern  string
	matcher  glob.Glob
	tags     []string
	ops      map[string]bool // nil = any
	severity string          // empty = derive from tag×op
}

// FsEventClassifier matches paths against a baseline of dangerous-path
// patterns and tags + ranks each event. Constructed via
// NewFsEventClassifier with optional override file.
type FsEventClassifier struct {
	rules []compiledRule
}

// Classification is the verdict for one event.
type Classification struct {
	Severity string   // "info" (default), "warn", or "critical"
	Tags     []string // distinct tag names that matched
}

// op classes used by severity derivation.
var (
	readOps  = map[string]bool{"open_read": true}
	writeOps = map[string]bool{"open_write": true, "create": true, "unlink": true, "rename": true, "symlink": true, "link": true, "mkdir": true}
)

// NewFsEventClassifier builds the classifier from the baseline plus any
// rules in overridePath. Pass "" to skip the override lookup. Errors from
// the override are returned so a misconfigured file is loud at startup.
func NewFsEventClassifier(overridePath string) (*FsEventClassifier, error) {
	rules := append([]FsEventRule(nil), baselineFsEventRules()...)

	if overridePath != "" {
		extra, err := loadFsEventRules(overridePath)
		if err != nil {
			return nil, fmt.Errorf("load %s: %w", overridePath, err)
		}
		rules = append(rules, extra...)
	}

	c := &FsEventClassifier{}
	for _, r := range rules {
		expanded := expandTilde(r.Pattern)
		g, err := glob.Compile(expanded, '/')
		if err != nil {
			return nil, fmt.Errorf("compile pattern %q: %w", r.Pattern, err)
		}
		cr := compiledRule{
			pattern:  expanded,
			matcher:  g,
			tags:     r.Tags,
			severity: r.Severity,
		}
		if len(r.Ops) > 0 {
			cr.ops = make(map[string]bool, len(r.Ops))
			for _, o := range r.Ops {
				cr.ops[o] = true
			}
		}
		c.rules = append(c.rules, cr)
	}
	return c, nil
}

// Classify applies every rule to the event and returns the highest
// severity plus the union of matching tags. A path with no matching rule
// is classified as info / no tags.
func (c *FsEventClassifier) Classify(e FsEvent) Classification {
	if c == nil || len(c.rules) == 0 {
		return Classification{Severity: SeverityInfo}
	}
	var tags []string
	seen := make(map[string]bool)
	severity := SeverityInfo

	for _, r := range c.rules {
		if r.ops != nil && !r.ops[e.Op] {
			continue
		}
		if !pathMatches(r.matcher, e.Path) && !(e.Path2 != "" && pathMatches(r.matcher, e.Path2)) {
			continue
		}
		for _, t := range r.tags {
			if !seen[t] {
				seen[t] = true
				tags = append(tags, t)
			}
		}
		var sev string
		if r.severity != "" {
			sev = r.severity
		} else {
			sev = deriveSeverity(r.tags, e.Op)
		}
		severity = maxSeverity(severity, sev)
	}
	return Classification{Severity: severity, Tags: tags}
}

func pathMatches(g glob.Glob, p string) bool {
	if p == "" {
		return false
	}
	return g.Match(p)
}

// deriveSeverity picks a severity from the tag×op when a rule omits one.
// The matrix is conservative: anything credentials or kernel related is
// critical (no matter the op — even a touch of /dev/kmem is worth flagging);
// system-config / shell-init / git-hooks lift to warn on writes; reads of
// those land at info.
func deriveSeverity(tags []string, op string) string {
	for _, t := range tags {
		switch t {
		case "credentials", "kernel":
			return SeverityCritical
		}
	}
	if writeOps[op] {
		for _, t := range tags {
			switch t {
			case "system-config", "shell-init", "git-hooks", "launch-agents":
				return SeverityWarn
			}
		}
	}
	if readOps[op] {
		for _, t := range tags {
			switch t {
			case "system-config", "shell-init":
				return SeverityInfo
			}
		}
	}
	return SeverityInfo
}

var severityRank = map[string]int{
	SeverityInfo:     0,
	SeverityWarn:     1,
	SeverityCritical: 2,
}

func maxSeverity(a, b string) string {
	if severityRank[b] > severityRank[a] {
		return b
	}
	return a
}

// loadFsEventRules reads the override YAML. Returns nil rules (no error)
// when the file does not exist so the override file is genuinely optional.
func loadFsEventRules(path string) ([]FsEventRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var doc struct {
		Rules []FsEventRule `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return doc.Rules, nil
}

// expandTilde replaces a leading "~/" with the user's home directory so
// rules can be written in user-relative form. Falls back to the literal
// path if HOME cannot be resolved.
func expandTilde(p string) string {
	if !strings.HasPrefix(p, "~/") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return p
	}
	return filepath.Join(home, p[2:])
}

// baselineFsEventRules is the hardcoded default list. Keep this list
// small, opinionated, and easy to audit. Anything noisy or
// environment-specific belongs in the override file.
func baselineFsEventRules() []FsEventRule {
	return []FsEventRule{
		// --- Credentials (SSH / cloud / SCM / package registries) ---
		{Pattern: "~/.ssh/id_*", Tags: []string{"credentials", "ssh"}},
		{Pattern: "~/.ssh/*_rsa", Tags: []string{"credentials", "ssh"}},
		{Pattern: "~/.ssh/*_ed25519", Tags: []string{"credentials", "ssh"}},
		{Pattern: "~/.ssh/*_ecdsa", Tags: []string{"credentials", "ssh"}},
		{Pattern: "~/.ssh/authorized_keys", Tags: []string{"credentials", "ssh"}},
		{Pattern: "~/.ssh/known_hosts", Tags: []string{"credentials", "ssh"}, Severity: SeverityWarn},
		{Pattern: "~/.aws/credentials", Tags: []string{"credentials", "aws"}},
		{Pattern: "~/.aws/config", Tags: []string{"credentials", "aws"}, Severity: SeverityWarn},
		{Pattern: "~/.config/gcloud/**", Tags: []string{"credentials", "gcp"}},
		{Pattern: "~/.azure/**", Tags: []string{"credentials", "azure"}},
		{Pattern: "~/.kube/config", Tags: []string{"credentials", "kube"}},
		{Pattern: "~/.docker/config.json", Tags: []string{"credentials", "docker"}},
		{Pattern: "~/.gnupg/**", Tags: []string{"credentials", "gpg"}},
		{Pattern: "~/.netrc", Tags: []string{"credentials"}},
		{Pattern: "~/.pgpass", Tags: []string{"credentials", "postgres"}},
		{Pattern: "~/.npmrc", Tags: []string{"credentials", "npm"}},
		{Pattern: "~/.pypirc", Tags: []string{"credentials", "pypi"}},
		{Pattern: "~/.config/gh/hosts.yml", Tags: []string{"credentials", "github"}},
		{Pattern: "~/.config/git/credentials", Tags: []string{"credentials", "git"}},
		{Pattern: "~/Library/Keychains/**", Tags: []string{"credentials", "keychain"}},
		{Pattern: "/etc/shadow", Tags: []string{"credentials"}},
		{Pattern: "/etc/sudoers", Tags: []string{"credentials"}},
		{Pattern: "/etc/sudoers.d/**", Tags: []string{"credentials"}},

		// Project-scoped secrets — match in any cwd.
		{Pattern: "**/.env", Tags: []string{"credentials", "dotenv"}},
		{Pattern: "**/.env.*", Tags: []string{"credentials", "dotenv"}},
		{Pattern: "**/secrets.yml", Tags: []string{"credentials"}},
		{Pattern: "**/secrets.yaml", Tags: []string{"credentials"}},

		// --- Kernel / direct memory ---
		{Pattern: "/dev/kmem", Tags: []string{"kernel"}},
		{Pattern: "/dev/mem", Tags: []string{"kernel"}},
		{Pattern: "/dev/kcore", Tags: []string{"kernel"}},
		{Pattern: "/dev/port", Tags: []string{"kernel"}},
		{Pattern: "/proc/kcore", Tags: []string{"kernel"}},
		{Pattern: "/proc/kallsyms", Tags: []string{"kernel"}},
		{Pattern: "/proc/*/mem", Tags: []string{"kernel", "process-mem"}},
		{Pattern: "/sys/kernel/**", Tags: []string{"kernel"}},
		{Pattern: "/sys/firmware/efi/efivars/**", Tags: []string{"kernel", "firmware"}},
		{Pattern: "/System/Library/Kernels/**", Tags: []string{"kernel"}},
		{Pattern: "/Library/Extensions/**", Tags: []string{"kernel", "kext"}},
		{Pattern: "/System/Library/Extensions/**", Tags: []string{"kernel", "kext"}},

		// --- Shell init (hijack vectors) ---
		{Pattern: "~/.bashrc", Tags: []string{"shell-init"}},
		{Pattern: "~/.bash_profile", Tags: []string{"shell-init"}},
		{Pattern: "~/.profile", Tags: []string{"shell-init"}},
		{Pattern: "~/.zshrc", Tags: []string{"shell-init"}},
		{Pattern: "~/.zprofile", Tags: []string{"shell-init"}},
		{Pattern: "~/.zshenv", Tags: []string{"shell-init"}},
		{Pattern: "~/.config/fish/config.fish", Tags: []string{"shell-init"}},

		// --- System config (writes are warn; reads info) ---
		{Pattern: "/etc/**", Tags: []string{"system-config"}},
		{Pattern: "/usr/local/bin/**", Tags: []string{"system-config", "binaries"}},
		{Pattern: "/usr/local/sbin/**", Tags: []string{"system-config", "binaries"}},
		{Pattern: "/opt/homebrew/bin/**", Tags: []string{"system-config", "binaries"}},

		// --- macOS persistence ---
		{Pattern: "/Library/LaunchAgents/**", Tags: []string{"launch-agents"}, Severity: SeverityWarn},
		{Pattern: "/Library/LaunchDaemons/**", Tags: []string{"launch-agents"}, Severity: SeverityWarn},
		{Pattern: "~/Library/LaunchAgents/**", Tags: []string{"launch-agents"}, Severity: SeverityWarn},

		// --- Linux persistence ---
		{Pattern: "/etc/systemd/system/**", Tags: []string{"launch-agents"}, Severity: SeverityWarn},
		{Pattern: "~/.config/systemd/user/**", Tags: []string{"launch-agents"}, Severity: SeverityWarn},
		{Pattern: "/etc/cron.*/**", Tags: []string{"launch-agents", "cron"}, Severity: SeverityWarn},
		{Pattern: "/var/spool/cron/**", Tags: []string{"launch-agents", "cron"}, Severity: SeverityWarn},

		// --- Git hooks (mirrors greywall's hard-floor list) ---
		{Pattern: "**/.git/hooks/**", Tags: []string{"git-hooks"}, Severity: SeverityWarn,
			Ops: []string{"open_write", "create", "rename", "link", "symlink"}},
	}
}
