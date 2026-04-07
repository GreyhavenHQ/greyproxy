package dissector

import (
	"fmt"
	"path/filepath"
	"strings"
)

// ExtractToolSummary produces a short human-readable summary from a tool
// invocation. It handles all known tool name casings across clients:
// Claude Code (PascalCase), OpenCode (lowercase), Codex (snake_case),
// Gemini CLI (snake_case).
func ExtractToolSummary(name string, input map[string]any) string {
	str := func(key string) string {
		if v, ok := input[key].(string); ok {
			return v
		}
		return ""
	}

	switch strings.ToLower(name) {
	case "read", "read_file":
		return summarizeFilePath(str)

	case "edit", "write", "write_file", "replace":
		return summarizeFilePath(str)

	case "apply_patch":
		if p := str("patch"); p != "" {
			for _, line := range strings.SplitN(p, "\n", 5) {
				if strings.HasPrefix(line, "*** ") {
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						return filepath.Base(parts[1])
					}
				}
			}
			if len(p) > 60 {
				return p[:60] + "..."
			}
			return p
		}

	case "bash", "exec_command", "run_shell_command":
		if desc := str("description"); desc != "" {
			return desc
		}
		if cmd := str("command"); cmd != "" {
			if len(cmd) > 80 {
				return cmd[:80] + "..."
			}
			return cmd
		}

	case "grep", "grep_search":
		if pat := str("pattern"); pat != "" {
			summary := "pattern: " + pat
			if p := str("path"); p != "" {
				summary += " in " + filepath.Base(p)
			}
			return summary
		}

	case "glob":
		if pat := str("pattern"); pat != "" {
			return pat
		}

	case "agent", "task", "spawn_agent":
		if desc := str("description"); desc != "" {
			return desc
		}
		if prompt := str("prompt"); prompt != "" {
			if len(prompt) > 80 {
				return prompt[:80] + "..."
			}
			return prompt
		}

	case "toolsearch":
		if q := str("query"); q != "" {
			return q
		}

	case "webfetch":
		if u := str("url"); u != "" {
			return u
		}

	case "websearch":
		if q := str("query"); q != "" {
			return q
		}

	case "skill":
		if n := str("name"); n != "" {
			return n
		}
		if n := str("skill"); n != "" {
			return n
		}
	}

	return summarizeGenericArgs(input)
}

func summarizeFilePath(str func(string) string) string {
	if fp := str("file_path"); fp != "" {
		dir := filepath.Base(filepath.Dir(fp))
		base := filepath.Base(fp)
		if dir != "." && dir != "/" {
			return dir + "/" + base
		}
		return base
	}
	return ""
}

func summarizeGenericArgs(input map[string]any) string {
	var parts []string
	for k, v := range input {
		if s, ok := v.(string); ok && len(s) <= 40 {
			parts = append(parts, fmt.Sprintf("%s=%s", k, s))
		}
	}
	if len(parts) > 0 {
		s := strings.Join(parts, " ")
		if len(s) > 80 {
			return s[:80] + "..."
		}
		return s
	}
	return ""
}
