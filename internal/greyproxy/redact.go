package greyproxy

import (
	"net/http"
	"strings"
)

const RedactedValue = "[REDACTED]"

// DefaultRedactedHeaders are header patterns redacted by default.
// Patterns are case-insensitive. A pattern with no wildcards matches
// the full header name exactly; a leading/trailing "*" matches as a
// substring (contains).
var DefaultRedactedHeaders = []string{
	"Authorization",
	"Proxy-Authorization",
	"Cookie",
	"Set-Cookie",
	"*api-key*",
	"*token*",
	"*secret*",
}

// HeaderRedactor strips sensitive values from HTTP headers before storage.
type HeaderRedactor struct {
	patterns []string
}

// NewHeaderRedactor creates a redactor using the given patterns merged
// with the defaults. Each pattern is case-insensitive. A "*" prefix or
// suffix acts as a wildcard (contains match).
func NewHeaderRedactor(extraPatterns []string) *HeaderRedactor {
	seen := make(map[string]struct{}, len(DefaultRedactedHeaders)+len(extraPatterns))
	patterns := make([]string, 0, len(DefaultRedactedHeaders)+len(extraPatterns))
	for _, p := range DefaultRedactedHeaders {
		low := strings.ToLower(p)
		if _, ok := seen[low]; !ok {
			seen[low] = struct{}{}
			patterns = append(patterns, low)
		}
	}
	for _, p := range extraPatterns {
		low := strings.ToLower(strings.TrimSpace(p))
		if low == "" {
			continue
		}
		if _, ok := seen[low]; !ok {
			seen[low] = struct{}{}
			patterns = append(patterns, low)
		}
	}
	return &HeaderRedactor{patterns: patterns}
}

// Redact returns a shallow copy of the headers with sensitive values
// replaced by "[REDACTED]". The original headers are not modified.
// Returns nil if the input is nil.
func (r *HeaderRedactor) Redact(h http.Header) http.Header {
	if h == nil {
		return nil
	}
	out := make(http.Header, len(h))
	for key, vals := range h {
		if r.isSensitive(key) {
			out[key] = []string{RedactedValue}
		} else {
			out[key] = vals
		}
	}
	return out
}

// isSensitive checks whether a header name matches any redaction pattern.
func (r *HeaderRedactor) isSensitive(name string) bool {
	low := strings.ToLower(name)
	for _, p := range r.patterns {
		if matchPattern(p, low) {
			return true
		}
	}
	return false
}

// matchPattern does case-insensitive matching. Both p and name must
// already be lowercased.
//   - "*foo*" matches if name contains "foo"
//   - "*foo"  matches if name ends with "foo"
//   - "foo*"  matches if name starts with "foo"
//   - "foo"   matches if name equals "foo"
func matchPattern(p, name string) bool {
	starPrefix := strings.HasPrefix(p, "*")
	starSuffix := strings.HasSuffix(p, "*")
	core := strings.Trim(p, "*")
	if core == "" {
		return starPrefix || starSuffix // "*" alone matches everything
	}
	switch {
	case starPrefix && starSuffix:
		return strings.Contains(name, core)
	case starPrefix:
		return strings.HasSuffix(name, core)
	case starSuffix:
		return strings.HasPrefix(name, core)
	default:
		return name == core
	}
}
