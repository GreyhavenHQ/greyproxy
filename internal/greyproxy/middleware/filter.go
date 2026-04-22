package middleware

import (
	"path/filepath"
	"regexp"
	"strings"
)

// compiledPaths returns the regexes compiled from f.Path. Compilation is
// cached on the HookFilter itself (see HookFilter.compiled) so the result is
// GC'd together with the filter. The previous implementation kept a global
// map keyed by *HookFilter pointer, which leaked one entry per reconnect
// since each hello response produced a fresh filter pointer.
func (f *HookFilter) compiledPaths() []*regexp.Regexp {
	if f == nil {
		return nil
	}
	f.compileOnce.Do(func() {
		for _, p := range f.Path {
			re, err := regexp.Compile(p)
			if err != nil {
				continue
			}
			f.compiled = append(f.compiled, re)
		}
	})
	return f.compiled
}

// PrecompileFilters precompiles regex patterns in all hook specs for
// hot-path performance. It is safe (but not necessary) to skip — the first
// match call would compile on demand.
func PrecompileFilters(hooks []HookSpec) {
	for i := range hooks {
		_ = hooks[i].Filters.compiledPaths()
	}
}

// MatchesFilter evaluates a HookFilter against request/response metadata.
// Returns true if the middleware should be called.
// nil filter = always true.
//
// isLLM must reflect the live state of the endpoint registry at call time
// (i.e. endpointRegistry.Match(...) != ""). We intentionally don't cache
// this: the registry is authoritative, and a user toggling a rule off in
// the UI should take effect on the very next request without any middleware
// reconnect or cache invalidation.
func MatchesFilter(f *HookFilter, host, path, method, contentType, container string, tls, isLLM bool) bool {
	if f == nil {
		return true
	}

	// TLS filter
	if f.TLS != nil && *f.TLS != tls {
		return false
	}

	// LLM filter
	if f.LLM != nil && *f.LLM != isLLM {
		return false
	}

	// Host filter (glob)
	if len(f.Host) > 0 {
		if !matchAnyGlob(f.Host, host) {
			return false
		}
	}

	// Path filter (regex)
	if len(f.Path) > 0 {
		if !matchAnyRegex(f.compiledPaths(), path) {
			return false
		}
	}

	// Method filter (exact, case-insensitive)
	if len(f.Method) > 0 {
		if !matchAnyExactCI(f.Method, method) {
			return false
		}
	}

	// ContentType filter (glob)
	if len(f.ContentType) > 0 {
		// Strip parameters (e.g., "application/json; charset=utf-8" -> "application/json")
		ct := contentType
		if i := strings.IndexByte(ct, ';'); i >= 0 {
			ct = strings.TrimSpace(ct[:i])
		}
		if !matchAnyGlob(f.ContentType, ct) {
			return false
		}
	}

	// Container filter (glob)
	if len(f.Container) > 0 {
		if !matchAnyGlob(f.Container, container) {
			return false
		}
	}

	return true
}

// matchAnyGlob returns true if value matches any of the glob patterns.
// Uses filepath.Match semantics with an extension: a leading "*." matches
// any number of subdomain segments (e.g., "*.openai.com" matches "api.openai.com").
func matchAnyGlob(patterns []string, value string) bool {
	for _, p := range patterns {
		// filepath.Match doesn't handle "*.domain.com" matching "sub.domain.com"
		// because * doesn't match dots. Handle this common case explicitly.
		if strings.HasPrefix(p, "*.") {
			suffix := p[1:] // ".openai.com"
			if strings.HasSuffix(value, suffix) {
				return true
			}
		}
		if matched, _ := filepath.Match(p, value); matched {
			return true
		}
	}
	return false
}

func matchAnyRegex(regexes []*regexp.Regexp, value string) bool {
	for _, re := range regexes {
		if re.MatchString(value) {
			return true
		}
	}
	return false
}

func matchAnyExactCI(patterns []string, value string) bool {
	for _, p := range patterns {
		if strings.EqualFold(p, value) {
			return true
		}
	}
	return false
}
