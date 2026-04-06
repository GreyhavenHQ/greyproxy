package middleware

import (
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// compiledFilter caches compiled regexes for a HookFilter's path patterns.
type compiledFilter struct {
	pathRegexes []*regexp.Regexp
}

var (
	filterCacheMu sync.RWMutex
	filterCache   = make(map[*HookFilter]*compiledFilter)
)

func getCompiledFilter(f *HookFilter) *compiledFilter {
	if f == nil {
		return nil
	}
	filterCacheMu.RLock()
	cf := filterCache[f]
	filterCacheMu.RUnlock()
	if cf != nil {
		return cf
	}

	cf = &compiledFilter{}
	for _, p := range f.Path {
		re, err := regexp.Compile(p)
		if err != nil {
			continue
		}
		cf.pathRegexes = append(cf.pathRegexes, re)
	}

	filterCacheMu.Lock()
	filterCache[f] = cf
	filterCacheMu.Unlock()
	return cf
}

// PrecompileFilters precompiles regex patterns in all hook specs for hot-path performance.
func PrecompileFilters(hooks []HookSpec) {
	for i := range hooks {
		if hooks[i].Filters != nil {
			getCompiledFilter(hooks[i].Filters)
		}
	}
}

// MatchesFilter evaluates a HookFilter against request/response metadata.
// Returns true if the middleware should be called.
// nil filter = always true.
func MatchesFilter(f *HookFilter, host, path, method, contentType, container string, tls bool) bool {
	if f == nil {
		return true
	}

	// TLS filter
	if f.TLS != nil && *f.TLS != tls {
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
		cf := getCompiledFilter(f)
		if !matchAnyRegex(cf.pathRegexes, path) {
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
