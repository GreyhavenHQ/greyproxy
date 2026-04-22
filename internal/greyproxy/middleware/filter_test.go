package middleware

import "testing"

// Filter tests focus on the match semantics that the protocol doc promises,
// since regressions here silently enable/disable a middleware for traffic
// the operator thought was filtered.

func TestMatchesFilter_NilMatchesEverything(t *testing.T) {
	if !MatchesFilter(nil, "api.openai.com", "/v1/chat/completions", "POST", "application/json", "app", true, true) {
		t.Fatal("nil filter must match everything")
	}
}

func TestMatchesFilter_HostGlobWildcard(t *testing.T) {
	host := "*.openai.com"
	f := &HookFilter{Host: []string{host}}
	if !MatchesFilter(f, "api.openai.com", "/", "GET", "", "", false, false) {
		t.Fatal("*.openai.com must match api.openai.com")
	}
	if MatchesFilter(f, "openai.com", "/", "GET", "", "", false, false) {
		t.Fatal("*.openai.com must NOT match bare openai.com (no subdomain)")
	}
	if MatchesFilter(f, "api.anthropic.com", "/", "GET", "", "", false, false) {
		t.Fatal("*.openai.com must not match api.anthropic.com")
	}
}

func TestMatchesFilter_PathRegexCompiledOnce(t *testing.T) {
	f := &HookFilter{Path: []string{`^/v1/.*$`}}
	for i := 0; i < 3; i++ {
		if !MatchesFilter(f, "h", "/v1/messages", "POST", "", "", false, false) {
			t.Fatalf("iter %d: /v1/messages must match ^/v1/.*$", i)
		}
	}
	// Compiled list is cached on the filter, not in a global map; assert
	// that the lazy initialiser ran exactly once by comparing the slice
	// identity across calls.
	first := f.compiledPaths()
	second := f.compiledPaths()
	if len(first) != 1 || len(second) != 1 || &first[0] != &second[0] {
		t.Fatal("compiledPaths should return the same cached slice on repeat calls")
	}
}

func TestMatchesFilter_LLMGate(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		name    string
		filter  *HookFilter
		isLLM   bool
		wantHit bool
	}{
		{"llm:true matches LLM", &HookFilter{LLM: &yes}, true, true},
		{"llm:true skips non-LLM", &HookFilter{LLM: &yes}, false, false},
		{"llm:false matches non-LLM", &HookFilter{LLM: &no}, false, true},
		{"llm:false skips LLM", &HookFilter{LLM: &no}, true, false},
		{"llm absent: don't care", &HookFilter{}, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := MatchesFilter(tc.filter, "h", "/", "GET", "", "", false, tc.isLLM)
			if got != tc.wantHit {
				t.Fatalf("got %v want %v", got, tc.wantHit)
			}
		})
	}
}

func TestMatchesFilter_ContentTypeStripsParameters(t *testing.T) {
	// `application/json; charset=utf-8` must match `application/json`.
	f := &HookFilter{ContentType: []string{"application/json"}}
	if !MatchesFilter(f, "h", "/", "POST", "application/json; charset=utf-8", "", false, false) {
		t.Fatal("content-type match must ignore parameters after ';'")
	}
}
