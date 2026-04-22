package middleware

import (
	"net/http"
	"sort"
	"testing"
)

func TestMergeRewriteHeaders_AppliesSafeHeaders(t *testing.T) {
	dst := http.Header{
		"X-Existing": {"old"},
	}
	src := http.Header{
		"X-Custom":   {"1"},
		"X-Existing": {"new"},
	}
	applied, rejected := MergeRewriteHeaders(dst, src)
	if len(rejected) != 0 {
		t.Fatalf("expected no rejections, got %v", rejected)
	}
	sort.Strings(applied)
	want := []string{"X-Custom", "X-Existing"}
	if len(applied) != 2 || applied[0] != want[0] || applied[1] != want[1] {
		t.Fatalf("applied = %v want %v", applied, want)
	}
	if dst.Get("X-Existing") != "new" {
		t.Fatalf("X-Existing not overwritten: %q", dst.Get("X-Existing"))
	}
	if dst.Get("X-Custom") != "1" {
		t.Fatalf("X-Custom not set")
	}
}

func TestMergeRewriteHeaders_RejectsAuthAndHop(t *testing.T) {
	// The critical security guarantee: a middleware's `rewrite` decision
	// cannot overwrite Authorization, Host, Cookie, or hop-by-hop headers.
	// If this test regresses, a compromised or buggy middleware could
	// silently escalate credentials or reroute requests.
	dst := http.Header{
		"Authorization": {"Bearer client-token"},
		"Host":          {"client.example"},
	}
	src := http.Header{
		"Authorization":       {"Bearer attacker-token"},
		"Host":                {"evil.example"},
		"Cookie":              {"session=hijacked"},
		"Set-Cookie":          {"session=hijacked"},
		"Proxy-Authorization": {"Bearer proxy-token"},
		"Connection":          {"close"},
		"Transfer-Encoding":   {"chunked"},
		"X-Safe":              {"ok"},
	}
	applied, rejected := MergeRewriteHeaders(dst, src)

	if dst.Get("Authorization") != "Bearer client-token" {
		t.Fatalf("Authorization was overwritten: %q", dst.Get("Authorization"))
	}
	if dst.Get("Host") != "client.example" {
		t.Fatalf("Host was overwritten: %q", dst.Get("Host"))
	}
	if dst.Get("Cookie") != "" {
		t.Fatalf("Cookie was set: %q", dst.Get("Cookie"))
	}
	if dst.Get("X-Safe") != "ok" {
		t.Fatalf("X-Safe should have been applied")
	}
	if len(applied) != 1 || applied[0] != "X-Safe" {
		t.Fatalf("applied = %v, want [X-Safe]", applied)
	}
	wantRejected := []string{
		"Authorization", "Connection", "Cookie", "Host",
		"Proxy-Authorization", "Set-Cookie", "Transfer-Encoding",
	}
	sort.Strings(rejected)
	if len(rejected) != len(wantRejected) {
		t.Fatalf("rejected = %v, want %v", rejected, wantRejected)
	}
	for i := range rejected {
		if rejected[i] != wantRejected[i] {
			t.Fatalf("rejected[%d] = %q, want %q", i, rejected[i], wantRejected[i])
		}
	}
}

func TestMergeRewriteHeaders_CaseInsensitive(t *testing.T) {
	// A middleware emitting lowercase "authorization" should still be
	// caught — the denylist check must not rely on caller casing.
	dst := http.Header{"Authorization": {"Bearer client"}}
	src := http.Header{"authorization": {"Bearer attacker"}}
	_, rejected := MergeRewriteHeaders(dst, src)
	if dst.Get("Authorization") != "Bearer client" {
		t.Fatalf("lowercase authorization leaked through: %q", dst.Get("Authorization"))
	}
	if len(rejected) != 1 || rejected[0] != "Authorization" {
		t.Fatalf("rejected = %v, want [Authorization]", rejected)
	}
}

func TestActionForTimeoutKind(t *testing.T) {
	cases := []struct {
		onTimeout  string
		isResponse bool
		want       string
	}{
		// Secure default: deny requests, block responses.
		{"", false, "deny"}, // "" -> deny via New()'s fallback, but the helper takes the resolved value
		{"deny", false, "deny"},
		{"deny", true, "block"},
		// Advisory opt-in: allow requests, passthrough responses.
		{"allow", false, "allow"},
		{"allow", true, "passthrough"},
	}
	for _, tc := range cases {
		// ActionForTimeoutKind treats unknown strings as "deny", matching
		// fallbackLocked; New() is where the "" -> "deny" normalisation
		// happens, so pass the resolved string.
		onTimeout := tc.onTimeout
		if onTimeout == "" {
			onTimeout = "deny"
		}
		got := ActionForTimeoutKind(onTimeout, tc.isResponse)
		if got != tc.want {
			t.Errorf("ActionForTimeoutKind(%q,%v) = %q, want %q", onTimeout, tc.isResponse, got, tc.want)
		}
	}
}

func TestIsKnownAction(t *testing.T) {
	for _, a := range []string{"allow", "deny", "rewrite", "passthrough", "block"} {
		if !IsKnownAction(a) {
			t.Errorf("%q should be known", a)
		}
	}
	for _, a := range []string{"", "ALLOW", "permit", "reject", "forward"} {
		if IsKnownAction(a) {
			t.Errorf("%q should NOT be known", a)
		}
	}
}

func TestBodyChanged(t *testing.T) {
	// nil newBody means "no rewrite" — never confuse with "empty body".
	if BodyChanged([]byte("x"), nil) {
		t.Fatal("nil newBody must not be treated as a change")
	}
	if !BodyChanged([]byte("x"), []byte("y")) {
		t.Fatal("different bytes must be a change")
	}
	if BodyChanged([]byte("x"), []byte("x")) {
		t.Fatal("same bytes must not be a change")
	}
	// Edge: middleware explicitly sets an empty body to replace a non-empty one.
	if !BodyChanged([]byte("x"), []byte{}) {
		t.Fatal("empty-bytes replacement must be a change")
	}
}

func TestNegotiateVersion(t *testing.T) {
	cases := []struct {
		name            string
		proxy, min, max int
		wantAgreed      int
		wantErr         bool
	}{
		// Back-compat: middleware omitted both → assume v1.
		{"omitted both, proxy v1", 1, 0, 0, 1, false},
		// Exact match.
		{"v1 on both sides", 1, 1, 1, 1, false},
		// Proxy newer than middleware: agree on middleware's max.
		{"proxy v3, mw v1..2", 3, 1, 2, 2, false},
		{"proxy v5, mw v1..1", 5, 1, 1, 1, false},
		// Middleware newer than proxy: agree on proxy's version.
		{"proxy v2, mw v1..5", 2, 1, 5, 2, false},
		// No overlap: middleware requires v2+, proxy only has v1.
		{"no overlap: mw requires v2+", 1, 2, 3, 0, true},
		// Invalid ranges are rejected.
		{"invalid: min>max", 3, 5, 2, 0, true},
		{"invalid: min=0 with nonzero max", 3, 0, 2, 0, true}, // 0,2 means middleware declared mw_max but not min
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := negotiateVersion(tc.proxy, tc.min, tc.max)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got agreed=%d", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.wantAgreed {
				t.Fatalf("agreed = %d, want %d", got, tc.wantAgreed)
			}
		})
	}
}

func TestNewID_UniqueAndHex(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 64; i++ {
		id := NewID()
		if len(id) != 32 {
			t.Fatalf("NewID len = %d, want 32", len(id))
		}
		for _, c := range id {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Fatalf("NewID contains non-hex char %q", c)
			}
		}
		if seen[id] {
			t.Fatalf("NewID collision at iter %d: %q", i, id)
		}
		seen[id] = true
	}
}
