package greyproxy

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestHeaderRedactorDefaults(t *testing.T) {
	r := NewHeaderRedactor(nil)

	h := http.Header{
		"Authorization":       {"Bearer sk-ant-xxx"},
		"Proxy-Authorization": {"Basic dXNlcjpwYXNz"},
		"Cookie":              {"session=abc123"},
		"Set-Cookie":          {"session=abc123; Path=/"},
		"Content-Type":        {"application/json"},
		"Accept":              {"*/*"},
	}
	out := r.Redact(h)

	// Sensitive headers should be redacted
	if out.Get("Authorization") != RedactedValue {
		t.Errorf("Authorization = %q, want %q", out.Get("Authorization"), RedactedValue)
	}
	if out.Get("Proxy-Authorization") != RedactedValue {
		t.Errorf("Proxy-Authorization = %q, want %q", out.Get("Proxy-Authorization"), RedactedValue)
	}
	if out.Get("Cookie") != RedactedValue {
		t.Errorf("Cookie = %q, want %q", out.Get("Cookie"), RedactedValue)
	}
	if out.Get("Set-Cookie") != RedactedValue {
		t.Errorf("Set-Cookie = %q, want %q", out.Get("Set-Cookie"), RedactedValue)
	}

	// Non-sensitive headers should be preserved
	if out.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q, want %q", out.Get("Content-Type"), "application/json")
	}
	if out.Get("Accept") != "*/*" {
		t.Errorf("Accept = %q, want %q", out.Get("Accept"), "*/*")
	}

	// Original should not be modified
	if h.Get("Authorization") != "Bearer sk-ant-xxx" {
		t.Error("original headers were modified")
	}
}

func TestHeaderRedactorWildcardPatterns(t *testing.T) {
	r := NewHeaderRedactor(nil)

	h := http.Header{
		"X-Api-Key":       {"key123"},
		"X-Custom-Token":  {"tok456"},
		"X-Client-Secret": {"sec789"},
		"X-Request-Id":    {"req-001"},
	}
	out := r.Redact(h)

	// Wildcard *api-key* should match X-Api-Key
	if out.Get("X-Api-Key") != RedactedValue {
		t.Errorf("X-Api-Key = %q, want %q", out.Get("X-Api-Key"), RedactedValue)
	}
	// Wildcard *token* should match X-Custom-Token
	if out.Get("X-Custom-Token") != RedactedValue {
		t.Errorf("X-Custom-Token = %q, want %q", out.Get("X-Custom-Token"), RedactedValue)
	}
	// Wildcard *secret* should match X-Client-Secret
	if out.Get("X-Client-Secret") != RedactedValue {
		t.Errorf("X-Client-Secret = %q, want %q", out.Get("X-Client-Secret"), RedactedValue)
	}
	// X-Request-Id should not be matched
	if out.Get("X-Request-Id") != "req-001" {
		t.Errorf("X-Request-Id = %q, want %q", out.Get("X-Request-Id"), "req-001")
	}
}

func TestHeaderRedactorCaseInsensitive(t *testing.T) {
	r := NewHeaderRedactor(nil)

	// Go's http.Header normalizes keys via textproto.CanonicalMIMEHeaderKey,
	// but the redactor should still match regardless of the key casing
	// stored in the map (e.g. from a raw map assignment).
	h := make(http.Header)
	h["authorization"] = []string{"Bearer xxx"} //nolint:staticcheck // intentionally non-canonical
	h["COOKIE"] = []string{"session=abc"}       //nolint:staticcheck // intentionally non-canonical
	h["x-api-key"] = []string{"key"}            //nolint:staticcheck // intentionally non-canonical
	out := r.Redact(h)

	// Access by raw key since these are non-canonical
	if v := out["authorization"]; len(v) != 1 || v[0] != RedactedValue { //nolint:staticcheck
		t.Errorf("authorization = %v, want [%q]", v, RedactedValue)
	}
	if v := out["COOKIE"]; len(v) != 1 || v[0] != RedactedValue { //nolint:staticcheck
		t.Errorf("COOKIE = %v, want [%q]", v, RedactedValue)
	}
	if v := out["x-api-key"]; len(v) != 1 || v[0] != RedactedValue { //nolint:staticcheck
		t.Errorf("x-api-key = %v, want [%q]", v, RedactedValue)
	}
}

func TestHeaderRedactorExtraPatterns(t *testing.T) {
	r := NewHeaderRedactor([]string{"X-Custom-Auth", "*password*"})

	h := http.Header{
		"X-Custom-Auth":   {"auth123"},
		"X-User-Password": {"pass"},
		"X-Request-Id":    {"req-001"},
		"Authorization":   {"Bearer xxx"}, // default still works
	}
	out := r.Redact(h)

	if out.Get("X-Custom-Auth") != RedactedValue {
		t.Errorf("X-Custom-Auth = %q, want %q", out.Get("X-Custom-Auth"), RedactedValue)
	}
	if out.Get("X-User-Password") != RedactedValue {
		t.Errorf("X-User-Password = %q, want %q", out.Get("X-User-Password"), RedactedValue)
	}
	if out.Get("Authorization") != RedactedValue {
		t.Errorf("Authorization = %q, want %q", out.Get("Authorization"), RedactedValue)
	}
	if out.Get("X-Request-Id") != "req-001" {
		t.Errorf("X-Request-Id = %q, want %q", out.Get("X-Request-Id"), "req-001")
	}
}

func TestHeaderRedactorNilHeaders(t *testing.T) {
	r := NewHeaderRedactor(nil)
	if out := r.Redact(nil); out != nil {
		t.Errorf("Redact(nil) = %v, want nil", out)
	}
}

func TestHeaderRedactorMultipleValues(t *testing.T) {
	r := NewHeaderRedactor(nil)

	h := http.Header{
		"Set-Cookie": {"session=abc; Path=/", "tracking=xyz; Path=/"},
	}
	out := r.Redact(h)

	// Multi-value sensitive header should be collapsed to single [REDACTED]
	vals := out["Set-Cookie"]
	if len(vals) != 1 || vals[0] != RedactedValue {
		t.Errorf("Set-Cookie = %v, want [%q]", vals, RedactedValue)
	}
}

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"authorization", "authorization", true},
		{"authorization", "content-type", false},
		{"*token*", "x-auth-token", true},
		{"*token*", "token", true},
		{"*token*", "x-request-id", false},
		{"*key", "x-api-key", true},
		{"*key", "key-name", false},
		{"x-*", "x-custom", true},
		{"x-*", "authorization", false},
		{"*", "anything", true},
	}
	for _, tt := range tests {
		got := matchPattern(tt.pattern, tt.name)
		if got != tt.want {
			t.Errorf("matchPattern(%q, %q) = %v, want %v", tt.pattern, tt.name, got, tt.want)
		}
	}
}

func TestSettingsManagerRedactedHeaders(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "settings.json")
	m := NewSettingsManager(tmp, true)

	// Default redactor should work
	r := m.HeaderRedactor()
	h := http.Header{"Authorization": {"Bearer xxx"}}
	out := r.Redact(h)
	if out.Get("Authorization") != RedactedValue {
		t.Errorf("default redactor failed: Authorization = %q", out.Get("Authorization"))
	}

	// Update with extra patterns
	extra := []string{"*password*"}
	_, _ = m.Update(UserSettings{RedactedHeaders: extra})

	r = m.HeaderRedactor()
	h = http.Header{
		"Authorization":   {"Bearer xxx"},
		"X-User-Password": {"secret"},
		"Content-Type":    {"application/json"},
	}
	out = r.Redact(h)
	if out.Get("Authorization") != RedactedValue {
		t.Errorf("Authorization = %q, want %q", out.Get("Authorization"), RedactedValue)
	}
	if out.Get("X-User-Password") != RedactedValue {
		t.Errorf("X-User-Password = %q, want %q", out.Get("X-User-Password"), RedactedValue)
	}
	if out.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q, want preserved", out.Get("Content-Type"))
	}

	// Resolved settings should include both defaults and extras
	resolved := m.Get()
	if len(resolved.RedactedHeaders) <= len(DefaultRedactedHeaders) {
		t.Error("resolved RedactedHeaders should include extra patterns")
	}
}

func TestSettingsManagerRedactedHeadersPersistence(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "settings.json")
	m := NewSettingsManager(tmp, true)

	extra := []string{"X-My-Secret"}
	_, _ = m.Update(UserSettings{RedactedHeaders: extra})

	// Read back from disk
	m2 := NewSettingsManager(tmp, true)
	if err := m2.Load(); err != nil {
		t.Fatal(err)
	}

	r := m2.HeaderRedactor()
	h := http.Header{"X-My-Secret": {"value"}}
	out := r.Redact(h)
	if out.Get("X-My-Secret") != RedactedValue {
		t.Errorf("persisted pattern not applied: X-My-Secret = %q", out.Get("X-My-Secret"))
	}
}

func TestCreateHttpTransactionRedactsHeaders(t *testing.T) {
	db := setupTestDB(t)

	txn, err := CreateHttpTransaction(db, HttpTransactionCreateInput{
		ContainerName:   "test-app",
		DestinationHost: "api.example.com",
		DestinationPort: 443,
		Method:          "POST",
		URL:             "https://api.example.com/v1/test",
		RequestHeaders: NewHeaderRedactor(nil).Redact(http.Header{
			"Authorization": {"Bearer sk-secret-key"},
			"Content-Type":  {"application/json"},
			"X-Api-Key":     {"key-123"},
		}),
		StatusCode: 200,
		ResponseHeaders: NewHeaderRedactor(nil).Redact(http.Header{
			"Content-Type": {"application/json"},
			"Set-Cookie":   {"session=abc123"},
		}),
		Result: "auto",
	})
	if err != nil {
		t.Fatalf("CreateHttpTransaction: %v", err)
	}

	// Verify headers in DB are redacted
	var reqHeaders map[string][]string
	if err := json.Unmarshal([]byte(txn.RequestHeaders.String), &reqHeaders); err != nil {
		t.Fatalf("unmarshal request headers: %v", err)
	}
	if v := reqHeaders["Authorization"]; len(v) != 1 || v[0] != RedactedValue {
		t.Errorf("stored Authorization = %v, want [%q]", v, RedactedValue)
	}
	if v := reqHeaders["X-Api-Key"]; len(v) != 1 || v[0] != RedactedValue {
		t.Errorf("stored X-Api-Key = %v, want [%q]", v, RedactedValue)
	}
	if v := reqHeaders["Content-Type"]; len(v) != 1 || v[0] != "application/json" {
		t.Errorf("stored Content-Type = %v, want [application/json]", v)
	}

	var respHeaders map[string][]string
	if err := json.Unmarshal([]byte(txn.ResponseHeaders.String), &respHeaders); err != nil {
		t.Fatalf("unmarshal response headers: %v", err)
	}
	if v := respHeaders["Set-Cookie"]; len(v) != 1 || v[0] != RedactedValue {
		t.Errorf("stored Set-Cookie = %v, want [%q]", v, RedactedValue)
	}
	if v := respHeaders["Content-Type"]; len(v) != 1 || v[0] != "application/json" {
		t.Errorf("stored Content-Type = %v, want [application/json]", v)
	}
}

func TestRedactExistingTransactionHeaders(t *testing.T) {
	db := setupTestDB(t)

	// Insert transactions with plaintext sensitive headers (simulating old data)
	for _, input := range []HttpTransactionCreateInput{
		{
			ContainerName:   "app1",
			DestinationHost: "api.example.com",
			DestinationPort: 443,
			Method:          "POST",
			URL:             "https://api.example.com/v1/data",
			RequestHeaders: http.Header{
				"Authorization": {"Bearer sk-secret-key"},
				"Content-Type":  {"application/json"},
				"X-Api-Key":     {"key-123"},
			},
			StatusCode: 200,
			ResponseHeaders: http.Header{
				"Content-Type": {"application/json"},
				"Set-Cookie":   {"session=abc123"},
			},
			Result: "auto",
		},
		{
			ContainerName:   "app2",
			DestinationHost: "other.example.com",
			DestinationPort: 443,
			Method:          "GET",
			URL:             "https://other.example.com/health",
			RequestHeaders: http.Header{
				"Accept": {"*/*"},
			},
			StatusCode: 200,
			Result:     "auto",
		},
	} {
		if _, err := CreateHttpTransaction(db, input); err != nil {
			t.Fatal(err)
		}
	}

	// Run batch redaction
	redactor := NewHeaderRedactor(nil)
	count, err := RedactExistingTransactionHeaders(db, redactor, nil)
	if err != nil {
		t.Fatalf("RedactExistingTransactionHeaders: %v", err)
	}
	if count != 2 {
		t.Errorf("processed %d rows, want 2", count)
	}

	// Verify first transaction's headers are redacted
	txn, err := GetHttpTransaction(db, 1)
	if err != nil {
		t.Fatal(err)
	}
	var reqHeaders map[string][]string
	if err := json.Unmarshal([]byte(txn.RequestHeaders.String), &reqHeaders); err != nil {
		t.Fatal(err)
	}
	if v := reqHeaders["Authorization"]; len(v) != 1 || v[0] != RedactedValue {
		t.Errorf("Authorization = %v, want [%q]", v, RedactedValue)
	}
	if v := reqHeaders["X-Api-Key"]; len(v) != 1 || v[0] != RedactedValue {
		t.Errorf("X-Api-Key = %v, want [%q]", v, RedactedValue)
	}
	if v := reqHeaders["Content-Type"]; len(v) != 1 || v[0] != "application/json" {
		t.Errorf("Content-Type = %v, want [application/json]", v)
	}

	var respHeaders map[string][]string
	if err := json.Unmarshal([]byte(txn.ResponseHeaders.String), &respHeaders); err != nil {
		t.Fatal(err)
	}
	if v := respHeaders["Set-Cookie"]; len(v) != 1 || v[0] != RedactedValue {
		t.Errorf("Set-Cookie = %v, want [%q]", v, RedactedValue)
	}

	// Verify second transaction is untouched (no sensitive headers)
	txn2, err := GetHttpTransaction(db, 2)
	if err != nil {
		t.Fatal(err)
	}
	var reqHeaders2 map[string][]string
	if err := json.Unmarshal([]byte(txn2.RequestHeaders.String), &reqHeaders2); err != nil {
		t.Fatal(err)
	}
	if v := reqHeaders2["Accept"]; len(v) != 1 || v[0] != "*/*" {
		t.Errorf("Accept = %v, want [*/*]", v)
	}

	// Running again should be idempotent
	count2, err := RedactExistingTransactionHeaders(db, redactor, nil)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if count2 != 2 {
		t.Errorf("second run processed %d rows, want 2", count2)
	}
}

func TestSettingsFileContainsRedactedHeaders(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "settings.json")
	m := NewSettingsManager(tmp, true)

	extra := []string{"X-Custom-Auth"}
	_, _ = m.Update(UserSettings{RedactedHeaders: extra})

	data, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatal(err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}

	headers, ok := raw["redactedHeaders"]
	if !ok {
		t.Fatal("settings file missing redactedHeaders field")
	}

	arr, ok := headers.([]any)
	if !ok || len(arr) != 1 {
		t.Fatalf("redactedHeaders = %v, want [X-Custom-Auth]", headers)
	}
	if arr[0] != "X-Custom-Auth" {
		t.Errorf("redactedHeaders[0] = %v, want X-Custom-Auth", arr[0])
	}
}
