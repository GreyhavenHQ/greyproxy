package greyproxy

import (
	"strings"
	"testing"
)

func enabledConfig() PIIFilterConfig {
	return PIIFilterConfig{
		Enabled: true,
		Action:  "redact",
		Types: map[string]bool{
			"email":       true,
			"phone":       true,
			"ssn":         true,
			"credit_card": true,
			"ip_address":  true,
		},
	}
}

func TestPIIFilter_Email(t *testing.T) {
	f := NewPIIFilter(enabledConfig())
	body := []byte(`Send to user@example.com please`)
	result, err := f.ScanAndRedact(body, "application/json")
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.MatchCount != 1 {
		t.Fatalf("expected 1 match, got %d", result.MatchCount)
	}
	if !strings.Contains(string(result.RedactedBody), "[PII_EMAIL_1]") {
		t.Fatalf("expected placeholder, got: %s", result.RedactedBody)
	}
	if strings.Contains(string(result.RedactedBody), "user@example.com") {
		t.Fatal("original email should be redacted")
	}
}

func TestPIIFilter_SSN(t *testing.T) {
	f := NewPIIFilter(enabledConfig())
	body := []byte(`SSN is 123-45-6789`)
	result, err := f.ScanAndRedact(body, "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	if !strings.Contains(string(result.RedactedBody), "[PII_SSN_1]") {
		t.Fatalf("expected SSN placeholder, got: %s", result.RedactedBody)
	}
}

func TestPIIFilter_Phone(t *testing.T) {
	f := NewPIIFilter(enabledConfig())
	body := []byte(`Call 555-123-4567 or (555) 987-6543`)
	result, err := f.ScanAndRedact(body, "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	if result.MatchCount < 2 {
		t.Fatalf("expected at least 2 matches, got %d", result.MatchCount)
	}
}

func TestPIIFilter_CreditCard_Luhn(t *testing.T) {
	f := NewPIIFilter(enabledConfig())
	// Valid Visa test number
	body := []byte(`Card: 4111111111111111`)
	result, err := f.ScanAndRedact(body, "application/json")
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected result for valid card")
	}
	if !strings.Contains(string(result.RedactedBody), "[PII_CREDIT_CARD_1]") {
		t.Fatalf("expected credit card placeholder, got: %s", result.RedactedBody)
	}

	// Invalid number (fails Luhn)
	body2 := []byte(`Card: 1234567890123456`)
	result2, err := f.ScanAndRedact(body2, "application/json")
	if err != nil {
		t.Fatal(err)
	}
	if result2 != nil {
		t.Fatal("expected nil result for invalid card number")
	}
}

func TestPIIFilter_IPAddress_SkipPrivate(t *testing.T) {
	f := NewPIIFilter(enabledConfig())

	// Public IP should be redacted
	body := []byte(`Server at 8.8.8.8`)
	result, err := f.ScanAndRedact(body, "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected result for public IP")
	}
	if !strings.Contains(string(result.RedactedBody), "[PII_IP_ADDRESS_1]") {
		t.Fatalf("expected IP placeholder, got: %s", result.RedactedBody)
	}

	// Private IPs should be skipped
	for _, ip := range []string{"192.168.1.1", "10.0.0.1", "172.16.0.1", "127.0.0.1"} {
		body := []byte("Server at " + ip)
		result, err := f.ScanAndRedact(body, "text/plain")
		if err != nil {
			t.Fatal(err)
		}
		if result != nil {
			t.Fatalf("expected nil result for private IP %s, got match count %d", ip, result.MatchCount)
		}
	}
}

func TestPIIFilter_Allowlist(t *testing.T) {
	cfg := enabledConfig()
	cfg.Allowlist = []string{"admin@example.com"}
	f := NewPIIFilter(cfg)

	body := []byte(`Contact admin@example.com or user@example.com`)
	result, err := f.ScanAndRedact(body, "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	// admin@example.com should NOT be redacted
	if !strings.Contains(string(result.RedactedBody), "admin@example.com") {
		t.Fatal("allowlisted email should not be redacted")
	}
	// user@example.com should be redacted
	if strings.Contains(string(result.RedactedBody), "user@example.com") {
		t.Fatal("non-allowlisted email should be redacted")
	}
	if result.MatchCount != 1 {
		t.Fatalf("expected 1 match (only user@), got %d", result.MatchCount)
	}
}

func TestPIIFilter_PlaceholderNumbering(t *testing.T) {
	f := NewPIIFilter(enabledConfig())
	body := []byte(`Emails: a@b.com and c@d.com and e@f.com`)
	result, err := f.ScanAndRedact(body, "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	s := string(result.RedactedBody)
	// Since we process in reverse, the numbering might be reversed.
	// But there should be 3 distinct numbered placeholders.
	if result.MatchCount != 3 {
		t.Fatalf("expected 3 matches, got %d", result.MatchCount)
	}
	if !strings.Contains(s, "[PII_EMAIL_1]") || !strings.Contains(s, "[PII_EMAIL_2]") || !strings.Contains(s, "[PII_EMAIL_3]") {
		t.Fatalf("expected 3 numbered placeholders, got: %s", s)
	}
}

func TestPIIFilter_ContentTypeSkip(t *testing.T) {
	f := NewPIIFilter(enabledConfig())
	body := []byte(`user@example.com`)
	result, err := f.ScanAndRedact(body, "image/png")
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Fatal("expected nil for binary content type")
	}
}

func TestPIIFilter_EmptyBody(t *testing.T) {
	f := NewPIIFilter(enabledConfig())
	result, err := f.ScanAndRedact(nil, "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Fatal("expected nil for empty body")
	}
}

func TestPIIFilter_Disabled(t *testing.T) {
	cfg := enabledConfig()
	cfg.Enabled = false
	f := NewPIIFilter(cfg)
	body := []byte(`user@example.com`)
	result, err := f.ScanAndRedact(body, "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Fatal("expected nil when disabled")
	}
}

func TestPIIFilter_BlockMode(t *testing.T) {
	cfg := enabledConfig()
	cfg.Action = "block"
	f := NewPIIFilter(cfg)
	body := []byte(`SSN: 123-45-6789`)
	result, err := f.ScanAndRedact(body, "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	if !result.Blocked {
		t.Fatal("expected Blocked to be true")
	}
	if result.RedactedBody != nil {
		t.Fatal("expected nil RedactedBody in block mode")
	}
}

func TestPIIFilter_TypeLabels(t *testing.T) {
	f := NewPIIFilter(enabledConfig())
	body := []byte(`Email: user@example.com SSN: 123-45-6789`)
	result, err := f.ScanAndRedact(body, "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	labels := make(map[string]bool)
	for _, l := range result.TypeLabels {
		labels[l] = true
	}
	if !labels["email"] || !labels["ssn"] {
		t.Fatalf("expected email and ssn in type labels, got %v", result.TypeLabels)
	}
}

func TestPIIFilter_SelectiveTypes(t *testing.T) {
	cfg := enabledConfig()
	cfg.Types = map[string]bool{
		"email":       true,
		"phone":       false,
		"ssn":         false,
		"credit_card": false,
		"ip_address":  false,
	}
	f := NewPIIFilter(cfg)
	body := []byte(`Email: user@example.com SSN: 123-45-6789`)
	result, err := f.ScanAndRedact(body, "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	// Only email should be detected
	if result.MatchCount != 1 {
		t.Fatalf("expected 1 match (email only), got %d", result.MatchCount)
	}
	if !strings.Contains(string(result.RedactedBody), "[PII_EMAIL_1]") {
		t.Fatal("expected email placeholder")
	}
	if !strings.Contains(string(result.RedactedBody), "123-45-6789") {
		t.Fatal("SSN should not be redacted when type is disabled")
	}
}

func TestPIIFilter_UpdateConfig(t *testing.T) {
	cfg := enabledConfig()
	f := NewPIIFilter(cfg)

	body := []byte(`user@example.com`)
	result, _ := f.ScanAndRedact(body, "text/plain")
	if result == nil {
		t.Fatal("expected result when enabled")
	}

	// Disable
	cfg.Enabled = false
	f.UpdateConfig(cfg)
	result, _ = f.ScanAndRedact(body, "text/plain")
	if result != nil {
		t.Fatal("expected nil when disabled")
	}

	// Re-enable
	cfg.Enabled = true
	f.UpdateConfig(cfg)
	result, _ = f.ScanAndRedact(body, "text/plain")
	if result == nil {
		t.Fatal("expected result when re-enabled")
	}
}

func TestPIIFilter_LargeBodySkip(t *testing.T) {
	f := NewPIIFilter(enabledConfig())
	// Create body larger than 10MB
	body := make([]byte, maxPIIBodySize+1)
	for i := range body {
		body[i] = 'a'
	}
	result, err := f.ScanAndRedact(body, "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Fatal("expected nil for large body")
	}
}

func TestLuhnValid(t *testing.T) {
	tests := []struct {
		input string
		valid bool
	}{
		{"4111111111111111", true},    // Visa test
		{"5500000000000004", true},    // Mastercard test
		{"340000000000009", true},     // Amex test
		{"1234567890123456", false},   // Invalid
		{"0000000000000000", true},    // All zeros passes Luhn
		{"4111-1111-1111-1111", true}, // With dashes
	}
	for _, tt := range tests {
		got := luhnValid(tt.input)
		if got != tt.valid {
			t.Errorf("luhnValid(%q) = %v, want %v", tt.input, got, tt.valid)
		}
	}
}

func TestIsPublicIP(t *testing.T) {
	tests := []struct {
		ip     string
		public bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"192.168.1.1", false},
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"172.31.255.255", false},
		{"172.15.0.1", true},
		{"172.32.0.1", true},
		{"127.0.0.1", false},
		{"0.0.0.0", false},
		{"169.254.1.1", false},
	}
	for _, tt := range tests {
		got := isPublicIP(tt.ip)
		if got != tt.public {
			t.Errorf("isPublicIP(%q) = %v, want %v", tt.ip, got, tt.public)
		}
	}
}

func TestPIIIsTextContentType(t *testing.T) {
	tests := []struct {
		ct   string
		text bool
	}{
		{"application/json", true},
		{"application/json; charset=utf-8", true},
		{"text/plain", true},
		{"text/html", true},
		{"image/png", false},
		{"application/octet-stream", false},
		{"application/vnd.api+json", true},
		{"application/xml", true},
		{"application/x-www-form-urlencoded", true},
		{"", true},
	}
	for _, tt := range tests {
		got := piiIsTextContentType(tt.ct)
		if got != tt.text {
			t.Errorf("piiIsTextContentType(%q) = %v, want %v", tt.ct, got, tt.text)
		}
	}
}
