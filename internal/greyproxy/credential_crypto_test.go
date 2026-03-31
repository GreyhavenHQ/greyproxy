package greyproxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := make([]byte, sessionKeySize)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("sk-ant-api03-real-secret-key-value")

	encrypted, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	if len(encrypted) <= len(plaintext) {
		t.Error("encrypted data should be longer than plaintext (nonce + tag)")
	}

	decrypted, err := Decrypt(key, encrypted)
	if err != nil {
		t.Fatal(err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptProducesDifferentCiphertexts(t *testing.T) {
	key := make([]byte, sessionKeySize)
	plaintext := []byte("same-input")

	enc1, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	enc2, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	if string(enc1) == string(enc2) {
		t.Error("two encryptions of the same plaintext should produce different ciphertext (random nonce)")
	}
}

func TestDecryptTamperedCiphertext(t *testing.T) {
	key := make([]byte, sessionKeySize)
	plaintext := []byte("sensitive-data")

	encrypted, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with a byte in the ciphertext
	encrypted[len(encrypted)-1] ^= 0xff

	_, err = Decrypt(key, encrypted)
	if err == nil {
		t.Error("expected error when decrypting tampered ciphertext")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1 := make([]byte, sessionKeySize)
	key2 := make([]byte, sessionKeySize)
	key2[0] = 1

	encrypted, err := Encrypt(key1, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = Decrypt(key2, encrypted)
	if err == nil {
		t.Error("expected error when decrypting with wrong key")
	}
}

func TestDecryptTooShortCiphertext(t *testing.T) {
	key := make([]byte, sessionKeySize)
	_, err := Decrypt(key, []byte("short"))
	if err == nil {
		t.Error("expected error for short ciphertext")
	}
}

func TestLoadOrGenerateKey_NewKey(t *testing.T) {
	dir := t.TempDir()

	key, isNew, err := LoadOrGenerateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !isNew {
		t.Error("expected isNew=true for first call")
	}
	if len(key) != sessionKeySize {
		t.Errorf("key length = %d, want %d", len(key), sessionKeySize)
	}

	// Verify file exists with correct permissions
	info, err := os.Stat(filepath.Join(dir, sessionKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key file permissions = %o, want 0600", info.Mode().Perm())
	}
}

func TestLoadOrGenerateKey_ExistingKey(t *testing.T) {
	dir := t.TempDir()

	key1, _, err := LoadOrGenerateKey(dir)
	if err != nil {
		t.Fatal(err)
	}

	key2, isNew, err := LoadOrGenerateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if isNew {
		t.Error("expected isNew=false for second call")
	}
	if string(key1) != string(key2) {
		t.Error("second load should return same key")
	}
}

func TestLoadOrGenerateKey_CorruptKeyFile(t *testing.T) {
	dir := t.TempDir()

	// Write a corrupt (too short) key file
	if err := os.WriteFile(filepath.Join(dir, sessionKeyFile), []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, err := LoadOrGenerateKey(dir)
	if err == nil {
		t.Fatal("expected error when key file is corrupt")
	}
	if !strings.Contains(err.Error(), "corrupt") {
		t.Errorf("error should mention corruption, got: %v", err)
	}
}

func TestLoadOrGenerateKey_UnreadableKeyFile(t *testing.T) {
	dir := t.TempDir()

	// Write a key file with no read permissions
	keyPath := filepath.Join(dir, sessionKeyFile)
	if err := os.WriteFile(keyPath, []byte("data"), 0o000); err != nil {
		t.Fatal(err)
	}

	_, _, err := LoadOrGenerateKey(dir)
	if err == nil {
		t.Fatal("expected error when key file is unreadable")
	}
}

func TestGeneratePlaceholder(t *testing.T) {
	p, err := GeneratePlaceholder("gw-test123")
	if err != nil {
		t.Fatal(err)
	}

	if len(p) == 0 {
		t.Error("placeholder should not be empty")
	}

	// Check prefix
	expected := PlaceholderPrefix + PlaceholderVersion + ":gw-test123:"
	if p[:len(expected)] != expected {
		t.Errorf("placeholder prefix = %q, want %q", p[:len(expected)], expected)
	}

	// Check hex tail length (32 hex chars = 16 bytes)
	tail := p[len(expected):]
	if len(tail) != 32 {
		t.Errorf("hex tail length = %d, want 32", len(tail))
	}
}

func TestGeneratePlaceholder_Uniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 10000; i++ {
		p, err := GeneratePlaceholder("test")
		if err != nil {
			t.Fatal(err)
		}
		if seen[p] {
			t.Fatalf("duplicate placeholder at iteration %d", i)
		}
		seen[p] = true
	}
}

func TestGeneratePlaceholder_Global(t *testing.T) {
	p, err := GeneratePlaceholder("global")
	if err != nil {
		t.Fatal(err)
	}
	expected := PlaceholderPrefix + PlaceholderVersion + ":global:"
	if p[:len(expected)] != expected {
		t.Errorf("global placeholder prefix = %q, want %q", p[:len(expected)], expected)
	}
}

func TestMaskCredentialValue(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"sk-ant-api03-abcdef-xyz", "sk-ant***xyz"},
		{"short", "***rt"},
		{"ab", "***"},
		{"", "***"},
		{"123456789", "123456***789"},
		{"12345678", "***78"},
	}
	for _, tt := range tests {
		got := MaskCredentialValue(tt.input)
		if got != tt.want {
			t.Errorf("MaskCredentialValue(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
