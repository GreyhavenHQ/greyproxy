package greyproxy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	// sessionKeyFile is the filename for the encryption master key.
	sessionKeyFile = "session.key"
	// sessionKeySize is the AES-256 key size in bytes.
	sessionKeySize = 32

	// PlaceholderPrefix is the prefix used to identify credential placeholders.
	PlaceholderPrefix = "greyproxy:credential:"
	// PlaceholderVersion is the current placeholder format version.
	PlaceholderVersion = "v1"
	// placeholderRandomBytes is the number of random bytes in the hex tail.
	placeholderRandomBytes = 16
)

// LoadOrGenerateKey loads the master encryption key from dataDir/session.key,
// or generates a new one if the file does not exist.
// Returns the 32-byte key and whether a new key was generated.
// If the file exists but has the wrong size, an error is returned rather than
// silently overwriting (which would make all stored credentials unreadable).
func LoadOrGenerateKey(dataDir string) ([]byte, bool, error) {
	keyPath := filepath.Join(dataDir, sessionKeyFile)

	data, err := os.ReadFile(keyPath)
	if err == nil {
		if len(data) == sessionKeySize {
			return data, false, nil
		}
		return nil, false, fmt.Errorf("encryption key file %s is corrupt (got %d bytes, want %d); "+
			"delete it manually to generate a new key (existing encrypted credentials will be lost)",
			keyPath, len(data), sessionKeySize)
	}

	if !os.IsNotExist(err) {
		return nil, false, fmt.Errorf("read key file: %w", err)
	}

	// File does not exist; generate new key
	key := make([]byte, sessionKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, false, fmt.Errorf("generate key: %w", err)
	}

	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, false, fmt.Errorf("create data dir: %w", err)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		return nil, false, fmt.Errorf("write key file: %w", err)
	}

	return key, true, nil
}

// Encrypt encrypts plaintext using AES-256-GCM with the given key.
// Returns nonce (12 bytes) || ciphertext || GCM tag (16 bytes).
func Encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts data encrypted by Encrypt using AES-256-GCM.
// Expects input format: nonce (12 bytes) || ciphertext || GCM tag (16 bytes).
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ct, nil)
}

// GeneratePlaceholder creates a credential placeholder string.
// Format: greyproxy:credential:v1:<sessionID>:<32_hex_chars>
func GeneratePlaceholder(sessionID string) (string, error) {
	b := make([]byte, placeholderRandomBytes)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("generate random: %w", err)
	}
	return fmt.Sprintf("%s%s:%s:%s", PlaceholderPrefix, PlaceholderVersion, sessionID, hex.EncodeToString(b)), nil
}

// MaskCredentialValue returns a masked preview of a credential value.
// Shows first 6 + last 3 chars for values >= 9 chars, otherwise masks all but last 2.
func MaskCredentialValue(value string) string {
	if len(value) >= 9 {
		return value[:6] + "***" + value[len(value)-3:]
	}
	if len(value) <= 2 {
		return "***"
	}
	return "***" + value[len(value)-2:]
}
