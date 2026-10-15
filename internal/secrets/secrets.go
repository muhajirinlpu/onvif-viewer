// Package secrets seals small credential values at rest under a single
// application key, in the shape Laravel uses: one base64-encoded 32-byte key,
// loaded once, never logged and never returned.
//
// AES-256-GCM is used with a fresh random 12-byte nonce per value. The wire
// value is base64(nonce || ciphertext || tag) in one column, which is what lets
// a sealed credential live beside plaintext configuration in the same row.
//
// Each value is bound to a caller-supplied context string through the GCM
// additional-authenticated-data. That is what stops a sealed S3 secret from
// being replayed into the session-token column: the bytes decrypt only under
// the exact field they were sealed for.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	// EnvAppKey is the environment variable holding the base64 app key.
	EnvAppKey = "ONVIF_APP_KEY"
	// EnvAppKeyFile is the path to a 0600 file holding the same value, used
	// when the install keeps its key on disk instead of in the unit file.
	EnvAppKeyFile = "ONVIF_APP_KEY_FILE"
	// KeyBytes is the required decoded key length.
	KeyBytes = 32
)

// ErrUnavailable means no app key is configured. It is reported rather than
// silently substituting an empty key, because the S3 driver must refuse to run
// without a real one.
var ErrUnavailable = errors.New("an application key is required")

// Cipher seals and opens values under one validated key.
type Cipher struct {
	aead cipher.AEAD
}

// New validates a base64-encoded 32-byte key. The key is never echoed: the
// error names only the rule that was broken.
func New(encoded string) (*Cipher, error) {
	if strings.TrimSpace(encoded) == "" {
		return nil, ErrUnavailable
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, errors.New("the application key is not valid base64")
	}
	if len(raw) != KeyBytes {
		return nil, fmt.Errorf("the application key must decode to exactly %d bytes", KeyBytes)
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, errors.New("the application key is unusable for AES-256")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("the application key cannot be used for GCM")
	}
	return &Cipher{aead: aead}, nil
}

// LoadFrom resolves the key from the environment, falling back to a key file.
// The file must not be readable by anyone but its owner: a world-readable key
// file is reported as a configuration error rather than used.
func LoadFrom(getenv func(string) string) (*Cipher, error) {
	if getenv == nil {
		return nil, ErrUnavailable
	}
	if encoded := strings.TrimSpace(getenv(EnvAppKey)); encoded != "" {
		return New(encoded)
	}
	path := strings.TrimSpace(getenv(EnvAppKeyFile))
	if path == "" {
		return nil, ErrUnavailable
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("the application key file %s is unreadable", path)
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("the application key file %s must not be readable by group or others (mode %04o)", path, info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("the application key file %s is unreadable", path)
	}
	return New(string(data))
}

// Seal encrypts plaintext for the named context. The context is authenticated,
// so a value cannot be replayed into a different field.
func (c *Cipher) Seal(context string, plaintext []byte) (string, error) {
	if c == nil || c.aead == nil {
		return "", ErrUnavailable
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", errors.New("a random nonce could not be generated")
	}
	sealed := c.aead.Seal(nonce, nonce, plaintext, []byte(context))
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Open decrypts a value sealed for the named context. A wrong key, a wrong
// context and a tampered value all fail closed.
func (c *Cipher) Open(context, value string) ([]byte, error) {
	if c == nil || c.aead == nil {
		return nil, ErrUnavailable
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, errors.New("the sealed value is not valid base64")
	}
	nonceSize := c.aead.NonceSize()
	if len(raw) < nonceSize+c.aead.Overhead() {
		return nil, errors.New("the sealed value is truncated")
	}
	plaintext, err := c.aead.Open(nil, raw[:nonceSize], raw[nonceSize:], []byte(context))
	if err != nil {
		return nil, errors.New("the sealed value failed authentication")
	}
	return plaintext, nil
}
