package secrets

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testKey generates a throwaway 32-byte key for this test run. Tests never read
// the real install key.
func testKey(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func TestSealOpenRoundTripAndNonceUniqueness(t *testing.T) {
	key := testKey(t)
	c, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	a, err := c.Seal("recording.s3.secret", []byte("private"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Seal("recording.s3.secret", []byte("private"))
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("identical plaintext produced identical ciphertext: nonce was reused")
	}
	raw, err := base64.StdEncoding.DecodeString(a)
	if err != nil {
		t.Fatalf("ciphertext is not single-column base64: %v", err)
	}
	if len(raw) < 12+16 {
		t.Fatalf("ciphertext too short to carry nonce||tag: %d", len(raw))
	}
	got, err := c.Open("recording.s3.secret", a)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "private" {
		t.Fatalf("round trip = %q", got)
	}
	// Empty plaintext must round trip too (an empty credential is meaningful).
	if _, err := c.Seal("recording.s3.session", nil); err != nil {
		t.Fatal(err)
	}
}

func TestTamperDetection(t *testing.T) {
	c, err := New(testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := c.Seal("recording.s3.secret", []byte("private"))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(sealed)
	// Flip a bit in every byte position, one at a time: tag, ciphertext and
	// nonce must all be authenticated.
	for i := range raw {
		broken := append([]byte(nil), raw...)
		broken[i] ^= 0x01
		if _, err := c.Open("recording.s3.secret", base64.StdEncoding.EncodeToString(broken)); err == nil {
			t.Fatalf("tampered ciphertext accepted at byte %d", i)
		}
	}
}

func TestWrongKeyRejected(t *testing.T) {
	first, _ := New(testKey(t))
	second, _ := New(testKey(t))
	sealed, err := first.Seal("recording.s3.secret", []byte("private"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Open("recording.s3.secret", sealed); err == nil {
		t.Fatal("a different key decrypted the value")
	}
}

func TestContextBindingRejectsReplay(t *testing.T) {
	c, _ := New(testKey(t))
	sealed, err := c.Seal("recording.s3.secret", []byte("private"))
	if err != nil {
		t.Fatal(err)
	}
	// The same key, the same ciphertext, a different field: must not decrypt.
	if _, err := c.Open("recording.s3.session", sealed); err == nil {
		t.Fatal("ciphertext replayed into another field was accepted")
	}
	if _, err := c.Open("", sealed); err == nil {
		t.Fatal("ciphertext stripped of its context was accepted")
	}
}

func TestMalformedKeyRejectedAndNeverLeaked(t *testing.T) {
	for _, bad := range []string{
		"",
		"secret-bad-key",
		base64.StdEncoding.EncodeToString([]byte("short")),
		base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 31)),
		base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 33)),
	} {
		c, err := New(bad)
		if err == nil {
			t.Fatalf("malformed key accepted: %q", bad)
		}
		if bad != "" && strings.Contains(err.Error(), bad) {
			t.Fatalf("the rejected key leaked into the error: %v", err)
		}
		if c != nil {
			t.Fatal("a cipher was returned alongside a rejected key")
		}
	}
}

func TestMalformedCiphertextRejected(t *testing.T) {
	c, _ := New(testKey(t))
	for _, bad := range []string{
		"",
		"garbage",
		"AA==",
		base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0}, 12)), // nonce only, no tag
	} {
		if _, err := c.Open("recording.s3.secret", bad); err == nil {
			t.Fatalf("malformed ciphertext accepted: %q", bad)
		}
	}
}

func TestLoadResolvesEnvThenFileAndRejectsMissing(t *testing.T) {
	key := testKey(t)
	lookup := func(values map[string]string) func(string) string {
		return func(name string) string { return values[name] }
	}
	// Environment wins when present.
	env := lookup(map[string]string{EnvAppKey: key})
	c, err := LoadFrom(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Seal("x", []byte("y")); err != nil {
		t.Fatal(err)
	}
	// A file is used when the environment is empty.
	dir := t.TempDir()
	path := filepath.Join(dir, "app-key")
	if err := os.WriteFile(path, []byte(key+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c, err = LoadFrom(lookup(map[string]string{EnvAppKeyFile: path}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Seal("x", []byte("y")); err != nil {
		t.Fatal(err)
	}
	// Nothing configured is a clear error, not a silent empty key.
	if _, err := LoadFrom(lookup(map[string]string{EnvAppKeyFile: filepath.Join(dir, "absent")})); err == nil {
		t.Fatal("a missing app key was treated as usable")
	}
	if _, err := LoadFrom(lookup(nil)); err == nil {
		t.Fatal("an unconfigured app key was treated as usable")
	}
}

func TestLoadWarnsOnLooseFilePermissions(t *testing.T) {
	key := testKey(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "app-key")
	if err := os.WriteFile(path, []byte(key), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFrom(func(name string) string {
		if name == EnvAppKeyFile {
			return path
		}
		return ""
	}); err == nil {
		t.Fatal("a world-readable app key file was accepted")
	}
}
