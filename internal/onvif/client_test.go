package onvif

import "testing"

func TestCalculatePasswordDigest(t *testing.T) {
	nonce := "mTpUsu30WzGhSlyyGBlhU3Mc72E="
	created := "2025-02-11T06:33:41.605Z"
	password := "password"
	expected := "qubmdsJ+YZQpXgpWPslB9ZG9hbk="
	if actual := calculatePasswordDigest(nonce, created, password); actual != expected {
		t.Fatalf("calculatePasswordDigest() = %s, want %s", actual, expected)
	}
}
