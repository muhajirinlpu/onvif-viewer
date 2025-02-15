package main

import (
	"testing"
)

func TestCalculatePasswordDigest(t *testing.T) {
	nonce := "mTpUsu30WzGhSlyyGBlhU3Mc72E="
	created := "2025-02-11T06:33:41.605Z"
	password := "password"
	expected := "qubmdsJ+YZQpXgpWPslB9ZG9hbk="
	actual := calculatePasswordDigest(nonce, created, password)

	if actual != expected {
		t.Errorf("Expected %s but got %s", expected, actual)
	}
}
