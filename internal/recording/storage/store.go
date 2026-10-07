// Package storage defines a byte-only object store. Metadata and retention belong to recording.
package storage

import (
	"context"
	"errors"
	"io"
	"path"
	"strings"
)

var (
	ErrNotFound     = errors.New("object not found")
	ErrInvalidKey   = errors.New("invalid object key")
	ErrIntegrity    = errors.New("object integrity conflict")
	ErrInvalidRange = errors.New("invalid byte range")
)

type ObjectInfo struct {
	Key         string
	Size        int64
	SHA256      string
	ContentType string
}
type ByteRange struct {
	Offset int64
	Length int64
}
type Store interface {
	Put(context.Context, ObjectInfo, io.Reader) error
	Stat(context.Context, string) (ObjectInfo, error)
	Open(context.Context, string, *ByteRange) (io.ReadCloser, ObjectInfo, error)
	Delete(context.Context, string) error
}

func ValidateKey(key string) error {
	if key == "" || strings.Contains(key, "\\") || strings.ContainsRune(key, 0) || strings.Contains(key, "//") || strings.HasPrefix(key, "/") || path.Clean(key) != key || strings.HasPrefix(key, "../") || key == ".." {
		return ErrInvalidKey
	}
	for _, p := range strings.Split(key, "/") {
		if p == "." || p == ".." || p == "" {
			return ErrInvalidKey
		}
	}
	return nil
}
func ValidateRange(span *ByteRange, size int64) error {
	if span != nil && (span.Offset < 0 || span.Length <= 0 || span.Offset >= size || span.Length > size-span.Offset) {
		return ErrInvalidRange
	}
	return nil
}
