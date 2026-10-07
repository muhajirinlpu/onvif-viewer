package local

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"

	"dengan.dev/camera-streamer/internal/recording/storage"
)

func TestLocalContract(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	body := "recorded bytes"
	digest := sha256.Sum256([]byte(body))
	obj := storage.ObjectInfo{Key: "camera/run/1.ts", Size: int64(len(body)), SHA256: hex.EncodeToString(digest[:]), ContentType: "video/mp2t"}
	for i := 0; i < 2; i++ {
		if err := s.Put(context.Background(), obj, strings.NewReader(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Put(context.Background(), obj, strings.NewReader("different bytes")); !errors.Is(err, storage.ErrIntegrity) {
		t.Fatalf("conflict: %v", err)
	}
	for _, key := range []string{"../escape", "/absolute", "camera/../../escape", "camera//empty"} {
		if err := s.Put(context.Background(), storage.ObjectInfo{Key: key}, strings.NewReader(body)); !errors.Is(err, storage.ErrInvalidKey) {
			t.Fatalf("key %q: %v", key, err)
		}
	}
	if _, err := s.Stat(context.Background(), "missing.ts"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatal(err)
	}
	r, info, err := s.Open(context.Background(), obj.Key, &storage.ByteRange{Offset: 2, Length: 4})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r)
	r.Close()
	if string(b) != "cord" || info.SHA256 != obj.SHA256 {
		t.Fatalf("range %q %+v", b, info)
	}
	if _, _, err := s.Open(context.Background(), obj.Key, &storage.ByteRange{Offset: -1, Length: 2}); !errors.Is(err, storage.ErrInvalidRange) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Put(ctx, obj, strings.NewReader(body)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := s.Delete(context.Background(), obj.Key); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Stat(context.Background(), obj.Key); !errors.Is(err, storage.ErrNotFound) {
		t.Fatal(err)
	}
}
