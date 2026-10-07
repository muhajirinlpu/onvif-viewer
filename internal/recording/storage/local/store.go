package local

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"dengan.dev/camera-streamer/internal/recording/storage"
)

type Store struct{ Root string }

func (s *Store) LocalRoot() string { return s.Root }

func New(root string) (*Store, error) {
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	return &Store{Root: abs}, nil
}
func (s *Store) location(key string) (string, error) {
	if err := storage.ValidateKey(key); err != nil {
		return "", err
	}
	p := s.Root
	parts := filepath.SplitList("")
	_ = parts
	for _, part := range splitKey(key) {
		p = filepath.Join(p, part)
		if fi, err := os.Lstat(p); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			return "", storage.ErrInvalidKey
		} else if err != nil && !os.IsNotExist(err) {
			return "", err
		}
	}
	return p, nil
}
func splitKey(k string) []string {
	var out []string
	for _, p := range filepath.SplitList(k) {
		_ = p
	}
	start := 0
	for i := 0; i < len(k); i++ {
		if k[i] == '/' {
			out = append(out, k[start:i])
			start = i + 1
		}
	}
	return append(out, k[start:])
}
func (s *Store) Put(ctx context.Context, o storage.ObjectInfo, body io.Reader) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p, err := s.location(o.Key)
	if err != nil {
		return err
	}
	if o.Size < 0 || len(o.SHA256) != 64 {
		return storage.ErrIntegrity
	}
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(p), ".stage-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	h := sha256.New()
	buf := make([]byte, 32768)
	var n int64
	for {
		if err = ctx.Err(); err != nil {
			f.Close()
			return err
		}
		var nr int
		nr, err = body.Read(buf)
		if nr > 0 {
			n += int64(nr)
			if n > o.Size {
				f.Close()
				return storage.ErrIntegrity
			}
			if _, e := f.Write(buf[:nr]); e != nil {
				f.Close()
				return e
			}
			h.Write(buf[:nr])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			f.Close()
			return err
		}
		if nr == 0 {
			f.Close()
			return io.ErrNoProgress
		}
	}
	if n != o.Size || hex.EncodeToString(h.Sum(nil)) != o.SHA256 {
		f.Close()
		return storage.ErrIntegrity
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	// Hard links make publication atomic and forbid replacement of an existing key.
	if err = os.Link(f.Name(), p); err != nil {
		if errors.Is(err, syscall.EEXIST) {
			existing, e := s.Stat(ctx, o.Key)
			if e != nil {
				return e
			}
			if existing.Size == o.Size && existing.SHA256 == o.SHA256 {
				return nil
			}
			return storage.ErrIntegrity
		}
		return err
	}
	if d, e := os.Open(filepath.Dir(p)); e == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
func (s *Store) Stat(ctx context.Context, key string) (storage.ObjectInfo, error) {
	r, o, err := s.Open(ctx, key, nil)
	if err != nil {
		return o, err
	}
	r.Close()
	return o, nil
}
func (s *Store) Open(ctx context.Context, key string, span *storage.ByteRange) (io.ReadCloser, storage.ObjectInfo, error) {
	var zero storage.ObjectInfo
	if err := ctx.Err(); err != nil {
		return nil, zero, err
	}
	p, err := s.location(key)
	if err != nil {
		return nil, zero, err
	}
	f, err := os.Open(p)
	if os.IsNotExist(err) {
		return nil, zero, storage.ErrNotFound
	}
	if err != nil {
		return nil, zero, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, zero, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, zero, storage.ErrInvalidKey
	}
	o := storage.ObjectInfo{Key: key, Size: fi.Size(), ContentType: "video/mp2t"}
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		f.Close()
		return nil, zero, err
	}
	o.SHA256 = hex.EncodeToString(h.Sum(nil))
	if err = storage.ValidateRange(span, o.Size); err != nil {
		f.Close()
		return nil, zero, err
	}
	offset, length := int64(0), o.Size
	if span != nil {
		offset, length = span.Offset, span.Length
	}
	if _, err = f.Seek(offset, io.SeekStart); err != nil {
		f.Close()
		return nil, zero, err
	}
	return struct {
		io.Reader
		io.Closer
	}{io.LimitReader(f, length), f}, o, nil
}
func (s *Store) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p, err := s.location(key)
	if err != nil {
		return err
	}
	if err = os.Remove(p); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove object: %w", err)
	}
	return nil
}
