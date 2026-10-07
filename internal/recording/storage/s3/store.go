// Package s3 implements a private, path-style S3-compatible byte store using SigV4.
// It has no bucket-discovery or ACL operations. Real endpoint interoperability requires
// a user-provided disposable bucket test before enabling production recordings.
package s3

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"dengan.dev/camera-streamer/internal/recording/storage"
)

type Config struct {
	Endpoint, Bucket, Region, AccessKey, SecretKey, SessionToken string
	AllowHTTP                                                    bool
	Client                                                       *http.Client
	SpoolDir                                                     string
}
type Store struct {
	cfg    Config
	base   *url.URL
	client *http.Client
}

func New(c Config) (*Store, error) {
	u, e := url.Parse(c.Endpoint)
	if e != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && c.AllowHTTP)) || c.Bucket == "" || strings.ContainsAny(c.Bucket, "/\\") || c.Region == "" || c.AccessKey == "" || c.SecretKey == "" {
		return nil, errors.New("S3 requires endpoint, private bucket, region and credentials (HTTPS unless explicitly allowed)")
	}
	cl := c.Client
	if cl == nil {
		cl = &http.Client{Timeout: 60 * time.Second}
	}
	return &Store{c, u, cl}, nil
}
func sign(key []byte, text string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(text))
	return mac.Sum(nil)
}
func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func (s *Store) request(ctx context.Context, method, key string, body io.Reader, payloadHash string, headers http.Header) (*http.Response, error) {
	if e := storage.ValidateKey(key); e != nil {
		return nil, e
	}
	u := *s.base
	u.Path = path.Join(u.Path, s.cfg.Bucket, key)
	u.RawPath = ""
	req, e := http.NewRequestWithContext(ctx, method, u.String(), body)
	if e != nil {
		return nil, e
	}
	for k, v := range headers {
		req.Header[k] = v
	}
	now := time.Now().UTC()
	date := now.Format("20060102")
	stamp := now.Format("20060102T150405Z")
	req.Header.Set("x-amz-date", stamp)
	req.Header.Set("x-amz-content-sha256", payloadHash)
	if s.cfg.SessionToken != "" {
		req.Header.Set("x-amz-security-token", s.cfg.SessionToken)
	}
	// SigV4 requires lexicographically sorted canonical header names.
	signed := []string{}
	canonical := ""
	names := []string{"content-type", "host", "range", "x-amz-content-sha256", "x-amz-date", "x-amz-meta-sha256", "x-amz-security-token"}
	for _, name := range names {
		value := req.Header.Get(name)
		if name == "host" {
			value = req.URL.Host
		}
		if value != "" {
			signed = append(signed, name)
			canonical += name + ":" + strings.TrimSpace(value) + "\n"
		}
	}
	signedNames := strings.Join(signed, ";")
	uri := req.URL.EscapedPath()
	if uri == "" {
		uri = "/"
	}
	canonicalRequest := method + "\n" + uri + "\n" + req.URL.Query().Encode() + "\n" + canonical + "\n" + signedNames + "\n" + payloadHash
	scope := date + "/" + s.cfg.Region + "/s3/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + stamp + "\n" + scope + "\n" + hash([]byte(canonicalRequest))
	k := sign([]byte("AWS4"+s.cfg.SecretKey), date)
	k = sign(k, s.cfg.Region)
	k = sign(k, "s3")
	k = sign(k, "aws4_request")
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+s.cfg.AccessKey+"/"+scope+", SignedHeaders="+signedNames+", Signature="+hex.EncodeToString(sign(k, toSign)))
	return s.client.Do(req)
}
func (s *Store) Stat(ctx context.Context, key string) (storage.ObjectInfo, error) {
	resp, e := s.request(ctx, "HEAD", key, nil, hash(nil), nil)
	if e != nil {
		return storage.ObjectInfo{}, e
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return storage.ObjectInfo{}, storage.ErrNotFound
	}
	if resp.StatusCode != 200 {
		return storage.ObjectInfo{}, fmt.Errorf("S3 HEAD status %d", resp.StatusCode)
	}
	size, e := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
	if e != nil {
		return storage.ObjectInfo{}, e
	}
	return storage.ObjectInfo{Key: key, Size: size, SHA256: resp.Header.Get("X-Amz-Meta-Sha256"), ContentType: resp.Header.Get("Content-Type")}, nil
}
func (s *Store) Put(ctx context.Context, o storage.ObjectInfo, body io.Reader) error {
	if e := storage.ValidateKey(o.Key); e != nil {
		return e
	}
	if o.Size < 0 || len(o.SHA256) != 64 {
		return storage.ErrIntegrity
	}
	if existing, e := s.Stat(ctx, o.Key); e == nil {
		if existing.Size == o.Size && existing.SHA256 == o.SHA256 {
			return nil
		}
		return storage.ErrIntegrity
	} else if !errors.Is(e, storage.ErrNotFound) {
		return e
	}
	// Spool once to compute SigV4 payload hash; bounded to declared object size.
	dir := s.cfg.SpoolDir
	if dir == "" {
		dir = os.Getenv("TMPDIR")
	}
	if dir == "" {
		return errors.New("S3 spool requires a home-backed TMPDIR or SpoolDir")
	}
	f, e := os.CreateTemp(dir, "s3-upload-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(f, h), io.LimitReader(body, o.Size+1))
	if e != nil {
		return e
	}
	if n != o.Size || hex.EncodeToString(h.Sum(nil)) != o.SHA256 {
		return storage.ErrIntegrity
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return e
	}
	headers := http.Header{}
	headers.Set("Content-Type", o.ContentType)
	headers.Set("X-Amz-Meta-Sha256", o.SHA256)
	resp, e := s.request(ctx, "PUT", o.Key, f, o.SHA256, headers)
	if e != nil {
		return e
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("S3 PUT status %d", resp.StatusCode)
	}
	saved, e := s.Stat(ctx, o.Key)
	if e != nil {
		return e
	}
	if saved.Size != o.Size || saved.SHA256 != o.SHA256 {
		return storage.ErrIntegrity
	}
	return nil
}
func (s *Store) Open(ctx context.Context, key string, span *storage.ByteRange) (io.ReadCloser, storage.ObjectInfo, error) {
	o, e := s.Stat(ctx, key)
	if e != nil {
		return nil, o, e
	}
	if e = storage.ValidateRange(span, o.Size); e != nil {
		return nil, o, e
	}
	headers := http.Header{}
	want := 200
	if span != nil {
		headers.Set("Range", fmt.Sprintf("bytes=%d-%d", span.Offset, span.Offset+span.Length-1))
		want = 206
	}
	resp, e := s.request(ctx, "GET", key, nil, hash(nil), headers)
	if e != nil {
		return nil, o, e
	}
	if resp.StatusCode != want {
		resp.Body.Close()
		return nil, o, fmt.Errorf("S3 GET status %d (expected %d)", resp.StatusCode, want)
	}
	if resp.Header.Get("X-Amz-Meta-Sha256") != o.SHA256 {
		resp.Body.Close()
		return nil, o, storage.ErrIntegrity
	}
	return resp.Body, o, nil
}
func (s *Store) Delete(ctx context.Context, key string) error {
	resp, e := s.request(ctx, "DELETE", key, nil, hash(nil), nil)
	if e != nil {
		return e
	}
	resp.Body.Close()
	if resp.StatusCode == 404 || resp.StatusCode == 204 || resp.StatusCode == 200 {
		return nil
	}
	return fmt.Errorf("S3 DELETE status %d", resp.StatusCode)
}
