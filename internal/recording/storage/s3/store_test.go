package s3

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"dengan.dev/camera-streamer/internal/recording/storage"
)

func TestSignedS3RequestsAndRange(t *testing.T) {
	var bytes []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=test/") {
			t.Errorf("unsigned %s", r.Method)
		}
		switch r.Method {
		case "PUT":
			bytes, _ = io.ReadAll(r.Body)
			w.WriteHeader(200)
		case "HEAD":
			if bytes == nil {
				w.WriteHeader(404)
				return
			}
			w.Header().Set("Content-Length", "3")
			w.Header().Set("X-Amz-Meta-Sha256", hex.EncodeToString(sha256Bytes(bytes)))
		case "GET":
			if r.Header.Get("Range") != "bytes=1-2" {
				t.Error("range missing")
			}
			w.Header().Set("X-Amz-Meta-Sha256", hex.EncodeToString(sha256Bytes(bytes)))
			w.WriteHeader(206)
			w.Write(bytes[1:3])
		case "DELETE":
			bytes = nil
			w.WriteHeader(204)
		}
	}))
	defer server.Close()
	s, e := New(Config{Endpoint: server.URL, Bucket: "bucket", Region: "us-east-1", AccessKey: "test", SecretKey: "secret", AllowHTTP: true})
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256([]byte("abc"))
	o := storage.ObjectInfo{Key: "cam/1.ts", Size: 3, SHA256: hex.EncodeToString(h[:]), ContentType: "video/mp2t"}
	if e = s.Put(context.Background(), o, strings.NewReader("abc")); e != nil {
		t.Fatal(e)
	}
	if e = s.Put(context.Background(), o, strings.NewReader("abc")); e != nil {
		t.Fatal(e)
	}
	r, _, e := s.Open(context.Background(), o.Key, &storage.ByteRange{Offset: 1, Length: 2})
	if e != nil {
		t.Fatal(e)
	}
	b, _ := io.ReadAll(r)
	r.Close()
	if string(b) != "bc" {
		t.Fatalf("%q", b)
	}
	if e = s.Delete(context.Background(), o.Key); e != nil {
		t.Fatal(e)
	}
}
func sha256Bytes(b []byte) []byte { h := sha256.Sum256(b); return h[:] }
