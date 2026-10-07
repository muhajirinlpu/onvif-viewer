package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"dengan.dev/camera-streamer/internal/logger"
	"dengan.dev/camera-streamer/internal/recording"
	"dengan.dev/camera-streamer/internal/recording/storage/local"
)

func TestRecordingMediaAuthorizationAndRange(t *testing.T) {
	root := t.TempDir()
	db, e := logger.NewLogger(filepath.Join(root, "app.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	store, e := local.New(filepath.Join(root, "objects"))
	if e != nil {
		t.Fatal(e)
	}
	rec, e := recording.New(db.DB(), filepath.Join(root, "spool"), store, recording.Config{QuotaBytes: 1024, RetentionDays: 1})
	if e != nil {
		t.Fatal(e)
	}
	rec.SetEnabled("onvif:test", true)
	dir := filepath.Join(root, "hls")
	os.Mkdir(dir, 0700)
	os.WriteFile(filepath.Join(dir, "stream0.ts"), []byte("abcdefgh"), 0600)
	os.WriteFile(filepath.Join(dir, "stream.m3u8"), []byte("#EXTM3U\n#EXTINF:2.0,\nstream0.ts\n"), 0600)
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	if e = rec.IngestPlaylist("onvif:test", "r1", dir, now); e != nil {
		t.Fatal(e)
	}
	v, e := rec.Coverage("onvif:test", now.Add(-time.Hour), now.Add(time.Hour))
	if e != nil || len(v) != 1 {
		t.Fatalf("%+v %v", v, e)
	}
	h := RecordingRoutes(rec, "secret")
	for _, tc := range []struct {
		method, rangeHeader string
		want                int
		body                string
	}{{"GET", "", 200, "abcdefgh"}, {"GET", "bytes=2-4", 206, "cde"}, {"HEAD", "bytes=2-4", 206, ""}, {"GET", "bytes=20-21", 416, ""}} {
		req := httptest.NewRequest(tc.method, "/api/recordings/segments/1", nil)
		req.Header.Set("Authorization", "Bearer secret")
		if tc.rangeHeader != "" {
			req.Header.Set("Range", tc.rangeHeader)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != tc.want || (tc.body != "" && w.Body.String() != tc.body) {
			t.Fatalf("%s %s: %d %q", tc.method, tc.rangeHeader, w.Code, w.Body.String())
		}
	}
	digest := sha256.Sum256([]byte("abcdefgh"))
	if v[0].SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("digest mismatch")
	}
}
