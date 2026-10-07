package recording

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dengan.dev/camera-streamer/internal/logger"
	"dengan.dev/camera-streamer/internal/recording/storage/local"
)

func TestIngestRestartAndCoverage(t *testing.T) {
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
	r, e := New(db.DB(), filepath.Join(root, "spool"), store, Config{QuotaBytes: 1024 * 1024, ReserveBytes: 0, RetentionDays: 1})
	if e != nil {
		t.Fatal(e)
	}
	if e = r.SetEnabled("tuya:device1", true); e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(root, "live")
	os.Mkdir(dir, 0700)
	os.WriteFile(filepath.Join(dir, "stream0.ts"), []byte("segment"), 0600)
	os.WriteFile(filepath.Join(dir, "stream.m3u8"), []byte("#EXTM3U\n#EXT-X-MEDIA-SEQUENCE:0\n#EXTINF:2.0,\nstream0.ts\n#EXTINF:2.0,\nstream1.ts\n"), 0600)
	if e = r.IngestPlaylist("tuya:device1", "run1", dir, time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)); e != nil {
		t.Fatal(e)
	}
	os.Remove(filepath.Join(dir, "stream0.ts"))
	if e = r.Process(context.Background()); e != nil {
		t.Fatal(e)
	}
	r2, e := New(db.DB(), filepath.Join(root, "spool"), store, Config{QuotaBytes: 1024 * 1024, RetentionDays: 1})
	if e != nil {
		t.Fatal(e)
	}
	segs, e := r2.Coverage("tuya:device1", time.Date(2026, 10, 4, 11, 0, 0, 0, time.UTC), time.Date(2026, 10, 4, 13, 0, 0, 0, time.UTC))
	if e != nil || len(segs) != 2 || segs[0].Duration != 2 || segs[0].State != "ready" || segs[1].State != "gap" {
		t.Fatalf("coverage %+v %v", segs, e)
	}
	f, _, e := r2.Open(context.Background(), segs[0].ID, nil)
	if e != nil {
		t.Fatal(e)
	}
	f.Close()
	if strings.Contains(segs[0].Camera, "secret") {
		t.Fatal("secret")
	}
}
func TestQuotaDoesNotRemoveLiveSegment(t *testing.T) {
	root := t.TempDir()
	db, e := logger.NewLogger(filepath.Join(root, "app.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	store, _ := local.New(filepath.Join(root, "objects"))
	r, e := New(db.DB(), filepath.Join(root, "spool"), store, Config{QuotaBytes: 2, RetentionDays: 1})
	if e != nil {
		t.Fatal(e)
	}
	r.SetEnabled("onvif:cam", true)
	dir := filepath.Join(root, "live")
	os.Mkdir(dir, 0700)
	os.WriteFile(filepath.Join(dir, "stream0.ts"), []byte("segment"), 0600)
	os.WriteFile(filepath.Join(dir, "stream.m3u8"), []byte("#EXTM3U\n#EXTINF:2.0,\nstream0.ts\n"), 0600)
	if e = r.IngestPlaylist("onvif:cam", "run", dir, time.Now()); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(dir, "stream0.ts")); e != nil {
		t.Fatal(e)
	}
	v, _ := r.Coverage("onvif:cam", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if len(v) != 1 || v[0].State != "gap" {
		t.Fatalf("quota loss not explicitly reported %+v", v)
	}
}
func TestStoreIdentityCannotSilentlySwitch(t *testing.T) {
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
	rec, e := New(db.DB(), filepath.Join(root, "spool"), store, Config{QuotaBytes: 1024, RetentionDays: 1})
	if e != nil {
		t.Fatal(e)
	}
	if e = rec.BindStore("local:first"); e != nil {
		t.Fatal(e)
	}
	if e = rec.BindStore("s3:other"); e == nil {
		t.Fatal("backend switch stranded catalog objects")
	}
}
