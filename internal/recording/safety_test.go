package recording

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"dengan.dev/camera-streamer/internal/logger"
	"dengan.dev/camera-streamer/internal/recording/storage"
	"dengan.dev/camera-streamer/internal/recording/storage/local"
)

func safetyRecorder(t *testing.T, quota int64, store storage.Store) (*Recorder, string) {
	t.Helper()
	root := t.TempDir()
	db, e := logger.NewLogger(filepath.Join(root, "app.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	if store == nil {
		store, e = local.New(filepath.Join(root, "objects"))
		if e != nil {
			t.Fatal(e)
		}
	}
	r, e := New(db.DB(), filepath.Join(root, "spool"), store, Config{QuotaBytes: quota, RetentionDays: 1})
	if e != nil {
		t.Fatal(e)
	}
	if e = r.SetEnabled("onvif:cam", true); e != nil {
		t.Fatal(e)
	}
	return r, root
}
func safetyPlaylist(t *testing.T, dir string, seq int, names ...string) {
	t.Helper()
	if e := os.MkdirAll(dir, 0700); e != nil {
		t.Fatal(e)
	}
	var b strings.Builder
	b.WriteString("#EXTM3U\n#EXT-X-MEDIA-SEQUENCE:")
	b.WriteString(strconv.Itoa(seq))
	b.WriteByte('\n')
	for _, n := range names {
		b.WriteString("#EXTINF:2,\n" + n + "\n")
	}
	if e := os.WriteFile(filepath.Join(dir, "stream.m3u8"), []byte(b.String()), 0600); e != nil {
		t.Fatal(e)
	}
}
func TestLocalPhysicalQuotaIncludesSpoolAndObjectsAndOrphans(t *testing.T) {
	r, root := safetyRecorder(t, 24, nil)
	dir := filepath.Join(root, "live")
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, "a.ts"), []byte("123456"), 0600)
	safetyPlaylist(t, dir, 0, "a.ts")
	if e := r.IngestPlaylist("onvif:cam", "run", dir, time.Now()); e != nil {
		t.Fatal(e)
	}
	if e := r.Process(context.Background()); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(dir, "b.ts"), []byte("123456"), 0600)
	safetyPlaylist(t, dir, 1, "b.ts")
	if e := r.IngestPlaylist("onvif:cam", "run", dir, time.Now()); e != nil {
		t.Fatal(e)
	}
	if e := r.Process(context.Background()); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(dir, "c.ts"), []byte("123456"), 0600)
	safetyPlaylist(t, dir, 2, "c.ts")
	if e := r.IngestPlaylist("onvif:cam", "run", dir, time.Now()); e != nil {
		t.Fatal(e)
	}
	v, e := r.Coverage("onvif:cam", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	if len(v) != 3 || v[2].State != "gap" {
		t.Fatalf("quota failed closed with gap: %+v", v)
	}
	if _, e := os.Stat(filepath.Join(dir, "c.ts")); e != nil {
		t.Fatal("live segment modified", e)
	}
}
func TestRestartReconcilesOrphanSpoolAndMissingStagedFile(t *testing.T) {
	r, root := safetyRecorder(t, 100, nil)
	dir := filepath.Join(root, "live")
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, "a.ts"), []byte("123456"), 0600)
	safetyPlaylist(t, dir, 0, "a.ts")
	if e := r.IngestPlaylist("onvif:cam", "run", dir, time.Now()); e != nil {
		t.Fatal(e)
	}
	orphan := filepath.Join(r.spool, ".stage-crash")
	os.WriteFile(orphan, []byte("orphan"), 0600)
	v, _ := r.Coverage("onvif:cam", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if len(v) != 1 {
		t.Fatal(v)
	}
	os.Remove(v[0].Spool)
	if e := r.Reconcile(); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(orphan); !os.IsNotExist(e) {
		t.Fatalf("orphan remains: %v", e)
	}
	v, _ = r.Coverage("onvif:cam", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if len(v) != 1 || v[0].State != "gap" {
		t.Fatalf("missing staged silently lost %+v", v)
	}
}
func TestExpiredStagedAndFailedObjectDeletionRetry(t *testing.T) {
	r, root := safetyRecorder(t, 100, nil)
	dir := filepath.Join(root, "live")
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, "a.ts"), []byte("123456"), 0600)
	safetyPlaylist(t, dir, 0, "a.ts")
	old := time.Now().Add(-48 * time.Hour)
	if e := r.IngestPlaylist("onvif:cam", "run", dir, old); e != nil {
		t.Fatal(e)
	}
	if e := r.Retain(context.Background(), time.Now()); e != nil {
		t.Fatal(e)
	}
	v, _ := r.Coverage("onvif:cam", old.Add(-time.Hour), time.Now())
	if len(v) != 0 {
		t.Fatalf("expired staged %+v", v)
	}
	entries, _ := os.ReadDir(r.spool)
	if len(entries) != 0 {
		t.Fatalf("staged file remains %+v", entries)
	}
}
func TestRestartRecoversPublishedObjectWithMissingSpool(t *testing.T) {
	r, root := safetyRecorder(t, 18, nil)
	dir := filepath.Join(root, "live")
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, "a.ts"), []byte("123456"), 0600)
	safetyPlaylist(t, dir, 0, "a.ts")
	if e := r.IngestPlaylist("onvif:cam", "run", dir, time.Now()); e != nil {
		t.Fatal(e)
	}
	v, _ := r.Coverage("onvif:cam", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if len(v) != 1 {
		t.Fatal(v)
	}
	f, e := os.Open(v[0].Spool)
	if e != nil {
		t.Fatal(e)
	}
	e = r.store.Put(context.Background(), storage.ObjectInfo{Key: v[0].Key, SHA256: v[0].SHA256, Size: v[0].Size}, f)
	f.Close()
	if e != nil {
		t.Fatal(e)
	}
	os.Remove(v[0].Spool)
	if e = r.Reconcile(); e != nil {
		t.Fatal(e)
	}
	v, _ = r.Coverage("onvif:cam", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if len(v) != 1 || v[0].State != "ready" {
		t.Fatalf("published object stranded %+v", v)
	}
}
func TestReserveRejectsStageWithoutTouchingLive(t *testing.T) {
	r, root := safetyRecorder(t, 100, nil)
	r.cfg.ReserveBytes = ^uint64(0)
	dir := filepath.Join(root, "live")
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, "a.ts"), []byte("123456"), 0600)
	safetyPlaylist(t, dir, 0, "a.ts")
	if e := r.IngestPlaylist("onvif:cam", "run", dir, time.Now()); e != nil {
		t.Fatal(e)
	}
	v, _ := r.Coverage("onvif:cam", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if len(v) != 1 || v[0].State != "gap" {
		t.Fatal(v)
	}
	if _, e := os.Stat(filepath.Join(dir, "a.ts")); e != nil {
		t.Fatal("live file touched", e)
	}
}
func TestReserveIncreaseBeforeUploadPreventsObjectCopy(t *testing.T) {
	r, root := safetyRecorder(t, 100, nil)
	dir := filepath.Join(root, "live")
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, "a.ts"), []byte("123456"), 0600)
	safetyPlaylist(t, dir, 0, "a.ts")
	if e := r.IngestPlaylist("onvif:cam", "run", dir, time.Now()); e != nil {
		t.Fatal(e)
	}
	r.cfg.ReserveBytes = ^uint64(0)
	if e := r.Process(context.Background()); e == nil {
		t.Fatal("uploaded below reserve")
	}
	v, _ := r.Coverage("onvif:cam", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if len(v) != 1 || v[0].State != "staged" {
		t.Fatalf("unexpected upload %+v", v)
	}
	entries, _ := os.ReadDir(filepath.Join(root, "objects"))
	if len(entries) != 0 {
		t.Fatalf("object created below reserve %+v", entries)
	}
}
func TestLocalUploadCrashBeforeCatalogReadyRecoversAtQuota(t *testing.T) {
	r, root := safetyRecorder(t, 18, nil)
	dir := filepath.Join(root, "live")
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, "a.ts"), []byte("123456"), 0600)
	safetyPlaylist(t, dir, 0, "a.ts")
	if e := r.IngestPlaylist("onvif:cam", "run", dir, time.Now()); e != nil {
		t.Fatal(e)
	}
	v, _ := r.Coverage("onvif:cam", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if len(v) != 1 {
		t.Fatal(v)
	}
	f, e := os.Open(v[0].Spool)
	if e != nil {
		t.Fatal(e)
	}
	e = r.store.Put(context.Background(), storage.ObjectInfo{Key: v[0].Key, SHA256: v[0].SHA256, Size: v[0].Size}, f)
	f.Close()
	if e != nil {
		t.Fatal(e)
	}
	if e := r.Process(context.Background()); e != nil {
		t.Fatal(e)
	}
	v, _ = r.Coverage("onvif:cam", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if v[0].State != "ready" {
		t.Fatalf("crash-retry lost ready transition %+v", v)
	}
}

type failingDeleteStore struct {
	storage.Store
	fail bool
}

func (s *failingDeleteStore) Delete(ctx context.Context, key string) error {
	if s.fail {
		return errors.New("storage outage")
	}
	return s.Store.Delete(ctx, key)
}
func TestDeletionOutageRetriesAfterRestartAndDoesNotLoseObject(t *testing.T) {
	root := t.TempDir()
	db, e := logger.NewLogger(filepath.Join(root, "app.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	base, e := local.New(filepath.Join(root, "objects"))
	if e != nil {
		t.Fatal(e)
	}
	store := &failingDeleteStore{Store: base, fail: true}
	r, e := New(db.DB(), filepath.Join(root, "spool"), store, Config{QuotaBytes: 100, RetentionDays: 1})
	if e != nil {
		t.Fatal(e)
	}
	r.SetEnabled("onvif:cam", true)
	dir := filepath.Join(root, "live")
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, "a.ts"), []byte("123456"), 0600)
	safetyPlaylist(t, dir, 0, "a.ts")
	old := time.Now().Add(-48 * time.Hour)
	if e = r.IngestPlaylist("onvif:cam", "run", dir, old); e != nil {
		t.Fatal(e)
	}
	if e = r.Process(context.Background()); e != nil {
		t.Fatal(e)
	}
	v, _ := r.Coverage("onvif:cam", old.Add(-time.Hour), time.Now())
	if len(v) != 1 {
		t.Fatal(v)
	}
	if e = r.Retain(context.Background(), time.Now()); e == nil {
		t.Fatal("deletion failure hidden")
	}
	if _, e = base.Stat(context.Background(), v[0].Key); e != nil {
		t.Fatal("deleted despite outage", e)
	}
	store.fail = false
	r2, e := New(db.DB(), r.spool, store, Config{QuotaBytes: 100, RetentionDays: 1})
	if e != nil {
		t.Fatal(e)
	}
	if e = r2.Retain(context.Background(), time.Now().Add(2*time.Minute)); e != nil {
		t.Fatal(e)
	}
	if _, e = base.Stat(context.Background(), v[0].Key); !errors.Is(e, storage.ErrNotFound) {
		t.Fatalf("object remains %v", e)
	}
	v, _ = r2.Coverage("onvif:cam", old.Add(-time.Hour), time.Now())
	if len(v) != 0 {
		t.Fatal(v)
	}
}

type stalledPutStore struct {
	storage.Store
	entered chan struct{}
	release chan struct{}
}

func (s *stalledPutStore) Put(ctx context.Context, info storage.ObjectInfo, body io.Reader) error {
	close(s.entered)
	select {
	case <-s.release:
		return s.Store.Put(ctx, info, body)
	case <-ctx.Done():
		return ctx.Err()
	}
}
func TestStorageOutageDoesNotStallClosedSegmentCapture(t *testing.T) {
	root := t.TempDir()
	base, e := local.New(filepath.Join(root, "objects"))
	if e != nil {
		t.Fatal(e)
	}
	stalled := &stalledPutStore{Store: base, entered: make(chan struct{}), release: make(chan struct{})}
	r, dirRoot := safetyRecorder(t, 100, stalled)
	dir := filepath.Join(dirRoot, "live")
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, "a.ts"), []byte("123456"), 0600)
	safetyPlaylist(t, dir, 0, "a.ts")
	if e = r.IngestPlaylist("onvif:cam", "run", dir, time.Now()); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { done <- r.Process(ctx) }()
	<-stalled.entered
	os.WriteFile(filepath.Join(dir, "b.ts"), []byte("123456"), 0600)
	safetyPlaylist(t, dir, 1, "b.ts")
	capture := make(chan error, 1)
	go func() { capture <- r.IngestPlaylist("onvif:cam", "run", dir, time.Now()) }()
	select {
	case e := <-capture:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("storage outage blocked capture")
	}
	cancel()
	close(stalled.release)
	<-done
}
func TestFirstObservedPlaylistAlreadyRolledReportsPrefixGap(t *testing.T) {
	r, root := safetyRecorder(t, 100, nil)
	dir := filepath.Join(root, "live")
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, "d.ts"), []byte("123456"), 0600)
	safetyPlaylist(t, dir, 3, "d.ts")
	now := time.Now()
	if e := r.IngestPlaylist("onvif:cam", "run", dir, now); e != nil {
		t.Fatal(e)
	}
	v, e := r.Coverage("onvif:cam", now.Add(-time.Hour), now.Add(time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	if len(v) != 4 || v[0].State != "gap" || v[1].State != "gap" || v[2].State != "gap" || v[3].State != "staged" {
		t.Fatalf("rolled prefix silently missed %+v", v)
	}
}
func TestMissingPlaylistSequenceAndMissingClosedFileExplicitGap(t *testing.T) {
	r, root := safetyRecorder(t, 100, nil)
	dir := filepath.Join(root, "live")
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, "a.ts"), []byte("123456"), 0600)
	safetyPlaylist(t, dir, 0, "a.ts")
	now := time.Now()
	r.IngestPlaylist("onvif:cam", "run", dir, now)
	safetyPlaylist(t, dir, 3, "gone.ts")
	r.IngestPlaylist("onvif:cam", "run", dir, now.Add(6*time.Second))
	v, e := r.Coverage("onvif:cam", now.Add(-time.Hour), now.Add(time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	if len(v) < 3 || v[len(v)-1].State != "gap" {
		t.Fatalf("silent loss %+v", v)
	}
	os.WriteFile(filepath.Join(dir, "d.ts"), []byte("123456"), 0600)
	safetyPlaylist(t, dir, 4, "d.ts")
	if e := r.IngestPlaylist("onvif:cam", "run", dir, now.Add(8*time.Second)); e != nil {
		t.Fatal(e)
	}
	playlist, e := r.Playlist("onvif:cam", now.Add(-time.Hour), now.Add(time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(playlist, "gone.ts") || !strings.Contains(playlist, "#EXT-X-DISCONTINUITY") {
		t.Fatalf("gap playback: %s", playlist)
	}
}
