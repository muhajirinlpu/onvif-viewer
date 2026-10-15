package recording

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dengan.dev/camera-streamer/internal/logger"
	"dengan.dev/camera-streamer/internal/recording/storage"
	"dengan.dev/camera-streamer/internal/recording/storage/local"
)

func statusRecorder(t *testing.T, quota int64) (*Recorder, string) {
	t.Helper()
	root := t.TempDir()
	db, e := logger.NewLogger(filepath.Join(root, "app.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	store, e := local.New(filepath.Join(root, "objects"))
	if e != nil {
		t.Fatal(e)
	}
	r, e := New(db.DB(), filepath.Join(root, "spool"), store, Config{QuotaBytes: quota, ReserveBytes: 0, RetentionDays: 7})
	if e != nil {
		t.Fatal(e)
	}
	return r, root
}

func TestStatusReportsDriverCapacityBacklogAndCameras(t *testing.T) {
	r, root := statusRecorder(t, 1<<20)
	if e := r.SetEnabled("onvif:cam", true); e != nil {
		t.Fatal(e)
	}
	if e := r.SetStoreDescription(StoreDescription{Driver: DriverLocal, LocalPath: filepath.Join(root, "objects"), Available: true, AppKey: false}); e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(root, "live")
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, "a.ts"), []byte("123456"), 0600)
	safetyPlaylist(t, dir, 0, "a.ts")
	if e := r.IngestPlaylist("onvif:cam", "run", dir, time.Now()); e != nil {
		t.Fatal(e)
	}
	st, e := r.Status()
	if e != nil {
		t.Fatal(e)
	}
	if st.Driver != DriverLocal || st.Location.Path != filepath.Join(root, "objects") || st.Location.Kind != DriverLocal {
		t.Fatalf("driver/location %+v", st)
	}
	if st.Capacity.QuotaBytes != 1<<20 || st.Capacity.UsedBytes <= 0 || st.Capacity.FreeBytes == 0 {
		t.Fatalf("capacity %+v", st.Capacity)
	}
	if st.Backlog.PendingUploads != 1 {
		t.Fatalf("pending uploads %+v", st.Backlog)
	}
	if st.Backlog.OldestUploadSeconds < 0 {
		t.Fatalf("oldest upload age %+v", st.Backlog)
	}
	if len(st.Cameras) != 1 || st.Cameras[0].Camera != "onvif:cam" || !st.Cameras[0].Enabled {
		t.Fatalf("cameras %+v", st.Cameras)
	}
	if st.RetentionDays != 7 {
		t.Fatalf("retention %d", st.RetentionDays)
	}
	// Now upload so the backlog clears and health records a success.
	if e := r.Process(context.Background()); e != nil {
		t.Fatal(e)
	}
	st, e = r.Status()
	if e != nil {
		t.Fatal(e)
	}
	if st.Backlog.PendingUploads != 0 {
		t.Fatalf("uploads not drained %+v", st.Backlog)
	}
	if st.Health.LastUploadNS <= 0 {
		t.Fatalf("health %+v", st.Health)
	}
	if st.Health.LastError != "" {
		t.Fatalf("a healthy recorder reported an error %q", st.Health.LastError)
	}
}

func TestStatusPausedWhenQuotaOrReserveReached(t *testing.T) {
	r, root := statusRecorder(t, 4)
	r.SetStoreDescription(StoreDescription{Driver: DriverLocal, LocalPath: filepath.Join(root, "objects"), Available: true})
	st, e := r.Status()
	if e != nil {
		t.Fatal(e)
	}
	if st.Capacity.Paused {
		t.Fatalf("a recorder with room was reported paused: %+v", st.Capacity)
	}
	// Physical usage at or above the quota is the real pause condition.
	if e := os.WriteFile(filepath.Join(r.spool, "oversize"), []byte("0123456789abcdef"), 0600); e != nil {
		t.Fatal(e)
	}
	st, e = r.Status()
	if e != nil {
		t.Fatal(e)
	}
	if !st.Capacity.Paused || st.Capacity.UsedBytes < st.Capacity.QuotaBytes {
		t.Fatalf("quota exhaustion must report paused: %+v", st.Capacity)
	}
	// A reserve larger than the volume's free space pauses admission too.
	r2, root2 := statusRecorder(t, 1<<20)
	r2.SetStoreDescription(StoreDescription{Driver: DriverLocal, LocalPath: filepath.Join(root2, "objects"), Available: true})
	if e := r2.ApplyLimits(1<<20, 1<<50, 7); e != nil {
		t.Fatal(e)
	}
	st, e = r2.Status()
	if e != nil {
		t.Fatal(e)
	}
	if !st.Capacity.Paused {
		t.Fatalf("a reserve above free space must report paused: %+v", st.Capacity)
	}
}

func TestStatusLastErrorIsSanitizedNeverRaw(t *testing.T) {
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
	r, e := New(db.DB(), filepath.Join(root, "spool"), &statusFailingStore{Store: base}, Config{QuotaBytes: 1 << 20, RetentionDays: 1})
	if e != nil {
		t.Fatal(e)
	}
	r.SetStoreDescription(StoreDescription{Driver: DriverLocal, LocalPath: filepath.Join(root, "objects"), Available: true})
	dir := filepath.Join(root, "live")
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, "a.ts"), []byte("123456"), 0600)
	safetyPlaylist(t, dir, 0, "a.ts")
	r.SetEnabled("onvif:cam", true)
	if e := r.IngestPlaylist("onvif:cam", "run", dir, time.Now()); e != nil {
		t.Fatal(e)
	}
	if e := r.Process(context.Background()); e == nil {
		t.Fatal("a failing store did not surface an error")
	}
	st, e := r.Status()
	if e != nil {
		t.Fatal(e)
	}
	if st.Health.LastError == "" {
		t.Fatal("no health error was recorded")
	}
	// The raw store error carries a path and an object key; neither may leak.
	for _, forbidden := range []string{root, "Objects at", "SUPER-SECRET"} {
		if strings.Contains(st.Health.LastError, forbidden) {
			t.Fatalf("health error leaked %q: %q", forbidden, st.Health.LastError)
		}
	}
}

type statusFailingStore struct {
	storage.Store
}

func (s *statusFailingStore) Put(context.Context, storage.ObjectInfo, io.Reader) error {
	return errors.New("Objects at /home/operator/recordings/objects/cam/deadbeef.ts are unreadable")
}

func TestSummaryBucketsAreBoundedAndHonest(t *testing.T) {
	r, root := statusRecorder(t, 1<<20)
	r.SetStoreDescription(StoreDescription{Driver: DriverLocal, LocalPath: filepath.Join(root, "objects"), Available: true})
	r.SetEnabled("onvif:cam", true)
	dir := filepath.Join(root, "live")
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, "a.ts"), []byte("123456"), 0600)
	// Media sequence 1 with 0 already behind means the prefix is an explicit gap.
	safetyPlaylist(t, dir, 1, "a.ts")
	now := time.Now().UTC()
	if e := r.IngestPlaylist("onvif:cam", "run", dir, now); e != nil {
		t.Fatal(e)
	}
	from, to := now.Add(-time.Hour), now.Add(time.Hour)
	// The bucket count is clamped, never honoured past the cap.
	s, e := r.Summary("onvif:cam", from, to, 100000)
	if e != nil {
		t.Fatal(e)
	}
	if len(s.Buckets) > MaxSummaryBuckets {
		t.Fatalf("bucket count %d exceeded the cap %d", len(s.Buckets), MaxSummaryBuckets)
	}
	if len(s.Buckets) == 0 {
		t.Fatal("a window with segments produced no buckets")
	}
	var recorded, gap float64
	for _, b := range s.Buckets {
		recorded += b.RecordedSeconds
		gap += b.GapSeconds
	}
	if gap <= 0 {
		t.Fatalf("an explicit gap row produced no gap seconds: %+v", s.Buckets)
	}
	if recorded <= 0 {
		t.Fatalf("a staged segment produced no recorded seconds: %+v", s.Buckets)
	}
	// The bucket windows must tile the requested window exactly.
	if !s.Buckets[0].Start.Equal(from.UTC()) {
		t.Fatalf("first bucket starts at %s, want %s", s.Buckets[0].Start, from)
	}
	if !s.Buckets[len(s.Buckets)-1].End.Equal(to.UTC()) {
		t.Fatalf("last bucket ends at %s, want %s", s.Buckets[len(s.Buckets)-1].End, to)
	}
}

func TestSummaryEmptyWindowAndBoundsEnforced(t *testing.T) {
	r, root := statusRecorder(t, 1<<20)
	r.SetStoreDescription(StoreDescription{Driver: DriverLocal, LocalPath: filepath.Join(root, "objects"), Available: true})
	now := time.Now().UTC()
	s, e := r.Summary("onvif:cam", now.Add(-time.Hour), now, 60)
	if e != nil {
		t.Fatal(e)
	}
	if len(s.Buckets) != 0 {
		t.Fatalf("an empty window returned %d buckets", len(s.Buckets))
	}
	if _, e := r.Summary("onvif:cam", now, now, 60); e == nil {
		t.Fatal("a non-positive window was accepted")
	}
	if _, e := r.Summary("onvif:cam", now.Add(-40*24*time.Hour), now, 60); e == nil {
		t.Fatal("an over-long window was accepted")
	}
	if _, e := r.Summary("", now.Add(-time.Hour), now, 60); e == nil {
		t.Fatal("an empty camera was accepted")
	}
	// A bucket request of zero must still produce a usable, bounded strip.
	s, e = r.Summary("onvif:cam", now.Add(-time.Hour), now, 0)
	if e != nil {
		t.Fatal(e)
	}
	if len(s.Buckets) > MaxSummaryBuckets {
		t.Fatal("default bucket count ignored the cap")
	}
}

func TestSummarySurfacesTruncation(t *testing.T) {
	r, root := statusRecorder(t, 1<<20)
	r.SetStoreDescription(StoreDescription{Driver: DriverLocal, LocalPath: filepath.Join(root, "objects"), Available: true})
	db := r.db
	now := time.Now().UTC()
	// Seed more segments than the summary will read, directly in the catalog.
	tx, e := db.Begin()
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < MaxSummarySegments+50; i++ {
		start := now.Add(time.Duration(i) * time.Second)
		if _, e := tx.Exec(`INSERT INTO recording_segments(camera,run,sequence,start_ns,end_ns,duration,discontinuity,key,sha256,size,spool,state) VALUES('onvif:many','r',?,?,?,2,0,'','',0,'','ready')`, i, start.UnixNano(), start.Add(2*time.Second).UnixNano()); e != nil {
			tx.Rollback()
			t.Fatal(e)
		}
	}
	if e := tx.Commit(); e != nil {
		t.Fatal(e)
	}
	s, e := r.Summary("onvif:many", now.Add(-time.Hour), now.Add(time.Hour), 60)
	if e != nil {
		t.Fatal(e)
	}
	if !s.Truncated {
		t.Fatalf("a catalog larger than the read bound was reported as complete: %+v", s)
	}
}

func TestSummaryJSONCarriesNoHiddenSegmentFields(t *testing.T) {
	r, root := statusRecorder(t, 1<<20)
	r.SetStoreDescription(StoreDescription{Driver: DriverLocal, LocalPath: filepath.Join(root, "objects"), Available: true})
	r.SetEnabled("onvif:cam", true)
	dir := filepath.Join(root, "live")
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, "a.ts"), []byte("123456"), 0600)
	safetyPlaylist(t, dir, 0, "a.ts")
	now := time.Now().UTC()
	if e := r.IngestPlaylist("onvif:cam", "run", dir, now); e != nil {
		t.Fatal(e)
	}
	s, e := r.Summary("onvif:cam", now.Add(-time.Hour), now.Add(time.Hour), 10)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(s)
	if e != nil {
		t.Fatal(e)
	}
	for _, forbidden := range []string{"sha256", "spool", "key\"", "\"Key\"", "SUPER-SECRET"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("summary JSON leaked %q: %s", forbidden, raw)
		}
	}
	st, _ := r.Status()
	raw, _ = json.Marshal(st)
	for _, forbidden := range []string{"sha256", "spool", "cipher", "secretKey", "SecretKey", "sessionToken", "accessKey"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("status JSON leaked %q: %s", forbidden, raw)
		}
	}
}

func TestLimitsAreEditableAtRuntimeWithoutRestart(t *testing.T) {
	r, root := statusRecorder(t, 1<<20)
	r.SetStoreDescription(StoreDescription{Driver: DriverLocal, LocalPath: filepath.Join(root, "objects"), Available: true})
	if e := r.ApplyLimits(4096, 1024, 3); e != nil {
		t.Fatal(e)
	}
	st, e := r.Status()
	if e != nil {
		t.Fatal(e)
	}
	if st.Capacity.QuotaBytes != 4096 || st.Capacity.ReserveBytes != 1024 || st.RetentionDays != 3 {
		t.Fatalf("a saved limit did not take effect immediately: %+v", st)
	}
	// The new retention must actually drive Retain, not just be reported.
	if e := r.ApplyLimits(1<<20, 0, 1); e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(root, "live")
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, "a.ts"), []byte("123456"), 0600)
	safetyPlaylist(t, dir, 0, "a.ts")
	r.SetEnabled("onvif:cam", true)
	old := time.Now().Add(-48 * time.Hour)
	if e := r.IngestPlaylist("onvif:cam", "run", dir, old); e != nil {
		t.Fatal(e)
	}
	if e := r.Process(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e := r.Retain(context.Background(), time.Now()); e != nil {
		t.Fatal(e)
	}
	v, _ := r.Coverage("onvif:cam", old.Add(-time.Hour), time.Now())
	if len(v) != 0 {
		t.Fatalf("the runtime retention limit did not drive Retain: %+v", v)
	}
}

func TestApplyLimitsRejectsNonsense(t *testing.T) {
	r, root := statusRecorder(t, 1<<20)
	r.SetStoreDescription(StoreDescription{Driver: DriverLocal, LocalPath: filepath.Join(root, "objects"), Available: true})
	for _, tc := range []struct {
		quota   int64
		reserve uint64
		days    int
	}{
		{0, 0, 1},
		{-1, 0, 1},
		{1 << 20, 0, 0},
		{1 << 20, 0, -5},
		{1 << 20, ^uint64(0), 1},
	} {
		if e := r.ApplyLimits(tc.quota, tc.reserve, tc.days); e == nil {
			t.Fatalf("accepted quota=%d reserve=%d days=%d", tc.quota, tc.reserve, tc.days)
		}
	}
	if e := r.ApplyLimits(1<<20, 0, 7); e != nil {
		t.Fatal(e)
	}
}

func TestSaveLimitsPersistsAndSurvivesRestart(t *testing.T) {
	r, root := statusRecorder(t, 1<<20)
	r.SetStoreDescription(StoreDescription{Driver: DriverLocal, LocalPath: filepath.Join(root, "objects"), Available: true})
	// SaveLimits writes the settings row, so it must exist first.
	if _, _, e := ResolveStorageSettings(r.db, StorageEnv{Driver: DriverLocal, LocalPath: filepath.Join(root, "objects"), QuotaBytes: 1 << 20, RetentionDays: 7}, nil); e != nil {
		t.Fatal(e)
	}
	if e := r.SaveLimits(4096, 512, 2); e != nil {
		t.Fatal(e)
	}
	q, res, days := r.Limits()
	if q != 4096 || res != 512 || days != 2 {
		t.Fatalf("saved limits not effective immediately: %d %d %d", q, res, days)
	}
	var storedQuota, storedDays int64
	if e := r.db.QueryRow(`SELECT quota_bytes,retention_days FROM recording_storage_settings WHERE id=1`).Scan(&storedQuota, &storedDays); e != nil {
		t.Fatal(e)
	}
	if storedQuota != 4096 || storedDays != 2 {
		t.Fatalf("saved limits were not persisted: %d %d", storedQuota, storedDays)
	}
	// A restart resolves the row, so the saved limits are the boot limits now.
	again, fromDB, e := ResolveStorageSettings(r.db, StorageEnv{Driver: DriverLocal, LocalPath: "/env/other", QuotaBytes: 999, RetentionDays: 99}, nil)
	if e != nil {
		t.Fatal(e)
	}
	if !fromDB || again.QuotaBytes != 4096 || again.RetentionDays != 2 || again.ReserveBytes != 512 {
		t.Fatalf("a restart did not pick up the saved limits: %+v", again)
	}
	for _, bad := range []int64{0, -1} {
		if e := r.SaveLimits(bad, 0, 1); e == nil {
			t.Fatalf("SaveLimits accepted quota %d", bad)
		}
	}
	if e := r.SaveLimits(1024, 0, 0); e == nil {
		t.Fatal("SaveLimits accepted a zero retention")
	}
}

func TestDriverSwitchAllowedOnlyOnAnEmptyCatalog(t *testing.T) {
	r, root := statusRecorder(t, 1<<20)
	r.SetStoreDescription(StoreDescription{Driver: DriverLocal, LocalPath: filepath.Join(root, "objects"), Available: true})
	allowed, reason := r.DriverSwitch()
	if !allowed || reason != "" {
		t.Fatalf("an empty catalog must allow a switch: %t %q", allowed, reason)
	}
	dir := filepath.Join(root, "live")
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, "a.ts"), []byte("123456"), 0600)
	safetyPlaylist(t, dir, 0, "a.ts")
	r.SetEnabled("onvif:cam", true)
	if e := r.IngestPlaylist("onvif:cam", "run", dir, time.Now()); e != nil {
		t.Fatal(e)
	}
	allowed, reason = r.DriverSwitch()
	if allowed {
		t.Fatal("a populated catalog allowed a driver switch")
	}
	if !strings.Contains(reason, "migrat") {
		t.Fatalf("the refusal must name the migration: %q", reason)
	}
	// And the underlying guard must still refuse the switch itself, once an
	// identity is bound exactly as the wiring binds it at boot.
	if e := r.BindStore("local:" + filepath.Join(root, "objects")); e != nil {
		t.Fatal(e)
	}
	if e := r.BindStore("s3:elsewhere"); e == nil {
		t.Fatal("BindStore allowed a switch with catalog objects present")
	}
}

func TestStoreDescriptionRejectsUnknownDriverAndSecrets(t *testing.T) {
	r, root := statusRecorder(t, 1<<20)
	if e := r.SetStoreDescription(StoreDescription{Driver: "ftp", LocalPath: root, Available: true}); e == nil {
		t.Fatal("an unknown driver was accepted")
	}
	// An S3 description must never be able to carry a credential: the type has
	// nowhere to put one, so the assertion is that nothing sensitive is rendered.
	if e := r.SetStoreDescription(StoreDescription{Driver: DriverS3, S3Endpoint: "https://s3.example", S3Bucket: "b", S3Region: "r", Available: true, AppKey: false, Unavailable: "app key missing"}); e != nil {
		t.Fatal(e)
	}
	st, e := r.Status()
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(st)
	if strings.Contains(string(raw), "secret") || strings.Contains(string(raw), "credential") && !strings.Contains(string(raw), "app key missing") {
		t.Fatalf("s3 status carried something credential-shaped: %s", raw)
	}
	if st.Driver != DriverS3 || st.AppKeyAvailable {
		t.Fatalf("s3 status %+v", st)
	}
	if st.Location.Unavailable != "app key missing" {
		t.Fatalf("the reason s3 is unusable must be reported: %+v", st.Location)
	}
}

func TestStatusReportsPendingDeletion(t *testing.T) {
	r, root := statusRecorder(t, 1<<20)
	r.SetStoreDescription(StoreDescription{Driver: DriverLocal, LocalPath: filepath.Join(root, "objects"), Available: true})
	st, e := r.Status()
	if e != nil {
		t.Fatal(e)
	}
	if st.Backlog.PendingDeletions != 0 {
		t.Fatalf("an untouched catalog reported deletions: %+v", st.Backlog)
	}
	_ = errors.Is
}
