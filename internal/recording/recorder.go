package recording

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"dengan.dev/camera-streamer/internal/recording/storage"
)

type Config struct {
	QuotaBytes    int64
	ReserveBytes  uint64
	RetentionDays int
}
type Segment struct {
	ID            int64     `json:"id"`
	Camera        string    `json:"camera"`
	Start         time.Time `json:"start"`
	End           time.Time `json:"end"`
	Duration      float64   `json:"duration"`
	Discontinuity bool      `json:"discontinuity"`
	State         string    `json:"state"`
	Key           string    `json:"-"`
	SHA256        string    `json:"-"`
	Size          int64     `json:"-"`
	Spool         string    `json:"-"`
}
type Recorder struct {
	db        *sql.DB
	spool     string
	store     storage.Store
	cfg       Config
	mu        sync.Mutex
	processMu sync.Mutex
	inFlight  int64
}

func New(db *sql.DB, spool string, store storage.Store, cfg Config) (*Recorder, error) {
	if cfg.QuotaBytes <= 0 || cfg.RetentionDays <= 0 || store == nil {
		return nil, errors.New("finite quota, retention and store required")
	}
	if err := os.MkdirAll(spool, 0700); err != nil {
		return nil, err
	}
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS recording_settings(camera TEXT PRIMARY KEY,enabled INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS recording_store_identity(id INTEGER PRIMARY KEY CHECK(id=1), store_id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS recording_segments(id INTEGER PRIMARY KEY,camera TEXT NOT NULL,run TEXT NOT NULL,sequence INTEGER NOT NULL,start_ns INTEGER NOT NULL,end_ns INTEGER NOT NULL,duration REAL NOT NULL,discontinuity INTEGER NOT NULL,key TEXT NOT NULL,sha256 TEXT NOT NULL,size INTEGER NOT NULL,spool TEXT NOT NULL,state TEXT NOT NULL,UNIQUE(camera,run,sequence));
CREATE INDEX IF NOT EXISTS recording_camera_time ON recording_segments(camera,start_ns);
CREATE TABLE IF NOT EXISTS recording_upload_jobs(segment_id INTEGER PRIMARY KEY,attempts INTEGER NOT NULL DEFAULT 0,next_ns INTEGER NOT NULL DEFAULT 0,lease_ns INTEGER NOT NULL DEFAULT 0,last_error TEXT NOT NULL DEFAULT '',FOREIGN KEY(segment_id) REFERENCES recording_segments(id));
CREATE TABLE IF NOT EXISTS recording_deletion_jobs(segment_id INTEGER PRIMARY KEY,key TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,next_ns INTEGER NOT NULL DEFAULT 0);`)
	if err != nil {
		return nil, err
	}
	r := &Recorder{db: db, spool: spool, store: store, cfg: cfg}
	if err := r.Reconcile(); err != nil {
		return nil, err
	}
	return r, nil
}
func (r *Recorder) SetEnabled(camera string, enabled bool) error {
	if !validIdentity(camera) {
		return errors.New("invalid camera")
	}
	v := 0
	if enabled {
		v = 1
	}
	_, err := r.db.Exec(`INSERT INTO recording_settings(camera,enabled) VALUES(?,?) ON CONFLICT(camera) DO UPDATE SET enabled=excluded.enabled`, camera, v)
	return err
}
func validIdentity(s string) bool {
	return len(s) > 0 && len(s) < 256 && !strings.ContainsAny(s, "\x00\n\r")
}
func (r *Recorder) enabled(camera string) bool {
	var n int
	return r.db.QueryRow(`SELECT enabled FROM recording_settings WHERE camera=?`, camera).Scan(&n) == nil && n == 1
}
func safeID(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:12]) }

// physicalUsage includes temporary and orphan files, not just catalog rows. Local
// upload temporarily occupies both spool and object roots; count both copies.
func (r *Recorder) physicalUsage() (int64, error) {
	var total int64
	roots := []string{r.spool}
	if local, ok := r.store.(interface{ LocalRoot() string }); ok {
		roots = append(roots, local.LocalRoot())
	}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.Type()&os.ModeSymlink != 0 {
				return errors.New("symlink in recording storage")
			}
			if d.IsDir() {
				return nil
			}
			fi, err := d.Info()
			if err != nil {
				return err
			}
			if !fi.Mode().IsRegular() || fi.Size() < 0 || fi.Size() > math.MaxInt64-total {
				return errors.New("invalid recording storage entry")
			}
			total += fi.Size()
			return nil
		})
		if err != nil {
			return 0, err
		}
	}
	return total, nil
}

// Reconcile removes crash leftovers and makes missing staged data visible as gaps.
// Only app-owned spool files are touched; never the live HLS directory.
func (r *Recorder) Reconcile() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rows, err := r.db.Query(`SELECT id,spool,key,sha256,size FROM recording_segments WHERE state='staged'`)
	if err != nil {
		return err
	}
	known := make(map[string]bool)
	var missing, published []int64
	for rows.Next() {
		var id, size int64
		var name, key, sha string
		if err := rows.Scan(&id, &name, &key, &sha, &size); err != nil {
			rows.Close()
			return err
		}
		known[name] = true
		if _, err := os.Stat(name); os.IsNotExist(err) {
			if _, ok := r.store.(interface{ LocalRoot() string }); ok {
				info, e := r.store.Stat(context.Background(), key)
				if e == nil {
					if info.Size != size || info.SHA256 != sha {
						rows.Close()
						return storage.ErrIntegrity
					}
					published = append(published, id)
					continue
				}
				if !errors.Is(e, storage.ErrNotFound) {
					rows.Close()
					return e
				}
			}
			missing = append(missing, id)
		} else if err != nil {
			rows.Close()
			return err
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range published {
		if _, err = r.db.Exec(`UPDATE recording_segments SET state='ready',spool='' WHERE id=?`, id); err != nil {
			return err
		}
		if _, err = r.db.Exec(`DELETE FROM recording_upload_jobs WHERE segment_id=?`, id); err != nil {
			return err
		}
	}
	for _, id := range missing {
		if _, err = r.db.Exec(`UPDATE recording_segments SET state='gap',spool='' WHERE id=?`, id); err != nil {
			return err
		}
		if _, err = r.db.Exec(`DELETE FROM recording_upload_jobs WHERE segment_id=?`, id); err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(r.spool)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return errors.New("unexpected spool directory")
		}
		name := filepath.Join(r.spool, entry.Name())
		if !known[name] || strings.HasPrefix(entry.Name(), ".stage-") {
			if err := os.Remove(name); err != nil {
				return err
			}
		}
	}
	_, err = r.db.Exec(`INSERT OR IGNORE INTO recording_upload_jobs(segment_id) SELECT id FROM recording_segments WHERE state='staged'`)
	return err
}
func (r *Recorder) capacity(size int64) bool {
	used, err := r.physicalUsage()
	if err != nil || size <= 0 {
		return false
	}
	factor := int64(2) // stage plus S3 request-body spool
	if _, ok := r.store.(interface{ LocalRoot() string }); ok {
		factor = 3 // stage, local object temp, published object
	}
	if size > (r.cfg.QuotaBytes-used-atomic.LoadInt64(&r.inFlight))/factor {
		return false
	}
	var stat syscall.Statfs_t
	if syscall.Statfs(r.spool, &stat) != nil {
		return false
	}
	free := stat.Bavail * uint64(stat.Bsize)
	if uint64(size) > (free-r.cfg.ReserveBytes)/uint64(factor) || free < r.cfg.ReserveBytes {
		return false
	}
	return true
}

// BindStore refuses backend switches while catalog objects still depend on the old
// backend. A migration tool must copy and verify them before changing this identity.
func (r *Recorder) BindStore(id string) error {
	if id == "" {
		return errors.New("store identity required")
	}
	var old string
	err := r.db.QueryRow(`SELECT store_id FROM recording_store_identity WHERE id=1`).Scan(&old)
	if err == nil && old != id {
		return fmt.Errorf("recording store changed from %q to %q; migrate catalog before switching", old, id)
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = r.db.Exec(`INSERT OR IGNORE INTO recording_store_identity(id,store_id) VALUES(1,?)`, id)
	return err
}

// markGap records an attempted closed segment that was not safely captured.
func (r *Recorder) markGap(camera, run string, sequence int64, start, end time.Time, duration float64) error {
	_, err := r.db.Exec(`INSERT OR IGNORE INTO recording_segments(camera,run,sequence,start_ns,end_ns,duration,discontinuity,key,sha256,size,spool,state) VALUES(?,?,?,?,?,?,1,'','',0,'','gap')`, camera, run, sequence, start.UnixNano(), end.UnixNano(), duration)
	return err
}

// IngestPlaylist sees only atomically published playlist entries. It never waits for network I/O.
func (r *Recorder) IngestPlaylist(camera, run, dir string, received time.Time) error {
	if !r.enabled(camera) {
		return nil
	}
	if !validIdentity(run) {
		return errors.New("invalid run")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "stream.m3u8"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// Receipt time is only an estimate: align the playlist tail to receipt,
	// then walk its declared durations. Program-date-time overrides the estimate.
	var total float64
	for _, item := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(item, "#EXTINF:") {
			seconds, parseErr := strconv.ParseFloat(strings.SplitN(strings.TrimPrefix(item, "#EXTINF:"), ",", 2)[0], 64)
			if parseErr == nil && seconds > 0 && seconds <= 3600 {
				total += seconds
			}
		}
	}
	cursor := received.Add(-time.Duration(total * float64(time.Second)))
	sequence := int64(0)
	var previous int64
	_ = r.db.QueryRow(`SELECT COALESCE(MAX(sequence),-1) FROM recording_segments WHERE camera=? AND run=?`, camera, run).Scan(&previous)
	duration := float64(0)
	discontinuity := false
	var explicitTime *time.Time
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "#EXT-X-MEDIA-SEQUENCE:"):
			sequence, _ = strconv.ParseInt(strings.TrimPrefix(line, "#EXT-X-MEDIA-SEQUENCE:"), 10, 64)
		case strings.HasPrefix(line, "#EXT-X-PROGRAM-DATE-TIME:"):
			v, e := time.Parse(time.RFC3339Nano, strings.TrimPrefix(line, "#EXT-X-PROGRAM-DATE-TIME:"))
			if e == nil {
				explicitTime = &v
			}
		case strings.HasPrefix(line, "#EXTINF:"):
			duration, _ = strconv.ParseFloat(strings.SplitN(strings.TrimPrefix(line, "#EXTINF:"), ",", 2)[0], 64)
		case line == "#EXT-X-DISCONTINUITY":
			discontinuity = true
		case line != "" && line[0] != '#':
			start := cursor
			if explicitTime != nil {
				start = *explicitTime
			}
			cursor = start.Add(time.Duration(duration * float64(time.Second)))
			if sequence > previous+1 {
				// A huge discontinuity is represented by a bounded marker rather
				// than unbounded inserts or an unreported missing span.
				if sequence-previous > 1001 {
					if err := r.markGap(camera, run, previous+1, start, start, duration); err != nil {
						return err
					}
				} else {
					for missed := previous + 1; missed < sequence; missed++ {
						if err := r.markGap(camera, run, missed, start, start, duration); err != nil {
							return err
						}
					}
				}
			}
			if sequence > previous {
				previous = sequence
			}
			if duration <= 0 || duration > 3600 || strings.Contains(line, "/") || strings.Contains(line, "\\") || filepath.Base(line) != line {
				if err := r.markGap(camera, run, sequence, start, cursor, duration); err != nil {
					return err
				}
				sequence++
				duration = 0
				continue
			}
			var exists int
			_ = r.db.QueryRow(`SELECT 1 FROM recording_segments WHERE camera=? AND run=? AND sequence=?`, camera, run, sequence).Scan(&exists)
			if exists == 1 {
				sequence++
				duration = 0
				discontinuity = false
				explicitTime = nil
				continue
			}
			source, openErr := os.Open(filepath.Join(dir, line))
			if openErr != nil {
				if err := r.markGap(camera, run, sequence, start, cursor, duration); err != nil {
					return err
				}
				sequence++
				duration = 0
				continue
			}
			fi, statErr := source.Stat()
			if statErr != nil || !fi.Mode().IsRegular() || !r.capacity(fi.Size()) {
				source.Close()
				if err := r.markGap(camera, run, sequence, start, cursor, duration); err != nil {
					return err
				}
				sequence++
				duration = 0
				continue
			}
			key := safeID(camera) + "/" + safeID(run) + "/" + strconv.FormatInt(sequence, 10) + ".ts"
			spool := filepath.Join(r.spool, strings.ReplaceAll(key, "/", "_"))
			tmp, createErr := os.CreateTemp(r.spool, ".stage-")
			if createErr != nil {
				source.Close()
				return createErr
			}
			h := sha256.New()
			n, copyErr := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(source, fi.Size()+1))
			source.Close()
			if copyErr != nil || n != fi.Size() {
				tmp.Close()
				os.Remove(tmp.Name())
				if err := r.markGap(camera, run, sequence, start, cursor, duration); err != nil {
					return err
				}
				sequence++
				duration = 0
				continue
			}
			if err = tmp.Sync(); err == nil {
				err = tmp.Close()
			}
			if err == nil {
				err = os.Rename(tmp.Name(), spool)
			}
			if err != nil {
				os.Remove(tmp.Name())
				return err
			}
			end := cursor
			disc := 0
			if discontinuity {
				disc = 1
			}
			_, err = r.db.Exec(`INSERT OR IGNORE INTO recording_segments(camera,run,sequence,start_ns,end_ns,duration,discontinuity,key,sha256,size,spool,state) VALUES(?,?,?,?,?,?,?,?,?,?,?,'staged')`, camera, run, sequence, start.UnixNano(), end.UnixNano(), duration, disc, key, hex.EncodeToString(h.Sum(nil)), n, spool)
			if err != nil {
				return err
			}
			_, err = r.db.Exec(`INSERT OR IGNORE INTO recording_upload_jobs(segment_id) SELECT id FROM recording_segments WHERE camera=? AND run=? AND sequence=?`, camera, run, sequence)
			if err != nil {
				return err
			}
			sequence++
			duration = 0
			discontinuity = false
			explicitTime = nil
		}
	}
	return nil
}
func (r *Recorder) Coverage(camera string, from, to time.Time) ([]Segment, error) {
	if !validIdentity(camera) || !to.After(from) || to.Sub(from) > 31*24*time.Hour {
		return nil, errors.New("invalid bounded interval")
	}
	rows, err := r.db.Query(`SELECT id,camera,start_ns,end_ns,duration,discontinuity,state,key,sha256,size,spool FROM recording_segments WHERE camera=? AND end_ns>? AND start_ns<? AND state IN ('staged','ready','gap') ORDER BY start_ns,id LIMIT 1000`, camera, from.UnixNano(), to.UnixNano())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Segment
	for rows.Next() {
		var s Segment
		var a, b int64
		var disc int
		if err = rows.Scan(&s.ID, &s.Camera, &a, &b, &s.Duration, &disc, &s.State, &s.Key, &s.SHA256, &s.Size, &s.Spool); err != nil {
			return nil, err
		}
		s.Start = time.Unix(0, a).UTC()
		s.End = time.Unix(0, b).UTC()
		s.Discontinuity = disc != 0
		out = append(out, s)
	}
	return out, rows.Err()
}
func (r *Recorder) Segment(id int64) (Segment, error) {
	var s Segment
	var a, b int64
	var disc int
	err := r.db.QueryRow(`SELECT id,camera,start_ns,end_ns,duration,discontinuity,state,key,sha256,size,spool FROM recording_segments WHERE id=? AND state IN ('staged','ready')`, id).Scan(&s.ID, &s.Camera, &a, &b, &s.Duration, &disc, &s.State, &s.Key, &s.SHA256, &s.Size, &s.Spool)
	s.Start = time.Unix(0, a).UTC()
	s.End = time.Unix(0, b).UTC()
	s.Discontinuity = disc != 0
	return s, err
}
func (r *Recorder) Open(ctx context.Context, id int64, span *storage.ByteRange) (io.ReadCloser, storage.ObjectInfo, error) {
	s, err := r.Segment(id)
	if err != nil {
		return nil, storage.ObjectInfo{}, err
	}
	if s.State == "ready" {
		return r.store.Open(ctx, s.Key, span)
	}
	f, err := os.Open(s.Spool)
	if err != nil {
		return nil, storage.ObjectInfo{}, err
	}
	if err = storage.ValidateRange(span, s.Size); err != nil {
		f.Close()
		return nil, storage.ObjectInfo{}, err
	}
	n, offset := s.Size, int64(0)
	if span != nil {
		n, offset = span.Length, span.Offset
	}
	f.Seek(offset, io.SeekStart)
	return struct {
		io.Reader
		io.Closer
	}{io.LimitReader(f, n), f}, storage.ObjectInfo{Key: s.Key, Size: s.Size, SHA256: s.SHA256, ContentType: "video/mp2t"}, nil
}
func (r *Recorder) Process(ctx context.Context) error {
	r.processMu.Lock()
	defer r.processMu.Unlock()
	var first error
	rows, err := r.db.Query(`SELECT s.id,s.key,s.sha256,s.size,s.spool,j.attempts FROM recording_segments s JOIN recording_upload_jobs j ON j.segment_id=s.id WHERE s.state='staged' AND j.next_ns<=? LIMIT 16`, time.Now().UnixNano())
	if err != nil {
		return err
	}
	type job struct {
		id              int64
		key, sha, spool string
		size            int64
		attempts        int
	}
	var jobs []job
	for rows.Next() {
		var j job
		if err = rows.Scan(&j.id, &j.key, &j.sha, &j.size, &j.spool, &j.attempts); err != nil {
			rows.Close()
			return err
		}
		jobs = append(jobs, j)
	}
	rows.Close()
	for _, j := range jobs {
		var existing bool
		if _, ok := r.store.(interface{ LocalRoot() string }); ok {
			info, statErr := r.store.Stat(ctx, j.key)
			if statErr == nil {
				if info.Size != j.size || info.SHA256 != j.sha {
					return storage.ErrIntegrity
				}
				existing = true
			} else if !errors.Is(statErr, storage.ErrNotFound) {
				return statErr
			}
		}
		// The lock covers only quota reservation and catalog transitions; never
		// hold it across object-store I/O, which may be indefinitely unavailable.
		r.mu.Lock()
		var state string
		stateErr := r.db.QueryRow(`SELECT state FROM recording_segments WHERE id=?`, j.id).Scan(&state)
		if stateErr != nil || state != "staged" {
			r.mu.Unlock()
			continue
		}
		used, e := r.physicalUsage()
		if e == nil && !existing {
			var stat syscall.Statfs_t
			if syscall.Statfs(r.spool, &stat) != nil || stat.Bavail*uint64(stat.Bsize) < r.cfg.ReserveBytes || uint64(j.size) > ((stat.Bavail*uint64(stat.Bsize)-r.cfg.ReserveBytes)/2) {
				e = errors.New("recording free-space reserve reached")
			}
			factor := int64(1)
			if _, ok := r.store.(interface{ LocalRoot() string }); ok {
				factor = 2
			}
			if j.size > (r.cfg.QuotaBytes-used-atomic.LoadInt64(&r.inFlight))/factor {
				e = errors.New("recording object quota reached")
			}
		}
		if e != nil {
			r.mu.Unlock()
			if first == nil {
				first = e
			}
			continue
		}
		if !existing {
			atomic.AddInt64(&r.inFlight, j.size*2)
		}
		r.mu.Unlock()
		if !existing {
			f, openErr := os.Open(j.spool)
			e = openErr
			if e == nil {
				e = r.store.Put(ctx, storage.ObjectInfo{Key: j.key, SHA256: j.sha, Size: j.size, ContentType: "video/mp2t"}, f)
				f.Close()
			}
			atomic.AddInt64(&r.inFlight, -j.size*2)
		}
		r.mu.Lock()
		var current string
		if scanErr := r.db.QueryRow(`SELECT state FROM recording_segments WHERE id=?`, j.id).Scan(&current); scanErr != nil || current != "staged" {
			r.mu.Unlock()
			continue
		}
		if e == nil {
			_, e = r.db.Exec(`UPDATE recording_segments SET state='ready' WHERE id=?`, j.id)
			if e == nil {
				_, e = r.db.Exec(`DELETE FROM recording_upload_jobs WHERE segment_id=?`, j.id)
			}
			if e == nil {
				_ = os.Remove(j.spool)
			}
		} else {
			delay := time.Second * time.Duration(math.Min(3600, math.Pow(2, float64(min(j.attempts, 12)))))
			_, _ = r.db.Exec(`UPDATE recording_upload_jobs SET attempts=attempts+1,next_ns=?,last_error='storage unavailable' WHERE segment_id=?`, time.Now().Add(delay).UnixNano(), j.id)
			if first == nil {
				first = e
			}
		}
		r.mu.Unlock()
	}
	return first
}
func (r *Recorder) Retain(ctx context.Context, now time.Time) error {
	r.processMu.Lock()
	defer r.processMu.Unlock()
	cutoff := now.Add(-time.Duration(r.cfg.RetentionDays) * 24 * time.Hour).UnixNano()
	_, err := r.db.Exec(`INSERT OR IGNORE INTO recording_deletion_jobs(segment_id,key) SELECT id,key FROM recording_segments WHERE end_ns<? AND state IN ('ready','staged','gap','deleting')`, cutoff)
	if err != nil {
		return err
	}
	rows, err := r.db.Query(`SELECT j.segment_id,j.key,s.state,s.spool FROM recording_deletion_jobs j JOIN recording_segments s ON s.id=j.segment_id WHERE j.next_ns<=? LIMIT 16`, now.UnixNano())
	if err != nil {
		return err
	}
	type job struct {
		id                int64
		key, state, spool string
	}
	var jobs []job
	for rows.Next() {
		var j job
		if err := rows.Scan(&j.id, &j.key, &j.state, &j.spool); err != nil {
			rows.Close()
			return err
		}
		jobs = append(jobs, j)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, j := range jobs {
		// Exclude this segment from uploads and readers before any deletion.
		r.mu.Lock()
		_, err = r.db.Exec(`UPDATE recording_segments SET state='deleting' WHERE id=?`, j.id)
		if err == nil {
			_, err = r.db.Exec(`DELETE FROM recording_upload_jobs WHERE segment_id=?`, j.id)
		}
		r.mu.Unlock()
		if err != nil {
			return err
		}
		if j.key != "" {
			err = r.store.Delete(ctx, j.key)
		}
		if err == nil && j.spool != "" {
			err = os.Remove(j.spool)
			if os.IsNotExist(err) {
				err = nil
			}
		}
		if err != nil {
			_, _ = r.db.Exec(`UPDATE recording_deletion_jobs SET attempts=attempts+1,next_ns=? WHERE segment_id=?`, now.Add(time.Minute).UnixNano(), j.id)
			return err
		}
		r.mu.Lock()
		// Delete catalog and retry job atomically. A crash after object removal
		// simply retries an idempotent Delete on restart.
		tx, e := r.db.Begin()
		if e != nil {
			r.mu.Unlock()
			return e
		}
		if _, e = tx.Exec(`DELETE FROM recording_segments WHERE id=?`, j.id); e == nil {
			_, e = tx.Exec(`DELETE FROM recording_deletion_jobs WHERE segment_id=?`, j.id)
		}
		if e != nil {
			tx.Rollback()
			r.mu.Unlock()
			return e
		}
		e = tx.Commit()
		r.mu.Unlock()
		if e != nil {
			return e
		}
	}
	return nil
}
func (r *Recorder) Playlist(camera string, from, to time.Time) (string, error) {
	v, err := r.Coverage(camera, from, to)
	if err != nil {
		return "", err
	}
	var playable []Segment
	for _, s := range v {
		if s.State != "gap" {
			playable = append(playable, s)
		}
	}
	v = playable
	if len(v) == 0 {
		return "", sql.ErrNoRows
	}
	max := 1
	for _, s := range v {
		if x := int(math.Ceil(s.Duration)); x > max {
			max = x
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-PLAYLIST-TYPE:VOD\n#EXT-X-TARGETDURATION:%d\n#EXT-X-MEDIA-SEQUENCE:0\n", max)
	for i, s := range v {
		if i > 0 && (s.Discontinuity || s.Start.Sub(v[i-1].End) > time.Second || s.Start.Before(v[i-1].Start)) {
			b.WriteString("#EXT-X-DISCONTINUITY\n")
		}
		fmt.Fprintf(&b, "#EXTINF:%.3f,\n/api/recordings/segments/%d\n", s.Duration, s.ID)
	}
	b.WriteString("#EXT-X-ENDLIST\n")
	return b.String(), nil
}
