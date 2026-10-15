package recording

import (
	"database/sql"
	"errors"
	"regexp"
	"sync/atomic"
	"syscall"
	"time"

	"dengan.dev/camera-streamer/internal/recording/storage"
)

// MaxSummaryBuckets caps the number of histogram buckets a single summary may
// return. A wide window must not be able to ask for an unbounded response.
const MaxSummaryBuckets = 240

// MaxSummarySegments bounds the catalog read behind a summary, matching the
// Coverage bound so the timeline and the raw coverage agree on truncation.
const MaxSummarySegments = 1000

// Location is the non-secret place footage lives. It deliberately has nowhere to
// put a credential: endpoint, bucket and region are configuration, and an
// unusable driver reports WHY rather than silently looking healthy.
type Location struct {
	Kind        string `json:"kind"`
	Path        string `json:"path,omitempty"`
	Endpoint    string `json:"endpoint,omitempty"`
	Bucket      string `json:"bucket,omitempty"`
	Region      string `json:"region,omitempty"`
	Unavailable string `json:"unavailable,omitempty"`
}

// StoreDescription is supplied once, by whoever constructed the store, so the
// driver and its location have a single source of truth instead of two places
// re-deriving the answer from the environment.
type StoreDescription struct {
	Driver   string
	LocalPath string
	S3Endpoint string
	S3Bucket   string
	S3Region   string
	// Available is false when the driver is configured but unusable (for
	// example an S3 store with no application key); Unavailable says why.
	Available   bool
	Unavailable string
	// AppKey is whether an application key was loaded this boot.
	AppKey bool
}

// CapacityStatus is the live accounting an operator needs before trusting the
// archive: the quota, what is physically used, the reserve held back, and the
// free space the quota is bounded by.
type CapacityStatus struct {
	QuotaBytes   int64  `json:"quotaBytes"`
	UsedBytes    int64  `json:"usedBytes"`
	ReserveBytes uint64 `json:"reserveBytes"`
	FreeBytes    uint64 `json:"freeBytes"`
	Paused       bool   `json:"paused"`
}

// BacklogStatus reports work that has not completed yet.
type BacklogStatus struct {
	PendingUploads      int     `json:"pendingUploads"`
	OldestUploadSeconds float64 `json:"oldestUploadSeconds"`
	PendingDeletions    int     `json:"pendingDeletions"`
}

// HealthStatus reports the last successful upload and a sanitized last error.
// The error is a category, never a raw store message: a raw message carries
// object keys and filesystem paths.
type HealthStatus struct {
	LastUploadNS int64  `json:"lastUploadNs"`
	LastError    string `json:"lastError"`
}

// CameraSetting is one camera's recording enablement.
type CameraSetting struct {
	Camera  string `json:"camera"`
	Enabled bool   `json:"enabled"`
}

// Status is the token-gated operational view of recording.
type Status struct {
	Enabled             bool            `json:"enabled"`
	Driver              string          `json:"driver"`
	Location            Location        `json:"location"`
	Capacity            CapacityStatus  `json:"capacity"`
	Backlog             BacklogStatus   `json:"backlog"`
	Cameras             []CameraSetting `json:"cameras"`
	Health              HealthStatus    `json:"health"`
	RetentionDays       int             `json:"retentionDays"`
	AppKeyAvailable     bool            `json:"appKeyAvailable"`
	DriverSwitchAllowed bool            `json:"driverSwitchAllowed"`
	DriverSwitchReason  string          `json:"driverSwitchReason,omitempty"`
}

// SetStoreDescription records which driver and location are live. It is called
// once at wiring time; the handler never re-derives this from the environment.
func (r *Recorder) SetStoreDescription(d StoreDescription) error {
	if d.Driver != DriverLocal && d.Driver != DriverS3 {
		return errors.New("unknown storage driver")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.desc = d
	return nil
}

// ApplyLimits changes quota, reserve and retention at runtime under the
// recorder mutex, so a saved value takes effect on the next capture and the next
// retention pass without a restart. The environment stays the boot default.
func (r *Recorder) ApplyLimits(quota int64, reserve uint64, retentionDays int) error {
	if quota <= 0 {
		return errors.New("quota must be a positive byte count")
	}
	if reserve > uint64(1<<62) {
		return errors.New("reserve is implausibly large")
	}
	if retentionDays <= 0 {
		return errors.New("retention must be at least one day")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cfg.QuotaBytes = quota
	r.cfg.ReserveBytes = reserve
	r.cfg.RetentionDays = retentionDays
	return nil
}

// limits reads the mutable limits under the recorder mutex.
func (r *Recorder) limits() (int64, uint64, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cfg.QuotaBytes, r.cfg.ReserveBytes, r.cfg.RetentionDays
}

// Limits exposes the effective, runtime-editable limits.
func (r *Recorder) Limits() (int64, uint64, int) { return r.limits() }

// SaveLimits validates, persists and applies new limits so a saved value both
// takes effect immediately (under the recorder mutex) and survives a restart
// through the storage-settings row. The environment stays the boot default: the
// row is what the next boot resolves.
func (r *Recorder) SaveLimits(quota int64, reserve uint64, retentionDays int) error {
	if quota <= 0 {
		return errors.New("quota must be a positive byte count")
	}
	if reserve > uint64(1<<62) {
		return errors.New("reserve is implausibly large")
	}
	if retentionDays <= 0 {
		return errors.New("retention must be at least one day")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, err := r.db.Exec(`UPDATE recording_storage_settings SET quota_bytes=?,reserve_bytes=?,retention_days=?,updated_ns=? WHERE id=1`,
		quota, int64(reserve), retentionDays, time.Now().UTC().UnixNano()); err != nil {
		return err
	}
	r.cfg.QuotaBytes = quota
	r.cfg.ReserveBytes = reserve
	r.cfg.RetentionDays = retentionDays
	return nil
}

// DriverSwitch reports whether the storage driver may be changed. Switching is a
// migration, not a setting: it is offered ONLY while the catalog holds no
// segments. This never weakens BindStore's own refusal.
func (r *Recorder) DriverSwitch() (bool, string) {
	var count int
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM recording_segments`).Scan(&count); err != nil {
		return false, "the recording catalog could not be read"
	}
	if count > 0 {
		return false, "the recording catalog holds footage; migrating it is required before the storage driver can be changed"
	}
	return true, ""
}

// Status assembles the operational view. Every field here is safe to serialize:
// there is no credential, object key or path-derived secret in it.
func (r *Recorder) Status() (Status, error) {
	quota, reserve, days := r.limits()
	used, err := r.physicalUsage()
	if err != nil {
		return Status{}, err
	}
	var free uint64
	var stat syscall.Statfs_t
	if syscall.Statfs(r.spool, &stat) == nil {
		free = stat.Bavail * uint64(stat.Bsize)
	}
	inFlight := uint64(atomic.LoadInt64(&r.inFlight))
	paused := used >= quota || free < reserve || used+int64(inFlight) >= quota

	r.mu.Lock()
	desc := r.desc
	lastUpload := r.lastUploadNS
	lastError := r.lastError
	r.mu.Unlock()

	status := Status{
		Enabled: true,
		Driver:  desc.Driver,
		Location: Location{
			Kind:        desc.Driver,
			Path:        desc.LocalPath,
			Endpoint:    desc.S3Endpoint,
			Bucket:      desc.S3Bucket,
			Region:      desc.S3Region,
			Unavailable: desc.Unavailable,
		},
		Capacity: CapacityStatus{
			QuotaBytes:   quota,
			UsedBytes:    used,
			ReserveBytes: reserve,
			FreeBytes:    free,
			Paused:       paused,
		},
		Health:          HealthStatus{LastUploadNS: lastUpload, LastError: lastError},
		RetentionDays:   days,
		AppKeyAvailable: desc.AppKey,
	}
	// An unavailable driver is reported through the location, so a caller
	// cannot mistake a configured-but-unusable store for a working one.
	if !desc.Available && status.Location.Unavailable == "" {
		status.Location.Unavailable = "the storage driver is not available"
	}
	status.DriverSwitchAllowed, status.DriverSwitchReason = r.DriverSwitch()
	if err := r.backlog(&status.Backlog); err != nil {
		return Status{}, err
	}
	cameras, err := r.cameraSettings()
	if err != nil {
		return Status{}, err
	}
	status.Cameras = cameras
	return status, nil
}

func (r *Recorder) backlog(b *BacklogStatus) error {
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM recording_upload_jobs`).Scan(&b.PendingUploads); err != nil {
		return err
	}
	var oldest sql.NullInt64
	if err := r.db.QueryRow(`SELECT MIN(s.end_ns) FROM recording_upload_jobs j JOIN recording_segments s ON s.id=j.segment_id WHERE s.state='staged'`).Scan(&oldest); err != nil {
		return err
	}
	if oldest.Valid {
		age := time.Since(time.Unix(0, oldest.Int64)).Seconds()
		if age < 0 {
			age = 0
		}
		b.OldestUploadSeconds = age
	}
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM recording_deletion_jobs`).Scan(&b.PendingDeletions); err != nil {
		return err
	}
	return nil
}

// cameraSettings lists every camera that has a recording setting, so the UI can
// render toggles for exactly the set the recorder knows about.
func (r *Recorder) cameraSettings() ([]CameraSetting, error) {
	rows, err := r.db.Query(`SELECT camera,enabled FROM recording_settings ORDER BY camera LIMIT 256`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CameraSetting{}
	for rows.Next() {
		var c CameraSetting
		var enabled int
		if err := rows.Scan(&c.Camera, &enabled); err != nil {
			return nil, err
		}
		c.Enabled = enabled == 1
		out = append(out, c)
	}
	return out, rows.Err()
}

var (
	pathLike      = regexp.MustCompile(`(/[A-Za-z0-9._-]+){2,}`)
	s3StatusError = regexp.MustCompile(`\bS3 [A-Z]+ status [0-9]{3}\b`)
)

// recordFailureLocked stores a bounded, path-free summary of the last upload
// outcome. A raw store error carries object keys and absolute paths, so it must
// never be kept or returned.
func (r *Recorder) recordFailureLocked(err error) {
	if err == nil {
		return
	}
	r.lastError = sanitizeFailure(err)
}

func sanitizeFailure(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, storage.ErrIntegrity):
		return "object integrity check failed"
	case errors.Is(err, storage.ErrInvalidKey):
		return "invalid object key"
	case errors.Is(err, storage.ErrNotFound):
		return "object not found"
	}
	msg := err.Error()
	if m := s3StatusError.FindString(msg); m != "" {
		return m
	}
	switch msg {
	case "recording free-space reserve reached", "recording object quota reached", "recording storage write failed":
		return msg
	}
	// Anything else is reduced to a category: an unrecognised message could
	// carry a path, a key or a URL, and none of those may be exposed.
	if pathLike.MatchString(msg) {
		return "storage write failed"
	}
	if len(msg) > 0 && len(msg) <= 64 && !containsAny(msg, "/\\=") {
		return msg
	}
	return "storage write failed"
}

func containsAny(s, chars string) bool {
	for _, c := range chars {
		for _, r := range s {
			if r == c {
				return true
			}
		}
	}
	return false
}
