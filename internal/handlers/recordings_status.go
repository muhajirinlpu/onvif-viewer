package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"dengan.dev/camera-streamer/internal/recording"
)

// recordingRouteConfig carries the non-secret wiring the status surface needs.
// The resolved storage settings are passed in so the handler reports the driver
// and its non-secret location from a single source of truth instead of
// re-deriving them from the environment.
type recordingRouteConfig struct {
	storage *recording.StorageSettings
}

// RecordingOption configures the recording routes.
type RecordingOption func(*recordingRouteConfig)

// WithStorageSettings supplies the resolved storage settings. Only the driver
// and its non-secret location are ever read from it; the sealed credentials are
// never opened here and never serialized.
func WithStorageSettings(s recording.StorageSettings) RecordingOption {
	return func(c *recordingRouteConfig) { c.storage = &s }
}

func parseBuckets(raw string) (int, error) {
	if strings.TrimSpace(raw) == "" {
		return 0, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 || v > recording.MaxSummaryBuckets*4 {
		return 0, errors.New("invalid bucket count")
	}
	return v, nil
}

// writeRecordingJSON writes one JSON body for GET only. HEAD sends headers and no body,
// exactly as the media routes do.
func writeRecordingJSON(w http.ResponseWriter, r *http.Request, value any) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == "HEAD" {
		return
	}
	_ = json.NewEncoder(w).Encode(value)
}

// settingsView is the editable configuration surface. It is deliberately a
// distinct struct from Status: nothing credential-shaped can be added to it by
// accident, because the fields are enumerated here.
type settingsView struct {
	Cameras             []recording.CameraSetting `json:"cameras"`
	Driver              string                    `json:"driver"`
	RetentionDays       int                       `json:"retentionDays"`
	QuotaBytes          int64                     `json:"quotaBytes"`
	ReserveBytes        uint64                    `json:"reserveBytes"`
	DriverSwitchAllowed bool                      `json:"driverSwitchAllowed"`
	DriverSwitchReason  string                    `json:"driverSwitchReason,omitempty"`
}

// settingsWrite is the POST body. Unknown fields are rejected so a client cannot
// believe it saved something the server ignored.
type settingsWrite struct {
	Camera        *string `json:"camera"`
	Enabled       *bool   `json:"enabled"`
	RetentionDays *int    `json:"retentionDays"`
	QuotaBytes    *int64  `json:"quotaBytes"`
	ReserveBytes  *uint64 `json:"reserveBytes"`
}

func handleSettings(w http.ResponseWriter, r *http.Request, rec *recording.Recorder, cfg recordingRouteConfig) {
	if r.Method == "POST" {
		handleSettingsWrite(w, r, rec, cfg)
		return
	}
	writeSettingsView(w, r, rec, cfg)
}

// writeSettingsView renders the effective configuration. It is shared by the
// read path and the response to a successful write, so a save cannot report
// something the next read would contradict.
func writeSettingsView(w http.ResponseWriter, r *http.Request, rec *recording.Recorder, cfg recordingRouteConfig) {
	status, err := rec.Status()
	if err != nil {
		http.Error(w, "recording settings unavailable", http.StatusInternalServerError)
		return
	}
	driver := status.Driver
	if driver == "" && cfg.storage != nil {
		driver = cfg.storage.Driver
	}
	writeRecordingJSON(w, r, settingsView{
		Cameras:             status.Cameras,
		Driver:              driver,
		RetentionDays:       status.RetentionDays,
		QuotaBytes:          status.Capacity.QuotaBytes,
		ReserveBytes:        status.Capacity.ReserveBytes,
		DriverSwitchAllowed: status.DriverSwitchAllowed,
		DriverSwitchReason:  status.DriverSwitchReason,
	})
}

func handleSettingsWrite(w http.ResponseWriter, r *http.Request, rec *recording.Recorder, cfg recordingRouteConfig) {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	var body settingsWrite
	if err := decoder.Decode(&body); err != nil {
		http.Error(w, "invalid settings payload", http.StatusBadRequest)
		return
	}
	if body.Camera == nil && body.Enabled == nil && body.RetentionDays == nil && body.QuotaBytes == nil && body.ReserveBytes == nil {
		http.Error(w, "no setting supplied", http.StatusBadRequest)
		return
	}
	// A camera toggle is one atomic unit: an enabled flag without a camera, or a
	// camera without an enabled flag, is a client bug rather than a partial save.
	if body.Camera != nil || body.Enabled != nil {
		if body.Camera == nil || body.Enabled == nil {
			http.Error(w, "camera and enabled must be supplied together", http.StatusBadRequest)
			return
		}
		if err := rec.SetEnabled(*body.Camera, *body.Enabled); err != nil {
			http.Error(w, "invalid camera", http.StatusBadRequest)
			return
		}
	}
	if body.RetentionDays != nil || body.QuotaBytes != nil || body.ReserveBytes != nil {
		quota, reserve, days := rec.Limits()
		if body.QuotaBytes != nil {
			if *body.QuotaBytes <= 0 {
				http.Error(w, "quotaBytes must be positive", http.StatusBadRequest)
				return
			}
			quota = *body.QuotaBytes
		}
		if body.ReserveBytes != nil {
			reserve = *body.ReserveBytes
		}
		if body.RetentionDays != nil {
			if *body.RetentionDays <= 0 {
				http.Error(w, "retentionDays must be positive", http.StatusBadRequest)
				return
			}
			days = *body.RetentionDays
		}
		if err := rec.SaveLimits(quota, reserve, days); err != nil {
			http.Error(w, "invalid storage limits", http.StatusBadRequest)
			return
		}
	}
	writeSettingsView(w, r, rec, cfg)
}
