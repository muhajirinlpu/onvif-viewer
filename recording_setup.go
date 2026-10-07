package main

import (
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"dengan.dev/camera-streamer/internal/logger"
	"dengan.dev/camera-streamer/internal/recording"
	"dengan.dev/camera-streamer/internal/recording/storage"
	"dengan.dev/camera-streamer/internal/recording/storage/local"
	"dengan.dev/camera-streamer/internal/recording/storage/s3"
	"dengan.dev/camera-streamer/internal/stream"
)

// Recording stays entirely inert unless explicitly opted in with a private
// bearer token. Per-camera recording_settings must be enabled separately.
func setupRecording(db *logger.Logger, manager *stream.Manager) (*recording.Recorder, string, error) {
	if os.Getenv("ONVIF_RECORDING_ENABLED") != "1" {
		return nil, "", nil
	}
	token := os.Getenv("ONVIF_RECORDING_TOKEN")
	if len(token) < 32 {
		return nil, "", errors.New("recording requires a 32+ character bearer token")
	}
	home, e := os.UserHomeDir()
	if e != nil {
		return nil, "", e
	}
	base := filepath.Join(home, ".local/share/onvif-viewer/recordings")
	if custom := os.Getenv("ONVIF_RECORDING_DIR"); custom != "" {
		base = custom
	}
	if !filepath.IsAbs(base) {
		return nil, "", errors.New("recording directory must be absolute")
	}
	quota := int64(1 << 30)
	if v := os.Getenv("ONVIF_RECORDING_QUOTA_BYTES"); v != "" {
		quota, e = strconv.ParseInt(v, 10, 64)
		if e != nil {
			return nil, "", e
		}
	}
	reserve := uint64(2 << 30)
	if v := os.Getenv("ONVIF_RECORDING_RESERVE_BYTES"); v != "" {
		reserve, e = strconv.ParseUint(v, 10, 64)
		if e != nil {
			return nil, "", e
		}
	}
	days := 7
	if v := os.Getenv("ONVIF_RECORDING_RETENTION_DAYS"); v != "" {
		days, e = strconv.Atoi(v)
		if e != nil {
			return nil, "", e
		}
	}
	var store storage.Store
	switch os.Getenv("ONVIF_RECORDING_STORE") {
	case "", "local":
		store, e = local.New(filepath.Join(base, "objects"))
	case "s3":
		store, e = s3.New(s3.Config{Endpoint: os.Getenv("ONVIF_S3_ENDPOINT"), Bucket: os.Getenv("ONVIF_S3_BUCKET"), Region: os.Getenv("ONVIF_S3_REGION"), AccessKey: os.Getenv("ONVIF_S3_ACCESS_KEY"), SecretKey: os.Getenv("ONVIF_S3_SECRET_KEY"), SessionToken: os.Getenv("ONVIF_S3_SESSION_TOKEN"), SpoolDir: filepath.Join(base, "spool")})
	default:
		return nil, "", errors.New("unknown recording store")
	}
	if e != nil {
		return nil, "", e
	}
	rec, e := recording.New(db.DB(), filepath.Join(base, "spool"), store, recording.Config{QuotaBytes: quota, ReserveBytes: reserve, RetentionDays: days})
	if e != nil {
		return nil, "", e
	}
	storeID := "local:" + filepath.Join(base, "objects")
	if os.Getenv("ONVIF_RECORDING_STORE") == "s3" {
		storeID = "s3:" + os.Getenv("ONVIF_S3_ENDPOINT") + "/" + os.Getenv("ONVIF_S3_BUCKET")
	}
	if e = rec.BindStore(storeID); e != nil {
		return nil, "", e
	}
	manager.SetRecordingObserver(func(camera, run, dir string, received time.Time) {
		if e := rec.IngestPlaylist(camera, run, dir, received); e != nil {
			log.Printf("recording stage failed: %v", e)
		}
	})
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			_ = rec.Process(ctx)
			_ = rec.Retain(ctx, time.Now().UTC())
			cancel()
		}
	}()
	return rec, token, nil
}
