package main

import (
	"context"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"dengan.dev/camera-streamer/internal/logger"
	"dengan.dev/camera-streamer/internal/recording"
	"dengan.dev/camera-streamer/internal/recording/storage"
	"dengan.dev/camera-streamer/internal/recording/storage/local"
	"dengan.dev/camera-streamer/internal/recording/storage/s3"
	"dengan.dev/camera-streamer/internal/secrets"
	"dengan.dev/camera-streamer/internal/stream"
)

// Recording stays entirely inert unless explicitly opted in with a private
// bearer token. Per-camera recording_settings must be enabled separately.
//
// ONVIF_RECORDING_ENABLED and ONVIF_RECORDING_TOKEN remain environment-only and
// are never settable from the UI: a UI-triggered recording enable would be a
// privilege-escalation path, and the bearer token is the single authorization.
func setupRecording(db *logger.Logger, manager *stream.Manager) (*recording.Recorder, string, recording.StorageSettings, error) {
	if os.Getenv("ONVIF_RECORDING_ENABLED") != "1" {
		return nil, "", recording.StorageSettings{}, nil
	}
	token := os.Getenv("ONVIF_RECORDING_TOKEN")
	if len(token) < 32 {
		return nil, "", recording.StorageSettings{}, errors.New("recording requires a 32+ character bearer token")
	}
	home, e := os.UserHomeDir()
	if e != nil {
		return nil, "", recording.StorageSettings{}, e
	}
	base := filepath.Join(home, ".local/share/onvif-viewer/recordings")
	if custom := os.Getenv(recording.EnvRecordingDir); custom != "" {
		base = custom
	}
	if !filepath.IsAbs(base) {
		return nil, "", recording.StorageSettings{}, errors.New("recording directory must be absolute")
	}
	// The application key is environment-only and loaded once. Its absence does
	// not stop a local installation: only S3 needs it, because only S3 has a
	// credential to seal.
	appKey, keyErr := secrets.LoadFrom(os.Getenv)
	if keyErr != nil && !errors.Is(keyErr, secrets.ErrUnavailable) {
		return nil, "", recording.StorageSettings{}, keyErr
	}
	if appKey == nil {
		log.Printf("Recording has no application key; only the local storage driver can be used")
	}

	env, e := recording.StorageEnvFromProcess(filepath.Join(base, "objects"))
	if e != nil {
		return nil, "", recording.StorageSettings{}, e
	}
	// Storage settings resolve as: database row if present, otherwise the
	// environment defaults, materialised into the row on first boot. A tampered
	// or unopenable credential is a configuration error here, never an empty
	// credential that quietly looks configured.
	settings, fromDB, e := recording.ResolveStorageSettings(db.DB(), env, appKey)
	if e != nil {
		return nil, "", recording.StorageSettings{}, e
	}
	log.Printf("Recording storage resolved from %s", storageSource(fromDB))

	store, desc, e := buildStore(settings, appKey, base)
	if e != nil {
		return nil, "", recording.StorageSettings{}, e
	}
	rec, e := recording.New(db.DB(), filepath.Join(base, "spool"), store, recording.Config{
		QuotaBytes:    settings.QuotaBytes,
		ReserveBytes:  settings.ReserveBytes,
		RetentionDays: settings.RetentionDays,
	})
	if e != nil {
		return nil, "", recording.StorageSettings{}, e
	}
	if e = rec.SetStoreDescription(desc); e != nil {
		return nil, "", recording.StorageSettings{}, e
	}
	if e = rec.BindStore(storeIdentity(settings)); e != nil {
		return nil, "", recording.StorageSettings{}, e
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
	return rec, token, settings, nil
}

// buildStore constructs the active driver and the non-secret description the
// status surface reports. The description is the single source of truth for
// driver and location: handlers never re-derive it from the environment.
func buildStore(settings recording.StorageSettings, appKey *secrets.Cipher, base string) (storage.Store, recording.StoreDescription, error) {
	switch settings.Driver {
	case recording.DriverLocal:
		return buildLocalStore(settings, appKey, base)
	case recording.DriverS3:
		secret, session, err := settings.Credentials(appKey)
		if err != nil {
			// A sealed credential that cannot be opened must refuse to start the
			// store; it must never degrade to an empty credential.
			return nil, recording.StoreDescription{}, err
		}
		if secret == "" && settings.S3AccessKey != "" {
			// The driver is configured but unusable. Recording still starts, but
			// it reports itself unavailable and every write fails closed rather
			// than pretending the archive works.
			return unavailableStore{}, recording.StoreDescription{
				Driver:      recording.DriverS3,
				S3Endpoint:  settings.S3Endpoint,
				S3Bucket:    settings.S3Bucket,
				S3Region:    settings.S3Region,
				Available:   false,
				Unavailable: "the S3 secret is not configured",
				AppKey:      appKey != nil,
			}, nil
		}
		store, err := s3.New(s3.Config{
			Endpoint:     settings.S3Endpoint,
			Bucket:       settings.S3Bucket,
			Region:       settings.S3Region,
			AccessKey:    settings.S3AccessKey,
			SecretKey:    secret,
			SessionToken: session,
			AllowHTTP:    settings.S3AllowHTTP,
			SpoolDir:     filepath.Join(base, "spool"),
		})
		if err != nil {
			return nil, recording.StoreDescription{}, err
		}
		return store, recording.StoreDescription{
			Driver:     recording.DriverS3,
			S3Endpoint: settings.S3Endpoint,
			S3Bucket:   settings.S3Bucket,
			S3Region:   settings.S3Region,
			Available:  true,
			AppKey:     appKey != nil,
		}, nil
	default:
		return nil, recording.StoreDescription{}, errors.New("unknown storage driver")
	}
}

// buildLocalStore is the explicit local branch, kept separate so an unknown
// driver value (a tampered row, say) is refused rather than silently treated as
// local.
func buildLocalStore(settings recording.StorageSettings, appKey *secrets.Cipher, base string) (storage.Store, recording.StoreDescription, error) {
	root := filepath.Join(base, "objects")
	if settings.LocalPath != "" {
		root = settings.LocalPath
	}
	store, err := local.New(root)
	if err != nil {
		return nil, recording.StoreDescription{}, err
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, recording.StoreDescription{}, err
	}
	return store, recording.StoreDescription{
		Driver:    recording.DriverLocal,
		LocalPath: abs,
		Available: true,
		AppKey:    appKey != nil,
	}, nil
}

// storeIdentity is the catalog-bound description of where objects live.
// BindStore refuses a change, because switching the backend strands footage:
// that is a migration, not a setting.
func storeIdentity(settings recording.StorageSettings) string {
	if settings.Driver == recording.DriverS3 {
		return "s3:" + settings.S3Endpoint + "/" + settings.S3Bucket
	}
	return "local:" + settings.LocalPath
}

// unavailableStore is used only when a driver is configured but unusable (an S3
// store with no sealed secret). Every operation fails closed, so a
// misconfiguration cannot silently look like a working archive.
type unavailableStore struct{}

var errStoreUnavailable = errors.New("recording storage driver is not available")

// storageSource labels where the resolved configuration came from, so the boot
// log says whether an operator edited the database or is still on the env
// defaults.
func storageSource(fromDB bool) string {
	if fromDB {
		return "the database configuration"
	}
	return "the environment defaults"
}

func (unavailableStore) Put(context.Context, storage.ObjectInfo, io.Reader) error {
	return errStoreUnavailable
}

func (unavailableStore) Stat(context.Context, string) (storage.ObjectInfo, error) {
	return storage.ObjectInfo{}, errStoreUnavailable
}

func (unavailableStore) Open(context.Context, string, *storage.ByteRange) (io.ReadCloser, storage.ObjectInfo, error) {
	return nil, storage.ObjectInfo{}, errStoreUnavailable
}

func (unavailableStore) Delete(context.Context, string) error { return errStoreUnavailable }
