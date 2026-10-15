package main

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dengan.dev/camera-streamer/internal/logger"
	"dengan.dev/camera-streamer/internal/recording"
	"dengan.dev/camera-streamer/internal/secrets"
)

const wiringCredential = "WIRING-FAKE-SECRET-7d2f1a-MUST-NOT-LEAK"

func wiringCipher(t *testing.T) *secrets.Cipher {
	t.Helper()
	c, err := secrets.New(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func s3Settings(t *testing.T, dbPath, base string, cipher *secrets.Cipher) recording.StorageSettings {
	t.Helper()
	db, err := logger.NewLogger(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	env := recording.StorageEnv{
		Driver:        recording.DriverS3,
		S3Endpoint:    "https://s3.example.invalid",
		S3Bucket:      "footage",
		S3Region:      "eu-central-1",
		S3AccessKey:   "operator",
		S3Secret:      wiringCredential,
		S3Session:     "WIRING-FAKE-SESSION",
		QuotaBytes:    1 << 20,
		ReserveBytes:  0,
		RetentionDays: 7,
	}
	settings, _, err := recording.ResolveStorageSettings(db.DB(), env, cipher)
	if err != nil {
		t.Fatal(err)
	}
	return settings
}

func TestBuildStoreS3WithRealKeyDescribesLocationWithoutCredentials(t *testing.T) {
	dir := t.TempDir()
	settings := s3Settings(t, filepath.Join(dir, "app.db"), dir, wiringCipher(t))
	_, desc, err := buildStore(settings, wiringCipher(t), dir)
	if err != nil {
		t.Fatal(err)
	}
	if desc.Driver != recording.DriverS3 || desc.S3Endpoint != "https://s3.example.invalid" || desc.S3Bucket != "footage" {
		t.Fatalf("description %+v", desc)
	}
	if !desc.Available {
		t.Fatalf("a complete s3 configuration was reported unavailable: %+v", desc)
	}
	// The description must carry no credential-shaped field at all.
	rendered := desc.Driver + desc.LocalPath + desc.S3Endpoint + desc.S3Bucket + desc.S3Region + desc.Unavailable
	if strings.Contains(rendered, wiringCredential) || strings.Contains(rendered, "WIRING-FAKE-SESSION") {
		t.Fatalf("the store description carried a credential: %q", rendered)
	}
}

func TestBuildStoreS3WithoutAppKeyIsUnavailableNotInteractive(t *testing.T) {
	dir := t.TempDir()
	// Seal with a key, then resolve with none: the sealed credential cannot be
	// opened, which must be a configuration error, never an empty credential.
	db, err := logger.NewLogger(filepath.Join(dir, "app.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	env := recording.StorageEnv{
		Driver:        recording.DriverS3,
		S3Endpoint:    "https://s3.example.invalid",
		S3Bucket:      "footage",
		S3Region:      "eu-central-1",
		S3AccessKey:   "operator",
		S3Secret:      wiringCredential,
		QuotaBytes:    1 << 20,
		RetentionDays: 7,
	}
	if _, _, err := recording.ResolveStorageSettings(db.DB(), env, wiringCipher(t)); err != nil {
		t.Fatal(err)
	}
	// Re-resolving without the key must refuse rather than silently drop it.
	if _, _, err := recording.ResolveStorageSettings(db.DB(), env, nil); err == nil {
		t.Fatal("a sealed credential resolved without an application key")
	}
	// And buildStore must refuse a credential this key cannot open, rather than
	// build a working-looking store with an empty secret.
	settings, _, err := recording.ResolveStorageSettings(db.DB(), env, wiringCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	other, err := secrets.New(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := buildStore(settings, other, dir); err == nil {
		t.Fatal("buildStore accepted a credential sealed under a different key")
	}
}

func TestBuildStoreS3WithoutASecretIsReportedUnavailable(t *testing.T) {
	dir := t.TempDir()
	settings, _, err := recording.ResolveStorageSettings(openDB(t, dir), recording.StorageEnv{
		Driver:        recording.DriverS3,
		S3Endpoint:    "https://s3.example.invalid",
		S3Bucket:      "footage",
		S3Region:      "eu-central-1",
		S3AccessKey:   "operator",
		QuotaBytes:    1 << 20,
		RetentionDays: 7,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	store, desc, err := buildStore(settings, nil, dir)
	if err != nil {
		t.Fatal(err)
	}
	if desc.Available || desc.Unavailable == "" {
		t.Fatalf("a secret-less s3 store must report why it is unusable: %+v", desc)
	}
	if desc.AppKey {
		t.Fatal("a nil application key was reported as available")
	}
	// Every operation fails closed rather than looking like a working archive.
	if err := store.Delete(nil, "cam/1.ts"); err == nil {
		t.Fatal("an unavailable store silently accepted a delete")
	}
}

func TestBuildStoreLocalUsesAbsolutePathAndNoSecret(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "custom-objects")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	settings, _, err := recording.ResolveStorageSettings(openDB(t, dir), recording.StorageEnv{
		Driver:        recording.DriverLocal,
		LocalPath:     root,
		QuotaBytes:    1 << 20,
		RetentionDays: 7,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, desc, err := buildStore(settings, nil, dir)
	if err != nil {
		t.Fatal(err)
	}
	if desc.Driver != recording.DriverLocal || desc.LocalPath != root || !desc.Available {
		t.Fatalf("local description %+v", desc)
	}
	if desc.AppKey {
		t.Fatal("a nil app key was reported as available")
	}
}

func TestBuildStoreRejectsUnknownDriver(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := buildStore(recording.StorageSettings{Driver: "ftp"}, nil, dir); err == nil {
		t.Fatal("an unknown driver was accepted")
	}
}

func openDB(t *testing.T, dir string) *sql.DB {
	t.Helper()
	db, err := logger.NewLogger(filepath.Join(dir, "app.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db.DB()
}
