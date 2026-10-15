package recording

import (
	"database/sql"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"

	"dengan.dev/camera-streamer/internal/logger"
	"dengan.dev/camera-streamer/internal/secrets"
)

func storageTestCipher(t *testing.T) *secrets.Cipher {
	t.Helper()
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	c, e := secrets.New(key)
	if e != nil {
		t.Fatal(e)
	}
	return c
}

func storageTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, e := logger.NewLogger(filepath.Join(t.TempDir(), "app.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	return db.DB()
}

func localEnv() StorageEnv {
	return StorageEnv{
		Driver:        DriverLocal,
		LocalPath:     "/home/operator/recordings/objects",
		QuotaBytes:    1 << 30,
		ReserveBytes:  2 << 30,
		RetentionDays: 7,
	}
}

func TestStorageSettingsFallBackToEnvironmentAndWriteBack(t *testing.T) {
	db := storageTestDB(t)
	got, fromDB, e := ResolveStorageSettings(db, localEnv(), nil)
	if e != nil {
		t.Fatal(e)
	}
	if fromDB {
		t.Fatal("an empty table must resolve from the environment")
	}
	if got.Driver != DriverLocal || got.LocalPath != "/home/operator/recordings/objects" || got.QuotaBytes != 1<<30 || got.ReserveBytes != 2<<30 || got.RetentionDays != 7 {
		t.Fatalf("environment defaults not resolved: %+v", got)
	}
	if got.UpdatedNS <= 0 {
		t.Fatal("a resolved row must carry a write timestamp so the UI can show it was materialised")
	}
	// The resolved values are written back so the UI has something concrete.
	again, fromDB, e := ResolveStorageSettings(db, StorageEnv{Driver: DriverLocal, LocalPath: "/elsewhere", QuotaBytes: 9, RetentionDays: 1}, nil)
	if e != nil {
		t.Fatal(e)
	}
	if !fromDB {
		t.Fatal("the first boot did not materialise a row")
	}
	if again.LocalPath != "/home/operator/recordings/objects" || again.QuotaBytes != 1<<30 {
		t.Fatalf("the write-back was not authoritative: %+v", again)
	}
}

func TestStorageSettingsRowWinsOverEnvironment(t *testing.T) {
	db := storageTestDB(t)
	if _, _, e := ResolveStorageSettings(db, localEnv(), nil); e != nil {
		t.Fatal(e)
	}
	if _, e := db.Exec(`UPDATE recording_storage_settings SET driver='s3',local_path='',s3_endpoint='https://s3.example',s3_bucket='footage',s3_region='eu-central-1',s3_access_key='op',quota_bytes=42,reserve_bytes=1,retention_days=3 WHERE id=1`); e != nil {
		t.Fatal(e)
	}
	got, fromDB, e := ResolveStorageSettings(db, localEnv(), storageTestCipher(t))
	if e != nil {
		t.Fatal(e)
	}
	if !fromDB {
		t.Fatal("a present row must win")
	}
	if got.Driver != DriverS3 || got.S3Endpoint != "https://s3.example" || got.S3Bucket != "footage" || got.S3Region != "eu-central-1" || got.S3AccessKey != "op" || got.QuotaBytes != 42 || got.ReserveBytes != 1 || got.RetentionDays != 3 {
		t.Fatalf("the row did not win: %+v", got)
	}
}

func TestStorageSettingsEmptyFieldSurvivesBecausePresenceDecides(t *testing.T) {
	db := storageTestDB(t)
	// A row that deliberately leaves the region empty while the environment
	// carries one: row PRESENCE decides, so the empty field must survive.
	if e := EnsureStorageSchema(db); e != nil {
		t.Fatal(e)
	}
	if _, e := db.Exec(`INSERT INTO recording_storage_settings(id,driver,local_path,s3_endpoint,s3_bucket,s3_region,s3_access_key,s3_secret_cipher,s3_session_cipher,s3_allow_http,quota_bytes,reserve_bytes,retention_days,updated_ns) VALUES(1,'s3','','https://s3.example','footage','','op','','',0,10,0,5,7)`); e != nil {
		t.Fatal(e)
	}
	env := localEnv()
	env.S3Region = "us-east-1"
	env.S3AccessKey = "from-env"
	env.RetentionDays = 99
	got, fromDB, e := ResolveStorageSettings(db, env, storageTestCipher(t))
	if e != nil {
		t.Fatal(e)
	}
	if !fromDB || got.S3Region != "" || got.S3AccessKey != "op" || got.RetentionDays != 5 {
		t.Fatalf("an empty field was silently replaced by an environment default: %+v", got)
	}
}

func TestStorageSettingsSealSecretsAndNeverStorePlaintext(t *testing.T) {
	db := storageTestDB(t)
	c := storageTestCipher(t)
	env := localEnv()
	env.Driver = DriverS3
	env.S3Endpoint = "https://s3.example"
	env.S3Bucket = "footage"
	env.S3Region = "eu-central-1"
	env.S3AccessKey = "op"
	env.S3Secret = "SUPER-SECRET-PLAINTEXT"
	env.S3Session = "SESSION-PLAINTEXT"
	got, _, e := ResolveStorageSettings(db, env, c)
	if e != nil {
		t.Fatal(e)
	}
	var stored string
	if e := db.QueryRow(`SELECT s3_secret_cipher FROM recording_storage_settings WHERE id=1`).Scan(&stored); e != nil {
		t.Fatal(e)
	}
	if stored == "" || stored == "SUPER-SECRET-PLAINTEXT" || strings.Contains(stored, "SUPER-SECRET-PLAINTEXT") {
		t.Fatalf("the secret was not sealed at rest: %q", stored)
	}
	var session string
	if e := db.QueryRow(`SELECT s3_session_cipher FROM recording_storage_settings WHERE id=1`).Scan(&session); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(session, "SESSION-PLAINTEXT") {
		t.Fatal("the session token was not sealed at rest")
	}
	secret, sess, e := got.Credentials(c)
	if e != nil || secret != "SUPER-SECRET-PLAINTEXT" || sess != "SESSION-PLAINTEXT" {
		t.Fatalf("sealed credentials did not open: %q %q %v", secret, sess, e)
	}
	if got.SealedSecret() != stored {
		t.Fatal("the in-memory settings disagree with the persisted row")
	}
}

func TestStorageSettingsTamperedCiphertextRefusesToStart(t *testing.T) {
	db := storageTestDB(t)
	c := storageTestCipher(t)
	env := localEnv()
	env.Driver = DriverS3
	env.S3Endpoint = "https://s3.example"
	env.S3Bucket = "footage"
	env.S3Region = "eu-central-1"
	env.S3AccessKey = "op"
	env.S3Secret = "SUPER-SECRET-PLAINTEXT"
	if _, _, e := ResolveStorageSettings(db, env, c); e != nil {
		t.Fatal(e)
	}
	var sealed string
	if e := db.QueryRow(`SELECT s3_secret_cipher FROM recording_storage_settings WHERE id=1`).Scan(&sealed); e != nil {
		t.Fatal(e)
	}
	raw, e := base64.StdEncoding.DecodeString(sealed)
	if e != nil {
		t.Fatal(e)
	}
	raw[len(raw)-1] ^= 1
	if _, e = db.Exec(`UPDATE recording_storage_settings SET s3_secret_cipher=? WHERE id=1`, base64.StdEncoding.EncodeToString(raw)); e != nil {
		t.Fatal(e)
	}
	got, _, e := ResolveStorageSettings(db, env, storageTestCipher(t))
	if e == nil {
		t.Fatal("a tampered credential resolved instead of refusing")
	}
	if secret, _, werr := got.Credentials(storageTestCipher(t)); werr == nil && secret != "" {
		t.Fatalf("a tampered credential degraded to a usable value: %q", secret)
	}
	if strings.Contains(e.Error(), "SUPER-SECRET-PLAINTEXT") {
		t.Fatal("the configuration error leaked the secret")
	}
}

func TestStorageSettingsMissingAppKeyRefusesEncryptedCredentials(t *testing.T) {
	db := storageTestDB(t)
	c := storageTestCipher(t)
	env := localEnv()
	env.Driver = DriverS3
	env.S3Endpoint = "https://s3.example"
	env.S3Bucket = "footage"
	env.S3Region = "eu-central-1"
	env.S3AccessKey = "op"
	env.S3Secret = "SECRET"
	if _, _, e := ResolveStorageSettings(db, env, c); e != nil {
		t.Fatal(e)
	}
	// With no application key the sealed credential cannot be opened, and that
	// must be a configuration error rather than an empty credential.
	if _, _, e := ResolveStorageSettings(db, env, nil); e == nil {
		t.Fatal("a sealed credential without an application key was accepted")
	}
}

func TestStorageEnvRejectsMalformedNumbers(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"ONVIF_RECORDING_QUOTA_BYTES", "not-a-number"},
		{"ONVIF_RECORDING_RESERVE_BYTES", "-1"},
		{"ONVIF_RECORDING_RETENTION_DAYS", "zero"},
		{"ONVIF_RECORDING_STORE", "ftp"},
	} {
		values := map[string]string{tc.name: tc.value}
		if _, e := StorageEnvFrom(func(k string) string { return values[k] }); e == nil {
			t.Fatalf("%s=%q was accepted", tc.name, tc.value)
		}
	}
}

func TestRecordingSettingsGainsUpdatedNSAdditively(t *testing.T) {
	db := storageTestDB(t)
	// Simulate the pre-existing table the live install already has.
	if _, e := db.Exec(`CREATE TABLE recording_settings(camera TEXT PRIMARY KEY,enabled INTEGER NOT NULL DEFAULT 0)`); e != nil {
		t.Fatal(e)
	}
	if _, e := db.Exec(`INSERT INTO recording_settings(camera,enabled) VALUES('onvif:old',1)`); e != nil {
		t.Fatal(e)
	}
	if e := EnsureStorageSchema(db); e != nil {
		t.Fatal(e)
	}
	var n int
	if e := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('recording_settings') WHERE name='updated_ns'`).Scan(&n); e != nil || n != 1 {
		t.Fatalf("updated_ns was not added additively: %d %v", n, e)
	}
	var enabled int
	if e := db.QueryRow(`SELECT enabled FROM recording_settings WHERE camera='onvif:old'`).Scan(&enabled); e != nil || enabled != 1 {
		t.Fatalf("the additive migration lost an existing row: %d %v", enabled, e)
	}
	if e := EnsureStorageSchema(db); e != nil {
		t.Fatalf("the migration is not idempotent: %v", e)
	}
}
