package recording

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"dengan.dev/camera-streamer/internal/secrets"
)

// Storage drivers. The driver is a closed set; anything else is refused rather
// than defaulted, because a typo in the environment silently selecting "local"
// would strand footage in the wrong place.
const (
	DriverLocal = "local"
	DriverS3    = "s3"
)

// Context strings bound into the GCM additional-authenticated-data. A sealed
// secret and a sealed session token are not interchangeable.
const (
	ContextS3Secret  = "recording.s3.secret"
	ContextS3Session = "recording.s3.session"
)

// StorageEnv is the environment-derived default for storage configuration,
// including the credentials. Secrets live here and only here: they are sealed
// on the way into the database and are never placed in a StorageSettings
// struct that a handler could serialise.
type StorageEnv struct {
	Driver        string
	LocalPath     string
	S3Endpoint    string
	S3Bucket      string
	S3Region      string
	S3AccessKey   string
	S3Secret      string
	S3Session     string
	S3AllowHTTP   bool
	QuotaBytes    int64
	ReserveBytes  uint64
	RetentionDays int
}

// StorageSettings is a resolved configuration row. It carries no plaintext
// credential by design: the sealed ciphertexts travel here and are opened only
// through Credentials, under the application key.
type StorageSettings struct {
	Driver         string
	LocalPath      string
	S3Endpoint     string
	S3Bucket       string
	S3Region       string
	S3AccessKey    string
	s3SecretCipher string
	s3SessionCipher string
	S3AllowHTTP    bool
	QuotaBytes     int64
	ReserveBytes   uint64
	RetentionDays  int
	UpdatedNS      int64
}

// SealedSecret exposes the persisted ciphertext (not the credential) so a test
// can prove that what is at rest is not the plaintext.
func (s StorageSettings) SealedSecret() string { return s.s3SecretCipher }

// Credentials opens the sealed secret and session token. A tampered ciphertext
// is a hard error: it must never be treated as an empty credential.
func (s StorageSettings) Credentials(c *secrets.Cipher) (string, string, error) {
	secret, err := openCredential(c, ContextS3Secret, s.s3SecretCipher)
	if err != nil {
		return "", "", err
	}
	session, err := openCredential(c, ContextS3Session, s.s3SessionCipher)
	if err != nil {
		return "", "", err
	}
	return secret, session, nil
}

func openCredential(c *secrets.Cipher, context, sealed string) (string, error) {
	if sealed == "" {
		return "", nil
	}
	if c == nil {
		return "", fmt.Errorf("the %s credential is sealed but no application key is configured", context)
	}
	plaintext, err := c.Open(context, sealed)
	if err != nil {
		return "", fmt.Errorf("the %s credential could not be decrypted", context)
	}
	return string(plaintext), nil
}

// EnvVars names every environment variable this package reads, so a caller can
// document them in one place and a test can drive them without a live process.
const (
	EnvRecordingDir           = "ONVIF_RECORDING_DIR"
	EnvRecordingStore         = "ONVIF_RECORDING_STORE"
	EnvRecordingQuotaBytes    = "ONVIF_RECORDING_QUOTA_BYTES"
	EnvRecordingReserveBytes  = "ONVIF_RECORDING_RESERVE_BYTES"
	EnvRecordingRetentionDays = "ONVIF_RECORDING_RETENTION_DAYS"
	EnvS3Endpoint             = "ONVIF_S3_ENDPOINT"
	EnvS3Bucket               = "ONVIF_S3_BUCKET"
	EnvS3Region               = "ONVIF_S3_REGION"
	EnvS3AccessKey            = "ONVIF_S3_ACCESS_KEY"
	EnvS3SecretKey            = "ONVIF_S3_SECRET_KEY"
	EnvS3SessionToken         = "ONVIF_S3_SESSION_TOKEN"
	EnvS3AllowHTTP            = "ONVIF_S3_ALLOW_HTTP"
)

// StorageEnvFrom reads and validates the environment defaults. base is the
// absolute recording directory the caller resolved (the environment override
// has already been applied by the caller, exactly as it was before).
func StorageEnvFrom(getenv func(string) string) (StorageEnv, error) {
	if getenv == nil {
		return StorageEnv{}, errors.New("no environment reader supplied")
	}
	driver := strings.TrimSpace(getenv(EnvRecordingStore))
	if driver == "" {
		driver = DriverLocal
	}
	if driver != DriverLocal && driver != DriverS3 {
		return StorageEnv{}, errors.New("unknown recording store")
	}
	env := StorageEnv{
		Driver:      driver,
		S3Endpoint:  getenv(EnvS3Endpoint),
		S3Bucket:    getenv(EnvS3Bucket),
		S3Region:    getenv(EnvS3Region),
		S3AccessKey: getenv(EnvS3AccessKey),
		S3Secret:    getenv(EnvS3SecretKey),
		S3Session:   getenv(EnvS3SessionToken),
	}
	if raw := strings.TrimSpace(getenv(EnvS3AllowHTTP)); raw != "" {
		v, err := strconv.ParseBool(raw)
		if err != nil {
			return StorageEnv{}, fmt.Errorf("%s must be a boolean", EnvS3AllowHTTP)
		}
		env.S3AllowHTTP = v
	}
	var err error
	env.QuotaBytes = 1 << 30
	if raw := strings.TrimSpace(getenv(EnvRecordingQuotaBytes)); raw != "" {
		env.QuotaBytes, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || env.QuotaBytes <= 0 {
			return StorageEnv{}, fmt.Errorf("%s must be a positive integer", EnvRecordingQuotaBytes)
		}
	}
	env.ReserveBytes = 2 << 30
	if raw := strings.TrimSpace(getenv(EnvRecordingReserveBytes)); raw != "" {
		v, parseErr := strconv.ParseUint(raw, 10, 64)
		if parseErr != nil {
			return StorageEnv{}, fmt.Errorf("%s must be a non-negative integer", EnvRecordingReserveBytes)
		}
		if v > uint64(1<<62) {
			return StorageEnv{}, fmt.Errorf("%s is implausibly large", EnvRecordingReserveBytes)
		}
		env.ReserveBytes = v
	}
	env.RetentionDays = 7
	if raw := strings.TrimSpace(getenv(EnvRecordingRetentionDays)); raw != "" {
		env.RetentionDays, err = strconv.Atoi(raw)
		if err != nil || env.RetentionDays <= 0 {
			return StorageEnv{}, fmt.Errorf("%s must be a positive integer", EnvRecordingRetentionDays)
		}
	}
	return env, nil
}

// storageSchema is the exact schema from the approved plan. It is created
// alongside the existing recording tables.
const storageSchema = `
CREATE TABLE IF NOT EXISTS recording_storage_settings(
  id INTEGER PRIMARY KEY CHECK(id=1),
  driver TEXT NOT NULL CHECK(driver IN ('local','s3')),
  local_path TEXT NOT NULL DEFAULT '',
  s3_endpoint TEXT NOT NULL DEFAULT '',
  s3_bucket TEXT NOT NULL DEFAULT '',
  s3_region TEXT NOT NULL DEFAULT '',
  s3_access_key TEXT NOT NULL DEFAULT '',
  s3_secret_cipher TEXT NOT NULL DEFAULT '',
  s3_session_cipher TEXT NOT NULL DEFAULT '',
  s3_allow_http INTEGER NOT NULL DEFAULT 0,
  quota_bytes INTEGER NOT NULL,
  reserve_bytes INTEGER NOT NULL,
  retention_days INTEGER NOT NULL,
  updated_ns INTEGER NOT NULL
);`

// settingsTable mirrors the definition recording.New already ships, so storage
// resolution is self-contained when it runs before a Recorder exists.
const settingsTable = `
CREATE TABLE IF NOT EXISTS recording_settings(camera TEXT PRIMARY KEY,enabled INTEGER NOT NULL DEFAULT 0);`

// EnsureStorageSchema creates the storage settings table and adds updated_ns to
// the pre-existing recording_settings table. Both steps are idempotent, so they
// run on every boot alongside recording.New.
func EnsureStorageSchema(db *sql.DB) error {
	if db == nil {
		return errors.New("storage schema requires a database")
	}
	if _, err := db.Exec(settingsTable + storageSchema); err != nil {
		return err
	}
	var present bool
	if err := db.QueryRow(`SELECT COUNT(*) > 0 FROM pragma_table_info('recording_settings') WHERE name='updated_ns'`).Scan(&present); err != nil {
		return err
	}
	if !present {
		// ALTER TABLE ADD COLUMN with a constant default is a metadata-only
		// change in SQLite, so an existing populated table keeps its rows.
		if _, err := db.Exec(`ALTER TABLE recording_settings ADD COLUMN updated_ns INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	return nil
}

// ResolveStorageSettings returns the effective storage configuration. A present
// database row wins over the environment defaults; when the row is absent the
// environment is materialised into the row so the UI has concrete values to
// show and edit. Presence, not emptiness, decides precedence, so a field the
// operator deliberately cleared is not silently restored from the environment.
func ResolveStorageSettings(db *sql.DB, env StorageEnv, c *secrets.Cipher) (StorageSettings, bool, error) {
	if db == nil {
		return StorageSettings{}, false, errors.New("storage settings require a database")
	}
	if err := EnsureStorageSchema(db); err != nil {
		return StorageSettings{}, false, err
	}
	if env.Driver != DriverLocal && env.Driver != DriverS3 {
		return StorageSettings{}, false, errors.New("unknown recording store")
	}
	sealedSecret, sealedSession, err := sealCredentials(env, c)
	if err != nil {
		return StorageSettings{}, false, err
	}
	var s StorageSettings
	var allowHTTP int
	err = db.QueryRow(`SELECT driver,local_path,s3_endpoint,s3_bucket,s3_region,s3_access_key,s3_secret_cipher,s3_session_cipher,s3_allow_http,quota_bytes,reserve_bytes,retention_days,updated_ns FROM recording_storage_settings WHERE id=1`).
		Scan(&s.Driver, &s.LocalPath, &s.S3Endpoint, &s.S3Bucket, &s.S3Region, &s.S3AccessKey, &s.s3SecretCipher, &s.s3SessionCipher, &allowHTTP, &s.QuotaBytes, &s.ReserveBytes, &s.RetentionDays, &s.UpdatedNS)
	if err == nil {
		s.S3AllowHTTP = allowHTTP != 0
		// The row decides, but a credential sealed with a key we no longer hold
		// is a configuration error, never an empty credential.
		if _, _, cerr := s.Credentials(c); cerr != nil && (s.s3SecretCipher != "" || s.s3SessionCipher != "") {
			return StorageSettings{}, true, cerr
		}
		return s, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return StorageSettings{}, false, err
	}
	now := time.Now().UTC().UnixNano()
	s = StorageSettings{
		Driver:          env.Driver,
		LocalPath:       env.LocalPath,
		S3Endpoint:      env.S3Endpoint,
		S3Bucket:        env.S3Bucket,
		S3Region:        env.S3Region,
		S3AccessKey:     env.S3AccessKey,
		s3SecretCipher:  sealedSecret,
		s3SessionCipher: sealedSession,
		S3AllowHTTP:     env.S3AllowHTTP,
		QuotaBytes:      env.QuotaBytes,
		ReserveBytes:    env.ReserveBytes,
		RetentionDays:   env.RetentionDays,
		UpdatedNS:       now,
	}
	if _, err := db.Exec(`INSERT INTO recording_storage_settings(id,driver,local_path,s3_endpoint,s3_bucket,s3_region,s3_access_key,s3_secret_cipher,s3_session_cipher,s3_allow_http,quota_bytes,reserve_bytes,retention_days,updated_ns) VALUES(1,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		s.Driver, s.LocalPath, s.S3Endpoint, s.S3Bucket, s.S3Region, s.S3AccessKey, s.s3SecretCipher, s.s3SessionCipher, boolInt(s.S3AllowHTTP), s.QuotaBytes, s.ReserveBytes, s.RetentionDays, s.UpdatedNS); err != nil {
		return StorageSettings{}, false, err
	}
	return s, false, nil
}

// sealCredentials seals only what is a credential. Endpoint, bucket, region and
// access key are configuration and stay plaintext; the secret and session token
// are bound to their own contexts so neither can be replayed into the other.
func sealCredentials(env StorageEnv, c *secrets.Cipher) (string, string, error) {
	if env.Driver != DriverS3 {
		return "", "", nil
	}
	if env.S3Secret == "" && env.S3Session == "" {
		return "", "", nil
	}
	if c == nil {
		return "", "", errors.New("S3 credentials require an application key to seal them at rest")
	}
	secret, err := c.Seal(ContextS3Secret, []byte(env.S3Secret))
	if err != nil {
		return "", "", err
	}
	session, err := c.Seal(ContextS3Session, []byte(env.S3Session))
	if err != nil {
		return "", "", err
	}
	return secret, session, nil
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// StorageEnvFromProcess reads the real environment for the default recording
// directory resolved by the caller.
func StorageEnvFromProcess(base string) (StorageEnv, error) {
	env, err := StorageEnvFrom(os.Getenv)
	if err != nil {
		return StorageEnv{}, err
	}
	env.LocalPath = base
	return env, nil
}
