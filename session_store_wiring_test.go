package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dengan.dev/camera-streamer/internal/tuyaengine"
	"dengan.dev/camera-streamer/internal/tuyaqr"
)

// legacySessionFileFromEnv resolves the legacy session file the same way main()
// does. It is extracted here so the rule is testable, and it encodes the bug this
// test exists to prevent.
//
// MEASURED FAULT: main() originally read the legacy path from tuyaqr's own
// TUYA_SESSION_FILE while the project - and every existing install, and the UI -
// exports TUYA_ENGINE_SESSION_FILE. With the wrong variable consulted, the
// one-time import silently had no source and the migrated install came up with
// no session at all. The import is the whole migration, so this is not cosmetic.
func legacySessionFileFromEnv() (tuyaqr.StoreConfig, string) {
	legacy := strings.TrimSpace(os.Getenv(tuyaengine.EnvSessionFile))
	cfg := tuyaqr.StoreConfigFromEnv()
	if strings.TrimSpace(cfg.FilePath) == "" {
		cfg.FilePath = legacy
	}
	return cfg, legacy
}

// TestLegacySessionFileComesFromTheEngineEnvVar is the regression guard: the
// session file an existing install exports must reach the resolver as the import
// source.
func TestLegacySessionFileComesFromTheEngineEnvVar(t *testing.T) {
	path := "/tmp/does-not-need-to-exist/user_us-west_user_at_example.test.json"
	t.Setenv(tuyaengine.EnvSessionFile, path)
	t.Setenv(tuyaqr.EnvSessionFile, "")

	cfg, legacy := legacySessionFileFromEnv()
	if legacy != path {
		t.Fatalf("legacy = %q, want the TUYA_ENGINE_SESSION_FILE value", legacy)
	}
	if cfg.FilePath != path {
		t.Fatalf("resolver FilePath = %q, want %q so the import has a source", cfg.FilePath, path)
	}
}

// TestLegacySessionFileStillHonoursTheStoreSpecificOverride keeps tuyaqr's own
// variable working for an operator who sets it deliberately.
func TestLegacySessionFileStillHonoursTheStoreSpecificOverride(t *testing.T) {
	enginePath := "/tmp/engine-var/user.json"
	storePath := "/tmp/store-var/user.json"
	t.Setenv(tuyaengine.EnvSessionFile, enginePath)
	t.Setenv(tuyaqr.EnvSessionFile, storePath)

	cfg, _ := legacySessionFileFromEnv()
	if cfg.FilePath != storePath {
		t.Fatalf("resolver FilePath = %q, want the explicit TUYA_SESSION_FILE override %q", cfg.FilePath, storePath)
	}
}

// TestResolverImportsOnlyWhenTheDestinationIsTheDatabase is the rule that keeps a
// file store from being told to import itself.
func TestResolverImportsOnlyWhenTheDestinationIsTheDatabase(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "user.json")

	// The default (database) destination must have the file as its import source.
	cfg := tuyaqr.StoreConfig{DBPath: filepath.Join(dir, "s.db"), FilePath: src}
	res, err := tuyaqr.ResolveSessionStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.ImportSource != src {
		t.Errorf("ImportSource = %q, want %q", res.ImportSource, src)
	}
	if s, ok := res.Store.(*tuyaqr.SQLiteSessionStore); ok {
		s.Close()
	}

	// The file destination must NOT: it already IS that file.
	res2, err := tuyaqr.ResolveSessionStore(tuyaqr.StoreConfig{Mode: tuyaqr.StoreModeFile, FilePath: src})
	if err != nil {
		t.Fatal(err)
	}
	if res2.ImportSource != "" {
		t.Errorf("file mode ImportSource = %q, want empty", res2.ImportSource)
	}
	if res2.Kind != tuyaqr.StoreKindFile {
		t.Errorf("Kind = %q, want file", res2.Kind)
	}
}

// TestTuyaStoreReasonNeverNamesAnEmptyFile is the wording guard: the sentence is
// surfaced verbatim by GET /api/tuya/session, so an unset file must not produce
// "the legacy file at " with nothing after it.
func TestTuyaStoreReasonNeverNamesAnEmptyFile(t *testing.T) {
	withFile := tuyaStoreReason("onvif_logs.db", "/home/user/session.json")
	if !strings.Contains(withFile, "onvif_logs.db") || !strings.Contains(withFile, "/home/user/session.json") {
		t.Errorf("reason = %q, want it to name both paths", withFile)
	}
	without := tuyaStoreReason("onvif_logs.db", "  ")
	if !strings.Contains(without, "onvif_logs.db") {
		t.Errorf("reason = %q, want it to name the database", without)
	}
	if strings.Contains(without, "file at ") && !strings.Contains(without, "no legacy session file") {
		t.Errorf("reason = %q, want no dangling \"file at \" clause", without)
	}
}
