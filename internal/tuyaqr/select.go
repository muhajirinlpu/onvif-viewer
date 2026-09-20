package tuyaqr

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// Environment variables that select and configure the session store.
//
// The selection mechanism is: an EXPLICIT mode variable, defaulting to "auto",
// where auto prefers the project database and only falls back to the legacy
// file when the database cannot be used at all. That shape was chosen over
// "default to the file, opt in to the database" because the point of this
// milestone is that session state belongs with the stream configs and logs the
// project already keeps in SQLite; and it was chosen over
// "default to the database, silently ignore a broken database" because falling
// back is only safe if it is LOUD. The decision - store kind, path and the
// reason - is reported by GET /api/tuya/session as `storeKind`, `storeLocation`
// and `storeReason`, so an operator never has to guess where a credential went.
const (
	// EnvSessionStore selects the store: "auto" (default), "db", "file".
	EnvSessionStore = "TUYA_SESSION_STORE"
	// EnvSessionDB is the database the session is kept in. Default
	// "onvif_logs.db" - the same file, relative to the same working directory,
	// that internal/logger already opens.
	EnvSessionDB = "TUYA_SESSION_DB"
	// EnvSessionFile is the legacy session file path. In file mode it IS the
	// store. In db/auto mode it is the one-time IMPORT SOURCE and the
	// read-only fallback, and is never written to.
	EnvSessionFile = "TUYA_SESSION_FILE"
	// EnvImportLegacySessions disables the one-time legacy import with "0".
	EnvImportLegacySessions = "TUYA_SESSION_IMPORT_LEGACY"

	// defaultSessionDBPath matches logger.NewLogger("onvif_logs.db") in main.go.
	defaultSessionDBPath = "onvif_logs.db"

	StoreModeAuto = "auto"
	StoreModeDB   = "db"
	StoreModeFile = "file"
)

// StoreConfig is the resolved selection input. Zero values are the defaults.
type StoreConfig struct {
	// Mode is auto|db|file, from TUYA_SESSION_STORE.
	Mode string
	// DBPath is the database path, from TUYA_SESSION_DB.
	DBPath string
	// FilePath is the legacy session file, from TUYA_SESSION_FILE (which is the
	// same variable as tuyaengine's TUYA_ENGINE_SESSION_FILE: one session,
	// however it is stored).
	FilePath string
	// DisableImport turns the one-time import of FilePath into the database off.
	//
	// It is phrased as a negative on purpose: the zero value must mean "import",
	// because a caller that constructs a StoreConfig by hand has not opted out of
	// anything, and a bool named ImportLegacy would silently default the import
	// off for exactly that caller.
	DisableImport bool
	// OpenDB opens the database. Injectable so selection can be tested without
	// a filesystem; nil means NewSQLiteSessionStore.
	OpenDB func(path string) (*SQLiteSessionStore, error)
}

// StoreConfigFromEnv reads the selection from the environment.
func StoreConfigFromEnv() StoreConfig {
	return StoreConfig{
		Mode:          strings.TrimSpace(os.Getenv(EnvSessionStore)),
		DBPath:        strings.TrimSpace(os.Getenv(EnvSessionDB)),
		FilePath:      strings.TrimSpace(os.Getenv(EnvSessionFile)),
		DisableImport: strings.TrimSpace(os.Getenv(EnvImportLegacySessions)) == "0",
	}
}

func (c StoreConfig) withDefaults() StoreConfig {
	if c.DBPath == "" {
		c.DBPath = defaultSessionDBPath
	}
	c.Mode = strings.ToLower(strings.TrimSpace(c.Mode))
	if c.Mode == "" {
		c.Mode = StoreModeAuto
	}
	return c
}

// ResolvedStore is the outcome of store selection. Everything in it is either a
// path, a word or an account label: no credential material.
type ResolvedStore struct {
	Store SessionStore
	// Kind is the store kind actually chosen (file|sqlite).
	Kind string
	// Location is where it lives (a path).
	Location string
	// Reason explains, in operator terms, why this store was chosen. It is
	// surfaced verbatim by the API and is the honest answer to "why is my
	// session in the database / in a file?".
	Reason string
	// ImportSource is the legacy file to import once, or "".
	ImportSource string
	// FallbackFrom names the mode that was tried and failed, when the legacy
	// file was chosen as a fallback.
	FallbackFrom string
	// LegacyFilePath is the file path from the environment, when one was set.
	LegacyFilePath string
}

// ResolveSessionStore picks the session store.
//
// Rules, in order - each one is reported in Reason so the choice is auditable:
//
//	file   TUYA_SESSION_STORE=file. Exactly the pre-milestone behaviour: the
//	       path in TUYA_ENGINE_SESSION_FILE is the store, byte for byte.
//	db     TUYA_SESSION_STORE=db. The database is the store. A failure to open
//	       it is an ERROR, not a silent downgrade.
//	auto   (default) prefer the database. If it cannot be opened - the path is
//	       not writable, the directory cannot be created, the file is not a
//	       SQLite database - fall back to the legacy file and SAY SO.
//
// Nothing here reads or writes a credential; the import happens separately and
// is separately idempotent (ImportSessionFile).
func ResolveSessionStore(cfg StoreConfig) (*ResolvedStore, error) {
	cfg = cfg.withDefaults()
	res := &ResolvedStore{LegacyFilePath: cfg.FilePath}

	switch cfg.Mode {
	case StoreModeFile:
		if cfg.FilePath == "" {
			return nil, fmt.Errorf("tuyaqr: %s=file needs %s to name the session file", EnvSessionStore, EnvSessionFile)
		}
		res.Store = NewFileSessionStore(cfg.FilePath)
		res.Kind = StoreKindFile
		res.Location = cfg.FilePath
		res.Reason = fmt.Sprintf("%s=file: the legacy session file is the store, exactly as before this milestone", EnvSessionStore)
		return res, nil
	case StoreModeDB:
		store, err := openSessionDB(cfg)
		if err != nil {
			return nil, fmt.Errorf("tuyaqr: %s=db: %w", EnvSessionStore, err)
		}
		return databaseStore(res, cfg, store,
			fmt.Sprintf("%s=db: the session is kept in the project database", EnvSessionStore)), nil
	case StoreModeAuto:
		store, err := openSessionDB(cfg)
		if err != nil {
			if cfg.FilePath == "" {
				return nil, fmt.Errorf("tuyaqr: no session store is usable: the database could not be opened (%v) and %s names no fallback file", err, EnvSessionFile)
			}
			res.Store = NewFileSessionStore(cfg.FilePath)
			res.Kind = StoreKindFile
			res.Location = cfg.FilePath
			res.FallbackFrom = StoreModeDB
			res.Reason = fmt.Sprintf("the session database %s could not be opened (%v), so the legacy session file is being used instead", cfg.DBPath, err)
			return res, nil
		}
		return databaseStore(res, cfg, store,
			fmt.Sprintf("auto: the session is kept in the project database %s", cfg.DBPath)), nil
	default:
		return nil, fmt.Errorf("tuyaqr: unknown %s=%q (want %s, %s or %s)",
			EnvSessionStore, cfg.Mode, StoreModeAuto, StoreModeDB, StoreModeFile)
	}
}

// databaseStore fills in the database-backed outcome.
func databaseStore(res *ResolvedStore, cfg StoreConfig, store *SQLiteSessionStore, reason string) *ResolvedStore {
	res.Store = store
	res.Kind = StoreKindSQLite
	res.Location = cfg.DBPath
	res.Reason = reason
	if !cfg.DisableImport {
		res.ImportSource = cfg.FilePath
	}
	return res
}

// openSessionDB opens the database through the configured opener.
func openSessionDB(cfg StoreConfig) (*SQLiteSessionStore, error) {
	if cfg.OpenDB != nil {
		return cfg.OpenDB(cfg.DBPath)
	}
	return NewSQLiteSessionStore(cfg.DBPath)
}

// SingleAccount returns the one account a store holds.
//
// It exists so a single-account install never has to be told which account it
// is: zero stored accounts means "no session" (ErrNoSession), one means "that
// one", and more than one is an error that NAMES the accounts rather than
// silently picking one - silently picking would mean stream A could be fed by
// account B's credential, which is a real bug, not a convenience.
func SingleAccount(store SessionStore) (Account, error) {
	if store == nil {
		return Account{}, fmt.Errorf("%w: no session store is configured", ErrNoSession)
	}
	stored, err := store.Accounts()
	if err != nil {
		return Account{}, err
	}
	switch len(stored) {
	case 0:
		return Account{}, fmt.Errorf("%w: the %s store holds no session", ErrNoSession, store.Kind())
	case 1:
		return stored[0].Account, nil
	default:
		labels := make([]string, 0, len(stored))
		for _, s := range stored {
			labels = append(labels, s.Account.String())
		}
		sort.Strings(labels)
		return Account{}, fmt.Errorf("tuyaqr: the %s store holds %d accounts (%s); name the one to use",
			store.Kind(), len(stored), strings.Join(labels, ", "))
	}
}

// ResolveAccount returns the account a caller asked for, or the single stored
// account when none was named.
func ResolveAccount(store SessionStore, want Account) (Account, error) {
	if !want.IsZero() {
		return want, nil
	}
	return SingleAccount(store)
}
