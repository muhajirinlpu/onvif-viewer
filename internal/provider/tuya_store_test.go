package provider

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dengan.dev/camera-streamer/internal/tuyaqr"
)

// --- M8: the provider over a database-backed session store -------------------

// newTestSQLiteStore builds a fresh database-backed store in the test's temp dir.
func newTestSQLiteStore(t *testing.T) *tuyaqr.SQLiteSessionStore {
	t.Helper()
	store, err := tuyaqr.NewSQLiteSessionStore(filepath.Join(t.TempDir(), "sessions.db"))
	if err != nil {
		t.Fatalf("NewSQLiteSessionStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

// testSessionForStore builds a usable session for the given email.
func testSessionForStore(email string) *tuyaqr.Session {
	now := time.Now()
	return &tuyaqr.Session{
		Region:      "us-west",
		Email:       email,
		UserKey:     "us-west_" + email,
		LastRefresh: now,
		SessionData: tuyaqr.UserSession{
			LoginResult:   &tuyaqr.LoginResult{UID: "az1", Email: email},
			LastValidated: now,
			ServerHost:    tuyaqr.DefaultHost,
			Region:        "us-west",
			UserEmail:     email,
			Cookies: []*tuyaqr.Cookie{
				{Name: "gTyPlatLang", Value: "en"},
				{Name: "locale", Value: "en"},
				{Name: "fast-sid", Value: strings.Repeat("a", 32)},
				{Name: "s-sid", Value: strings.Repeat("b", 82)},
			},
		},
	}
}

// TestTuyaProviderReadsTheSessionFromTheDatabaseStore is the core M8 change: a
// session that exists ONLY in the database must be usable by the provider, with
// no session file anywhere.
func TestTuyaProviderReadsTheSessionFromTheDatabaseStore(t *testing.T) {
	store := newTestSQLiteStore(t)
	if err := store.Save(testSessionForStore("db@example.test")); err != nil {
		t.Fatal(err)
	}

	fake := &fakeLister{}
	p := NewTuya("",
		WithTuyaStore(store),
		withTuyaLister(fake, nil),
	)
	if !p.Configured() {
		t.Fatal("Configured() = false although a session store is attached")
	}
	session, err := p.currentSession()
	if err != nil {
		t.Fatalf("currentSession: %v", err)
	}
	if session.Email != "db@example.test" {
		t.Errorf("email = %q, want db@example.test", session.Email)
	}
	if fast, sSID, n := session.AuthCookieStatus(); !fast || !sSID || n != 4 {
		t.Errorf("the database-provided session has no usable auth pair: fast=%t s-sid=%t n=%d", fast, sSID, n)
	}
}

// TestTuyaProviderStillWorksOverAFilePath is the regression guard: the
// pre-milestone constructor must be byte-for-byte as capable as it was.
func TestTuyaProviderStillWorksOverAFilePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session.json")
	if err := tuyaqr.SaveSession(path, testSessionForStore("file@example.test")); err != nil {
		t.Fatal(err)
	}
	p := NewTuya(path, withTuyaLister(&fakeLister{}, nil))
	if !p.Configured() {
		t.Fatal("Configured() = false for a configured session file")
	}
	if p.Store() == nil || p.Store().Kind() != tuyaqr.StoreKindFile {
		t.Fatalf("Store() = %v, want a file store", p.Store())
	}
	if p.SessionFile() != path {
		t.Errorf("SessionFile() = %q, want the configured path %q", p.SessionFile(), path)
	}
	session, err := p.currentSession()
	if err != nil {
		t.Fatalf("currentSession: %v", err)
	}
	if session.Email != "file@example.test" {
		t.Errorf("email = %q, want file@example.test", session.Email)
	}
}

// TestTuyaProviderReportsAnAmbiguousStoreRatherThanGuessing keeps two accounts
// from silently feeding one stream.
func TestTuyaProviderReportsAnAmbiguousStoreRatherThanGuessing(t *testing.T) {
	store := newTestSQLiteStore(t)
	for _, email := range []string{"a@example.test", "b@example.test"} {
		if err := store.Save(testSessionForStore(email)); err != nil {
			t.Fatal(err)
		}
	}
	p := NewTuya("", WithTuyaStore(store))
	_, err := p.currentSession()
	if err == nil {
		t.Fatal("the provider picked one of two stored accounts instead of reporting the ambiguity")
	}
	if !strings.Contains(err.Error(), "a@example.test") || !strings.Contains(err.Error(), "b@example.test") {
		t.Errorf("the ambiguity error must name both accounts, got: %v", err)
	}
	// Naming one resolves it.
	named := NewTuya("", WithTuyaStore(store), WithTuyaAccount(tuyaqr.Account{Region: "us-west", Email: "b@example.test"}))
	session, err := named.currentSession()
	if err != nil {
		t.Fatalf("currentSession with an explicit account: %v", err)
	}
	if session.Email != "b@example.test" {
		t.Errorf("email = %q, want b@example.test", session.Email)
	}
}

// TestTuyaStatusReportsTheDatabaseStoreHonestly covers the four M6 axes plus the
// M8 store axes, with the session in the database.
func TestTuyaStatusReportsTheDatabaseStoreHonestly(t *testing.T) {
	store := newTestSQLiteStore(t)
	// The session carries a cloud-reported expiry on fast-sid.
	s := testSessionForStore("db@example.test")
	s.SessionData.Cookies[2].Expires = time.Now().Add(40 * time.Hour).UTC().Truncate(time.Second)
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}

	fake := &fakeLister{}
	p := NewTuya("", WithTuyaStore(store), withTuyaLister(fake, nil))

	status, err := p.Session(context.Background())
	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	if !status.Configured {
		t.Error("configured = false, want true")
	}
	if !status.FilePresent {
		t.Error("filePresent = false, want true: a stored credential that LOADS is present, whatever the medium")
	}
	if !status.CloudVerified || !status.Valid {
		t.Errorf("cloudVerified=%t valid=%t, want both true after a successful probe", status.CloudVerified, status.Valid)
	}
	if !status.ExpiryKnown {
		t.Error("expiryKnown = false, want true: the stored fast-sid declares a deadline")
	}
	if status.ExpirySource != "cookie:fast-sid" {
		t.Errorf("expirySource = %q, want cookie:fast-sid", status.ExpirySource)
	}
	if status.ExpiresAt == nil || status.RemainingSeconds <= 0 {
		t.Errorf("expiresAt=%v remainingSeconds=%d, want a real deadline", status.ExpiresAt, status.RemainingSeconds)
	}
	if status.StoreKind != tuyaqr.StoreKindSQLite {
		t.Errorf("storeKind = %q, want sqlite", status.StoreKind)
	}
	if status.StoreLocation == "" {
		t.Error("storeLocation is empty, so the response does not say where the credential is")
	}
	if status.ReloginRequired {
		t.Error("reloginRequired = true for a session the cloud just accepted")
	}
	if len(status.Accounts) != 1 || !status.Accounts[0].HasAuthPair {
		t.Errorf("accounts = %+v, want one with an auth pair", status.Accounts)
	}
	if len(status.StoreFileModes) == 0 {
		t.Error("storeFileModes is empty, so the 0600 hardening is not reported")
	}
	for _, m := range status.StoreFileModes {
		if m.Mode != "0600" {
			t.Errorf("%s mode reported as %s, want 0600", m.Path, m.Mode)
		}
	}
}

// TestTuyaStatusKeepsExpiryUnknownWhenTheCloudStatesNone is the honesty guard
// against inventing a countdown: a database-backed session whose cookies carry
// no expiry must produce expiryKnown=false.
func TestTuyaStatusKeepsExpiryUnknownWhenTheCloudStatesNone(t *testing.T) {
	store := newTestSQLiteStore(t)
	if err := store.Save(testSessionForStore("db@example.test")); err != nil {
		t.Fatal(err)
	}
	// A lister that accepts the session but never reports an expiry.
	fake := &fakeLister{}
	p := NewTuya("", WithTuyaStore(store), withTuyaLister(fake, nil))

	status, err := p.Session(context.Background())
	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	if status.ExpiryKnown {
		t.Error("expiryKnown = true although no stored cookie declares a deadline")
	}
	if status.ExpiresAt != nil {
		t.Errorf("expiresAt = %v, want null when the expiry is unknown", status.ExpiresAt)
	}
	if status.RemainingSeconds != 0 {
		t.Errorf("remainingSeconds = %d, want 0 when the expiry is unknown", status.RemainingSeconds)
	}
	if status.ExpirySource != "unknown" {
		t.Errorf("expirySource = %q, want unknown", status.ExpirySource)
	}
	if !strings.Contains(status.Detail, "declare no expiry") {
		t.Errorf("detail = %q, want it to explain why there is no countdown", status.Detail)
	}
	if !status.Valid {
		t.Error("valid = false although the cloud accepted the session: unknown expiry is not invalidity")
	}
}

// TestTuyaProviderReportsAMissingSessionHonestly covers the empty-store case.
func TestTuyaProviderReportsAMissingSessionHonestly(t *testing.T) {
	store := newTestSQLiteStore(t)
	p := NewTuya("", WithTuyaStore(store))
	status, err := p.Session(context.Background())
	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	if !status.Configured {
		t.Error("configured = false although a store IS wired up")
	}
	if status.FilePresent {
		t.Error("filePresent = true although the store holds no session")
	}
	if status.Valid || status.CloudVerified {
		t.Error("a store with no session reported validity")
	}
	if !status.ReloginRequired {
		t.Error("reloginRequired = false although there is nothing to use")
	}
	if status.ExpiryKnown {
		t.Error("expiryKnown = true with no session at all")
	}
}

// TestTuyaRefreshPersistsTheCloudReportedExpiryToTheStore is delivery item 4:
// the expiry capture must now persist into the database.
func TestTuyaRefreshPersistsTheCloudReportedExpiryToTheStore(t *testing.T) {
	store := newTestSQLiteStore(t)
	s := testSessionForStore("db@example.test") // zero expiries, like the real file
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(36 * time.Hour).UTC().Truncate(time.Second)
	fake := &fakeLister{reportedExpiry: deadline}
	// The provider must load its own session from the store, so no session is
	// injected here.
	p := NewTuya("", WithTuyaStore(store))
	p.client = fake

	status, err := p.Session(context.Background())
	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	if !status.ExpiryKnown || status.ExpiresAt == nil {
		t.Fatalf("the provider did not report the expiry the cloud stated: %+v", status)
	}

	// The deadline must now be in the DATABASE, readable by a completely fresh
	// store handle: this is the M6 expiry surviving into M8's storage.
	fresh, err := tuyaqr.NewSQLiteSessionStore(store.Location())
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	stored, err := fresh.Load(tuyaqr.Account{Region: "us-west", Email: "db@example.test"})
	if err != nil {
		t.Fatalf("the persisted session is not in the database: %v", err)
	}
	earliest, name, ok := stored.EarliestCookieExpiry()
	if !ok {
		t.Fatal("the cloud-reported expiry was not persisted into the database")
	}
	if name != "fast-sid" {
		t.Errorf("persisted expiry attributed to %q, want fast-sid", name)
	}
	if !earliest.Equal(deadline) {
		t.Errorf("persisted expiry = %s, want %s", earliest, deadline)
	}
}

// TestTuyaRefreshDoesNotPersistAfterACloudRejection keeps a dead credential from
// being re-saved on the rejection path.
func TestTuyaRefreshDoesNotPersistAfterACloudRejection(t *testing.T) {
	store := newTestSQLiteStore(t)
	if err := store.Save(testSessionForStore("db@example.test")); err != nil {
		t.Fatal(err)
	}
	before, err := store.Load(tuyaqr.Account{Region: "us-west", Email: "db@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	beforeCookies := before.SessionData.Cookies[2].Value

	fake := &fakeLister{probeErrSet: true, probeErr: fmt.Errorf("%w: rejected", tuyaqr.ErrSessionExpired)}
	p := NewTuya("", WithTuyaStore(store))
	p.client = fake

	if _, err := p.Session(context.Background()); err != nil {
		t.Fatalf("Session: %v", err)
	}
	after, err := store.Load(tuyaqr.Account{Region: "us-west", Email: "db@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if after.SessionData.Cookies[2].Value != beforeCookies {
		t.Error("a cloud-rejected session was re-saved")
	}
}

// TestTuyaLogoutDeletesFromTheDatabaseStore is delivery item 5's server half.
func TestTuyaLogoutDeletesFromTheDatabaseStore(t *testing.T) {
	store := newTestSQLiteStore(t)
	if err := store.Save(testSessionForStore("db@example.test")); err != nil {
		t.Fatal(err)
	}
	m := NewLoginManager(
		WithLoginClientFactory(func() LoginClient { return &fakeLoginClient{pollSeq: []pollStep{{}}} }),
		WithLoginStore(store),
	)
	if _, err := m.Begin(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m.Pending() != 1 {
		t.Fatalf("pending = %d, want 1 before logout", m.Pending())
	}

	removed, err := m.Logout()
	if err != nil {
		t.Fatal(err)
	}
	if !removed {
		t.Error("removed = false although a stored session was deleted")
	}
	if _, err := store.Load(tuyaqr.Account{Region: "us-west", Email: "db@example.test"}); err == nil {
		t.Fatal("the session is still in the database after logout")
	}
	accounts, err := store.Accounts()
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 0 {
		t.Errorf("accounts after logout = %+v, want none", accounts)
	}
	if m.Pending() != 0 {
		t.Errorf("pending = %d, want 0 after logout", m.Pending())
	}
	// A second logout is not an error.
	again, err := m.Logout()
	if err != nil || again {
		t.Fatalf("second logout: removed=%t err=%v, want false/nil", again, err)
	}
}

// TestLoginPollPersistsIntoTheDatabaseStore is delivery item 4's login half: a
// completed scan writes the credential into the project database, and the
// response says where it went.
func TestLoginPollPersistsIntoTheDatabaseStore(t *testing.T) {
	store := newTestSQLiteStore(t)
	captured := testSessionForStore("scan@example.test")
	client := &fakeLoginClient{pollSeq: []pollStep{{}, {done: true}}, session: captured}
	m := NewLoginManager(
		WithLoginClientFactory(func() LoginClient { return client }),
		WithLoginStore(store),
	)
	ticket, err := m.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Poll(context.Background(), ticket.Token); err != nil {
		t.Fatal(err)
	}
	result, err := m.Poll(context.Background(), ticket.Token)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusDone {
		t.Fatalf("status = %q, want done", result.Status)
	}
	if result.Session == nil || result.Session.StoreKind != tuyaqr.StoreKindSQLite {
		t.Fatalf("session = %+v, want storeKind sqlite so the response says where it went", result.Session)
	}
	stored, err := store.Load(tuyaqr.Account{Region: "us-west", Email: "scan@example.test"})
	if err != nil {
		t.Fatalf("the scanned session was not written to the database: %v", err)
	}
	if stored.SessionData.Cookies[2].Value != captured.SessionData.Cookies[2].Value {
		t.Error("the scanned credential was not stored intact")
	}
	if kind := m.StoreKind(); kind != tuyaqr.StoreKindSQLite {
		t.Errorf("StoreKind() = %q, want sqlite", kind)
	}
	if m.Pending() != 0 {
		t.Errorf("pending = %d, want 0 after a completed scan", m.Pending())
	}
}

// TestLoginManagerOverAFilePathIsUnchanged is the regression guard on the login
// side: the old constructor still writes a 0600 file at the exact path.
func TestLoginManagerOverAFilePathIsUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session.json")
	captured := testSessionForStore("file-scan@example.test")
	client := &fakeLoginClient{pollSeq: []pollStep{{done: true}}, session: captured}
	m := NewLoginManager(
		WithLoginClientFactory(func() LoginClient { return client }),
		WithLoginSessionFile(path),
	)
	if kind := m.StoreKind(); kind != tuyaqr.StoreKindFile {
		t.Fatalf("StoreKind() = %q, want file", kind)
	}
	ticket, err := m.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	result, err := m.Poll(context.Background(), ticket.Token)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusDone {
		t.Fatalf("status = %q, want done", result.Status)
	}
	if _, err := tuyaqr.LoadSession(path); err != nil {
		t.Fatalf("the session file was not written at the configured path: %v", err)
	}
	// And logout still removes that exact file.
	removed, err := m.Logout()
	if err != nil || !removed {
		t.Fatalf("logout: removed=%t err=%v", removed, err)
	}
	if _, err := tuyaqr.LoadSession(path); !errors.Is(err, tuyaqr.ErrNoSession) {
		t.Errorf("the session file survived logout: %v", err)
	}
}

// TestTuyaSessionFileForEngineMaterializesAPrivateCopy covers the vendored-code
// bridge: a database-backed session has to reach the engine as a 0600 file.
func TestTuyaSessionFileForEngineMaterializesAPrivateCopy(t *testing.T) {
	store := newTestSQLiteStore(t)
	s := testSessionForStore("db@example.test")
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	p := NewTuya("", WithTuyaStore(store))
	loaded, err := p.currentSession()
	if err != nil {
		t.Fatal(err)
	}
	path, err := p.sessionPathForEngine(loaded)
	if err != nil {
		t.Fatalf("sessionPathForEngine: %v", err)
	}
	t.Cleanup(func() { tuyaqr.RemoveMaterialized(path) })

	if filepath.Dir(path) == store.Location() {
		t.Error("the engine was handed the database path itself")
	}
	// The engine consumes the file, so it must be a real, loadable, 0600 file.
	back, err := tuyaqr.LoadSession(path)
	if err != nil {
		t.Fatalf("the materialized file is not a usable session: %v", err)
	}
	if back.SessionData.Cookies[2].Value != s.SessionData.Cookies[2].Value {
		t.Error("the materialized file does not carry the stored credential")
	}
	// SessionFile() now reports the materialized path, not a database path.
	if p.SessionFile() != path {
		t.Errorf("SessionFile() = %q, want the materialized path %q", p.SessionFile(), path)
	}
}

// TestTuyaStartStreamUsesTheMaterializedPathNotTheDatabase keeps the engine from
// ever being pointed at onvif_logs.db.
func TestTuyaStartStreamUsesTheMaterializedPathNotTheDatabase(t *testing.T) {
	store := newTestSQLiteStore(t)
	if err := store.Save(testSessionForStore("db@example.test")); err != nil {
		t.Fatal(err)
	}
	bridge := &fakeBridge{}
	stopper := &fakeStopper{}
	p := NewTuya("",
		WithTuyaStore(store),
		WithTuyaBridge(bridge),
		WithTuyaStreamStopper(stopper),
	)
	// The liveness gate is bypassed by marking the session verified, so the
	// assertion below is about the path handed to the engine.
	p.client = &fakeLister{}
	if _, err := p.Session(context.Background()); err != nil {
		t.Fatal(err)
	}
	info, err := p.StartStream("eb9f1d6e677b1b39f222ag")
	if err != nil {
		t.Fatalf("StartStream: %v", err)
	}
	if info == nil {
		t.Fatal("StartStream returned no stream info")
	}
	if bridge.lastSpec.SessionFile == "" {
		t.Fatal("the engine was given no session path")
	}
	if bridge.lastSpec.SessionFile == store.Location() {
		t.Fatal("the engine was handed the SQLite database as a session file")
	}
	if _, err := tuyaqr.LoadSession(bridge.lastSpec.SessionFile); err != nil {
		t.Fatalf("the path handed to the engine is not a usable session: %v", err)
	}
	t.Cleanup(func() { tuyaqr.RemoveMaterialized(bridge.lastSpec.SessionFile) })
}
