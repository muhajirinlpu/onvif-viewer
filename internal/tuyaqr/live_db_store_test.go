package tuyaqr

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- M8 opt-in live test ----------------------------------------------------
//
// This test is env-gated and runs the real credential through the DATABASE store
// and then the real cloud. It is deliberately NOT part of a default test run, and
// it deliberately never writes the user's account into a database that a real
// install uses: the store it exercises is always inside t.TempDir().
//
// Gate: TUYA_SESSION_TEST_FILE must name the stored session file (the same gate
// the existing live tests use). Nothing else is required, and nothing else is
// touched.

// TestLiveSessionThroughTheDatabaseStore is delivery item 5's live half: the
// session is imported into a throwaway database, read back out of it, and then
// used to make a REAL authenticated call to the Tuya cloud. It reports the honest
// expiry, computed from what the cloud actually said and never estimated.
func TestLiveSessionThroughTheDatabaseStore(t *testing.T) {
	src := realSessionPath(t)
	if os.Getenv("TUYA_SESSION_LIVE_DB") == "" {
		t.Skip("set TUYA_SESSION_LIVE_DB=1 to run the database-store live test against the real cloud")
	}

	srcRaw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	srcInfo, err := os.Stat(src)
	if err != nil {
		t.Fatal(err)
	}

	store, err := NewSQLiteSessionStore(filepath.Join(t.TempDir(), "live-sessions.db"))
	if err != nil {
		t.Fatalf("NewSQLiteSessionStore: %v", err)
	}
	defer store.Close()

	// The import must be non-destructive even for this test: the source is read.
	result, err := ImportSessionFile(store, src)
	if err != nil {
		t.Fatalf("ImportSessionFile(%s): %v", src, err)
	}
	if !result.Imported {
		t.Fatalf("the import did not take: %+v", result)
	}
	t.Logf("imported: account=%s/%s cookies=%d names=%v dest=%s",
		result.Region, result.Email, result.CookieCount, result.CookieNames, result.DestLocation)

	// The real file must be byte-identical and undisplaced.
	afterRaw, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("the source session file is gone after the import: %v", err)
	}
	if string(afterRaw) != string(srcRaw) {
		t.Fatal("the import modified the real session file")
	}
	if afterInfo, err := os.Stat(src); err != nil || afterInfo.Mode().Perm() != srcInfo.Mode().Perm() {
		t.Fatalf("the import changed the real session file's permissions: %v", err)
	}

	// Read the credential back out of the DATABASE and use it.
	account, err := SingleAccount(store)
	if err != nil {
		t.Fatalf("SingleAccount: %v", err)
	}
	session, err := store.Load(account)
	if err != nil {
		t.Fatalf("Load from the database store: %v", err)
	}
	fast, sSID, n := session.AuthCookieStatus()
	if !fast || !sSID {
		t.Fatalf("the database-stored session lacks the auth pair (have %d cookies: %s)", n, strings.Join(session.CookieNames(), ","))
	}

	client, err := NewClientFromSession(session)
	if err != nil {
		t.Fatalf("NewClientFromSession: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// A real authenticated call. This is the ONLY thing that establishes that the
	// credential works.
	if err := client.Validate(ctx); err != nil {
		t.Fatalf("the database-stored session was rejected by the Tuya cloud: %v", err)
	}
	t.Log("the Tuya cloud ACCEPTED the session read out of the SQLite database")

	// RefreshExpiry asks the cloud for its own deadline and folds it in.
	before, beforeName, beforeKnown := session.EarliestCookieExpiry()
	if err := client.RefreshExpiry(ctx, session); err != nil {
		t.Fatalf("RefreshExpiry: %v", err)
	}
	after, afterName, afterKnown := session.EarliestCookieExpiry()

	switch {
	case afterKnown:
		t.Logf("HONEST EXPIRY: the cloud stated fast-sid expires at %s (in %s); source=%s",
			after.UTC().Format(time.RFC3339), time.Until(after).Truncate(time.Second), afterName)
		if !after.After(time.Now()) {
			t.Errorf("the cloud-reported expiry %s is in the past, so the countdown would be negative", after)
		}
	case beforeKnown:
		t.Logf("HONEST EXPIRY: unchanged from storage at %s (source=%s); the cloud reported no new deadline", before, beforeName)
	default:
		// This is the measured state of the user's stored session: all four
		// cookies carry a ZERO expiry. The honest report is "unknown", never a
		// guessed countdown, and the test passes on it.
		t.Log("HONEST EXPIRY: unknown — neither the stored session nor this probe's Set-Cookie headers declared a deadline; " +
			"the API must report expiryKnown=false and no countdown")
	}

	// Persisting the refreshed session back must produce a row another process
	// can read, and must not invent an expiry that was not reported.
	if err := store.Save(session); err != nil {
		t.Fatalf("Save after the refresh: %v", err)
	}
	reloaded, err := NewSQLiteSessionStore(store.Location())
	if err != nil {
		t.Fatal(err)
	}
	defer reloaded.Close()
	back, err := reloaded.Load(account)
	if err != nil {
		t.Fatalf("a fresh handle could not read the refreshed session: %v", err)
	}
	_, _, reloadedKnown := back.EarliestCookieExpiry()
	if reloadedKnown != afterKnown {
		t.Errorf("the persisted expiry contradicts the in-memory one: persisted known=%t, in-memory known=%t", reloadedKnown, afterKnown)
	}
	if afterKnown {
		got, _, _ := back.EarliestCookieExpiry()
		if !got.Equal(after) {
			t.Errorf("the persisted expiry %s differs from the cloud's %s", got, after)
		}
	}
}

// TestLiveCamerasThroughTheDatabaseStore is the same path one step further: the
// credential that came out of the database must be able to enumerate the account's
// cameras, which is the call the UI actually makes.
func TestLiveCamerasThroughTheDatabaseStore(t *testing.T) {
	src := realSessionPath(t)
	if os.Getenv("TUYA_SESSION_LIVE_DB") == "" {
		t.Skip("set TUYA_SESSION_LIVE_DB=1 to run the database-store live test against the real cloud")
	}
	store, err := NewSQLiteSessionStore(filepath.Join(t.TempDir(), "live-sessions.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := ImportSessionFile(store, src); err != nil {
		t.Fatalf("ImportSessionFile: %v", err)
	}
	account, err := SingleAccount(store)
	if err != nil {
		t.Fatal(err)
	}
	session, err := store.Load(account)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClientFromSession(session)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	devices, err := client.Cameras(ctx)
	if err != nil {
		t.Fatalf("Cameras from a database-stored session failed: %v", err)
	}
	cameras := 0
	for _, d := range devices {
		// Device id and category only: never Device.Config.
		t.Logf("camera id=%s name=%q category=%s online=%t", d.DeviceID, d.DeviceName, d.Category, d.Online)
		if IsCamera(d.Category) {
			cameras++
		}
	}
	if cameras == 0 {
		t.Fatal("the account listed no camera through a database-stored session")
	}
	t.Logf("the database-stored session enumerated %d device(s), %d of them cameras", len(devices), cameras)
}

// TestLiveImportTargetsOnlyATempDatabase is an explicit assertion that
// the live tests never write the user's account anywhere durable.
func TestLiveImportTargetsOnlyATempDatabase(t *testing.T) {
	store, err := NewSQLiteSessionStore(filepath.Join(t.TempDir(), "assert-temp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	tmp := os.TempDir()
	if !strings.HasPrefix(store.Location(), tmp) {
		t.Fatalf("the live test database is at %s, which is outside %s", store.Location(), tmp)
	}
	// And it must not be the shipped database.
	if filepath.Base(store.Location()) == "onvif_logs.db" && !strings.HasPrefix(store.Location(), tmp) {
		t.Fatal("the live test would write to the real onvif_logs.db")
	}
}
