package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dengan.dev/camera-streamer/internal/provider"
	"dengan.dev/camera-streamer/internal/tuyaqr"
)

// --- M8: the HTTP surface against a database-backed session store ------------
//
// These tests drive the REAL handler with a REAL SQLite session store, so the
// JSON the UI receives is produced by the same code path the running server uses.

// dbSessionEnv wires a handler whose Tuya session lives in a SQLite database and
// whose cloud is a fake, so no network is involved.
func dbSessionEnv(t *testing.T) (*testEnv, *tuyaqr.SQLiteSessionStore) {
	t.Helper()
	env := testHandler(t)
	store, err := tuyaqr.NewSQLiteSessionStore(filepath.Join(t.TempDir(), "sessions.db"))
	if err != nil {
		t.Fatalf("NewSQLiteSessionStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	tuyaProvider := provider.NewTuya("", provider.WithTuyaStore(store))
	// The cloud is faked through the same seam the provider tests use, so the
	// handler under test has no network dependency.
	tuyaProvider = provider.NewTuya("", provider.WithTuyaStore(store), provider.WithTuyaCloudClientForTest(&handlerFakeCloud{}))
	logins := provider.NewLoginManager(provider.WithLoginStore(store))
	env.handler.SetProviders(provider.NewSet(provider.NewONVIF(env.handler.onvifClient), tuyaProvider), logins, tuyaProvider, nil)
	return env, store
}

// handlerSession builds a DB-storable session, optionally with a cloud-stated
// expiry on fast-sid.
func handlerSession(expiry time.Time) *tuyaqr.Session {
	now := time.Now()
	cookies := []*tuyaqr.Cookie{
		{Name: "gTyPlatLang", Value: "en"},
		{Name: "locale", Value: "en"},
		{Name: "fast-sid", Value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{Name: "s-sid", Value: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"},
	}
	if !expiry.IsZero() {
		cookies[2].Expires = expiry
	}
	return &tuyaqr.Session{
		Region:      "us-west",
		Email:       "db@example.test",
		UserKey:     "us-west_db_at_example_test",
		LastRefresh: now,
		SessionData: tuyaqr.UserSession{
			LoginResult:   &tuyaqr.LoginResult{UID: "az1", Email: "db@example.test"},
			LastValidated: now,
			ServerHost:    tuyaqr.DefaultHost,
			Region:        "us-west",
			UserEmail:     "db@example.test",
			Cookies:       cookies,
		},
	}
}

// TestSessionEndpointReportsTheDatabaseStoreHonestly is delivery item 5: the
// four M6 axes must still be honest, and the response must say the credential is
// in the database rather than implying a file.
func TestSessionEndpointReportsTheDatabaseStoreHonestly(t *testing.T) {
	env, store := dbSessionEnv(t)
	expiry := time.Now().Add(30 * time.Hour).UTC().Truncate(time.Second)
	if err := store.Save(handlerSession(expiry)); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	env.handler.TuyaSession(rec, httptest.NewRequest(http.MethodGet, "/api/tuya/session", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)

	// The three honesty axes, unchanged in meaning.
	if body["configured"] != true {
		t.Errorf("configured = %#v, want true", body["configured"])
	}
	if body["filePresent"] != true {
		t.Errorf("filePresent = %#v, want true: a stored credential that loads is present whatever the medium", body["filePresent"])
	}
	if body["cloudVerified"] != true || body["valid"] != true {
		t.Errorf("cloudVerified=%#v valid=%#v, want both true", body["cloudVerified"], body["valid"])
	}
	if body["expiryKnown"] != true {
		t.Errorf("expiryKnown = %#v, want true: the stored fast-sid declares a deadline", body["expiryKnown"])
	}
	if body["expirySource"] != "cookie:fast-sid" {
		t.Errorf("expirySource = %#v, want cookie:fast-sid", body["expirySource"])
	}
	if body["reloginRequired"] != false {
		t.Errorf("reloginRequired = %#v, want false", body["reloginRequired"])
	}

	// The M8 store axes.
	if body["storeKind"] != tuyaqr.StoreKindSQLite {
		t.Errorf("storeKind = %#v, want sqlite", body["storeKind"])
	}
	if loc, _ := body["storeLocation"].(string); loc == "" {
		t.Error("storeLocation is empty, so the response does not say where the credential is")
	} else if filepath.Base(loc) != "sessions.db" {
		t.Errorf("storeLocation = %q, want the session database path", loc)
	}
	if reason, _ := body["storeReason"].(string); reason == "" {
		t.Error("storeReason is empty, so the response does not explain the store choice")
	}
	modeList, ok := body["storeFileModes"].([]any)
	if !ok || len(modeList) == 0 {
		t.Fatalf("storeFileModes = %#v, want the observed database permissions", body["storeFileModes"])
	}
	for _, raw := range modeList {
		m, _ := raw.(map[string]any)
		if m["mode"] != "0600" {
			t.Errorf("%v reported mode %v, want 0600", m["path"], m["mode"])
		}
	}
	accounts, ok := body["accounts"].([]any)
	if !ok || len(accounts) != 1 {
		t.Fatalf("accounts = %#v, want exactly one stored account", body["accounts"])
	}
}

// TestSessionEndpointKeepsExpiryUnknownWhenNothingDeclaresOne is the honesty
// guard at the HTTP boundary: no countdown may be invented for a DB-stored
// session whose cookies carry no expiry.
func TestSessionEndpointKeepsExpiryUnknownWhenNothingDeclaresOne(t *testing.T) {
	env, store := dbSessionEnv(t)
	if err := store.Save(handlerSession(time.Time{})); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	env.handler.TuyaSession(rec, httptest.NewRequest(http.MethodGet, "/api/tuya/session", nil))
	body := decodeBody(t, rec)

	if body["expiryKnown"] != false {
		t.Errorf("expiryKnown = %#v, want false", body["expiryKnown"])
	}
	if body["expiresAt"] != nil {
		t.Errorf("expiresAt = %#v, want null when the expiry is unknown", body["expiresAt"])
	}
	if body["remainingSeconds"] != float64(0) {
		t.Errorf("remainingSeconds = %#v, want 0", body["remainingSeconds"])
	}
	if body["expirySource"] != "unknown" {
		t.Errorf("expirySource = %#v, want unknown", body["expirySource"])
	}
	if body["valid"] != true {
		t.Error("valid = false although the cloud accepted the session: an unknown expiry is not invalidity")
	}
	if body["storeKind"] != tuyaqr.StoreKindSQLite {
		t.Errorf("storeKind = %#v, want sqlite", body["storeKind"])
	}
}

// TestSessionEndpointSaysNothingIsStoredWhenTheDatabaseIsEmpty keeps the empty
// case distinguishable from the dead-credential case.
func TestSessionEndpointSaysNothingIsStoredWhenTheDatabaseIsEmpty(t *testing.T) {
	env, _ := dbSessionEnv(t)
	rec := httptest.NewRecorder()
	env.handler.TuyaSession(rec, httptest.NewRequest(http.MethodGet, "/api/tuya/session", nil))
	body := decodeBody(t, rec)

	if body["configured"] != true {
		t.Errorf("configured = %#v, want true: a store IS wired up", body["configured"])
	}
	if body["filePresent"] != false {
		t.Errorf("filePresent = %#v, want false with an empty store", body["filePresent"])
	}
	if body["valid"] != false || body["cloudVerified"] != false {
		t.Errorf("an empty store reported validity: %#v", body)
	}
	if body["reloginRequired"] != true {
		t.Errorf("reloginRequired = %#v, want true", body["reloginRequired"])
	}
}

// TestLogoutDeletesFromTheDatabaseAndNamesTheStore is delivery item 5's logout
// half, over the real handler.
func TestLogoutDeletesFromTheDatabaseAndNamesTheStore(t *testing.T) {
	env, store := dbSessionEnv(t)
	if err := store.Save(handlerSession(time.Now().Add(time.Hour))); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	env.handler.TuyaLogout(rec, httptest.NewRequest(http.MethodPost, "/api/tuya/logout", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if body["removed"] != true {
		t.Errorf("removed = %#v, want true", body["removed"])
	}
	if body["sessionStore"] != tuyaqr.StoreKindSQLite {
		t.Errorf("sessionStore = %#v, want sqlite", body["sessionStore"])
	}
	if body["serverSideLogout"] != false {
		t.Errorf("serverSideLogout = %#v, want false: Tuya has no server-side logout", body["serverSideLogout"])
	}
	if detail, _ := body["detail"].(string); !contains(detail, "server-side logout") {
		t.Errorf("detail = %q, want the local-only honesty note", detail)
	}

	// The row must actually be gone.
	if _, err := store.Load(tuyaqr.Account{Region: "us-west", Email: "db@example.test"}); err == nil {
		t.Fatal("the session row survived logout")
	}
	accounts, err := store.Accounts()
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 0 {
		t.Errorf("accounts after logout = %+v, want none", accounts)
	}

	// And the session endpoint must now report the honest consequences.
	rec2 := httptest.NewRecorder()
	env.handler.TuyaSession(rec2, httptest.NewRequest(http.MethodGet, "/api/tuya/session", nil))
	body2 := decodeBody(t, rec2)
	if body2["filePresent"] != false || body2["valid"] != false || body2["reloginRequired"] != true {
		t.Errorf("after logout the status is %#v, want filePresent=false valid=false reloginRequired=true", body2)
	}
}

// TestLogoutTwiceIsNotAnError keeps a double sign-out from returning a failure.
func TestLogoutTwiceIsNotAnError(t *testing.T) {
	env, _ := dbSessionEnv(t)
	env.handler.TuyaLogout(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/tuya/logout", nil))
	rec := httptest.NewRecorder()
	env.handler.TuyaLogout(rec, httptest.NewRequest(http.MethodPost, "/api/tuya/logout", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("second logout status = %d, want 200", rec.Code)
	}
	body := decodeBody(t, rec)
	if body["removed"] != false {
		t.Errorf("removed = %#v, want false when nothing was stored", body["removed"])
	}
}

// TestSessionEndpointNeverLeaksACredential is an explicit guard on the JSON the
// browser receives: the response must carry names and counts and no values.
func TestSessionEndpointNeverLeaksACredential(t *testing.T) {
	env, store := dbSessionEnv(t)
	s := handlerSession(time.Now().Add(time.Hour))
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	env.handler.TuyaSession(rec, httptest.NewRequest(http.MethodGet, "/api/tuya/session", nil))

	raw := rec.Body.String()
	for _, c := range s.SessionData.Cookies {
		if contains(raw, c.Value) {
			t.Fatalf("the session response leaked the value of cookie %q", c.Name)
		}
	}
	if contains(raw, s.SessionData.LoginResult.SID) && s.SessionData.LoginResult.SID != "" {
		t.Fatal("the session response leaked the login sid")
	}
	// The names ARE expected: they are how the UI explains which cookie carries
	// the deadline, and a name is not a credential.
	if !contains(raw, "fast-sid") {
		t.Error("the response does not name the cookies, so the expiry cannot be audited")
	}
}

// TestLogoutResponseNeverLeaksACredential does the same for the logout response.
func TestLogoutResponseNeverLeaksACredential(t *testing.T) {
	env, store := dbSessionEnv(t)
	s := handlerSession(time.Now().Add(time.Hour))
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	env.handler.TuyaLogout(rec, httptest.NewRequest(http.MethodPost, "/api/tuya/logout", nil))
	raw := rec.Body.String()
	for _, c := range s.SessionData.Cookies {
		if contains(raw, c.Value) {
			t.Fatalf("the logout response leaked the value of cookie %q", c.Name)
		}
	}
	// Validate it is well-formed JSON too, so a future field cannot be a
	// non-serialisable struct that silently omits itself.
	var parsed map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("logout response is not JSON: %v", err)
	}
}

// handlerFakeCloud is the handler tests' stand-in for the Tuya cloud: it accepts
// every session and reports no expiry of its own (the stored cookies are the only
// source of a deadline, exactly as with the real cloud), so it satisfies the
// provider.TuyaList seam the handler tests need.
type handlerFakeCloud struct{}

func (f *handlerFakeCloud) Cameras(ctx context.Context) ([]tuyaqr.Device, error) {
	return nil, nil
}

func (f *handlerFakeCloud) Validate(ctx context.Context) error { return nil }

func (f *handlerFakeCloud) RefreshExpiry(ctx context.Context, s *tuyaqr.Session) error { return nil }

func contains(haystack, needle string) bool {
	// A needle this short ("en") appears in ordinary prose, so a naive substring
	// search would report false leaks. Credential-shaped values are never short;
	// below this length the check is meaningless and is skipped rather than made
	// to lie in either direction.
	if len(needle) < 8 {
		return false
	}
	return strings.Contains(haystack, needle)
}
