package tuyaqr

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// realSessionPath returns the path of the real stored session, or "" when the
// opt-in env var is unset. These tests never mutate the real file: they load
// it read-only and, when they need to write, they write to t.TempDir().
func realSessionPath(t *testing.T) string {
	t.Helper()
	p := os.Getenv("TUYA_SESSION_TEST_FILE")
	if p == "" {
		t.Skip("set TUYA_SESSION_TEST_FILE=<path> to run live tests against the stored session")
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("TUYA_SESSION_TEST_FILE=%s: %v", p, err)
	}
	return p
}

// TestSessionRoundTripRealFile proves the Session type is JSON-compatible with
// the REAL session file: load(real) -> save(copy) -> load(copy) -> deep equal.
func TestSessionRoundTripRealFile(t *testing.T) {
	src := realSessionPath(t)

	loaded, err := LoadSession(src)
	if err != nil {
		t.Fatalf("LoadSession(%s): %v", src, err)
	}
	fast, sSID, n := loaded.AuthCookieStatus()
	t.Logf("real session: host=%s region=%s email=%s uid=%s cookies=%d names=%v fast-sid=%t s-sid=%t",
		loaded.ServerHost(), loaded.Region, loaded.Email,
		loaded.SessionData.LoginResult.UID, n, loaded.CookieNames(), fast, sSID)
	if !fast || !sSID {
		t.Fatalf("real session is missing fast-sid/s-sid")
	}

	// Also record the raw JSON of the source so we can compare shape, not just
	// the parts our structs model.
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(t.TempDir(), "roundtrip", "user.json")
	if err := SaveSession(out, loaded); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	// Permissions: file 0600, dir 0700.
	fi, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("saved file mode = %o, want 600", perm)
	}
	di, err := os.Stat(filepath.Dir(out))
	if err != nil {
		t.Fatal(err)
	}
	if perm := di.Mode().Perm(); perm != 0o700 {
		t.Errorf("saved dir mode = %o, want 700", perm)
	}

	back, err := LoadSession(out)
	if err != nil {
		t.Fatalf("LoadSession(saved): %v", err)
	}
	if !reflect.DeepEqual(loaded, back) {
		t.Fatalf("deep-equal failed after round trip\n loaded=%+v\n back=%+v", loaded, back)
	}

	// The saved copy must preserve every JSON key of the source that our
	// structs claim to model. We compare key sets of the decoded maps.
	assertKeysPreserved(t, raw, out)

	// The real file must be untouched.
	after, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(raw) {
		t.Fatalf("the REAL session file at %s was modified by this test", src)
	}
	t.Logf("round trip OK: load -> save (0600 in 0700) -> load deep-equal; source file byte-identical")
}

func assertKeysPreserved(t *testing.T, srcRaw []byte, savedPath string) {
	t.Helper()
	savedRaw, err := os.ReadFile(savedPath)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := decodeKeys(srcRaw)
	if err != nil {
		t.Fatalf("decode source keys: %v", err)
	}
	dk, err := decodeKeys(savedRaw)
	if err != nil {
		t.Fatalf("decode saved keys: %v", err)
	}
	for _, path := range []string{"", "sessionData", "sessionData.loginResult", "sessionData.loginResult.domain", "sessionData.loginResult.extras", "sessionData.cookies[0]"} {
		src := sk[path]
		dst := dk[path]
		for k := range src {
			if !dst[k] {
				t.Errorf("key %q lost from %q on save", k, path)
			}
		}
	}
	t.Logf("key preservation OK across %d JSON objects", len(sk))
}

func decodeKeys(raw []byte) (map[string]map[string]bool, error) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	out := map[string]map[string]bool{}
	walkKeys("", doc, out)
	return out, nil
}

func walkKeys(prefix string, node any, out map[string]map[string]bool) {
	switch v := node.(type) {
	case map[string]any:
		if out[prefix] == nil {
			out[prefix] = map[string]bool{}
		}
		for k, child := range v {
			out[prefix][k] = true
			walkKeys(joinKey(prefix, k), child, out)
		}
	case []any:
		for i, child := range v {
			if i == 0 {
				walkKeys(prefix+"[0]", child, out)
			}
		}
	}
}

func joinKey(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

// TestLiveCameras lists the REAL account's cameras using ONLY the stored
// session. Secrets are never printed: cookie names and counts only.
func TestLiveCameras(t *testing.T) {
	src := realSessionPath(t)
	if os.Getenv("TUYA_LIVE") == "" {
		t.Skip("set TUYA_LIVE=1 (with TUYA_SESSION_TEST_FILE) to hit the real cloud")
	}

	sess, err := LoadSession(src)
	if err != nil {
		t.Fatalf("LoadSession: %v", err)
	}
	fast, sSID, n := sess.AuthCookieStatus()
	t.Logf("loaded session: host=%s region=%s uid=%s cookies=%d names=%v fast-sid=%t s-sid=%t",
		sess.ServerHost(), sess.Region, sess.SessionData.LoginResult.UID, n, sess.CookieNames(), fast, sSID)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	c, err := NewClientFromSession(sess)
	if err != nil {
		t.Fatalf("NewClientFromSession: %v", err)
	}
	if err := c.Validate(ctx); err != nil {
		t.Fatalf("session rejected by cloud: %v", err)
	}
	t.Logf("session VALIDATED against https://%s (no password used anywhere)", c.Host())

	all, err := c.Devices(ctx)
	if err != nil {
		t.Fatalf("Devices: %v", err)
	}
	t.Logf("account devices discovered: %d", len(all))
	for _, d := range all {
		t.Logf("  - %-18s %-32s online=%t", d.Category, d.DeviceName, d.Online)
	}

	cams, err := c.Cameras(ctx)
	if err != nil {
		t.Fatalf("Cameras: %v", err)
	}
	t.Logf("cameras discovered: %d", len(cams))

	const wantID = "eb9f1d6e677b1b39f222ag"
	var found *Device
	for i := range cams {
		if cams[i].DeviceID == wantID {
			found = &cams[i]
		}
	}
	if found == nil {
		t.Fatalf("camera %s not found (got %d cameras)", wantID, len(cams))
	}
	if found.DeviceName != "Security Camera" {
		t.Errorf("device name = %q, want %q", found.DeviceName, "Security Camera")
	}
	if found.Category != CategorySmartCamera {
		t.Errorf("category = %q, want %q", found.Category, CategorySmartCamera)
	}
	if found.Config == nil {
		t.Fatalf("camera has no /api/jarvis/config payload")
	}
	if found.Config.Auth == "" || found.Config.LocalKey == "" {
		t.Errorf("config missing auth/localKey (auth=%d bytes, localKey=%d bytes)",
			len(found.Config.Auth), len(found.Config.LocalKey))
	}
	skill, err := found.Skill()
	if err != nil {
		t.Fatalf("Skill: %v", err)
	}
	hd, sd := skill.VideoStream(2), skill.VideoStream(4)
	if hd == nil || sd == nil {
		t.Fatalf("skill missing streamType 2/4: %+v", skill.Videos)
	}
	t.Logf("MATCH %s name=%q category=%s productId=%s uuid=%s online=%t",
		found.DeviceID, found.DeviceName, found.Category, found.ProductID, found.UUID, found.Online)
	t.Logf("  config: auth=%dB localKey=%dB ices=%d gatewayId=%q nodeId=%q supportsWebrtc=%t p2pType=%d",
		len(found.Config.Auth), len(found.Config.LocalKey), len(found.Config.P2PConfig.Ices),
		found.Config.GatewayID, found.Config.NodeID, found.Config.SupportsWebrtc, found.Config.P2PType)
	t.Logf("  skill : webrtc=%d hd=%dx%d codecType=%d | sd=%dx%d codecType=%d | audios=%d",
		skill.WebRTC, hd.Width, hd.Height, hd.CodecType, sd.Width, sd.Height, sd.CodecType, len(skill.Audios))

	// The redacted view must not contain the secret material.
	red := found.Redacted()
	if red.Config.Auth != redacted || red.Config.LocalKey != redacted {
		t.Errorf("Redacted() leaked auth/localKey")
	}

	if _, err := c.MQTTCredentials(ctx); err != nil {
		t.Logf("jarvis/mqtt: %v (non-fatal)", err)
	} else {
		t.Logf("jarvis/mqtt returned credentials (values not printed)")
	}
}

// TestLiveBeginLoginQR exercises the REAL QR handshake far enough to prove a
// token is issued and a valid PNG is rendered. It cannot complete the login:
// that needs the account owner's phone to scan the image.
func TestLiveBeginLoginQR(t *testing.T) {
	if os.Getenv("TUYA_LIVE_QR") == "" {
		t.Skip("set TUYA_LIVE_QR=1 to request a real QR token from the cloud")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	token, png, err := BeginLogin(ctx)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	if len(token) != 65 || !strings.HasPrefix(token, "AZ") {
		// Print only the shape, never the value.
		t.Fatalf("unexpected token shape: len=%d hasAZPrefix=%t", len(token), strings.HasPrefix(token, "AZ"))
	}
	magic := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}
	if len(png) < 8 || string(png[:8]) != string(magic) {
		t.Fatalf("PNG magic bytes = % x", png[:minInt(8, len(png))])
	}
	// Write to a temp path only; generated QR images are never committed.
	f := filepath.Join(t.TempDir(), "login-qr.png")
	if err := os.WriteFile(f, png, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("REAL QR token issued by https://%s: length=%d prefix=AZ... (value deliberately not printed)", DefaultHost, len(token))
	t.Logf("REAL QR PNG: %d bytes, magic=% x, written to a temp path (mode 0600)", len(png), png[:8])
	t.Logf("NOTE: login is not completed here — that requires a human scan in the Bardi app.")
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
