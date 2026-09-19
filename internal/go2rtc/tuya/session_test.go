package tuya

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type sessionTransport func(*http.Request) (*http.Response, error)

func (f sessionTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestStoredSessionSkipsLogin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	fixture := `{"sessionData":{"serverHost":"protect-us.ismartlife.me","loginResult":{"domain":{"mobileMqttsUrl":"mqtt.example.test","mqttsPort":8883}},"cookies":[{"name":"fast-sid","value":"test-cookie","expires":"0001-01-01T00:00:00Z"},{"name":"s-sid","value":"test-cookie-2"}]}}`
	if err := os.WriteFile(path, []byte(fixture), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := NewTuyaSmartApiClientFromSession(nil, "protect-us.ismartlife.me", path, "test-device")
	if err != nil {
		t.Fatal(err)
	}
	if c.email != "" || c.password != "" {
		t.Fatal("session constructor populated account credentials")
	}
	calls := []string{}
	c.httpClient.Transport = sessionTransport(func(r *http.Request) (*http.Response, error) {
		calls = append(calls, r.URL.Path)
		cookie, err := r.Cookie("fast-sid")
		if err != nil || cookie.Value != "test-cookie" {
			t.Fatal("stored cookie missing")
		}
		if strings.Contains(r.URL.Path, "login") {
			t.Fatal("password login attempted")
		}
		body := `{"success":true,"result":{"auth":"fixture-auth","supportsWebrtc":true,"skill":"{\"videos\":[]}","p2pConfig":{"ices":[]}}}`
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})
	// initToken itself must be guarded so every caller is password-free in session mode.
	if err := c.initToken(); err != nil {
		t.Fatal(err)
	}
	cfg, err := c.loadWebrtcConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Auth == "" || !cfg.SupportsWebRTC {
		t.Fatal("missing WebRTC credentials")
	}
	if len(calls) != 1 || calls[0] != "/api/jarvis/config" {
		t.Fatalf("unexpected paths: %v", calls)
	}
	if c.mqttsUrl != "ssl://mqtt.example.test:8883" {
		t.Fatal("missing saved MQTT endpoint")
	}
}

func TestDialAcceptsSessionFileWithoutPassword(t *testing.T) {
	_, err := Dial("tuya://protect-us.ismartlife.me?device_id=test&session_file=/nonexistent/tuya-session.json&resolution=sd")
	if err == nil || !strings.Contains(err.Error(), "no such file") {
		t.Fatalf("expected session file read, got %v", err)
	}
}

func TestLiveStoredSessionCredentials(t *testing.T) {
	path := os.Getenv("TUYA_SESSION_TEST_FILE")
	if path == "" {
		t.Skip("opt-in live cookie-only API verification")
	}
	c, err := NewTuyaSmartApiClientFromSession(nil, "protect-us.ismartlife.me", path, "eb9f1d6e677b1b39f222ag")
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{}
	transport := http.DefaultTransport
	c.httpClient.Transport = sessionTransport(func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, "login") {
			return nil, fmt.Errorf("forbidden login endpoint")
		}
		paths = append(paths, r.URL.Path)
		t.Logf("HTTP %s %s cookie_count=%d", r.Method, r.URL.Path, len(r.Cookies()))
		return transport.RoundTrip(r)
	})
	if err := c.initToken(); err != nil {
		t.Fatal(err)
	}
	cfg, err := c.loadWebrtcConfig()
	if err != nil {
		t.Fatal(err)
	}
	hub, err := c.loadHubConfig()
	if err != nil {
		t.Fatal(err)
	}
	evidence := map[string]any{"request_paths": paths, "account_email_empty": c.email == "", "account_password_empty": c.password == "", "auth_present": cfg.Auth != "", "local_key_present": c.localKey != "", "ice_servers": len(cfg.P2PConfig.Ices), "supports_webrtc": cfg.SupportsWebRTC, "mqtt_credentials_present": hub.Password != "", "mqtt_url_present": hub.Url != ""}
	b, _ := json.Marshal(evidence)
	t.Log(string(b))
	if cfg.Auth == "" || !cfg.SupportsWebRTC || hub.Password == "" || len(cfg.P2PConfig.Ices) == 0 {
		t.Fatal("incomplete credentials")
	}
}
