package tuyaqr

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Session is the on-disk Tuya login session. Its JSON shape is byte-compatible
// with the session files written by tuya-ipc-terminal (and therefore with the
// user's existing .tuya-data/user_<region>_<email>.json file): every key and
// nested key is mirrored so that load -> save -> load is lossless.
//
// A legacy "password" key is deliberately NOT modelled: saving a session
// scrubs any stored password. Everything else round-trips.
type Session struct {
	Region      string      `json:"region"`
	Email       string      `json:"email"`
	UserKey     string      `json:"userKey"`
	SessionData UserSession `json:"sessionData"`
	LastRefresh time.Time   `json:"lastRefresh"`
}

// UserSession is the credential-bearing half of the session file.
type UserSession struct {
	LoginResult   *LoginResult `json:"loginResult"`
	Cookies       []*Cookie    `json:"cookies"`
	LastValidated time.Time    `json:"lastValidated"`
	ServerHost    string       `json:"serverHost"`
	Region        string       `json:"region"`
	UserEmail     string       `json:"userEmail"`
}

// LoginResult mirrors the cloud's login payload (big and mostly informational;
// field-for-field so nothing is lost on rewrite).
type LoginResult struct {
	Attribute          int    `json:"attribute"`
	ClientID           string `json:"clientId"`
	DataVersion        int    `json:"dataVersion"`
	Domain             Domain `json:"domain"`
	Ecode              string `json:"ecode"`
	Email              string `json:"email"`
	Extras             Extras `json:"extras"`
	HeadPic            string `json:"headPic"`
	ImproveCompanyInfo bool   `json:"improveCompanyInfo"`
	Nickname           string `json:"nickname"`
	PartnerIdentity    string `json:"partnerIdentity"`
	PhoneCode          string `json:"phoneCode"`
	Receiver           string `json:"receiver"`
	RegFrom            int    `json:"regFrom"`
	SID                string `json:"sid"`
	SnsNickname        string `json:"snsNickname"`
	TempUnit           int    `json:"tempUnit"`
	Timezone           string `json:"timezone"`
	TimezoneID         string `json:"timezoneId"`
	UID                string `json:"uid"`
	UserType           int    `json:"userType"`
	Username           string `json:"username"`
}

// Domain carries the regional service endpoints (MQTT brokers, API hosts).
type Domain struct {
	AispeechHttpsURL    string `json:"aispeechHttpsUrl"`
	AispeechQuicURL     string `json:"aispeechQuicUrl"`
	DeviceHTTPURL       string `json:"deviceHttpUrl"`
	DeviceHttpsPskURL   string `json:"deviceHttpsPskUrl"`
	DeviceHTTPSURL      string `json:"deviceHttpsUrl"`
	DeviceMediaMqttURL  string `json:"deviceMediaMqttUrl"`
	DeviceMediaMqttsURL string `json:"deviceMediaMqttsUrl"`
	DeviceMqttsPskURL   string `json:"deviceMqttsPskUrl"`
	DeviceMqttsURL      string `json:"deviceMqttsUrl"`
	GwAPIURL            string `json:"gwApiUrl"`
	GwMqttURL           string `json:"gwMqttUrl"`
	HTTPPort            int    `json:"httpPort"`
	HTTPSPort           int    `json:"httpsPort"`
	HTTPSPskPort        int    `json:"httpsPskPort"`
	MobileAPIURL        string `json:"mobileApiUrl"`
	MobileMediaMqttURL  string `json:"mobileMediaMqttUrl"`
	MobileMqttURL       string `json:"mobileMqttUrl"`
	MobileMqttsURL      string `json:"mobileMqttsUrl"`
	MobileQuicURL       string `json:"mobileQuicUrl"`
	MqttPort            int    `json:"mqttPort"`
	MqttQuicURL         string `json:"mqttQuicUrl"`
	MqttsPort           int    `json:"mqttsPort"`
	MqttsPskPort        int    `json:"mqttsPskPort"`
	RegionCode          string `json:"regionCode"`
}

// Extras holds assorted account extras.
type Extras struct {
	HomeID    string `json:"homeId"`
	SceneType string `json:"sceneType"`
}

// Cookie is one stored HTTP cookie. It mirrors http.Cookie's JSON encoding.
type Cookie struct {
	Name     string    `json:"name"`
	Value    string    `json:"value"`
	Domain   string    `json:"domain"`
	Path     string    `json:"path"`
	Expires  time.Time `json:"expires"`
	Secure   bool      `json:"secure"`
	HttpOnly bool      `json:"httpOnly"`
}

// regionHosts maps the region label used in session file names to the actual
// Tuya data-centre host. Measured for this account: us-west -> protect-us.
var regionHosts = map[string]string{
	"us-west":    "protect-us.ismartlife.me",
	"us-east":    "protect-us.ismartlife.me",
	"eu-central": "protect-eu.ismartlife.me",
	"eu-west":    "protect-eu.ismartlife.me",
	"cn":         "protect-cn.ismartlife.me",
	"in":         "protect-in.ismartlife.me",
}

// HostForRegion returns the data-centre host for a region label.
func HostForRegion(region string) (string, bool) {
	h, ok := regionHosts[strings.ToLower(strings.TrimSpace(region))]
	return h, ok
}

// DefaultSessionPath returns the conventional session file location for an
// account, matching tuya-ipc-terminal's layout.
func DefaultSessionPath(dir, region, email string) string {
	safe := strings.NewReplacer("@", "_at_", ".", "_").Replace(email)
	return filepath.Join(dir, "user_"+region+"_"+safe+".json")
}

// ServerHost returns the stored host, falling back to the region default.
func (s *Session) ServerHost() string {
	if s == nil {
		return ""
	}
	if s.SessionData.ServerHost != "" {
		return s.SessionData.ServerHost
	}
	if h, ok := HostForRegion(s.SessionData.Region); ok {
		return h
	}
	return ""
}

// Expired reports whether the refresh timestamp is older than maxAge.
// A session's cookies are typically valid far longer (weeks); this is a
// cheap freshness gate, not the authority — only the cloud is. Use Validate
// for a real check.
func (s *Session) Expired(maxAge time.Duration) bool {
	if s == nil || s.LastRefresh.IsZero() {
		return true
	}
	return time.Since(s.LastRefresh) > maxAge
}

// CookieNames returns the names of the stored cookies. Values are never
// exposed here: safe to log.
func (s *Session) CookieNames() []string {
	if s == nil {
		return nil
	}
	names := make([]string, 0, len(s.SessionData.Cookies))
	for _, c := range s.SessionData.Cookies {
		if c != nil {
			names = append(names, c.Name)
		}
	}
	return names
}

// AuthCookieStatus reports which of the two credential cookies (fast-sid,
// s-sid) are present and non-empty. Safe to log; returns only booleans.
func (s *Session) AuthCookieStatus() (fastSID, sSID bool, count int) {
	if s == nil {
		return false, false, 0
	}
	for _, c := range s.SessionData.Cookies {
		if c == nil || c.Value == "" {
			continue
		}
		count++
		switch strings.ToLower(c.Name) {
		case "fast-sid":
			fastSID = true
		case "s-sid":
			sSID = true
		}
	}
	return fastSID, sSID, count
}

// CookieJar builds an http.CookieJar seeded with the stored cookies. The
// cookies are registered for the session's server host. An error is returned
// when the session lacks fast-sid or s-sid, because every authenticated
// endpoint then answers USER_SESSION_LOSS.
func (s *Session) CookieJar() (http.CookieJar, error) {
	if s == nil {
		return nil, ErrNoSession
	}
	host := s.ServerHost()
	if host == "" {
		return nil, fmt.Errorf("%w: session has no serverHost", ErrNoSession)
	}
	fastSID, sSID, n := s.AuthCookieStatus()
	if !fastSID || !sSID {
		return nil, fmt.Errorf("%w: missing fast-sid/s-sid (have %d cookies: %s)",
			ErrNoSession, n, strings.Join(s.CookieNames(), ","))
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	origin := &url.URL{Scheme: "https", Host: host, Path: "/"}
	jar.SetCookies(origin, s.httpCookies())
	return jar, nil
}

// httpCookies converts stored cookies for injection into a jar. Kept
// unexported: it materialises secret values.
func (s *Session) httpCookies() []*http.Cookie {
	out := make([]*http.Cookie, 0, len(s.SessionData.Cookies))
	for _, c := range s.SessionData.Cookies {
		if c == nil || c.Name == "" {
			continue
		}
		hc := &http.Cookie{Name: c.Name, Value: c.Value, Path: c.Path}
		if hc.Path == "" {
			hc.Path = "/"
		}
		// The stored sessions have empty Domain and a zero Expires; leave both
		// unset so net/http associates the cookie with the request host.
		if !c.Expires.IsZero() {
			hc.Expires = c.Expires
		}
		out = append(out, hc)
	}
	return out
}

// LoadSession reads and validates a session file. The file is opened
// read-only and never modified.
func LoadSession(path string) (*Session, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoSession, err)
	}
	var s Session
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("%w: invalid session JSON: %v", ErrNoSession, err)
	}
	if s.SessionData.LoginResult == nil {
		return nil, fmt.Errorf("%w: session has no loginResult", ErrNoSession)
	}
	if _, err := s.CookieJar(); err != nil {
		return nil, err
	}
	return &s, nil
}

// SaveSession writes s to path atomically, mode 0600, inside a 0700 directory.
// It refuses to write a session that cannot be used (missing fast-sid/s-sid).
func SaveSession(path string, s *Session) error {
	if s == nil {
		return errors.New("tuyaqr: nil session")
	}
	if _, err := s.CookieJar(); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// Tighten a pre-existing, more permissive directory.
	_ = os.Chmod(dir, 0o700)

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".session-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
