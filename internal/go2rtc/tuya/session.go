package tuya

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
)

// NewTuyaSmartApiClientFromSession imports a tuya-ipc-terminal QR session read-only.
// It never falls back to password login; renew expired sessions in the QR tool.
func NewTuyaSmartApiClientFromSession(httpClient *http.Client, baseURL, sessionFile, deviceID string) (*TuyaSmartApiClient, error) {
	data, err := os.ReadFile(sessionFile)
	if err != nil {
		return nil, err
	}
	var saved struct {
		SessionData struct {
			ServerHost  string         `json:"serverHost"`
			LoginResult LoginResult    `json:"loginResult"`
			Cookies     []*http.Cookie `json:"cookies"`
		} `json:"sessionData"`
	}
	if err := json.Unmarshal(data, &saved); err != nil {
		return nil, errors.New("tuya: invalid stored session JSON")
	}
	session := saved.SessionData
	if session.ServerHost != baseURL {
		return nil, errors.New("tuya: session host differs from requested host")
	}
	c, err := NewTuyaSmartApiClient(nil, baseURL, "", "", deviceID)
	if err != nil {
		return nil, err
	}
	if httpClient != nil {
		clone := *httpClient
		clone.Jar = c.httpClient.Jar
		c.httpClient = &clone
	}
	// Do not send session credentials to a redirected origin.
	c.httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" || req.URL.Host != baseURL {
			return errors.New("tuya: cross-origin session redirect refused")
		}
		if len(via) >= 10 {
			return errors.New("tuya: too many redirects")
		}
		return nil
	}
	origin := &url.URL{Scheme: "https", Host: baseURL, Path: "/"}
	c.httpClient.Jar.SetCookies(origin, session.Cookies)
	found := map[string]bool{}
	for _, cookie := range c.httpClient.Jar.Cookies(origin) {
		found[cookie.Name] = cookie.Value != ""
	}
	if !found["fast-sid"] || !found["s-sid"] {
		return nil, errors.New("tuya: stored session lacks valid fast-sid/s-sid cookies; renew QR login")
	}
	domain := session.LoginResult.Domain
	if domain.MobileMqttsUrl == "" || domain.MqttsPort == 0 {
		return nil, errors.New("tuya: stored session lacks MQTT endpoint")
	}
	c.mqttsUrl = fmt.Sprintf("ssl://%s:%d", domain.MobileMqttsUrl, domain.MqttsPort)
	c.sessionOnly = true
	return c, nil
}
