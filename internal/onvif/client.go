package onvif

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"dengan.dev/camera-streamer/internal/models"
)

// CameraFunction defines the type for ONVIF camera functions
type CameraFunction string

// Constants for all supported camera functions
const (
	GetCapabilities       CameraFunction = "GetCapabilities"
	GetDeviceInformation  CameraFunction = "GetDeviceInformation"
	GetProfiles           CameraFunction = "GetProfiles"
	GetStreamUri          CameraFunction = "GetStreamUri"
	GetSnapshotUri        CameraFunction = "GetSnapshotUri"
	GetVideoEncoderConfig CameraFunction = "GetVideoEncoderConfig"
	GetSystemDateAndTime  CameraFunction = "GetSystemDateAndTime"
)

// Client is an ONVIF client
type Client struct {
	httpClient *http.Client
}

// NewClient creates a new ONVIF client
func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{},
	}
}

// ToCameraFunction converts a string to a CameraFunction type
func ToCameraFunction(s string) CameraFunction {
	switch s {
	case string(GetCapabilities):
		return GetCapabilities
	case string(GetDeviceInformation):
		return GetDeviceInformation
	case string(GetProfiles):
		return GetProfiles
	case string(GetStreamUri):
		return GetStreamUri
	case string(GetSnapshotUri):
		return GetSnapshotUri
	case string(GetVideoEncoderConfig):
		return GetVideoEncoderConfig
	case string(GetSystemDateAndTime):
		return GetSystemDateAndTime
	default:
		return ""
	}
}

// URI returns the service URI for a given camera function
func (f CameraFunction) URI() string {
	switch f {
	case GetCapabilities, GetDeviceInformation, GetSystemDateAndTime:
		return "onvif/device_service"
	case GetProfiles, GetStreamUri, GetSnapshotUri, GetVideoEncoderConfig:
		return "onvif/media_service"
	default:
		return ""
	}
}

// Envelope returns the SOAP envelope for a camera function
func (f CameraFunction) Envelope(cam models.CameraRequest, params ...string) string {
	securityHeader := generateSecurityHeader(cam)
	body := ""

	switch f {
	case GetCapabilities:
		body = `<tds:GetCapabilities/>`
	case GetDeviceInformation:
		body = `<tds:GetDeviceInformation/>`
	case GetProfiles:
		body = `<trt:GetProfiles/>`
	case GetStreamUri:
		token := ""
		if len(params) > 0 {
			token = params[0]
		}
		body = fmt.Sprintf(`<trt:GetStreamUri>
			<StreamSetup>
				<Stream xmlns="http://www.onvif.org/ver10/schema">RTP-Unicast</Stream>
				<Transport xmlns="http://www.onvif.org/ver10/schema"><Protocol>RTSP</Protocol></Transport>
			</StreamSetup>
			<ProfileToken>%s</ProfileToken>
		</trt:GetStreamUri>`, token)
	case GetSnapshotUri:
		token := ""
		if len(params) > 0 {
			token = params[0]
		}
		body = fmt.Sprintf(`<trt:GetSnapshotUri><ProfileToken>%s</ProfileToken></trt:GetSnapshotUri>`, token)
	case GetVideoEncoderConfig:
		token := ""
		if len(params) > 0 {
			token = params[0]
		}
		body = fmt.Sprintf(`<trt:GetVideoEncoderConfiguration><ProfileToken>%s</ProfileToken></trt:GetVideoEncoderConfiguration>`, token)
	case GetSystemDateAndTime:
		body = `<tds:GetSystemDateAndTime/>`
	}

	return `
		<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"
			xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
			xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
			xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
			xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
			` + securityHeader + `
			<SOAP-ENV:Body>
				` + body + `
			</SOAP-ENV:Body>
		</SOAP-ENV:Envelope>`
}

// SendRequest sends a SOAP request to the camera
func (c *Client) SendRequest(cam models.CameraRequest, f CameraFunction, token string) (*http.Response, error) {
	url := fmt.Sprintf("http://%s:%s/%s", cam.CameraIp, cam.CameraPort, f.URI())
	envelope := f.Envelope(cam, token)

	req, err := http.NewRequest("POST", url, bytes.NewBufferString(envelope))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/soap+xml; charset=utf-8")

	return c.httpClient.Do(req)
}

// GetProfiles sends a GetProfiles request
func (c *Client) GetProfiles(cam models.CameraRequest) (string, error) {
	resp, err := c.SendRequest(cam, GetProfiles, "")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// GetStreamUri sends a GetStreamUri request
func (c *Client) GetStreamUri(cam models.CameraRequest, profileToken string) (string, error) {
	resp, err := c.SendRequest(cam, GetStreamUri, profileToken)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// GetSystemDateAndTime sends a GetSystemDateAndTime request
func (c *Client) GetSystemDateAndTime(cam models.CameraRequest) (string, error) {
	resp, err := c.SendRequest(cam, GetSystemDateAndTime, "")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// ExtractProfileToken extracts the profile token from a SOAP response
func ExtractProfileToken(soapResponse string) (string, error) {
	parts := strings.Split(soapResponse, `<trt:Profiles token="`)
	if len(parts) > 1 {
		end := strings.Index(parts[1], `"`)
		if end != -1 {
			return parts[1][:end], nil
		}
	}
	return "", fmt.Errorf("no profile token found")
}

// generateNonce creates a random nonce
func generateNonce() string {
	b := make([]byte, 20)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// calculatePasswordDigest calculates the password digest for authentication
func calculatePasswordDigest(nonceBase64, created, password string) string {
	nonce, _ := base64.StdEncoding.DecodeString(nonceBase64)
	createdBytes := []byte(created)
	passwordBytes := []byte(password)

	h := sha1.New()
	h.Write(nonce)
	h.Write(createdBytes)
	h.Write(passwordBytes)
	sha := h.Sum(nil)

	return base64.StdEncoding.EncodeToString(sha)
}

// generateSecurityHeader creates the WS-Security header
func generateSecurityHeader(cam models.CameraRequest) string {
	created := time.Now().UTC().Format(time.RFC3339)
	nonce := generateNonce()
	passwordDigest := calculatePasswordDigest(nonce, created, cam.Password)

	return fmt.Sprintf(`
	<SOAP-ENV:Header>
		<wsse:Security SOAP-ENV:mustUnderstand="1">
			<wsse:UsernameToken>
				<wsse:Username>%s</wsse:Username>
				<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">%s</wsse:Password>
				<wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">%s</wsse:Nonce>
				<wsu:Created>%s</wsu:Created>
			</wsse:UsernameToken>
		</wsse:Security>
	</SOAP-ENV:Header>`, cam.Username, passwordDigest, nonce, created)
}
