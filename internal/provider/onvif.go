package provider

import (
	"context"
	"errors"
	"fmt"

	"dengan.dev/camera-streamer/internal/models"
	"dengan.dev/camera-streamer/internal/onvif"
)

// ONVIF is a pure passthrough over the existing internal/onvif SOAP client.
//
// It deliberately adds NO camera discovery machinery of its own. The client is
// connection-oriented and stateless (NewClient() just builds an http.Client):
// SOAP calls only exist in the context of credentials for one specific camera,
// which the UI supplies through the unchanged Camera Setup form. There is no
// camera-address book in this program and this milestone does not invent one.
//
// So "Discover" here is the narrow, honest operation the existing client can
// actually perform with a set of credentials: ask that one camera for its media
// profiles and report them as cameras. That is exactly what the old ONVIF-only
// flow did implicitly via POST /api/stream/uri, and it is exposed now so both
// providers answer the same interface.
//
// Streaming is not part of the seam: the caller keeps using the existing
// POST /api/stream/start (or GetStreamUri -> start), which is byte-for-byte the
// pre-milestone behaviour.
type ONVIF struct {
	client *onvif.Client
}

// NewONVIF wraps an existing ONVIF client. A nil client is replaced by the real
// one so the provider is always usable.
func NewONVIF(client *onvif.Client) *ONVIF {
	if client == nil {
		client = onvif.NewClient()
	}
	return &ONVIF{client: client}
}

// Kind reports ONVIF.
func (o *ONVIF) Kind() Kind { return KindONVIF }

// Client exposes the wrapped ONVIF client so the HTTP layer can keep serving the
// existing SOAP endpoints (uri, functest, synchronize, datetime) with the exact
// same instance.
func (o *ONVIF) Client() *onvif.Client { return o.client }

// Cameras lists the media profiles of ONE camera, using the credentials given in
// req. This is a passthrough: it calls the same GetProfiles SOAP request the
// existing /api/stream/uri endpoint calls, and nothing else.
//
// An empty CameraIp means "no camera was offered"; that is reported as an empty
// list rather than an error, because the ONVIF provider has no ambient account
// to enumerate and the UI legitimately calls this before a camera is typed in.
func (o *ONVIF) Cameras(ctx context.Context) ([]Camera, error) {
	return nil, ErrNeedsCredentials
}

// CamerasFor lists the profiles of the camera named by req. It exists as a
// separate method (rather than being folded into Cameras) so the interface
// implementation stays honest about the fact that ONVIF discovery is
// credential-scoped.
func (o *ONVIF) CamerasFor(ctx context.Context, req models.CameraRequest) ([]Camera, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.CameraIp == "" {
		return nil, nil
	}
	if req.CameraPort == "" {
		req.CameraPort = "8000"
	}
	response, err := o.client.GetProfiles(req)
	if err != nil {
		return nil, fmt.Errorf("provider: onvif get profiles: %w", err)
	}
	token, err := onvif.ExtractProfileToken(response)
	if err != nil {
		// A reachable camera that exposes no profile is still a camera the user
		// should see, so fall back to identifying it by address.
		return []Camera{{
			ID:       req.CameraIp,
			Name:     req.CameraIp,
			Provider: KindONVIF,
			Detail:   fmt.Sprintf("%s:%s (no media profile reported)", req.CameraIp, req.CameraPort),
			Online:   true,
		}}, nil
	}
	return []Camera{{
		ID:       token,
		Name:     token,
		Provider: KindONVIF,
		Detail:   fmt.Sprintf("%s:%s", req.CameraIp, req.CameraPort),
		Online:   true,
	}}, nil
}

// StreamURL returns the RTSP URL for a profile token using the existing
// internal/onvif GetStreamUri call. Passthrough: no new SOAP, no behaviour
// change, and the URL is returned exactly as the camera gave it.
func (o *ONVIF) StreamURL(ctx context.Context, req models.CameraRequest, profileToken string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if req.CameraPort == "" {
		req.CameraPort = "8000"
	}
	response, err := o.client.GetStreamUri(req, profileToken)
	if err != nil {
		return "", fmt.Errorf("provider: onvif get stream uri: %w", err)
	}
	uri, err := onvif.ExtractUri(response)
	if err != nil {
		return "", fmt.Errorf("provider: onvif response carried no Uri: %w", err)
	}
	return uri, nil
}

// SetSynchronizationPoint forwards to the existing SOAP call.
func (o *ONVIF) SetSynchronizationPoint(req models.CameraRequest, profileToken string) error {
	return o.client.SetSynchronizationPoint(req, profileToken)
}

// ErrNeedsCredentials is returned by ONVIF.Cameras because ONVIF has no account
// to enumerate: the caller must use CamerasFor with camera credentials.
var ErrNeedsCredentials = errors.New("provider: onvif cameras require camera credentials")
