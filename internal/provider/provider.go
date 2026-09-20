// Package provider is the seam between "how do I discover a camera and get an
// RTSP URL for it" and "how do I turn an RTSP URL into HLS".
//
// It exists so the viewer is no longer ONVIF-only. A Provider knows one camera
// ecosystem (ONVIF/SOAP or Tuya/Smart Life) and does exactly two things:
//
//   - Kind reports which ecosystem it is.
//   - Cameras lists the cameras it can see, in a shape the UI can render
//     without knowing anything about SOAP or the Tuya cloud.
//
// Streaming stays out of the interface on purpose. Both providers ultimately
// hand a plain RTSP URL to the existing (unmodified) stream.Manager; only the
// *Tuya* path additionally needs to register that URL with the Tuya engine
// first, which is a provider-specific extra step exposed as a concrete method
// on *Tuya rather than bolted onto every provider.
//
// Nothing in this package re-implements SOAP or the Tuya cloud protocol: the
// ONVIF provider is a thin adapter over internal/onvif and the Tuya provider a
// thin adapter over internal/tuyaqr + internal/tuyaengine.
package provider

import (
	"context"
	"errors"
	"fmt"

	"dengan.dev/camera-streamer/internal/models"
)

// Kind identifies a camera ecosystem. It is an alias of models.ProviderKind
// rather than a distinct type so a provider kind can be stored straight onto
// models.StreamInfo without a conversion at every boundary.
type Kind = models.ProviderKind

// The supported providers. Values are the exact strings that appear on the wire
// (query parameters, JSON, the stream_configs.provider column).
const (
	KindONVIF Kind = models.ProviderONVIF
	KindTuya  Kind = models.ProviderTuya
)

// ErrUnknownProvider is returned when a caller names a provider that is not
// registered (or is not configured in this process).
var ErrUnknownProvider = errors.New("provider: unknown provider")

// Camera is one discoverable camera, normalised across ecosystems. It carries no
// credentials: safe to serialise straight to an HTTP response.
type Camera struct {
	// ID is stable within a provider. For ONVIF it is the stream profile token;
	// for Tuya it is the cloud device id.
	ID string `json:"id"`
	// Name is a human label. For ONVIF there is no name service call in the
	// existing client, so it is the profile token; for Tuya it is the cloud
	// device name (e.g. "Security Camera").
	Name string `json:"name"`
	// Provider is the owning ecosystem.
	Provider Kind `json:"provider"`
	// Detail is a short, secret-free description for the UI (address, online
	// state, product id). Never contains credentials.
	Detail string `json:"detail,omitempty"`
	// Online is the best-known reachability state. ONVIF cameras are reported
	// online when the profile call succeeded; Tuya cameras report the cloud's
	// own online flag.
	Online bool `json:"online"`
	// Resolution is the camera's STORED video resolution ("sd" or "hd"), so the
	// UI can show the per-camera choice before the camera is started instead of
	// guessing it from a running stream. Empty means the provider does not model
	// resolutions (every ONVIF camera), and the UI then renders no note.
	Resolution string `json:"resolution,omitempty"`
	// ResolutionOptions are the values this camera's provider accepts, so the
	// control is driven by the server rather than by a hardcoded list in the
	// page. Empty means "no resolution choice applies".
	ResolutionOptions []string `json:"resolutionOptions,omitempty"`
}

// Provider lists the cameras of one ecosystem.
type Provider interface {
	// Kind reports the ecosystem this provider serves.
	Kind() Kind
	// Cameras lists every camera this provider can currently see. Context
	// cancellation must be honoured because both implementations do network I/O.
	Cameras(ctx context.Context) ([]Camera, error)
}

// Set is a registry of the providers configured in this process. It is the
// single place the HTTP layer asks "what is available?".
type Set struct {
	byKind map[Kind]Provider
	order  []Kind
}

// NewSet builds a registry. The first provider registered is the default, which
// is how an ONVIF-only install keeps behaving exactly as before.
func NewSet(providers ...Provider) *Set {
	s := &Set{byKind: make(map[Kind]Provider, len(providers))}
	for _, p := range providers {
		if p == nil {
			continue
		}
		if _, dup := s.byKind[p.Kind()]; dup {
			continue
		}
		s.byKind[p.Kind()] = p
		s.order = append(s.order, p.Kind())
	}
	return s
}

// Get returns the provider with the given kind. An empty kind means "the
// default provider", so a legacy caller that never heard of providers gets the
// first registered one (ONVIF).
func (s *Set) Get(kind Kind) (Provider, error) {
	if s == nil || len(s.byKind) == 0 {
		return nil, fmt.Errorf("%w: no providers configured", ErrUnknownProvider)
	}
	if kind == "" {
		return s.defaultProvider(), nil
	}
	p, ok := s.byKind[kind]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownProvider, kind)
	}
	return p, nil
}

// Kinds returns the registered kinds in registration order.
func (s *Set) Kinds() []Kind {
	if s == nil {
		return nil
	}
	out := make([]Kind, len(s.order))
	copy(out, s.order)
	return out
}

// Cameras lists cameras from one provider.
func (s *Set) Cameras(ctx context.Context, kind Kind) ([]Camera, error) {
	p, err := s.Get(kind)
	if err != nil {
		return nil, err
	}
	cams, err := p.Cameras(ctx)
	if err != nil {
		return nil, err
	}
	// A provider must never be able to smuggle a blank kind into the UI.
	for i := range cams {
		cams[i].Provider = p.Kind()
	}
	return cams, nil
}

// CamerasFromAll lists cameras from every registered provider, in registration
// order. A single failing provider does not sink the list: its error is
// returned alongside the cameras that did resolve so the UI can show a partial
// result plus the reason.
func (s *Set) CamerasFromAll(ctx context.Context) ([]Camera, []error) {
	var cams []Camera
	var errs []error
	for _, kind := range s.Kinds() {
		got, err := s.Cameras(ctx, kind)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", kind, err))
			continue
		}
		cams = append(cams, got...)
	}
	return cams, errs
}

func (s *Set) defaultProvider() Provider {
	if p, ok := s.byKind[KindONVIF]; ok {
		return p
	}
	// Fall back to whichever provider was registered first.
	return s.byKind[s.order[0]]
}
