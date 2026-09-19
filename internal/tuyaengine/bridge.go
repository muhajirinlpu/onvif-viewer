package tuyaengine

import (
	"fmt"
	"os"
	"strings"

	"dengan.dev/camera-streamer/internal/logger"
	"dengan.dev/camera-streamer/internal/models"
)

// StreamStarter is the slice of stream.Manager this package needs. Declaring it
// here keeps tuyaengine free of an import of internal/stream (so tests need no
// manager) while the real *stream.Manager satisfies it directly.
type StreamStarter interface {
	StartStream(profileToken, rtspURL string) (*models.StreamInfo, error)
}

// Bridge wires a supervised Tuya engine to the viewer's existing HLS pipeline.
type Bridge struct {
	engine  *Engine
	starter StreamStarter
}

// NewBridge creates a bridge over an already constructed engine.
func NewBridge(engine *Engine, starter StreamStarter) *Bridge {
	return &Bridge{engine: engine, starter: starter}
}

// StartStream registers the device with the engine, waits for the engine to be
// ready, and then starts the HLS stream through the existing manager using the
// namespaced profile token.
//
// This is the single end-to-end entry point: one call turns a Tuya device into an
// HLS stream served by the viewer's normal pipeline.
func (b *Bridge) StartStream(spec DeviceSpec) (*models.StreamInfo, error) {
	if b == nil || b.engine == nil {
		return nil, fmt.Errorf("tuyaengine: bridge has no engine")
	}
	if b.starter == nil {
		return nil, fmt.Errorf("tuyaengine: bridge has no stream starter")
	}
	rtspURL, token, err := b.engine.AddStream(spec)
	if err != nil {
		return nil, err
	}
	return b.starter.StartStream(token, rtspURL)
}

// Resolve returns the RTSP URL currently served for a device id.
func (b *Bridge) Resolve(deviceID string) (string, error) { return b.engine.Resolve(deviceID) }

// Engine exposes the supervised engine (ports, events, config paths).
func (b *Bridge) Engine() *Engine { return b.engine }

// Stop shuts the engine down and releases its ports.
func (b *Bridge) Stop() { b.engine.Stop() }

// NewBridgeFromEnv builds a bridge from the environment, or returns (nil, nil)
// when no Tuya session is configured.
//
// This is the whole of the process-level wiring: the engine child is started
// lazily by the first StartStream, and an install without
// TUYA_ENGINE_SESSION_FILE never spawns anything.
func NewBridgeFromEnv(starter StreamStarter, log *logger.Logger) (*Bridge, error) {
	session := strings.TrimSpace(os.Getenv(EnvSessionFile))
	if session == "" {
		return nil, nil
	}
	engine := New(DefaultConfig())
	engine.SetEventSink(func(event Event) {
		log.LogInfo("tuya-engine", "engine", event.String())
	})
	return NewBridge(engine, starter), nil
}

// ProfileToken returns the namespaced profile token a device id maps to.
func ProfileToken(deviceID string) (string, error) { return ProfileTokenFor(deviceID) }
