package tuyaengine

import (
	"fmt"

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
	rtspURL, token, err := b.RegisterStream(spec)
	if err != nil {
		return nil, err
	}
	return b.starter.StartStream(token, rtspURL)
}

// RegisterStream registers the device with the engine and returns the live
// loopback RTSP URL plus the namespaced profile token, WITHOUT starting the
// viewer's HLS pipeline.
//
// It is the NARROW half of StartStream, and it exists for the start-up path: a
// Tuya stream's URL points at our own in-process engine on an ephemeral port, so
// (a) the persisted row carries an EMPTY url and (b) nothing can restore that row
// until the device is registered with THIS process's engine again. Calling
// StartStream to achieve that would be wrong twice over: it would spawn a second
// ffmpeg for a camera that is about to be restored, and it would re-persist a
// stream_configs row that already exists (with an empty URL, which is the new,
// correct value). RegisterStream touches ONLY the engine.
func (b *Bridge) RegisterStream(spec DeviceSpec) (rtspURL, profileToken string, err error) {
	if b == nil || b.engine == nil {
		return "", "", fmt.Errorf("tuyaengine: bridge has no engine")
	}
	return b.engine.AddStream(spec)
}

// Resolve returns the RTSP URL currently served for a device id.
func (b *Bridge) Resolve(deviceID string) (string, error) { return b.engine.Resolve(deviceID) }

// ResolveProfileToken returns the RTSP URL currently served for a namespaced
// profile token ("tuya:<deviceID>"). The stream manager needs this at restore
// time, because the loopback port changes on every start and a stored URL would
// otherwise point at a port the engine no longer owns.
func (b *Bridge) ResolveProfileToken(profileToken string) (string, error) {
	return b.engine.ResolveStream(profileToken)
}

// Engine exposes the supervised engine (ports, events, config paths).
func (b *Bridge) Engine() *Engine { return b.engine }

// Stop shuts the engine down and releases its ports.
func (b *Bridge) Stop() { b.engine.Stop() }

// NewBridgeFromEnv builds a bridge from the environment.
//
// The environment is only consulted for the *engine's* own configuration
// (DefaultConfig) - never to decide whether Tuya exists at all. See
// NewBridgeForSession for why that decision is no longer made here.
func NewBridgeFromEnv(starter StreamStarter, log *logger.Logger) (*Bridge, error) {
	return NewBridgeForSession(starter, log)
}

// NewBridgeForSession builds a bridge over a fresh supervisor engine.
//
// It deliberately NO LONGER takes an "is a Tuya session configured?" flag, and
// that removal is the fix for a MEASURED defect. The flag answered the question
// ONCE, at start-up: when the project database held no `tuya_sessions` row yet
// (the session arrived later, through an import or the periodic cloud refresh),
// the bridge stayed nil for the whole lifetime of the process. The only symptom
// was an opaque "tuya streaming is not configured in this process" at start
// time, with NO warning at boot, and the operator had to restart to fix it.
//
// A bridge is now always constructed. It costs nothing until a stream is
// started: Engine.New allocates no ports, spawns no child and binds no listener
// - the RTSP listener comes up on the first AddStream (see Engine.EnsureRunning).
// A start with no session is refused by the provider, which reads the session
// from the store on every start and answers with the QR-relogin prompt that the
// UI can act on. The net effect is that a session which appears AFTER start-up
// is usable immediately, with no restart.
func NewBridgeForSession(starter StreamStarter, log *logger.Logger) (*Bridge, error) {
	engine := New(DefaultConfig())
	engine.SetEventSink(func(event Event) {
		log.LogInfo("tuya-engine", "engine", event.String())
	})
	return NewBridge(engine, starter), nil
}

// ProfileToken returns the namespaced profile token a device id maps to.
func ProfileToken(deviceID string) (string, error) { return ProfileTokenFor(deviceID) }
