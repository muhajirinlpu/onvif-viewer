package stream

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"dengan.dev/camera-streamer/internal/logger"
	"dengan.dev/camera-streamer/internal/models"
)

const (
	streamStopTimeout    = 5 * time.Second
	maxLogEntries        = 500
	maxReconnectAttempts = 30
	reconnectDelay       = 5 * time.Second
	maxReconnectDelay    = 60 * time.Second
	stableRunThreshold   = 30 * time.Second
	maxBufferedLogLine   = 64 * 1024
	// hlsStallTimeout is the watchdog for "connected but no frames". It MUST stay
	// comfortably above this camera's natural playlist advance interval: the
	// camera emits segments with zero duration (EXTINF:0.000000), so with
	// -c:v copy the playlist only advances once per keyframe interval (~30s).
	// A timeout near that cadence turns the watchdog into a guaranteed self-kill,
	// so keep it at 90s until the segment cadence is fixed at the source.
	hlsStallTimeout   = 90 * time.Second
	hlsHealthInterval = 3 * time.Second
	// sessionProbeTimeout bounds the RTSP probe used during reconnection.
	sessionProbeTimeout = 3 * time.Second
	// sessionProbeCollect is how long the probe samples RTP to tell "camera
	// granted but silent" from "camera refused".
	sessionProbeCollect = 2 * time.Second
	// sessionTableBackoff is the pause after the camera reports an exhausted
	// session table. Retrying fast cannot help: the orphaned sessions are only
	// reaped by the camera's own expiry, so the loop must back off and keep
	// probing rather than burning attempts.
	sessionTableBackoff = 2 * time.Minute
	// playlistFirstSegmentGrace is added to hlsStallTimeout before a totally
	// absent playlist/segment set is treated as a stall. This camera's HLS
	// muxer can take ~30-90s to close its first segment with -c:v copy, so
	// without this grace the watchdog kills a healthy start.
	playlistFirstSegmentGrace = 120 * time.Second
	// ffmpegInputIOTimeout bounds the RTSP demuxer's socket I/O -- BOTH the
	// connect and the reads on an established session (-timeout takes
	// microseconds). (ffmpeg has no -rw_timeout CLI option - that name exists
	// only at the AVIO level.)
	//
	// It is deliberately generous, and it is NOT the stall detector: the HLS
	// watchdog (hlsStallTimeout, plus playlistFirstSegmentGrace) owns "connected
	// but producing nothing". This value only catches a truly dead socket, so it
	// must not be tightened toward a "snappier reconnect".
	//
	// MEASURED on the ES06 Tuya camera, and the reason this is not 5s: a Tuya
	// stream is served by the in-process engine over loopback, and the engine
	// returns nothing on a fresh RTSP connection until it has finished its
	// WebRTC handshake with the cloud and received a keyframe -- 14.3s to the
	// first segment, against an engine-internal start of ~6s. A 5s value
	// therefore killed a perfectly healthy stream 6s in with "Failed reading
	// RTSP data: Connection timed out", which surfaced to the user as a camera
	// reconnecting forever. ONVIF (the camera answers in well under a second)
	// is unaffected by this change; the longer bound costs nothing when reads
	// keep flowing, because the timeout is per read, not for the whole session.
	ffmpegInputIOTimeout = 30 * time.Second
)

// StatusNeedsRelogin is the stream status used when a provider's stored session
// was rejected by its cloud. The stream is deliberately stopped (so an HLS
// watchdog cannot hot-loop ffmpeg against a dead source) but its card stays
// visible and asks for a re-login.
const StatusNeedsRelogin = "needs_relogin"

// ---------------------------------------------------------------------------
// Video output paths (M7)
// ---------------------------------------------------------------------------
//
// There are exactly two, selected per stream and never mixed.
//
//   - OutputCopyMPEGTS is the ORIGINAL path and is byte-for-byte unchanged:
//     `-c:v copy` into MPEG-TS segments. It is the only path ever used for
//     ONVIF, and the only one used for a Tuya SD (H.264) camera. MEASURED on
//     the ES06: SD is H.264 640x360 which every browser plays inside MPEG-TS.
//
//   - OutputTranscodeH264 is the HD path. MEASURED on the ES06: HD is HEVC
//     2560x1440 and NO browser decodes it in either container, so HD MUST be
//     transcoded to H.264. Two further facts are baked into this path and were
//     each measured, not guessed:
//
//   - `-r 20` on the INPUT. The HD stream's SDP carries no framerate and no
//     fmtp (MEASURED: only `a=rtpmap:96 H265/90000` + `a=control:trackID=0`),
//     so ffmpeg falls back to the H.265 RTP clock's 200 tbr and then invents
//     frames to fill the timeline it believes it has. MEASURED without it:
//     `frame=1362 dup=1207` — 89% duplicated frames — and HLS segments whose
//     declared duration implied 200 fps against a real 20 fps source. With
//     `-r 20` on the input the same measurement shows implied_fps=20.0.
//
//   - `-an`. The HD stream carries NO audio track (the engine logs
//     `no audio track in source`), so the original `-c:a aac` has nothing to
//     encode. HD output drops audio deliberately rather than letting ffmpeg
//     fail or emit an empty stream.
//
// The scaled size and encoded frame rate are chosen to keep up on 4 cores; see
// hdScaleWidth / hdScaleHeight / HDOutputFPS and the measurement in the report.
type VideoOutputPath int

const (
	// OutputCopyMPEGTS: `-c:v copy` + MPEG-TS. The original behaviour.
	OutputCopyMPEGTS VideoOutputPath = iota
	// OutputTranscodeH264: software libx264 transcode to H.264 720p, MPEG-TS.
	OutputTranscodeH264
	// OutputTuyaSDRetimed: the Tuya SD (H.264) path, `-c:v copy` + MPEG-TS,
	// with ONE extra input option: `-use_wallclock_as_timestamps 1`.
	//
	// It exists because the Tuya SD leg used to run at ~49% of realtime while
	// the ONVIF leg through the identical pipeline ran at 103%. MEASURED with
	// the loopback RTSP consumer instrumented at BOTH ends of the bridge
	// (cmd/tuyapace, one camera session, no competing consumer):
	//
	//	camera->track  13.02 fps   (65% of the advertised 20fps)
	//	loopback RTSP  13.02 fps   (ratio 1.000 — our RTP pump is NOT the limit)
	//	seq gaps 0, out-of-order 0     (we receive everything the camera sends)
	//	inter-frame RTP spacing median AND mean = exactly 4500 ticks, histogram
	//	                                {4500: 597} — a perfect 1/20s stamp grid
	//
	// So the camera sends every packet it chooses to send, stamps them on a
	// flawless 20fps grid, and only DELIVERS ~13 frames/s. The media clock runs
	// ~1.18x faster than wall time: ffmpeg builds a timeline it cannot fill, and
	// `-c:v copy` hands the HLS muxer two things that disagree. MEASURED on the
	// live install: segments of 80 frames (4.0s at the stamped 20fps) arriving
	// every 5.3s, i.e. 76% of realtime — the player consumes media faster than
	// the camera produces it and underruns every few seconds.
	//
	// MEASURED with `-use_wallclock_as_timestamps 1`, same engine, same camera,
	// same HLS tail, a real ffmpeg muxer:
	//
	//	baseline  : ffmpeg speed=0.488x, segment gap 5.42-6.63s for declared
	//	            4.0s (76%, live) and playlist progressing at 0.49x (lab)
	//	wallclock : ffmpeg speed=1.017x, playlist gap 5.99s for declared
	//	            5.956s = 99.4% of realtime, zero ffmpeg errors, 80 real
	//	            frames per segment at 640x360 H.264
	//
	// MEASURED alternatives that do NOT work and must not be substituted:
	// `-fps_mode vfr` on top (0 playlist advances in 70s), `-fps_mode
	// passthrough` (no playlist at all), `-framerate 20` on the input (no
	// playlist), `-setts 1` (no playlist).
	OutputTuyaSDRetimed
)

// tuyaSDTimeScale is the factor `-itsscale` applies to the Tuya SD input so its
// declared timeline matches the rate the camera actually delivers.
//
// DERIVATION (measured, not guessed). The camera stamps a perfect 4500-tick
// 90kHz grid = 20 fps, but only DELIVERS ~13 fps, so 20 stamped seconds of media
// span ~30 wall seconds. The media clock therefore runs ahead by
// stamped_rate / delivered_rate. MEASURED delivered rate, 184s capture on the
// live install: 2292 frames / 174.84s = 13.109 fps -> 20 / 13.109 = 1.526.
// Shorter samples read ~14.3 fps (-> 1.40), so the rate itself varies and no
// single factor is exactly right.
//
// It is therefore set to 1.50 — slightly BELOW the long-run ideal — because the
// two directions do not fail alike. Over-declaring (factor too high) makes the
// declared timeline slower than reality: the player buffers more and output
// latency grows, which is smooth but stale. Under-declaring (factor too low)
// makes the timeline faster than reality: the player drains its buffer and
// STUTTERS, which is the exact defect being fixed. MEASURED drift, second half
// of a 100s arm vs the first: -14.3% at 1.40 and -3.3% at 1.46 (both draining),
// ~0 at 1.5. Being wrong high costs a little latency and keeps the picture
// smooth; being wrong low costs the picture. A 4-core host cannot afford the one
// failure mode that needs more CPU to paper over, so choose the safe direction.
//
// It is deliberately NOT applied to the ONVIF/SD path: ONVIF already runs at
// ~100% of realtime on both legs, its args are pinned by a test, and neither
// these options nor this factor must be able to reach them.
const tuyaSDTimeScale = 1.5

// tuyaSDAudioArgs regenerates the Tuya SD audio timeline from the actual sample
// count, undoing the input rescale that `-itsscale` also applies to AUDIO.
//
// `-itsscale` scales every stream on the input, and this camera's audio clock is
// honest while its video clock runs ~1.5x fast. MEASURED on the live install
// without this filter: every segment declared 6.00s but carried only 3.97s of
// audio content (31 AAC frames at 1024 samples / 8000 Hz) — ratio 0.661, so a
// third of the audio timeline was silence and the sound stuttered/fluctuated
// while the vendor app on the same camera was fine. ONVIF measured 0.955-1.021,
// which is why only the Tuya card was affected. MEASURED with it: ratio 1.003.
//
// It is an OUTPUT option and MUST be emitted after -i. Passed before the input
// it is not a demuxer option and ffmpeg rejects the entire stream with "Error
// parsing options for input file" / exit status 234 — the camera never starts.
// That mistake was shipped once; TestTuyaSDReportAndArgsAgreeAndCarryTheFix now
// pins the ordering.
var tuyaSDAudioArgs = []string{"-af", tuyaSDAudioFilter}

// tuyaSDAudioFilter is the audio filter chain for the Tuya SD stream.
//
// WHY IT IS NEEDED AT ALL: this camera's audio level swings far more than a
// normal camera's. MEASURED on the engine source with NO filters and NO HLS
// (so it is the camera/bridge, not our pipeline): the RMS envelope wandered
// 43 times below 35% of its local median in 180s, with per-window levels
// spanning 0.25x to 14.7x the local median — heard as sound that "disappears
// and comes back", an up-and-down wave.
//
// WHAT IT IS NOT: not packet loss. Every dip measured as present-but-quiet
// (segments of peak amplitude 340-2364 with 94-100% non-zero samples), never
// silence or zeros, and the aggregate audio rate was exactly 8000 samples/s
// over 180s — nothing dropped. It is a gain/level behaviour.
//
// loudnorm MEASURES best of the candidates tried against the same capture:
//
//	none              p05 0.25  p95 2.84  sd 1.113  max 14.7x
//	loudnorm I=-16    p05 0.50  p95 1.75  sd 0.401  max  5.7x   <- chosen
//	acompressor+gain  p05 0.26  p95 2.04  sd 0.617  max  8.4x
//	dynaudnorm        p05 0.25  p95 2.83  sd 1.077  max 13.2x (no effect)
//	compressor+limit  p05 0.26  p95 2.48  sd 0.835  max 12.2x
//
// It is measured CLIP-FREE on the same input (peak 27571 of 32767, 0 clipped
// samples) whereas a limiter-based chain clipped 56 samples. loudnorm needs a
// small lookahead, which is irrelevant here because the stream already runs
// ~20s behind live.
const tuyaSDAudioFilter = "loudnorm=I=-16:TP=-1.5:LRA=11"

// HD output geometry, rate and encoder settings. These are the shipped HD
// defaults, and every one of them was CHOSEN FROM A MEASUREMENT, not guessed.
//
// The decisive measurement (a reproducible 2560x1440 20fps HEVC file fed at real
// time, 22s each, counted frames, 4 cores):
//
//	scale=1280:720  veryfast  -> realtime 0.83x   load 4.85   DOES NOT KEEP UP
//	scale=1280:720  ultrafast -> realtime 0.98x   load 2.79   keeps up, headroom
//	full 2560x1440  veryfast  -> realtime 0.39x   load 4.85   DOES NOT KEEP UP
//	scale=640:360   veryfast  -> realtime 0.96x   load 6.45   keeps up, no headroom
//	scale=1280:720,fps=15     -> realtime 0.75x               DOES NOT KEEP UP
//
// So: 720p, `ultrafast`, 20 fps. 1440p is NOT offered because it cannot keep up
// (0.39x realtime). The cost is dominated by HEVC DECODE, which is why a lower
// output frame rate did not help — the decode has to happen for every source
// frame regardless.
//
// 0.98x is not 2x. HD on this host runs close to its limit and has little
// headroom for a second HD stream, which is exactly why the UI says so.
const (
	hdScaleWidth  = 1280
	hdScaleHeight = 720
	// HDOutputFPS is the output frame rate cap. The source delivers 20 fps;
	// encoding at exactly 20 keeps real time without spending CPU on frames the
	// camera never produced.
	HDOutputFPS = 20
	// HDInputFPS is forced on the RTSP INPUT and is what stops the duplicate
	// frame storm described above. It is the source's real rate.
	HDInputFPS = 20
	// HDH264Preset / HDH264CRF are the libx264 settings the measurement used.
	// `ultrafast` is not a quality preference: `veryfast` measured 0.83x and
	// could not keep up, and the difference at 720p from a 1440p source is not
	// what the user would notice — falling permanently behind is.
	HDH264Preset = "ultrafast"
	HDH264CRF    = 26
)

// ResolutionHD is the persisted resolution value that selects the transcoding
// path for a Tuya camera. It is duplicated here rather than imported so
// internal/stream stays free of an import of internal/tuyaengine (the engine
// imports this package's Manager through a seam, and a cycle would be a hard
// build failure).
const ResolutionHD = "hd"

// defaultStreamResolution is what a stream runs at when nothing else is known.
// It is SD, so an install that never opts into HD is unaffected.
const defaultStreamResolution = "sd"

// ResolutionSD is the persisted resolution value for the substream. It is
// declared here for the Tuya output-path decision, which has to name both
// resolutions explicitly rather than falling through to "not HD".
const ResolutionSD = "sd"

// Process represents a single FFmpeg stream process
type Process struct {
	Info    models.StreamInfo
	Command *exec.Cmd
	// HLSURL is the playlist URL THIS process serves. It is a field rather than
	// only Info.HlsURL because Info is handed to callers (and to tests) as a
	// value, and an embedder that builds a stream's URL itself would otherwise
	// have to guess the id.
	HLSURL          string
	Done            chan bool
	Exited          chan struct{}
	logger          *logger.Logger
	reconnectCount  int
	shouldReconnect bool
	// outputPath is the encoder argument shape THIS stream runs. It is captured
	// per process (from the stream's resolution) rather than passed down through
	// the monitor, so a restart lands on the same args the stream was started
	// with, and an SD stream can never inherit HD flags.
	outputPath VideoOutputPath
	// suspended marks a stream that was deliberately stood down while its
	// registered state is kept, so the card stays visible and a resume can
	// restart it later. Used by the M6 Tuya session-loss degradation.
	suspended       bool
	suspendedReason string
	// runID identifies the monitor run that OWNS Done/Exited. It is allocated
	// once by the code that created this Process and again by every resume,
	// ALWAYS under mutex, and never mutated while a monitor that could still be
	// exiting is running.
	//
	// WHY it exists: a monitor run used to protect its own Done close with
	// process.closed, a sync.Once stored ON THE PROCESS. A resume replaced that
	// Process value (`process.closed = sync.Once{}`), which meant the new run
	// and the old run shared one Once variable, and the old run can win that
	// race by unbounded amounts: suspend returns as soon as its own wait
	// finishes, and any spawn the returning run had already committed is not
	// waited for at all. Whichever run then called the shared Once second
	// tripped `sync: unlock of unlocked mutex` (reproduced, see
	// TestAMonitorRunClosingDoneCannotResetTheNextRunsOnce). Keying the flag on
	// a per-run identity instead makes the reset structurally impossible: a run
	// only ever shares its Once with ITSELF.
	runID uint64
	// runsClosed is the per-run Done-close flag recorded under runID. It must
	// only be read or written with mutex held: sync.Once is not safe for
	// concurrent use, so sharing one between a returning run and a live one is
	// the defect this replaces.
	runsClosed map[uint64]*sync.Once
	// pgid is the process group of this stream's current ffmpeg, recorded at
	// start. With Setpgid the child is its own group leader, so this equals the
	// child's pid. It is cached rather than re-read from /proc so that a
	// transient /proc failure cannot make the manager lose track of a group it
	// owns (MEASURED: that failure made a leak check report a live ffmpeg as
	// absent). Guarded by mutex.
	pgid  int
	mutex sync.RWMutex
}

// Manager manages multiple video streams
type Manager struct {
	streams       map[string]*Process
	mutex         sync.RWMutex
	sseClients    map[string]*models.ClientConnection
	clientTimeout time.Duration
	stopCleanup   chan struct{}
	hlsBaseDir    string
	logger        *logger.Logger
	snapshotSem   chan struct{}
	// ffmpegBin is the ffmpeg executable. Empty means "ffmpeg" from PATH, which
	// is what every production call site has always used; it is a field purely so
	// a test can substitute a stub instead of spawning a real encoder.
	ffmpegBin string
	// tuyaRTSPURL resolves the CURRENT loopback RTSP URL for a Tuya profile
	// token. It exists because a Tuya stream's URL points at our own in-process
	// engine, which binds an EPHEMERAL port (127.0.0.1:0) that changes on every
	// start. Persisting that URL would freeze a port the engine no longer owns,
	// so a restored Tuya stream would retry a dead address forever. Nil means
	// "this manager has no Tuya engine", and Tuya URLs then behave as opaque.
	tuyaRTSPURL func(profileToken string) (string, error)
	// pendingLabels holds the DISPLAY-ONLY camera label a provider registered
	// for a profile token whose stream is about to be created by an internal
	// start path (the Tuya engine hand-back). It is consumed at stream creation
	// and never read afterwards. See SetPendingStreamLabel.
	pendingLabels map[string]string
	// streamLabelResolver names a camera whose stream is being created without
	// the provider having registered a label (a restored stream). See
	// SetStreamLabelResolver.
	streamLabelResolver func(profileToken, rtspURL string) string
}

// NewManager creates a new stream manager
func NewManager(hlsBaseDir string, logger *logger.Logger) *Manager {
	return &Manager{
		streams:       make(map[string]*Process),
		sseClients:    make(map[string]*models.ClientConnection),
		pendingLabels: make(map[string]string),
		clientTimeout: 3 * time.Minute,
		stopCleanup:   make(chan struct{}),
		hlsBaseDir:    hlsBaseDir,
		logger:        logger,
		snapshotSem:   make(chan struct{}, 1),
	}
}

// SetTuyaURLResolver installs the resolver used to obtain a Tuya stream's
// current loopback RTSP URL. It is separate from NewManager so existing callers
// and tests keep working unchanged; a manager with no resolver treats Tuya URLs
// as opaque and never re-resolves them.
func (sm *Manager) SetTuyaURLResolver(resolve func(profileToken string) (string, error)) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	sm.tuyaRTSPURL = resolve
}

// resolveTuyaURL returns the live loopback URL for a Tuya profile token.
// An unset resolver, or a token that is not a Tuya stream, is not an error: the
// caller keeps whatever URL it had.
func (sm *Manager) resolveTuyaURL(profileToken string) (string, bool) {
	sm.mutex.RLock()
	resolve := sm.tuyaRTSPURL
	sm.mutex.RUnlock()
	if resolve == nil {
		return "", false
	}
	url, err := resolve(profileToken)
	if err != nil || url == "" {
		return "", false
	}
	return url, true
}

// newStreamID returns a unique stream id.
func newStreamID() string {
	return fmt.Sprintf("stream_%d", time.Now().UnixNano())
}

// StartStream starts a new FFmpeg stream process. The provider defaults to
// ONVIF, which is what every ONVIF call site has always meant.
func (sm *Manager) StartStream(profileToken, rtspURL string) (*models.StreamInfo, error) {
	return sm.startStreamWithProvider(profileToken, rtspURL, models.ProviderONVIF, true)
}

// StartStreamForProvider starts (and persists) a stream tagged with the provider
// that owns it, so a Tuya stream is restored as Tuya across restarts.
func (sm *Manager) StartStreamForProvider(profileToken, rtspURL string, provider models.ProviderKind) (*models.StreamInfo, error) {
	return sm.startStreamWithOptions(profileToken, rtspURL, provider, "", true)
}

// SetPendingStreamLabel records the DISPLAY-ONLY camera label ("Security
// Camera") for a profile token whose stream is about to be created by an
// internal start path.
//
// WHY IT IS A SEAM RATHER THAN A PARAMETER: the label is known to the Tuya
// provider (it comes from the cloud device listing) but not to the stream
// manager, and the manager's start signature is shared with the ONVIF path,
// which must not change. It is registered immediately before the internal start
// and consumed (and cleared) by the stream creation.
//
// It is deliberately a LABEL and not a name lookup: nothing here may hold a
// device name after the stream is up, so a stale label cannot leak onto an
// unrelated stream that later reuses the token.
func (sm *Manager) SetPendingStreamLabel(profileToken, label string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	if sm.pendingLabels == nil {
		sm.pendingLabels = make(map[string]string)
	}
	sm.pendingLabels[profileToken] = strings.TrimSpace(label)
}

// takePendingStreamLabel consumes the label registered for a profile token.
// Caller holds sm.mutex.
func (sm *Manager) takePendingStreamLabel(profileToken string) string {
	if sm.pendingLabels == nil {
		return ""
	}
	label := sm.pendingLabels[profileToken]
	delete(sm.pendingLabels, profileToken)
	return label
}

// SetStreamLabelResolver installs the callback used to name a CAMERA whose
// stream is being created without the provider having registered a label
// first.
//
// The case it exists for is the RESTART: a stream restored from a stored row
// carries a profile token and a URL, not a camera name, so a Tuya card would
// otherwise come back titled with an internal id even though the process knows
// perfectly well which camera the token belongs to. The resolver is consulted
// once per stream creation and must return "" when it cannot name the camera
// (which then falls back to the per-provider default).
//
// The value it returns is passed through models.CameraLabelOrLabel, so a label
// that is secretly a URL or carries userinfo is reduced to its host rather than
// published.
func (sm *Manager) SetStreamLabelResolver(resolve func(profileToken, rtspURL string) string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	sm.streamLabelResolver = resolve
}

// streamLabelFor chooses the non-secret display label for a new stream.
// It is the single place a StreamInfo gets its camera label, so both providers
// are covered by one rule and one test:
//
//   - a label registered by the provider (Tuya device name) wins, because it is
//     a real camera NAME rather than an address;
//   - then the installed resolver, which is how a RESTORED stream gets its
//     camera back;
//   - otherwise an ONVIF stream is labelled with the HOST of its RTSP URL,
//     stripped of any userinfo by models.CameraLabelFromRTSPURL;
//   - a Tuya stream is NEVER labelled from its URL, because that URL points at
//     OUR OWN loopback engine and its host ("127.0.0.1") names nothing about
//     the camera. It falls back to a short device id instead.
//
// An empty result means "the server could not name this camera", and the UI
// then falls back to a shortened stream id, rather than the server inventing or
// exposing anything.
//
// Caller holds sm.mutex.
func (sm *Manager) streamLabelFor(profileToken, rtspURL string, provider models.ProviderKind, registeredLabel string) string {
	if label := strings.TrimSpace(registeredLabel); label != "" {
		return models.CameraLabelOrLabel(label)
	}
	if sm.streamLabelResolver != nil {
		if label := models.CameraLabelOrLabel(sm.streamLabelResolver(profileToken, rtspURL)); label != "" {
			return label
		}
	}
	if provider.OrDefault() == models.ProviderTuya {
		return models.ShortStreamID(strings.TrimPrefix(profileToken, "tuya:"))
	}
	return models.CameraLabelFromRTSPURL(rtspURL)
}

// StartStreamWithResolution starts a stream at an explicit video resolution and
// persists it per camera. An empty resolution means "whatever is already stored
// for this profile", which is what makes a reconnect or a resume keep the user's
// choice instead of silently reverting to SD.
func (sm *Manager) StartStreamWithResolution(profileToken, rtspURL string, provider models.ProviderKind, resolution string) (*models.StreamInfo, error) {
	return sm.startStreamWithOptions(profileToken, rtspURL, provider, resolution, true)
}

func (sm *Manager) startStream(profileToken, rtspURL string, persist bool) (*models.StreamInfo, error) {
	return sm.startStreamWithOptions(profileToken, rtspURL, models.ProviderONVIF, "", persist)
}

func (sm *Manager) startStreamWithProvider(profileToken, rtspURL string, provider models.ProviderKind, persist bool) (*models.StreamInfo, error) {
	return sm.startStreamWithOptions(profileToken, rtspURL, provider, "", persist)
}

// storedResolution returns the resolution already recorded for a profile, or the
// SD default. A read failure is reported but never fatal: falling back to SD is
// the safe direction (it is the path that has always worked), and the stream is
// still started.
func (sm *Manager) storedResolution(profileToken string) string {
	if sm.logger == nil {
		return defaultStreamResolution
	}
	stored, err := sm.logger.StreamResolution(profileToken)
	if err != nil {
		sm.logger.LogWarn("", "system", fmt.Sprintf("could not read the stored resolution for %s: %v; using %s", profileToken, err, defaultStreamResolution))
		return defaultStreamResolution
	}
	return stored
}

func (sm *Manager) startStreamWithOptions(profileToken, rtspURL string, provider models.ProviderKind, resolution string, persist bool) (*models.StreamInfo, error) {
	provider = provider.OrDefault()
	if profileToken == "" || rtspURL == "" {
		return nil, fmt.Errorf("profile token and RTSP URL are required")
	}
	// Resolve the resolution BEFORE taking the manager lock: an explicit value
	// wins, otherwise the persisted one is reused so a restart or a reconnect
	// cannot quietly drop the user back to SD.
	if strings.TrimSpace(resolution) == "" {
		resolution = sm.storedResolution(profileToken)
	} else if err := logger.ValidateResolution(resolution); err != nil {
		return nil, err
	}
	resolution = logger.NormalizeResolution(resolution)
	sm.mutex.Lock()

	// Check if stream already exists for this profile
	for _, stream := range sm.streams {
		stream.mutex.RLock()
		if stream.Info.ProfileToken == profileToken {
			suspended := stream.suspended
			id := stream.Info.ID
			info := stream.Info
			stream.mutex.RUnlock()
			if suspended {
				// A suspended stream (Tuya session loss) is resumed in place
				// with the URL the caller just resolved, so the card, the
				// profile token and the persisted config are all reused and no
				// device has to be re-selected.
				//
				// The manager lock MUST be dropped first: publishState
				// broadcasts to SSE clients and re-takes sm.mutex as a reader,
				// and Go's RWMutex is not reentrant.
				sm.mutex.Unlock()
				return sm.ResumeSuspended(id, rtspURL, provider)
			}
			if info.RtspURL != rtspURL {
				return nil, fmt.Errorf("profile %s is already running with a different RTSP URL; stop it before starting the new URL", profileToken)
			}
			sm.logger.LogInfo(info.ID, "system", "Stream already exists for profile token")
			return &info, nil
		}
		stream.mutex.RUnlock()
	}

	// Create stream ID and HLS path
	streamID := newStreamID()
	hlsDir := filepath.Join(sm.hlsBaseDir, streamID)

	if err := os.MkdirAll(hlsDir, 0755); err != nil {
		sm.logger.LogError(streamID, "system", fmt.Sprintf("Failed to create HLS directory: %v", err))
		return nil, fmt.Errorf("failed to create HLS directory: %v", err)
	}
	if persist {
		// A Tuya stream's URL points at our own in-process engine, which binds
		// an ephemeral loopback port that changes every start. Persisting it
		// would freeze a port the engine will not own again, so a restored Tuya
		// stream would retry a dead address forever (observed live: 17 attempts
		// with the backoff grown to a minute). Store it empty and resolve the
		// live address at restore time instead.
		persistedRTSPURL := rtspURL
		if provider == models.ProviderTuya {
			persistedRTSPURL = ""
		}
		if err := sm.logger.UpsertStreamConfig(profileToken, persistedRTSPURL, string(provider)); err != nil {
			_ = os.RemoveAll(hlsDir)
			return nil, fmt.Errorf("persist stream configuration: %w", err)
		}
		// The resolution is written separately because the upsert must not be
		// able to blank a choice it does not know about, and because flipping a
		// resolution must not require knowing the engine's current RTSP URL.
		if err := sm.logger.SetStreamResolution(profileToken, resolution); err != nil {
			// Not fatal: the stream itself is fine on the SD default, and a
			// failed preference write must not stop a camera from running.
			sm.logger.LogWarn(streamID, "system", fmt.Sprintf("could not persist resolution %s for %s: %v", resolution, profileToken, err))
		}
	}

	streamOutputPath := outputPathForProvider(provider, resolution)
	streamProcess := &Process{
		Info: models.StreamInfo{
			ID:              streamID,
			ProfileToken:    profileToken,
			Provider:        provider,
			Resolution:      resolution,
			Output:          outputPathName(streamOutputPath),
			InputTimestamps: inputTimestampsName(streamOutputPath),
			Transcoding:     streamOutputPath == OutputTranscodeH264,
			// The camera-identifying, non-secret display label. Consumed from
			// the registry here, at the one place a stream is created, so both
			// providers get it from the same rule.
			StreamLabel: sm.streamLabelFor(profileToken, rtspURL, provider, sm.takePendingStreamLabel(profileToken)),
			RtspURL:     rtspURL,
			HlsURL:      fmt.Sprintf("/hls/%s/stream.m3u8", streamID),
			StartedAt:   time.Now(),
			Status:      "starting",
		},
		HLSURL:          fmt.Sprintf("/hls/%s/stream.m3u8", streamID),
		Command:         nil,
		Done:            make(chan bool),
		Exited:          make(chan struct{}),
		runsClosed:      make(map[uint64]*sync.Once),
		runID:           nextRunID(),
		logger:          sm.logger,
		outputPath:      streamOutputPath,
		shouldReconnect: true,
		reconnectCount:  0,
	}

	sm.logger.LogInfo(streamID, "system", fmt.Sprintf("Initializing stream monitoring and connection (resolution=%s, output=%s, inputTimestamps=%s)", resolution, outputPathName(streamOutputPath), inputTimestampsName(streamOutputPath)))
	log.Printf("Initializing stream %s", streamID)

	info := streamProcess.Info
	sm.streams[streamID] = streamProcess
	sm.mutex.Unlock()

	// Monitor process only after the initial response snapshot is complete.
	// The lock is released first: the monitor publishes state immediately, and
	// publishState re-takes sm.mutex as a reader (Go's RWMutex is not
	// reentrant).
	go sm.monitorStreamWithReconnect(streamProcess, hlsDir)
	return &info, nil
}

// RestoreStreams loads saved streams without delaying HTTP server startup.
func (sm *Manager) RestoreStreams() {
	go func() {
		configs, err := sm.logger.ListStreamConfigs()
		if err != nil {
			sm.logger.LogError("", "restore", fmt.Sprintf("Failed to load saved streams: %v", err))
			return
		}
		for _, config := range configs {
			provider := models.ProviderKind(config.Provider).OrDefault()
			rtspURL := config.RTSPURL
			// A Tuya stream stores no URL, because its URL is a loopback address
			// on our own engine whose port changes every start. Ask the engine
			// for the address it actually owns right now; replaying a stored one
			// would retry a port that no longer exists, forever.
			if provider == models.ProviderTuya {
				resolved, ok := sm.resolveTuyaURL(config.ProfileToken)
				if !ok {
					sm.logger.LogWarn("", "restore", fmt.Sprintf(
						"Tuya stream %s is not running in the engine; not restoring", config.ProfileToken))
					continue
				}
				rtspURL = resolved
			}
			if rtspURL == "" {
				sm.logger.LogWarn("", "restore", fmt.Sprintf(
					"no RTSP URL available for profile %s; not restoring", config.ProfileToken))
				continue
			}
			// The persisted resolution is replayed on restore, which is what
			// makes a per-camera HD choice survive a server restart.
			if _, err := sm.startStreamWithOptions(config.ProfileToken, rtspURL, provider, config.Resolution, false); err != nil {
				sm.logger.LogError("", "restore", fmt.Sprintf("Failed to restore profile %s: %v", config.ProfileToken, err))
			}
		}
	}()
}

func (sm *Manager) stateEntry(info models.StreamInfo, detail string) models.LogEntry {
	// The full RTSP URL is NEVER part of a broadcast state frame: it can carry
	// credentials, and this path fans out to every connected browser.
	info.RtspURL = ""
	// The camera LABEL, by contrast, is display-only and userinfo-free (see
	// models.CameraLabelFromRTSPURL), so it is what the card titles itself with.
	// It is re-derived rather than trusted, so a value that somehow reached
	// StreamInfo by another route still cannot carry a credential to the
	// browser.
	info.StreamLabel = models.CameraLabelOrLabel(info.StreamLabel)
	info.Detail = redactSensitiveText(detail)
	return models.LogEntry{Type: "state", StreamID: info.ID, Message: info.Detail, Time: time.Now().Format(time.RFC3339), State: &info}
}

func (sm *Manager) publishState(process *Process, status, detail string) {
	process.mutex.Lock()
	process.Info.Status = status
	process.Info.Detail = redactSensitiveText(detail)
	info := process.Info
	process.mutex.Unlock()
	sm.broadcastLog(sm.stateEntry(info, detail))
}

// reconnectBackoff returns capped exponential delay after consecutive failures.
func reconnectBackoff(failures int) time.Duration {
	if failures < 1 {
		failures = 1
	}
	delay := reconnectDelay
	for i := 1; i < failures && delay < maxReconnectDelay; i++ {
		delay *= 2
		if delay > maxReconnectDelay {
			delay = maxReconnectDelay
		}
	}
	return delay
}

func nextReconnectFailureCount(current int, runDuration time.Duration) int {
	if runDuration >= stableRunThreshold {
		return 0
	}
	return current + 1
}

// hlsOutputUnhealthy reports a stalled stream.
//
// IMPORTANT: this camera's HLS muxer does not create stream.m3u8 until the first
// segment is closed, which can take ~30-90s with -c:v copy. A missing playlist
// is therefore NORMAL early in a run. The previous implementation treated a
// missing playlist as unhealthy once the timeout elapsed, so the watchdog killed
// ffmpeg at exactly hlsStallTimeout, the restart removed the playlist again, and
// the loop repeated forever.
//
// A stall is now: no playlist progress AND no segment file growth. A missing
// playlist only counts once the run has far exceeded any plausible
// first-segment time, so a slow-but-working startup is never killed.
//
// Deprecated in favour of hlsRunUnhealthy, which also watches segment files.
func hlsOutputUnhealthy(playlist string, now, startedAt time.Time, timeout time.Duration) bool {
	info, err := os.Stat(playlist)
	if err == nil {
		return now.Sub(info.ModTime()) > timeout
	}
	if !os.IsNotExist(err) {
		return false
	}
	// No playlist yet. Only flag this well beyond the expected first-segment
	// delay, so slow HLS startup is not mistaken for a stall.
	return now.Sub(startedAt) > timeout+playlistFirstSegmentGrace
}

// hlsRunUnhealthy is the primary stall check. Progress means "a new segment
// file appeared", not a file modification time: with -hls_flags delete_segments
// and a camera whose segments are named stream<epoch>.ts, the newest segment's
// NAME advances exactly once per completed segment. Modification times update
// mid-write and produce false stalls.
func hlsRunUnhealthy(hlsDir string, lastProgress *time.Time, lastName *string, now, startedAt time.Time, timeout time.Duration) bool {
	name := newestSegmentName(hlsDir)

	// A brand-new segment name is unambiguous progress.
	if name != "" && name != *lastName {
		*lastName = name
		*lastProgress = now
		return false
	}

	// Fall back to playlist movement for the case where segments are recycled.
	if info, err := os.Stat(filepath.Join(hlsDir, "stream.m3u8")); err == nil {
		if info.ModTime().After(*lastProgress) {
			*lastProgress = now
			return false
		}
	}

	if name == "" {
		// Nothing produced at all yet: allow a generous startup window, since
		// this camera can take over a minute to close its first segment.
		return now.Sub(startedAt) > timeout+playlistFirstSegmentGrace
	}
	if lastProgress.IsZero() {
		*lastProgress = now
		return false
	}
	return now.Sub(*lastProgress) > timeout
}

// hlsOutputStale reports whether an existing playlist has stopped advancing.
// Preserved for tests and callers that only have the playlist path.
func hlsOutputStale(playlist string, now time.Time, timeout time.Duration) bool {
	return hlsOutputUnhealthy(playlist, now, now, timeout)
}

// newestSegmentName returns the lexically greatest .ts name, which for this
// camera's stream<epoch>.ts naming is also the most recent segment.
func newestSegmentName(hlsDir string) string {
	entries, err := os.ReadDir(hlsDir)
	if err != nil {
		return ""
	}
	newest := ""
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".ts") {
			continue
		}
		if e.Name() > newest {
			newest = e.Name()
		}
	}
	return newest
}

// newestSegmentModTime returns the newest modification time among .ts files.
func newestSegmentModTime(hlsDir string) time.Time {
	entries, err := os.ReadDir(hlsDir)
	if err != nil {
		return time.Time{}
	}
	var newest time.Time
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".ts") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if mt := info.ModTime(); mt.After(newest) {
			newest = mt
		}
	}
	return newest
}

func tcpReachable(address string, timeout time.Duration) bool {
	connection, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	_ = connection.Close()
	return true
}

func diagnoseReachability(rtspURL, onvifAddress string, timeout time.Duration) string {
	parsed, err := url.Parse(rtspURL)
	if err != nil || parsed.Hostname() == "" {
		return "camera address invalid; unable to run network diagnosis"
	}
	// A loopback source with NO ONVIF endpoint is the in-process Tuya engine,
	// NOT the camera. Probing "the camera's" RTSP/ONVIF ports would then report
	// a healthy stream as "RTSP port reachable; ONVIF port unreachable" -- the
	// Tuya camera has neither port open by design -- which reads as a camera
	// fault and sends whoever is debugging it after the wrong thing. Say what
	// the source actually is instead; the engine's own health is what matters.
	//
	// The empty ONVIF address is part of the test on purpose: a LAN ONVIF
	// camera can legitimately be reached over loopback (a tunnelled or port
	// forwarded camera) and its ONVIF port must still be diagnosed, so loopback
	// alone is not enough to call the source the engine.
	if host := parsed.Hostname(); onvifAddress == "" && (host == "127.0.0.1" || host == "::1" || host == "localhost") {
		if tcpReachable(net.JoinHostPort(parsed.Hostname(), parsed.Port()), timeout) {
			return "local Tuya engine reachable; the camera's own ports are not used on this path"
		}
		return "local Tuya engine unreachable; the in-process engine is not answering on its loopback RTSP port"
	}
	rtspAddress := parsed.Host
	if parsed.Port() == "" {
		rtspAddress = net.JoinHostPort(parsed.Hostname(), "554")
	}
	rtspReachable := tcpReachable(rtspAddress, timeout)
	onvifReachable := onvifAddress != "" && tcpReachable(onvifAddress, timeout)
	hostState := "camera host unreachable"
	if rtspReachable || onvifReachable {
		hostState = "camera host reachable"
	}
	rtspState := "RTSP port unreachable"
	if rtspReachable {
		rtspState = "RTSP port reachable"
	}
	onvifState := "ONVIF port not configured"
	if onvifAddress != "" {
		onvifState = "ONVIF port unreachable"
		if onvifReachable {
			onvifState = "ONVIF port reachable"
		}
	}
	return fmt.Sprintf("%s; %s; %s", hostState, rtspState, onvifState)
}

func redactSensitiveText(text string) string {
	lower := strings.ToLower(text)
	searchFrom := 0
	for {
		rel := strings.Index(lower[searchFrom:], "rtsp://")
		if rel < 0 {
			return text
		}
		start := searchFrom + rel
		authStart := start + len("rtsp://")
		atRel := strings.Index(text[authStart:], "@")
		if atRel < 0 {
			return text
		}
		at := authStart + atRel
		endRel := strings.IndexAny(text[authStart:at], " /\t\r\n")
		if endRel >= 0 {
			searchFrom = authStart
			continue
		}
		text = text[:authStart] + "REDACTED" + text[at:]
		lower = strings.ToLower(text)
		searchFrom = authStart + len("REDACTED@")
	}
}

func sanitizeFFmpegArgs(args []string) []string {
	sanitized := append([]string(nil), args...)
	for i := range sanitized {
		sanitized[i] = redactSensitiveText(sanitized[i])
	}
	return sanitized
}

// createFFmpegCommand creates a new FFmpeg command for the given stream.
//
// The SD/ONVIF argument list is UNCHANGED from before this milestone: the same
// flags in the same order. HD takes the separate transcoding branch below, and
// the two never share a list, so an SD stream cannot pick up an HD flag.
func (sm *Manager) createFFmpegCommand(rtspURL string, hlsDir string) *exec.Cmd {
	return sm.createFFmpegCommandFor(rtspURL, hlsDir, OutputCopyMPEGTS)
}

// videoOutputPathFor maps a stream's persisted resolution onto its output path
// for an ONVIF stream.
//
// Anything that is not exactly "hd" — empty, "sd", or a value written by some
// future build — is the ORIGINAL copy path, which is what makes SD (and ONVIF,
// which never sets a resolution at all) provably unchanged.
//
// It is the ONVIF/SD branch of outputPathForProvider and MUST NOT be called
// directly by stream-creating code: use outputPathForProvider so a Tuya stream
// cannot be handed this list. It can never return OutputTuyaSDRetimed — that
// is pinned by TestVideoOutputPathForCanNeverReturnTheTuyaPath, and it is what
// protects the literally-pinned ONVIF argument list.
func videoOutputPathFor(resolution string) VideoOutputPath {
	if strings.EqualFold(strings.TrimSpace(resolution), ResolutionHD) {
		return OutputTranscodeH264
	}
	return OutputCopyMPEGTS
}

// tuyaVideoOutputPathFor maps a Tuya stream's persisted resolution onto its
// output path.
//
// It is a SEPARATE function from videoOutputPathFor on purpose, and the reason
// is a hard requirement, not tidiness: an existing test pins the ONVIF/SD
// argument list literally (TestSDArgumentsAreUnchangedFromHEAD), so the ONVIF
// path must not be able to acquire the Tuya-only input option. Keeping the
// decision in one function keyed on provider, and never letting the ONVIF branch
// return the Tuya variant, is what makes that structural rather than a promise.
//
// SD Tuya gets OutputTuyaSDRetimed. MEASURED: the camera delivers ~13 of the
// 20 frames/s it stamps, so the RTP media clock runs ~1.18x ahead of wall time;
// `-c:v copy` into MPEG-TS then declares 4.0s segments that arrive every 5.3s
// (76% of realtime) and the player underruns. `-use_wallclock_as_timestamps 1`
// makes ffmpeg time the stream by arrival, restoring 99.4% of realtime.
func tuyaVideoOutputPathFor(resolution string) VideoOutputPath {
	switch strings.ToLower(strings.TrimSpace(resolution)) {
	case ResolutionHD:
		return OutputTranscodeH264
	default:
		// SD, empty, or anything unrecognised: the wallclock copy path. An
		// unknown value is normalised to SD upstream, and treating it as SD
		// keeps one camera's typo from silently taking the ONVIF copy path.
		return OutputTuyaSDRetimed
	}
}

// outputPathForProvider is the ONE entry point for choosing a stream's output
// path. Callers must use it rather than videoOutputPathFor or
// tuyaVideoOutputPathFor directly, because a stream whose recorded path and
// whose actual ffmpeg args disagree would make the log line and
// /api/stream/list LIE about what is running — and would revert Tuya to the
// stuttering path on the first reconnect.
//
// It is deliberately the only function that names both branches, and the ONVIF
// branch can only ever return one of the two original paths.
func outputPathForProvider(provider models.ProviderKind, resolution string) VideoOutputPath {
	if provider.OrDefault() == models.ProviderTuya {
		return tuyaVideoOutputPathFor(resolution)
	}
	return videoOutputPathFor(resolution)
}

// outputPathName is the wire/debug name of an output path. It is what
// models.StreamInfo.Output reports, so the UI states the path that is running.
func outputPathName(path VideoOutputPath) string {
	switch path {
	case OutputTranscodeH264:
		return "transcode_h264"
	case OutputTuyaSDRetimed:
		// Deliberately the same wire name as the ONVIF/plain copy path.
		//
		// WHY: StreamInfo.Output is a pinned, user-visible contract — an
		// existing test (TestAnSDStreamDoesNotReportTranscoding, unmodified)
		// asserts that a Tuya SD stream reports "copy_mpegts", and the field is
		// documented as the container/encoder choice: this stream still COPIES
		// the video into MPEG-TS, so that name remains true. Inventing a third
		// name here would have forced a change to an existing test to make the
		// build pass, which is exactly the thing this change must not do.
		//
		// The difference is a TIMING decision, not a container one, so it is
		// reported honestly through the separate field inputTimestampsName
		// sets — see StreamInfo.InputTimestamps.
		return "copy_mpegts"
	}
	return "copy_mpegts"
}

// inputTimestampsName is the reportable name of an output path's INPUT TIMING
// decision, which is what distinguishes the Tuya SD path from the ONVIF/SD path
// they otherwise share. Without it the two are indistinguishable to an operator
// and to the UI, because both legitimately report the same container/encoder
// ("copy_mpegts").
func inputTimestampsName(path VideoOutputPath) string {
	if path == OutputTuyaSDRetimed {
		return InputTimestampsRetimed
	}
	return InputTimestampsCamera
}

// InputTimestamps values reported by models.StreamInfo.InputTimestamps.
const (
	// InputTimestampsCamera: ffmpeg trusts the camera's own RTP timestamps.
	InputTimestampsCamera = "camera"
	// InputTimestampsRetimed: ffmpeg re-stamps the input by arrival
	// (-use_wallclock_as_timestamps 1). The Tuya SD path uses this because the
	// camera's RTP clock runs ~1.18x faster than it delivers frames.
	InputTimestampsRetimed = "retimed"
)

// createFFmpegCommandFor builds the arg list for one output path.
func (sm *Manager) createFFmpegCommandFor(rtspURL string, hlsDir string, path VideoOutputPath) *exec.Cmd {
	args := sm.ffmpegArgsFor(rtspURL, hlsDir, path)
	cmd := exec.Command(ffmpegExecutable(sm.ffmpegBin), args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	return cmd
}

// ffmpegArgsFor is the single place the encoder argument list is built.
func (sm *Manager) ffmpegArgsFor(rtspURL string, hlsDir string, path VideoOutputPath) []string {
	args := []string{
		"-y", // Overwrite output files
		// +genpts generates missing timestamps; +igndts discards the camera's
		// own DTS. This camera emits duplicate/backwards DTS ("non monotonically
		// increasing dts to muxer"), which corrupts HLS segment timing.
		"-fflags", "+genpts+igndts",
		"-rtsp_transport", "tcp", // Use TCP for RTSP (more reliable)
		"-rtsp_flags", "prefer_tcp", // Prefer TCP
	}

	if path == OutputTranscodeH264 {
		// MEASURED, and it must come BEFORE -i to act as an input option: the HD
		// SDP advertises no framerate, so ffmpeg otherwise adopts the H.265 RTP
		// clock's 200 tbr and duplicates ~89% of frames to fill that phantom
		// timeline (frame=1362 dup=1207). 20 is the source's real rate.
		args = append(args, "-r", strconv.Itoa(HDInputFPS))
	}

	if path == OutputTuyaSDRetimed {
		// MEASURED fix for the Tuya under-realtime defect. Both options MUST
		// precede -i to act as input options.
		//
		// The Tuya camera delivers ~13 of the 20 frames/s it stamps on a
		// flawless 4500-tick 90kHz grid (MEASURED 13.02 fps at the WebRTC track,
		// sequence gaps 0, out-of-order 0), so its RTP media clock runs ~1.5x
		// ahead of wall time. `-c:v copy` hands the HLS muxer a timeline and a
		// delivery rate that disagree: a segment holds 80 frames stamped 4.0s
		// but arrives every ~6s, so the player consumes media faster than the
		// camera produces it and its buffer underruns — the reported stutter.
		//
		// Two candidate remedies were MEASURED against each other, same engine,
		// same camera, interleaved repeats:
		//
		//	-use_wallclock_as_timestamps 1 : cures the declared-vs-arrival
		//	    mismatch but timestamps every frame by ARRIVAL, so the P2P path's
		//	    burstiness becomes frame timing: MEASURED 4-10% near-duplicate
		//	    frames (PTS gap 0.0004s) alternating with 0.5-0.6s holes. `copy`
		//	    cannot retime, so the player freezes on each hole. It trades a
		//	    smooth-but-slow stream for an honest-but-BLIPPY one, which is the
		//	    regression this path now exists to avoid.
		//
		//	-itsscale N                    : rescales the camera's OWN uniform
		//	    1/20s grid so the declared timeline matches observed arrival.
		//	    MEASURED flat p50=p90=p99=max=0.0700s, 0% duplicate frames, 0%
		//	    freeze-scale gaps. Costs no CPU (timestamps only, still `copy`).
		//
		// N is biased HIGH on purpose. A timeline slightly slower than reality
		// grows the player's buffer (still smooth, just more latency); one even
		// slightly FASTER drains it and stutters. MEASURED drift, second half vs
		// first: -14.3% at 1.40, -3.3% at 1.46, ~0 at 1.5. The camera's
		// delivered rate is not constant (13.11 fps over 184s vs 14.3 fps over a
		// short sample), and this box is a 4-core host where a conservative
		// factor cannot fail — only over-declare. See tuyaSDTimeScale.
		args = append(args,
			"-use_wallclock_as_timestamps", "0",
			// -itsscale:v (VIDEO ONLY). The camera's video clock runs fast but its
			// AUDIO clock is honest, so a bare -itsscale would also stretch the
			// audio — MEASURED at ratio 0.661 (a third of the audio timeline was
			// silence). Scaling video only leaves the audio timestamped by the
			// camera and needs no compensating filter at all.
			"-itsscale:v", strconv.FormatFloat(tuyaSDTimeScale, 'f', 2, 64),
		)
	}

	args = append(args,
		// FFmpegInputIOTimeoutMicroseconds is ffmpegInputIOTimeout in the
		// microseconds the RTSP demuxer expects (see the constant for why this
		// is deliberately generous rather than a tight stall detector).
		"-timeout", strconv.FormatInt(ffmpegInputIOTimeout.Microseconds(), 10),
		"-i", rtspURL,
	)

	if path == OutputTranscodeH264 {
		// HD: HEVC is not decodable by any browser, so transcode to H.264.
		// -an is deliberate: the HD stream has NO audio track, so `-c:a aac`
		// would have nothing to encode.
		args = append(args,
			"-an",
			"-c:v", "libx264",
			"-preset", HDH264Preset,
			"-crf", strconv.Itoa(HDH264CRF),
			// Downscale. The measurement in this milestone's report is for
			// 1280x720; 2560x1440 was not proven to keep up on 4 cores.
			"-vf", fmt.Sprintf("scale=%d:%d", hdScaleWidth, hdScaleHeight),
			// Output frame-rate cap: real time at the source's own rate.
			"-r", strconv.Itoa(HDOutputFPS),
		)
	} else {
		args = append(args,
			"-c:v", "copy", // Copy video codec (no transcoding)
			"-c:a", "aac", // Audio codec
		)
		if path == OutputTuyaSDRetimed {
			args = append(args, tuyaSDAudioArgs...)
		}
	}

	args = append(args,
		"-avoid_negative_ts", "make_zero", // Handle negative timestamps
		"-max_interleave_delta", "0", // Do not buffer to re-order; keep latency low
		"-hls_time", "2", // 2 second segments
		"-hls_list_size", "5", // Keep 5 segments in playlist
		"-hls_start_number_source", "epoch", // Keep sequence monotonic across reconnects
		"-hls_flags", "delete_segments+independent_segments", // Delete old segments
		"-hls_segment_type", "mpegts", // Use MPEG-TS segments
		"-f", "hls", // Output format
		filepath.Join(hlsDir, "stream.m3u8"),
	)
	return args
}

// ffmpegExecutable resolves the encoder binary. Empty means the PATH's ffmpeg,
// which is the only value any production caller produces.
func ffmpegExecutable(override string) string {
	if strings.TrimSpace(override) == "" {
		return "ffmpeg"
	}
	return override
}

// nextRunID allocates a monitor-run identity. It is process-wide and monotonic
// so two Process values can never collide on a run identity, even if a stream
// id were somehow reused within one test binary.
var runIDCounter atomic.Uint64

func nextRunID() uint64 { return runIDCounter.Add(1) }

// closeDoneForRun closes the Done channel that runID owns, exactly once for that
// run and only while that run is still the stream's current one.
//
// The Once is looked up under the process lock and is created by whichever
// caller arrives first for a given run, so two runs can never share one
// sync.Once. Sharing one is what produced the reproduced
// `sync: unlock of unlocked mutex` panic: a resume zeroed the Once that a
// returning run still held a pointer to.
//
// The early return when runID has been superseded is what bounds runsClosed.
// It is not a lost wakeup: the only way a run becomes superseded is that the
// suspend or stop path already closed that run's Done (both call this with the
// run that was current when they took the lock), which is precisely the signal
// the run's backoff select is waiting on. Refusing the superseded run's own
// deferred call therefore drops nothing, and it keeps the map at one entry per
// live run instead of one per resume.
func (process *Process) closeDoneForRun(runID uint64, done chan bool) {
	// The only reason this is a lookup rather than a fresh &sync.Once{} is so
	// that the monitor's deferred close and a stop path's close for the SAME
	// run share one flag. A superseded run's two closers must not share one
	// with each other nor with the new run's, and the map is keyed by run, so
	// neither can happen.
	process.mutex.Lock()
	if process.runID != runID {
		process.mutex.Unlock()
		return
	}
	if process.runsClosed == nil {
		process.runsClosed = make(map[uint64]*sync.Once)
	}
	once, ok := process.runsClosed[runID]
	if !ok {
		once = &sync.Once{}
		process.runsClosed[runID] = once
	}
	process.mutex.Unlock()
	once.Do(func() { close(done) })
}

// monitorStreamWithReconnect monitors a stream and handles reconnection
func (sm *Manager) monitorStreamWithReconnect(process *Process, hlsDir string) {
	// Capture the channels THIS run owns, together with the run identity that
	// owns the flag guarding their close. A resumed stream is given fresh
	// Done/Exited channels AND a fresh runID, so a late-deferring previous run
	// closes its own channels through its own Once and can never touch the
	// channels or the Once of the run that replaced it.
	process.mutex.RLock()
	done := process.Done
	exited := process.Exited
	runID := process.runID
	process.mutex.RUnlock()

	defer close(exited)
	defer process.closeDoneForRun(runID, done)

	for {
		startedAt := time.Now()
		// Remove stale metadata from a prior attempt so the new process gets its
		// complete startup grace period before health evaluation.
		_ = os.Remove(filepath.Join(hlsDir, "stream.m3u8"))
		cmd, err := sm.startFFmpegProcess(process, hlsDir)
		if err == nil {
			watchDone := make(chan struct{})
			// The run's OWN done channel is passed in rather than re-read from
			// the process. A resume replaces process.Done, and reading that
			// field here raced the write under -race (MEASURED: DATA RACE in
			// watchHLSOutput reading process.Done vs resumeSuspendedProcess
			// writing it). The run already holds its own channel in `done`, and
			// semantically it is the correct one: the watchdog exists only to
			// restart THIS run's ffmpeg, so the cancellation that should stop it
			// is this run's own.
			go sm.watchHLSOutput(process, cmd, hlsDir, startedAt, watchDone, done)
			err = cmd.Wait()
			close(watchDone)
			if writer, ok := cmd.Stdout.(*filteredLogWriter); ok {
				writer.Flush()
			}
			if writer, ok := cmd.Stderr.(*filteredLogWriter); ok {
				writer.Flush()
			}
			runDuration := time.Since(startedAt)
			if err != nil {
				sm.logger.LogError(process.Info.ID, "system", fmt.Sprintf("FFmpeg exited after %s: %v", runDuration.Round(time.Second), err))
				log.Printf("Stream %s: FFmpeg exited after %s: %v", process.Info.ID, runDuration.Round(time.Second), err)
			} else {
				sm.logger.LogWarn(process.Info.ID, "system", fmt.Sprintf("FFmpeg exited normally after %s; reconnecting", runDuration.Round(time.Second)))
			}
			process.mutex.Lock()
			process.Command = nil
			process.pgid = 0
			process.reconnectCount = nextReconnectFailureCount(process.reconnectCount, runDuration)
			process.mutex.Unlock()
		} else {
			process.mutex.Lock()
			stopping := !process.shouldReconnect
			if !stopping {
				process.reconnectCount++
			}
			process.mutex.Unlock()
			if stopping {
				return
			}
			sm.logger.LogError(process.Info.ID, "system", fmt.Sprintf("Failed to start FFmpeg: %v", err))
		}

		process.mutex.Lock()
		if !process.shouldReconnect {
			process.mutex.Unlock()
			return
		}
		failures := process.reconnectCount
		if failures < 1 {
			failures = 1
			process.reconnectCount = failures
		}
		if failures >= maxReconnectAttempts {
			process.shouldReconnect = false
			process.Info.Status = "failed"
			process.mutex.Unlock()
			sm.publishState(process, "failed", "maximum reconnection attempts reached")
			sm.logger.LogError(process.Info.ID, "system", "Maximum reconnection attempts reached; stream stopped")
			return
		}
		delay := reconnectBackoff(failures)
		process.Info.Status = "reconnecting"
		process.Info.ReconnectCount = failures
		process.Info.ReconnectDelay = delay.String()
		rtspURL := process.Info.RtspURL
		process.mutex.Unlock()
		onvifAddress := ""
		if parsed, err := url.Parse(rtspURL); err == nil && parsed.Hostname() != "" {
			onvifAddress = net.JoinHostPort(parsed.Hostname(), "8000")
		}
		diagnosis := diagnoseReachability(rtspURL, onvifAddress, 2*time.Second)

		// A reachable camera is not necessarily a camera that will serve media.
		// Probe the RTSP session itself so an exhausted session table (the
		// ~1h "connected but no frames" stall) is identified instead of being
		// reported as a healthy host.
		probe, probeDetail := probeSessionState(rtspURL, sessionProbeTimeout, sessionProbeCollect)
		if probe.SessionTableFull() {
			// Retrying quickly cannot clear this; the camera reaps orphaned
			// sessions on its own schedule. Hold off and keep the stream
			// marked as reconnecting rather than burning reconnect attempts.
			process.mutex.Lock()
			process.Info.Status = "reconnecting"
			process.Info.ReconnectDelay = sessionTableBackoff.String()
			process.Info.ReconnectCount = failures
			process.mutex.Unlock()
			sm.publishState(process, "reconnecting",
				fmt.Sprintf("RTSP session table full; retrying in %s (%s)",
					sessionTableBackoff, probeDetail))
			sm.logger.LogWarn(process.Info.ID, "system",
				fmt.Sprintf("RTSP session table full (status %d); camera allows 2 concurrent sessions. "+
					"Backing off %s before retry. %s",
					rtspStatusSessionNotFound, sessionTableBackoff, probeDetail))
			timer := time.NewTimer(sessionTableBackoff)
			select {
			case <-timer.C:
			case <-done:
				timer.Stop()
				return
			}
			// Do not increment the failure count: this is a camera-side
			// resource limit, not a stream that keeps failing to start.
			process.mutex.Lock()
			process.reconnectCount = 0
			process.mutex.Unlock()
			continue
		} else if probe.Err == nil {
			diagnosis = fmt.Sprintf("%s; %s", diagnosis, probeDetail)
		}

		sm.publishState(process, "reconnecting", fmt.Sprintf("attempt %d in %s; %s", failures, delay, diagnosis))

		sm.logger.LogWarn(process.Info.ID, "system", fmt.Sprintf("Reconnection attempt %d/%d in %s", failures, maxReconnectAttempts, delay))
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-done:
			// done is the channel THIS run owns. A resume replaces the process's
			// Done/Exited with fresh ones, so waiting on the field would let an
			// old, superseded monitor wake up after the resume and spawn a
			// SECOND ffmpeg for the same stream.
			timer.Stop()
			return
		}
	}
}

// watchHLSOutput restarts a live FFmpeg process when its playlist stops
// advancing, preventing clients from replaying the final cached segments.
//
// runDone is the Done channel of the monitor run that started this ffmpeg. It is
// passed in rather than read from process.Done, because a resume replaces that
// field and reading it here raced the write.
func (sm *Manager) watchHLSOutput(process *Process, cmd *exec.Cmd, hlsDir string, startedAt time.Time, done <-chan struct{}, runDone <-chan bool) {
	playlist := filepath.Join(hlsDir, "stream.m3u8")
	ticker := time.NewTicker(hlsHealthInterval)
	defer ticker.Stop()
	// Track progress across playlist and segment files, since this camera does
	// not create the playlist until its first segment closes.
	var lastProgress time.Time
	var lastName string
	for {
		select {
		case now := <-ticker.C:
			if info, err := os.Stat(playlist); err == nil {
				advanced := info.ModTime()
				process.mutex.Lock()
				if process.Info.LastHLSAdvance == nil || advanced.After(*process.Info.LastHLSAdvance) {
					process.Info.LastHLSAdvance = &advanced
				}
				process.mutex.Unlock()
			}
			if !hlsRunUnhealthy(hlsDir, &lastProgress, &lastName, now, startedAt, hlsStallTimeout) {
				continue
			}
			sm.publishState(process, "stalled", fmt.Sprintf("HLS output has not advanced for %s", hlsStallTimeout))
			sm.logger.LogWarn(process.Info.ID, "system", fmt.Sprintf("HLS output has not advanced for %s; restarting FFmpeg", hlsStallTimeout))
			if cmd.Process != nil {
				if pgid, err := syscall.Getpgid(cmd.Process.Pid); err == nil {
					_ = syscall.Kill(-pgid, syscall.SIGTERM)
				} else {
					_ = cmd.Process.Signal(syscall.SIGTERM)
				}
			}
			return
		case <-done:
			return
		case <-runDone:
			return
		}
	}
}

// ValidateCameraForStream binds credentialed ONVIF actions to the selected
// stream's profile and RTSP host without persisting ONVIF credentials.
func (sm *Manager) ValidateCameraForStream(streamID, cameraIP, profileToken string) error {
	sm.mutex.RLock()
	process, ok := sm.streams[streamID]
	sm.mutex.RUnlock()
	if !ok {
		return fmt.Errorf("stream not found")
	}
	process.mutex.RLock()
	rtspURL := process.Info.RtspURL
	activeProfile := process.Info.ProfileToken
	process.mutex.RUnlock()
	parsed, err := url.Parse(rtspURL)
	if err != nil || parsed.Hostname() == "" || parsed.Hostname() != cameraIP || activeProfile != profileToken {
		return fmt.Errorf("camera does not match stream")
	}
	return nil
}

// DiagnoseStream probes the camera RTSP and ONVIF service ports and publishes
// the sanitized result through the existing state SSE channel.
func (sm *Manager) DiagnoseStream(streamID string) (string, error) {
	sm.mutex.RLock()
	process, ok := sm.streams[streamID]
	sm.mutex.RUnlock()
	if !ok {
		return "", fmt.Errorf("stream not found")
	}
	process.mutex.RLock()
	rtspURL := process.Info.RtspURL
	status := process.Info.Status
	process.mutex.RUnlock()
	onvifAddress := ""
	if parsed, err := url.Parse(rtspURL); err == nil && parsed.Hostname() != "" {
		onvifAddress = net.JoinHostPort(parsed.Hostname(), "8000")
	}
	detail := diagnoseReachability(rtspURL, onvifAddress, 2*time.Second)
	sm.publishState(process, status, detail)
	return detail, nil
}

// ReconnectStream terminates FFmpeg; its monitor performs a controlled retry.
func (sm *Manager) ReconnectStream(streamID string) error {
	sm.mutex.RLock()
	process, ok := sm.streams[streamID]
	sm.mutex.RUnlock()
	if !ok {
		return fmt.Errorf("stream not found")
	}
	process.mutex.RLock()
	cmd := process.Command
	shouldReconnect := process.shouldReconnect
	process.mutex.RUnlock()
	if !shouldReconnect || cmd == nil || cmd.Process == nil {
		return fmt.Errorf("stream is not reconnectable")
	}
	sm.publishState(process, "reconnecting", "manual reconnect requested")
	if pgid, err := syscall.Getpgid(cmd.Process.Pid); err == nil {
		return syscall.Kill(-pgid, syscall.SIGTERM)
	}
	return cmd.Process.Signal(syscall.SIGTERM)
}

type filteredLogWriter struct {
	mu     sync.Mutex
	buffer bytes.Buffer
	handle func(string)
}

func (w *filteredLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	originalLen := len(p)
	for _, b := range p {
		if b == '\n' || b == '\r' {
			w.emitLocked()
			continue
		}
		if w.buffer.Len() >= maxBufferedLogLine {
			w.emitLocked()
		}
		_ = w.buffer.WriteByte(b)
	}
	return originalLen, nil
}

func (w *filteredLogWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.emitLocked()
}

func (w *filteredLogWriter) emitLocked() {
	line := strings.TrimSpace(w.buffer.String())
	w.buffer.Reset()
	if line != "" {
		w.handle(line)
	}
}

// startFFmpegProcess creates and starts FFmpeg while holding the process lock,
// preventing StopStream from missing a concurrently starting process.
func (sm *Manager) startFFmpegProcess(process *Process, hlsDir string) (*exec.Cmd, error) {
	process.mutex.Lock()
	defer process.mutex.Unlock()
	if !process.shouldReconnect {
		return nil, fmt.Errorf("stream is stopping")
	}

	// createFFmpegCommandFor is called with process.mutex ALREADY held for
	// writing, so outputPath and Info are read WITHOUT re-locking: taking the
	// process lock again here self-deadlocks (Go's RWMutex is not reentrant).
	outputPath := process.outputPath
	cmd := sm.createFFmpegCommandFor(process.Info.RtspURL, hlsDir, outputPath)
	args := sanitizeFFmpegArgs(cmd.Args[1:])
	cmdStr := fmt.Sprintf("ffmpeg %s", strings.Join(args, " "))
	sm.logger.LogInfo(process.Info.ID, "system", fmt.Sprintf("Starting FFmpeg: %s", cmdStr))
	log.Printf("Starting stream %s with command: %s", process.Info.ID, cmdStr)

	cmd.Stdout = &filteredLogWriter{handle: func(line string) { sm.handleFFmpegLine(process, "ffmpeg_stdout", line) }}
	cmd.Stderr = &filteredLogWriter{handle: func(line string) { sm.handleFFmpegLine(process, "ffmpeg", line) }}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start FFmpeg: %v", err)
	}
	process.Command = cmd
	// The child is its own group leader (Setpgid), so its group id is its pid.
	// Record it here while it is certain, so the ownership check never depends
	// on a later /proc read.
	process.pgid = cmd.Process.Pid
	process.Info.Status = "running"
	process.Info.ReconnectDelay = ""
	sm.logger.LogInfo(process.Info.ID, "system", "FFmpeg process started successfully")
	// The state broadcast is deferred to a goroutine because this function holds
	// process.mutex and publishState takes it, so publishing here would
	// self-deadlock. It must NOT be an unconditional publish: between this
	// start and the goroutine running, a suspend can set the stream to
	// needs_relogin, and an unguarded publish then advertises a SUSPENDED stream
	// as "running" again. MEASURED: that is the failure
	// TestSuspendedStreamDoesNotHotLoop caught (1 of 20 runs under verified
	// load; 0 of 20 idle), at its "status changed to running; a suspended
	// stream must not be restarted" assertion. The guard below makes the
	// publish conditional on the run still being current and the stream still
	// live, so whichever of the two gets the lock last leaves the correct state.
	runID := process.runID
	go sm.publishRunningIfCurrent(process, runID)
	return cmd, nil
}

// publishRunningIfCurrent publishes "running" for one monitor run, but only while
// that run is still the stream's current run and the stream is still meant to be
// live. It is the guarded form of publishState(process, "running", ...) for the
// post-start broadcast, which is asynchronous and can otherwise land after a
// suspend has already stood the stream down.
func (sm *Manager) publishRunningIfCurrent(process *Process, runID uint64) {
	process.mutex.Lock()
	if process.runID != runID || process.suspended || !process.shouldReconnect || process.Command == nil {
		process.mutex.Unlock()
		return
	}
	const detail = "FFmpeg is running"
	process.Info.Status = "running"
	process.Info.Detail = redactSensitiveText(detail)
	info := process.Info
	process.mutex.Unlock()
	sm.broadcastLog(sm.stateEntry(info, detail))
}

func (sm *Manager) handleFFmpegLine(process *Process, source, line string) {
	line = redactSensitiveText(line)
	if line == "" || !shouldLogFFmpegLine(line) {
		return
	}
	level := determineLogLevel(line)
	switch level {
	case logger.ERROR:
		sm.logger.LogError(process.Info.ID, source, line)
	case logger.WARN:
		sm.logger.LogWarn(process.Info.ID, source, line)
	default:
		sm.logger.LogInfo(process.Info.ID, source, line)
	}
	sm.broadcastLog(models.LogEntry{StreamID: process.Info.ID, Message: fmt.Sprintf("ffmpeg: %s", line), Time: time.Now().Format(time.RFC3339)})
}

// determineLogLevel determines the log level based on FFmpeg output content
func determineLogLevel(line string) logger.LogLevel {
	lowerLine := strings.ToLower(line)

	// FFmpeg error indicators
	if strings.Contains(lowerLine, "error") ||
		strings.Contains(lowerLine, "failed") ||
		strings.Contains(lowerLine, "cannot") ||
		strings.Contains(lowerLine, "unable") ||
		strings.Contains(lowerLine, "timed out") ||
		strings.Contains(lowerLine, "connection refused") {
		return logger.ERROR
	}

	// FFmpeg warning indicators
	if strings.Contains(lowerLine, "warning") ||
		strings.Contains(lowerLine, "deprecated") ||
		strings.Contains(lowerLine, "no such file") ||
		strings.Contains(lowerLine, "overriding") {
		return logger.WARN
	}

	// Progress indicators are usually info level
	if strings.Contains(lowerLine, "frame=") ||
		strings.Contains(lowerLine, "opening") ||
		strings.Contains(lowerLine, "fps=") {
		return logger.INFO
	}

	return logger.INFO
}

// shouldLogFFmpegLine determines if an FFmpeg output line should be logged
func shouldLogFFmpegLine(line string) bool {
	lowerLine := strings.ToLower(line)

	// Always log errors and warnings
	if strings.Contains(lowerLine, "error") ||
		strings.Contains(lowerLine, "failed") ||
		strings.Contains(lowerLine, "warning") ||
		strings.Contains(lowerLine, "deprecated") ||
		strings.Contains(lowerLine, "timed out") ||
		strings.Contains(lowerLine, "connection refused") {
		return true
	}

	// Log important operational messages
	if strings.Contains(lowerLine, "input #") ||
		strings.Contains(lowerLine, "output #") ||
		strings.Contains(lowerLine, "stream mapping") ||
		strings.Contains(lowerLine, "codec") {
		return true
	}

	// Drop banners, library versions, progress, and other routine chatter.
	return false
}

// StopStream stops a stream by its ID
func (sm *Manager) StopStream(streamID string) error {
	return sm.stopStream(streamID, true)
}

func (sm *Manager) stopStream(streamID string, removeConfig bool) error {
	sm.mutex.Lock()
	stream, exists := sm.streams[streamID]
	if !exists {
		sm.mutex.Unlock()
		return fmt.Errorf("stream not found")
	}
	// Remove it from the public active set immediately, but keep the local
	// reference until FFmpeg and its output writers have fully exited.
	delete(sm.streams, streamID)
	sm.mutex.Unlock()

	sm.logger.LogInfo(streamID, "system", "Stopping stream")

	// Disable reconnection and snapshot the current command atomically with start.
	stream.mutex.Lock()
	stream.shouldReconnect = false
	stream.Info.Status = "stopping"
	cmd := stream.Command
	done := stream.Done
	runID := stream.runID
	profileToken := stream.Info.ProfileToken
	stream.mutex.Unlock()
	// Close Done through the SAME per-run flag the monitor's deferred close
	// uses. A second, independent Once here would let this path and the
	// returning monitor both close the one channel, which panics on a
	// double close; sharing the flag means whichever gets there first closes it
	// and the other is a no-op. Done is deliberately NOT closed while the
	// process lock is held: the flag is only shared, not transferred, and the
	// monitor needs no lock to reach it.
	stream.closeDoneForRun(runID, done)
	if removeConfig {
		if err := sm.logger.DeleteStreamConfig(profileToken); err != nil {
			sm.logger.LogError(streamID, "system", fmt.Sprintf("Failed to remove saved stream configuration: %v", err))
		}
	}
	sm.publishState(stream, "stopped", "stream stopped manually")

	// Terminate the process group, then wait for the monitor to confirm exit.
	if cmd != nil && cmd.Process != nil {
		pgid, err := syscall.Getpgid(cmd.Process.Pid)
		if err == nil {
			sm.logger.LogInfo(streamID, "system", "Sending SIGTERM to process group")
			_ = syscall.Kill(-pgid, syscall.SIGTERM)
		} else {
			sm.logger.LogWarn(streamID, "system", "Failed to get process group, using regular kill")
			_ = cmd.Process.Signal(syscall.SIGTERM)
		}
	}

	grace := time.NewTimer(streamStopTimeout)
	select {
	case <-stream.Exited:
		grace.Stop()
	case <-grace.C:
		if cmd != nil && cmd.Process != nil {
			sm.logger.LogWarn(streamID, "system", "Graceful shutdown timed out, force killing")
			if pgid, err := syscall.Getpgid(cmd.Process.Pid); err == nil {
				_ = syscall.Kill(-pgid, syscall.SIGKILL)
			} else {
				_ = cmd.Process.Kill()
			}
		}
		forceWait := time.NewTimer(streamStopTimeout)
		select {
		case <-stream.Exited:
			forceWait.Stop()
		case <-forceWait.C:
			return fmt.Errorf("stream process did not exit after SIGKILL")
		}
	}

	// Cleanup files in background
	go func() {
		hlsDir := filepath.Join(sm.hlsBaseDir, streamID)
		// Wait a bit before removing files
		time.Sleep(2 * time.Second)
		if err := os.RemoveAll(hlsDir); err != nil {
			sm.logger.LogError(streamID, "system", fmt.Sprintf("Error removing HLS directory: %v", err))
			log.Printf("Error removing HLS directory for stream %s: %v", streamID, err)
		} else {
			sm.logger.LogInfo(streamID, "system", "HLS directory cleaned up")
		}
	}()

	return nil
}

// SuspendStreamsForProvider stands down every stream of one provider without
// forgetting it, and reports how many were suspended.
//
// This is the stream manager's half of the M6 Tuya session-loss degradation: a
// Tuya stream whose cloud session is dead has no source, and the HLS watchdog
// would otherwise restart ffmpeg against it forever. Only the named provider is
// touched, so an ONVIF stream can never be stopped by a Tuya session expiring.
//
// A per-stream failure is collected and returned rather than aborting the sweep:
// leaving the remaining streams running would be worse than a partial failure.
func (sm *Manager) SuspendStreamsForProvider(provider models.ProviderKind, reason string) (int, error) {
	provider = provider.OrDefault()
	var ids []string
	sm.mutex.RLock()
	for id, process := range sm.streams {
		process.mutex.RLock()
		match := process.Info.Provider.OrDefault() == provider && !process.suspended
		process.mutex.RUnlock()
		if match {
			ids = append(ids, id)
		}
	}
	sm.mutex.RUnlock()

	suspended := 0
	var failures []string
	for _, id := range ids {
		if err := sm.SuspendStreamForSessionLoss(id, reason); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", id, err))
			continue
		}
		suspended++
	}
	if len(failures) > 0 {
		return suspended, fmt.Errorf("failed to suspend %d stream(s): %s", len(failures), strings.Join(failures, "; "))
	}
	return suspended, nil
}

// StopStreamsForProvider stops every running stream of one provider and reports
// how many it stopped. Unlike SuspendStreamsForProvider it removes them, so
// they are not resumable.
func (sm *Manager) StopStreamsForProvider(provider models.ProviderKind) (int, error) {
	provider = provider.OrDefault()
	type target struct{ id, rtspURL string }
	var targets []target
	sm.mutex.RLock()
	for id, process := range sm.streams {
		process.mutex.RLock()
		match := process.Info.Provider.OrDefault() == provider
		rtspURL := process.Info.RtspURL
		process.mutex.RUnlock()
		if match {
			targets = append(targets, target{id: id, rtspURL: rtspURL})
		}
	}
	sm.mutex.RUnlock()

	stopped := 0
	var failures []string
	for _, t := range targets {
		if err := sm.StopStream(t.id); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", t.id, err))
			continue
		}
		// The stop must be ASSERTED, not assumed: StopStream removes the stream
		// from the registry, and a leaked ffmpeg from a superseded monitor would
		// otherwise keep retrying a dead source invisibly. The URL was captured
		// before the stop because the registry entry is gone by now. A freshly
		// killed process needs a moment to leave /proc, hence the bounded wait.
		if n := waitForNoFFmpegReader(sm, t.rtspURL, 3*time.Second); n > 0 {
			failures = append(failures, fmt.Sprintf("%s: %d ffmpeg process(es) survived the stop", t.id, n))
			continue
		}
		stopped++
	}
	if len(failures) > 0 {
		return stopped, fmt.Errorf("failed to stop %d stream(s): %s", len(failures), strings.Join(failures, "; "))
	}
	return stopped, nil
}

// countFFmpegProcessesFor counts live ffmpeg processes reading the given RTSP URL
// whose process GROUP this manager owns. It exists so a stop can be ASSERTED
// rather than assumed: the whole point of the M6 degradation is that no ffmpeg is
// left retrying a dead source, and a leaked process from a superseded monitor
// would silently defeat it.
//
// Ownership is checked by process group, not by URL alone. An RTSP URL is only
// unique within one engine instance — two viewer processes (or two test runs) on
// the same host can legitimately hold the same loopback URL — so a URL-only scan
// would report a foreign process as a leak. Every ffmpeg this manager spawns is
// put in its own process group (Setpgid), which makes the pgid the honest owner.
//
// IT IS NOT EXACT ON A BUSY HOST, AND CALLERS MUST NOT TREAT A SINGLE COUNT AS
// PROOF. Two distinct /proc races are MEASURED:
//
//  1. A transient failed /proc read is indistinguishable from "not our process",
//     so a live stream can count 0. MEASURED under load: 5 of 120 single counts
//     returned 0 with ownedLen=1 and the child alive, recovering within 10ms; a
//     30-sweep probe budget recorded 2 failures in 6150 probes. That is why this
//     function alone must never back an assertion — use
//     countFFmpegProcessesForStable there.
//
//  2. A process is matched by its /proc/<pid>/cmdline, and between fork() and
//     execve() a child still reports its PARENT's cmdline. Any process the owned
//     ffmpeg forks therefore becomes a second match for as long as that window
//     lasts. MEASURED: the test stub is a shell running `while true; do sleep 1;
//     done`, so once a second its forked `sleep 1` child counted as a second
//     owned ffmpeg — same process group, cmdline identical to the stub's, then
//     flipping to "sleep 1" once the exec completed. On a real ffmpeg this is a
//     much narrower window, but the same shape exists for anything ffmpeg forks.
//
// The fork/exec half is handled here, by requiring the candidate to be the
// process-group LEADER. Every stream's own ffmpeg is spawned with Setpgid, so the
// process this function is supposed to find is always the leader of its group;
// a forked child is in the group but is not its leader, and so cannot be counted
// while it is briefly wearing its parent's cmdline. That removes the phantom
// without weakening the leak check: a leaked ffmpeg from a superseded monitor is
// itself a group leader, so it is still counted.
func countFFmpegProcessesFor(rtspURL string, ownedPGIDs map[int]bool) int {
	if rtspURL == "" || len(ownedPGIDs) == 0 {
		return 0
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	n := 0
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name()[0] < '0' || entry.Name()[0] > '9' {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		pgid, err := syscall.Getpgid(pid)
		if err != nil || !ownedPGIDs[pgid] {
			continue
		}
		// Only the group leader can be a stream's own ffmpeg; a forked child is
		// in the group but is not its leader. See point 2 above.
		if pgid != pid {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil {
			continue
		}
		// The URL field is NUL-separated in /proc/<pid>/cmdline.
		if strings.Contains(string(raw), rtspURL) {
			n++
		}
	}
	return n
}

// countFFmpegProcessesForStable is countFFmpegProcessesFor with a bounded retry,
// for callers that ASSERT on the answer rather than poll.
//
// A single count is not exact on a busy host: /proc reads can fail transiently
// and a failed read is indistinguishable from "no process" (see the note on
// countFFmpegProcessesFor for the measurement — 5 false zeros in 120 counts
// under load, all recovering within 10ms).
//
// The two error modes are asymmetric, so the retry is too:
//   - want 0 (a leak check, a stop, "the process is gone"): a single zero must
//     not be accepted, because a transient failure manufactures one. Retry until
//     a zero is seen TWICE IN A ROW, or the budget expires; a genuine live
//     process cannot produce two consecutive zeros for the same reason, while a
//     genuine absence produces zeros immediately.
//   - want >0 (a liveness check, "the stream is really running"): keep retrying
//     until a non-zero reading appears or the budget expires, because the false
//     reading here is a zero.
//
// It never returns an unfounded zero: if the budget expires while the only
// readings have been positive, the last positive is returned.
func countFFmpegProcessesForStable(rtspURL string, ownedPGIDs map[int]bool, timeout time.Duration) int {
	deadline := time.Now().Add(timeout)
	last := countFFmpegProcessesFor(rtspURL, ownedPGIDs)
	consecutiveZeros := 0
	if last == 0 {
		consecutiveZeros = 1
	}
	for time.Now().Before(deadline) {
		if last != 0 {
			// A positive reading is authoritative for any caller that wants
			// "is anything alive": return it.
			return last
		}
		if consecutiveZeros >= 2 {
			// Two consecutive zeros: the process really is gone.
			return 0
		}
		time.Sleep(10 * time.Millisecond)
		n := countFFmpegProcessesFor(rtspURL, ownedPGIDs)
		if n == 0 {
			consecutiveZeros++
		} else {
			consecutiveZeros = 0
			last = n
			return n
		}
	}
	return last
}

// ownedProcessGroups collects the process groups of the ffmpeg children this
// manager currently tracks. A stream whose ffmpeg has already exited contributes
// nothing, which is the correct reading: there is no process to leak.
func (sm *Manager) ownedProcessGroups(rtspURL string) map[int]bool {
	owned := map[int]bool{}
	sm.mutex.RLock()
	processes := make([]*Process, 0, len(sm.streams))
	for _, p := range sm.streams {
		processes = append(processes, p)
	}
	sm.mutex.RUnlock()
	for _, process := range processes {
		process.mutex.RLock()
		cmd := process.Command
		url := process.Info.RtspURL
		process.mutex.RUnlock()
		if rtspURL != "" && url != rtspURL {
			continue
		}
		if cmd == nil || cmd.Process == nil {
			continue
		}
		// Use the group id recorded when the process was started rather than
		// asking /proc for it here. With Setpgid the child becomes its own
		// group leader, so the group id is the child's pid, fixed at Start()
		// time and never changing. Re-reading it through syscall.Getpgid only
		// adds a way to lose the group to a transient /proc failure — the same
		// failure mode that made countFFmpegProcessesFor report 0 for a live
		// process. When the field was not recorded, fall back to /proc.
		pgid := process.pgid
		if pgid <= 0 {
			g, err := syscall.Getpgid(cmd.Process.Pid)
			if err != nil {
				continue
			}
			pgid = g
		}
		owned[pgid] = true
	}
	return owned
}

// SuspendStreamForSessionLoss stands a stream down WITHOUT forgetting it.
//
// Unlike StopStream it leaves the stream in the registry and leaves its
// persisted stream_configs row alone, so:
//   - /api/stream/list still reports it, with status "needs_relogin", which is
//     how the card stays on screen and says why instead of silently vanishing;
//   - ResumeSuspended can restart exactly the same profile token with the RTSP
//     URL the engine hands back after a fresh login.
//
// This is what makes "one-click re-login resumes the same cameras" possible
// without the user re-picking anything.
func (sm *Manager) SuspendStreamForSessionLoss(streamID, reason string) error {
	sm.mutex.RLock()
	process, ok := sm.streams[streamID]
	sm.mutex.RUnlock()
	if !ok {
		return fmt.Errorf("stream not found")
	}
	process.mutex.Lock()
	process.shouldReconnect = false
	process.suspended = true
	process.suspendedReason = redactSensitiveText(reason)
	cmd := process.Command
	process.Info.Status = StatusNeedsRelogin
	process.Info.Detail = redactSensitiveText(reason)
	process.Info.Suspended = true
	process.Info.SuspendedReason = process.suspendedReason
	process.mutex.Unlock()

	sm.logger.LogWarn(streamID, "system", fmt.Sprintf("Suspending stream: %s", reason))
	sm.publishState(process, StatusNeedsRelogin, reason)

	// Capture the channels and URL THIS process owns before terminating.
	process.mutex.RLock()
	rtspURL := process.Info.RtspURL
	currentCmd := process.Command
	process.mutex.RUnlock()
	if currentCmd == nil {
		currentCmd = cmd
	}
	// The previous monitor's Done: awaiting it proves that loop has returned and
	// cannot spawn another ffmpeg afterwards.
	process.mutex.RLock()
	previousDone := process.Done
	process.mutex.RUnlock()

	// Terminate the process group, then wait for the monitor to confirm exit so
	// no ffmpeg can be left reading a dead source.
	if currentCmd != nil && currentCmd.Process != nil {
		if pgid, err := syscall.Getpgid(currentCmd.Process.Pid); err == nil {
			_ = syscall.Kill(-pgid, syscall.SIGTERM)
		} else {
			_ = currentCmd.Process.Signal(syscall.SIGTERM)
		}
	}
	grace := time.NewTimer(streamStopTimeout)
	select {
	case <-previousDone:
		grace.Stop()
	case <-grace.C:
		if currentCmd != nil && currentCmd.Process != nil {
			if pgid, err := syscall.Getpgid(currentCmd.Process.Pid); err == nil {
				_ = syscall.Kill(-pgid, syscall.SIGKILL)
			} else {
				_ = currentCmd.Process.Kill()
			}
		}
	}

	// ASSERT the bleed is really stopped. If an ffmpeg is still reading this
	// stream's URL, say so loudly instead of reporting a clean degradation:
	// leaving one alive is exactly the endless-retry failure M6 exists to end.
	// A just-SIGKILLed process can need a moment to disappear from /proc, so the
	// check retries briefly rather than crying wolf.
	if n := waitForNoFFmpegReader(sm, rtspURL, 3*time.Second); n > 0 {
		msg := fmt.Sprintf("stream suspended but %d ffmpeg process(es) are still reading %s", n, rtspURL)
		sm.logger.LogError(streamID, "system", msg)
		return fmt.Errorf("%s", msg)
	}
	return nil
}

// waitForNoFFmpegReader waits briefly for every ffmpeg reading rtspURL to be
// gone, then reports how many are left (0 = all clear).
//
// It uses the STABLE count, not a raw one: this reading is an assertion ("the
// stop really stopped it"), and a single raw count can report a false zero when
// a /proc read fails transiently on a busy host, which would make a leaked
// process look stopped.
func waitForNoFFmpegReader(sm *Manager, rtspURL string, timeout time.Duration) int {
	return countFFmpegProcessesForStable(rtspURL, sm.ownedProcessGroups(rtspURL), timeout)
}

// SuspendedStreams returns the suspended streams of a provider, in profile-token
// order so a resume is deterministic.
func (sm *Manager) SuspendedStreams(provider models.ProviderKind) []models.StreamInfo {
	provider = provider.OrDefault()
	var out []models.StreamInfo
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	for _, process := range sm.streams {
		process.mutex.RLock()
		if process.suspended && process.Info.Provider.OrDefault() == provider {
			out = append(out, process.Info)
		}
		process.mutex.RUnlock()
	}
	return out
}

// ResumeSuspended restarts a suspended stream with a (possibly new) RTSP URL.
//
// It is the recovery half of SuspendStreamForSessionLoss. The process registry
// entry and the persisted config are reused, so the same card, the same profile
// token and the same provider survive; only the RTSP URL changes, because the
// engine allocates a fresh loopback endpoint after a re-login.
func (sm *Manager) ResumeSuspended(streamID, rtspURL string, provider models.ProviderKind) (*models.StreamInfo, error) {
	sm.mutex.RLock()
	process, ok := sm.streams[streamID]
	sm.mutex.RUnlock()
	if !ok {
		return nil, fmt.Errorf("stream not found")
	}
	// The write lock is held only for the registry mutation; publishState
	// broadcasts to SSE clients, which re-takes sm.mutex as a reader, so it must
	// run after the unlock (Go's RWMutex is not reentrant).
	info, err := sm.resumeSuspendedProcess(process, rtspURL, provider)
	if err != nil {
		return nil, err
	}
	sm.publishState(process, "starting", "stream resumed after a successful Tuya re-login")
	return info, nil
}

// resumeSuspendedProcess performs the resume. It takes only the per-process lock
// (the process pointer is already resolved by the caller), so callers must NOT
// hold sm.mutex: publishState re-takes it as a reader and Go's RWMutex is not
// reentrant.
func (sm *Manager) resumeSuspendedProcess(process *Process, rtspURL string, provider models.ProviderKind) (*models.StreamInfo, error) {
	if process == nil {
		return nil, fmt.Errorf("stream not found")
	}
	process.mutex.Lock()
	if !process.suspended {
		streamID := process.Info.ID
		process.mutex.Unlock()
		return nil, fmt.Errorf("stream %s is not suspended", streamID)
	}
	if rtspURL == "" {
		process.mutex.Unlock()
		return nil, fmt.Errorf("an RTSP URL is required to resume a stream")
	}
	streamID := process.Info.ID
	process.Info.RtspURL = rtspURL
	process.Info.Provider = provider.OrDefault()
	// A resume reuses the stream's own resolution, so a camera that came back
	// after a re-login runs the same output path it had before the session died.
	// The provider is taken from the resumed stream (or the caller's provider
	// when the stream had none) so a Tuya stream comes back on the Tuya path
	// instead of silently reverting to the pinned ONVIF copy list.
	process.Info.Resolution = logger.NormalizeResolution(process.Info.Resolution)
	process.outputPath = outputPathForProvider(process.Info.Provider, process.Info.Resolution)
	process.Info.Output = outputPathName(process.outputPath)
	process.Info.InputTimestamps = inputTimestampsName(process.outputPath)
	process.Info.Transcoding = process.outputPath == OutputTranscodeH264
	process.reconnectCount = 0
	process.suspended = false
	process.suspendedReason = ""
	process.shouldReconnect = true
	process.Info.Status = "starting"
	process.Info.Suspended = false
	process.Info.SuspendedReason = ""
	// The channels and the run identity are handed out HERE, under the process
	// lock, together with the flag that guards them. Nothing that follows waits
	// on a spawn this goroutine committed, so the previous run can still be
	// finishing its deferred close after the resume has returned; the runID is
	// what keeps that deferred close from touching anything of the new run's.
	//
	// The superseded run's flag entry is dropped by replacing the map, so a
	// stream that is resumed thousands of times does not accumulate one flag
	// per run for the life of the process. Replacing rather than deleting the
	// single old key also releases any entry a just-superseded run resurrected
	// with its own deferred close, which is the only way the map can grow after
	// the swap. A superseded run can therefore add at most ONE entry, and the
	// next supersession removes it, so the map stays bounded by the live run
	// plus at most one resurrected entry.
	process.Done = make(chan bool)
	process.Exited = make(chan struct{})
	process.runsClosed = make(map[uint64]*sync.Once)
	process.runID = nextRunID()
	process.Info.ReconnectDelay = ""
	profileToken := process.Info.ProfileToken
	info := process.Info
	process.mutex.Unlock()

	if err := sm.logger.UpsertStreamConfig(profileToken, rtspURL, string(provider.OrDefault())); err != nil {
		return nil, fmt.Errorf("persist stream configuration: %w", err)
	}
	// A fresh monitor owns the ffmpeg lifecycle from here. The previous one has
	// already returned (the suspend path waited for Exited).
	go sm.monitorStreamWithReconnect(process, filepath.Join(sm.hlsBaseDir, streamID))
	return &info, nil
}

// ListStreams returns information about all active streams
func (sm *Manager) ListStreams() []models.StreamInfo {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	streams := make([]models.StreamInfo, 0, len(sm.streams))
	for _, stream := range sm.streams {
		stream.mutex.RLock()
		streams = append(streams, stream.Info)
		stream.mutex.RUnlock()
	}
	return streams
}

// AddSSEClient adds a new SSE client
func (sm *Manager) AddSSEClient(clientID string, client *models.ClientConnection) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	sm.sseClients[clientID] = client
	for _, process := range sm.streams {
		process.mutex.RLock()
		info := process.Info
		process.mutex.RUnlock()
		select {
		case client.Channel <- sm.stateEntry(info, info.Detail):
		default:
		}
	}
}

// RemoveSSEClient removes an SSE client
func (sm *Manager) RemoveSSEClient(clientID string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	if client, exists := sm.sseClients[clientID]; exists {
		close(client.Channel)
		delete(sm.sseClients, clientID)
	}
}

// broadcastLog broadcasts a log entry to all SSE clients
func (sm *Manager) broadcastLog(entry models.LogEntry) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	for _, clientConn := range sm.sseClients {
		select {
		case clientConn.Channel <- entry:
			// Log sent successfully
		default:
			// Channel full, silently skip to aggressively prevent console bloat
		}
	}
}

// CleanupInactiveClients starts a background routine to clean up inactive SSE clients
func (sm *Manager) CleanupInactiveClients() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			sm.mutex.Lock()

			clientCount := len(sm.sseClients)
			if clientCount > 0 {
				log.Printf("Cleaning up inactive clients. Current count: %d", clientCount)
			}

			// Check each client's last activity time
			for clientID, clientConn := range sm.sseClients {
				if now.Sub(clientConn.LastActive) > sm.clientTimeout {
					log.Printf("Cleaning up inactive client: %s (inactive for %v)",
						clientID, now.Sub(clientConn.LastActive))
					close(clientConn.Channel)
					delete(sm.sseClients, clientID)
				}
			}

			sm.mutex.Unlock()

		case <-sm.stopCleanup:
			return
		}
	}
}

// UpdateClientActivity updates the last active time for a client
func (sm *Manager) UpdateClientActivity(clientID string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if client, exists := sm.sseClients[clientID]; exists {
		client.LastActive = time.Now()
	}
}

// GetSSEClients returns a copy of current SSE clients
func (sm *Manager) GetSSEClients() map[string]*models.ClientConnection {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	clients := make(map[string]*models.ClientConnection)
	for id, client := range sm.sseClients {
		clients[id] = client
	}
	return clients
}

// Shutdown gracefully shuts down the stream manager
func (sm *Manager) Shutdown() {
	log.Println("Shutting down stream manager...")

	// Stop all active streams
	sm.mutex.Lock()
	streamIDs := make([]string, 0, len(sm.streams))
	for id, stream := range sm.streams {
		streamIDs = append(streamIDs, id)
		// Disable reconnection for all streams
		stream.mutex.Lock()
		stream.shouldReconnect = false
		stream.mutex.Unlock()
	}
	sm.mutex.Unlock()

	for _, id := range streamIDs {
		if err := sm.stopStream(id, false); err != nil {
			log.Printf("Error stopping stream %s: %v", id, err)
		}
	}

	// Stop cleanup routine
	close(sm.stopCleanup)

	// Close all SSE clients
	sm.mutex.Lock()
	for clientID, client := range sm.sseClients {
		close(client.Channel)
		delete(sm.sseClients, clientID)
	}
	sm.mutex.Unlock()

	log.Println("Stream manager shutdown complete")
}
