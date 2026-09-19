package tuyaengine

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Defaults for the Tuya engine. Everything that can move at packaging time is
// configurable through Config / environment variables; these are only defaults.
const (
	// DefaultTuyaHost is the Smart Life region host of the ES06 camera.
	DefaultTuyaHost = "protect-us.ismartlife.me"
	// DefaultResolution is the only resolution proven to work on the ES06; HD
	// (2560x1440) is unproven and must not be assumed.
	DefaultResolution = "sd"
	// DefaultRTSPHost is the address written into the RTSP URL that is handed to
	// the viewer. The engine itself only ever binds loopback.
	DefaultRTSPHost = "127.0.0.1"
)

// Environment variables honoured by DefaultConfig. They exist so the packaging
// question (where the engine binary and its generated config live) can be
// settled without touching this package.
const (
	EnvBinPath     = "TUYA_ENGINE_BIN"
	EnvConfigDir   = "TUYA_ENGINE_CONFIG_DIR"
	EnvAPIPort     = "TUYA_ENGINE_API_PORT"
	EnvRTSPPort    = "TUYA_ENGINE_RTSP_PORT"
	EnvRTSPHost    = "TUYA_ENGINE_RTSP_HOST"
	EnvSessionFile = "TUYA_ENGINE_SESSION_FILE"
	EnvTuyaHost    = "TUYA_ENGINE_TUYA_HOST"
	EnvLogLevel    = "TUYA_ENGINE_LOG_LEVEL"
)

const (
	defaultReadyTimeout = 20 * time.Second
	defaultStopTimeout  = 5 * time.Second
	defaultBaseBackoff  = 500 * time.Millisecond
	defaultMaxBackoff   = 30 * time.Second
	defaultProbeTimeout = 3 * time.Second
	defaultPollInterval = 200 * time.Millisecond
	defaultLogLevel     = "info"
	defaultConfigName   = "go2rtc"
)

// DefaultBinCandidates is the search order used when Config.BinPath is empty.
// The first candidate that resolves is used; the temp path is last because it is
// the already-proven build during bring-up, not a packaging location.
var DefaultBinCandidates = []string{
	"go2rtc-qr",
	"/usr/local/bin/go2rtc-qr",
	"/usr/local/bin/go2rtc",
	"/tmp/go2rtc-qr",
}

// Config describes how to run and supervise the Tuya->RTSP engine.
type Config struct {
	// BinPath is the engine executable. Empty means "search DefaultBinCandidates"
	// (or whatever DefaultBinCandidates has been replaced with).
	BinPath string
	// ConfigDir receives the generated engine YAML and its log file. Empty means
	// os.TempDir()/tuyaengine.
	ConfigDir string
	// APIPort / RTSPPort pin the engine ports. 0 means "allocate a free port on
	// every spawn".
	APIPort  int
	RTSPPort int
	// RTSPHost is the host component of the URL handed to ffmpeg.
	RTSPHost string
	// SessionFile and TuyaHost are resolver defaults for DeviceSpec.
	SessionFile string
	TuyaHost    string
	// LogLevel is the engine's own log level.
	LogLevel string
	// ReadyTimeout bounds WaitReady, StopTimeout bounds graceful child shutdown.
	ReadyTimeout time.Duration
	StopTimeout  time.Duration
	// BaseBackoff/MaxBackoff bound the supervision restart delay.
	BaseBackoff time.Duration
	MaxBackoff  time.Duration
	// MaxRestarts caps consecutive respawn attempts (0 = unlimited). A child
	// that stays up longer than stableRunThreshold clears the counter, so a rare
	// crash never counts against this limit.
	MaxRestarts int
}

// DefaultConfig returns an environment-aware Config.
func DefaultConfig() Config {
	return Config{
		BinPath:      os.Getenv(EnvBinPath),
		ConfigDir:    os.Getenv(EnvConfigDir),
		APIPort:      envPort(EnvAPIPort),
		RTSPPort:     envPort(EnvRTSPPort),
		RTSPHost:     strings.TrimSpace(os.Getenv(EnvRTSPHost)),
		SessionFile:  strings.TrimSpace(os.Getenv(EnvSessionFile)),
		TuyaHost:     strings.TrimSpace(os.Getenv(EnvTuyaHost)),
		LogLevel:     strings.TrimSpace(os.Getenv(EnvLogLevel)),
		ReadyTimeout: defaultReadyTimeout,
		StopTimeout:  defaultStopTimeout,
		BaseBackoff:  defaultBaseBackoff,
		MaxBackoff:   defaultMaxBackoff,
	}
}

func envPort(name string) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return 0
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 0 || port > 65535 {
		return 0
	}
	return port
}

// withDefaults fills every zero field so callers may pass a partial Config.
func (c Config) withDefaults() Config {
	if c.ConfigDir == "" {
		c.ConfigDir = filepath.Join(os.TempDir(), "tuyaengine")
	}
	if c.RTSPHost == "" {
		c.RTSPHost = DefaultRTSPHost
	}
	if c.TuyaHost == "" {
		c.TuyaHost = DefaultTuyaHost
	}
	if c.LogLevel == "" {
		c.LogLevel = defaultLogLevel
	}
	if c.ReadyTimeout <= 0 {
		c.ReadyTimeout = defaultReadyTimeout
	}
	if c.StopTimeout <= 0 {
		c.StopTimeout = defaultStopTimeout
	}
	if c.BaseBackoff <= 0 {
		c.BaseBackoff = defaultBaseBackoff
	}
	if c.MaxBackoff <= 0 {
		c.MaxBackoff = defaultMaxBackoff
	}
	if c.MaxBackoff < c.BaseBackoff {
		c.MaxBackoff = c.BaseBackoff
	}
	return c
}

// Validate reports configuration that cannot produce a working engine.
func (c Config) Validate() error {
	if c.APIPort != 0 && c.RTSPPort != 0 && c.APIPort == c.RTSPPort {
		return fmt.Errorf("tuyaengine: api port and rtsp port must differ (%d)", c.APIPort)
	}
	if c.RTSPHost == "" {
		return fmt.Errorf("tuyaengine: rtsp host is required")
	}
	return nil
}

// FindEngineBinary resolves the engine executable: an explicit path wins,
// otherwise DefaultBinCandidates is searched (PATH lookup for bare names).
func FindEngineBinary(explicit string) (string, error) {
	explicit = strings.TrimSpace(explicit)
	if explicit != "" {
		if err := checkExecutable(explicit); err != nil {
			return "", err
		}
		return explicit, nil
	}
	var tried []string
	for _, candidate := range DefaultBinCandidates {
		tried = append(tried, candidate)
		if err := checkExecutable(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("tuyaengine: no engine binary found (tried %s); set %s", strings.Join(tried, ", "), EnvBinPath)
}

func checkExecutable(path string) error {
	resolved := path
	if !strings.ContainsRune(path, os.PathSeparator) {
		found, err := exec.LookPath(path)
		if err != nil {
			return err
		}
		resolved = found
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return fmt.Errorf("tuyaengine: engine binary %s: %w", resolved, err)
	}
	if info.IsDir() {
		return fmt.Errorf("tuyaengine: engine binary %s is a directory", resolved)
	}
	if info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("tuyaengine: engine binary %s is not executable", resolved)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Engine configuration file rendering
// ---------------------------------------------------------------------------

// renderEngineConfig renders the go2rtc YAML used by the engine. Stream URLs are
// quoted and validated, so a device id or path can never inject YAML.
func (e *Engine) renderEngineConfig(apiPort, rtspPort int) (string, error) {
	var b strings.Builder
	b.WriteString("# Generated by internal/tuyaengine. Do not edit: it is rewritten on every spawn.\n")
	b.WriteString("api:\n  listen: \"127.0.0.1:" + strconv.Itoa(apiPort) + "\"\n")
	b.WriteString("rtsp:\n  listen: \"127.0.0.1:" + strconv.Itoa(rtspPort) + "\"\n")
	// The Tuya producer is a WebRTC *client*; the engine must never open its own
	// WebRTC listener, because other go2rtc instances already own 8555/8558.
	b.WriteString("webrtc:\n  listen: \"\"\n")
	b.WriteString("log:\n  level: " + yamlQuote(e.cfg.LogLevel) + "\n")
	b.WriteString("streams:\n")
	if len(e.streams) == 0 {
		b.WriteString("  {}\n")
		return b.String(), nil
	}
	for _, name := range e.streamNamesLocked() {
		url := e.streams[name]
		b.WriteString("  " + name + ":\n    - " + yamlQuote(url) + "\n")
	}
	return b.String(), nil
}

// yamlQuote renders a single-line double-quoted YAML scalar.
func yamlQuote(value string) string {
	replacer := strings.NewReplacer("\\", "\\\\", "\"", "\\\"")
	return "\"" + replacer.Replace(value) + "\""
}
