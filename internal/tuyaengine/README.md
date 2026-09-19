# Tuya engine bridge

Turns a Tuya camera into an RTSP endpoint **inside the viewer process**, so the
existing HLS pipeline (`internal/stream`) can consume a Tuya camera exactly like
an ONVIF camera.

## The architectural change

This package used to supervise an **external 27 MB go2rtc binary** as a child
process. That is gone from the default path. The Tuya→RTSP bridge is now built
from code **vendored into this repository**:

| Layer | Where it lives now |
| --- | --- |
| Tuya cloud + WebRTC session (session-file reuse) | `internal/go2rtc/tuya` (vendored, `tuya.Dial`) |
| RTSP protocol / interleaved RTP server | `internal/go2rtc/rtsp` (vendored) |
| In-process RTSP endpoint for the viewer | `internal/tuyartsp` (this repo) |
| Process-level wiring + stream registry | `internal/tuyaengine` (this package) |

`go build ./...` now produces a binary that streams Tuya video with **no
external executable present**. See `internal/go2rtc/README.md` for the
provenance (upstream commit, MIT license, local patches).

## Layout

| File | Role |
| --- | --- |
| `local.go` | **The default in-process backend**: binds the loopback RTSP listener, registers streams, reports readiness. No child process, no `FindEngineBinary`. |
| `engine.go` | The stream registry shared by both backends, plus the **opt-in** external-binary supervisor (spawn, readiness race, restart/backoff, Stop). |
| `config.go` | `Config` (mode, ports, timings), env defaults, external-engine YAML rendering, binary discovery. |
| `resolver.go` | `DeviceSpec`: validates device id/session file/host/resolution and builds the engine URL, RTSP URL and namespaced profile token. |
| `probe.go` | Minimal RTSP client (OPTIONS/DESCRIBE), free-port reservation, port diagnostics. |
| `bridge.go` | The one-call end-to-end entry point onto `stream.Manager.StartStream`. |
| `testdata/fakeengine/` | Stand-in engine used by the *external* backend's tests; invisible to `go build ./...`. |

## Backends

### Default: in-process (`ModeInProcess`)

`EnsureRunning` binds `RTSPHost:RTSPPort` (or a kernel-allocated port) with
`internal/tuyartsp`, which speaks RTSP using the vendored `rtsp.Server`. On
`DESCRIBE` it dials the `tuya://` source with the vendored `tuya.Dial`, wires the
producer's tracks into the RTSP connection, and answers with an SDP carrying the
camera's real codec (H264 on the SD stream, HEVC on HD). On `PLAY` the producer
starts and RTP flows camera → WebRTC → track → RTSP interleaved framing → ffmpeg.

Nothing is executed. `Bridge.StartStream(DeviceSpec)` is unchanged and is still
the single entry point.

### Opt-in: external binary (`ModeExternal`)

Selected by `TUYA_ENGINE_MODE=external`, or by setting `Config.BinPath` /
`TUYA_ENGINE_BIN`. The supervisor loop, YAML rendering, port coordination and
`FindEngineBinary` all still work exactly as before; they are simply no longer
the default. `DefaultBinCandidates` no longer contains `/tmp/go2rtc-qr`: a /tmp
wipe must not be able to take Tuya streaming down.

## Design notes

**One producer per RTSP connection.** Tuya cameras accept very few concurrent
WebRTC sessions, so a producer is never shared between connections. The HLS
pipeline keeps exactly one ffmpeg (and therefore one RTSP client) per profile
token, so the steady state is one Tuya session per camera. Caching a producer
across reconnects would hold a camera session open while the viewer had no
reader — the failure mode the supervised-engine design had. The producer is
owned by the connection and stopped when its client disconnects.

**Port pinning.** Ports are reserved once per engine and then **pinned for the
engine's lifetime**, and the RTSP URL is built from that pinned port. This is a
correctness requirement, not tidiness: the URL is handed to ffmpeg and persisted
in `stream_configs`, so a per-spawn free port would silently invalidate every
running stream and every persisted config. Allocation uses a bind-to-`:0` probe
plus a process-local reservation set, so two engines in one process can never be
handed the same "free" port. Ports are released on `Stop`.

**Restart semantics changed with the backend.** The in-process server cannot
crash independently of the viewer: a failure surfaces inside the streaming
goroutine as a closed RTSP connection, and ffmpeg reconnects (that is what
`internal/stream`'s supervisor already handles). The external backend keeps its
process-level restart/backoff machinery, because a child process genuinely can
die on its own.

**Security.** Both backends bind loopback only. The generated external-engine
config contains no credentials — only the absolute path of the read-only Tuya
session file — and is written `0600`. The session file itself is never opened
for writing and is rejected unless it is `0600` and absolute; `internal/go2rtc/tuya`
refuses cross-origin redirects and never falls back to password login in session
mode. Device ids, hosts and stream names are validated against strict character
sets and YAML-quoted, so a device id can never inject YAML.
