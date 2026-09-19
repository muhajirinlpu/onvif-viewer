# Tuya engine bridge

Supervises a Tuya-cloud → RTSP bridge binary as a child process of the viewer, so
the existing HLS pipeline can consume a Tuya camera exactly like an ONVIF camera.

## Layout

| File | Role |
| --- | --- |
| `engine.go` | The supervised child process: spawn, readiness race, restart + backoff, Stop, live stream registry. |
| `config.go` | `Config` (binary/config paths, ports, timings), env defaults, engine YAML rendering, binary discovery. |
| `resolver.go` | `DeviceSpec`: validates device id/session file/host/resolution and builds the engine URL, RTSP URL and namespaced profile token. |
| `probe.go` | Minimal RTSP client (OPTIONS/DESCRIBE), free-port reservation, port diagnostics. |
| `bridge.go` | The one-call end-to-end entry point onto `stream.Manager.StartStream`. |
| `testdata/fakeengine/` | Stand-in engine used by unit tests; invisible to `go build ./...`. |

## Design notes

**Process supervision.** One `Engine` owns at most one child process, shared by
every Tuya camera (the engine multiplexes streams; spawning per camera would waste
WebRTC sessions on a camera that allows very few). The supervisor loop spawns the
child in its own process group, then races *readiness* (RTSP listener accepting)
against *exit* (`cmd.Wait`), because a child that dies during startup must be
noticed immediately rather than after `ReadyTimeout`. Both branches always collect
the wait result, so no zombie and no stale "running" state can survive a crash.
Restart delay is exponential from `BaseBackoff` to `MaxBackoff`; a child that
stayed up longer than `stableRunThreshold` (30s, matching `internal/stream`)
resets the attempt counter, so a rare crash does not inherit an escalated
backoff. `MaxRestarts` (0 = unlimited) bounds consecutive failures. Every
transition is published through `SetEventSink` and recorded in `Events()`.
`Stop` is idempotent: SIGTERM to the process group, SIGKILL after `StopTimeout`.

**Port allocation.** Ports are reserved once per engine and then **pinned for the
engine's lifetime**, and the RTSP URL is built from that pinned port. This is a
correctness requirement, not tidiness: the URL is handed to ffmpeg and persisted
in `stream_configs`, so a per-spawn free port would silently invalidate every
running stream and every persisted config on the first engine crash. Allocation
uses a bind-to-`:0` probe plus a process-local reservation set, so two engines in
one process can never be handed the same "free" port. Ports are released on
`Stop`. `Config.APIPort`/`RTSPPort` allow pinning from configuration instead.

**Security.** The generated engine config contains no credentials — only the
absolute path of the read-only Tuya session file — and is written `0600`. The
session file itself is never opened for writing and is rejected unless it is
`0600` and absolute. Device ids, hosts and stream names are validated against
strict character sets and YAML-quoted, so a device id can never inject YAML.
