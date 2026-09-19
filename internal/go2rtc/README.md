# Vendored go2rtc (MIT)

This directory is **vendored source code**, not a module dependency. It is a
subset of [github.com/AlexxIT/go2rtc](https://github.com/AlexxIT/go2rtc) copied
into this repository so `dengan.dev/camera-streamer` builds and runs Tuya
streaming as **one self-contained binary with no external executable**.

| Field | Value |
| --- | --- |
| Upstream repository | https://github.com/AlexxIT/go2rtc |
| Upstream commit | `c245815e75e2a5fd60b4290f12bfc04e55a984d3` (`c245815`, 2026-07-13) |
| Upstream license | MIT, Copyright (c) 2022 Alexey Khit — see `LICENSE-go2rtc` |
| Vendored on | 2026-09-19 |
| Local module path | `dengan.dev/camera-streamer/internal/go2rtc/...` |

## Why vendoring instead of a module requirement

The Tuya session-reuse feature (see `patches/`) is a *local patch* to
`pkg/tuya`. Requiring `github.com/AlexxIT/go2rtc` as a module would not pick up
that patch, and it would drag in go2rtc's whole application layer
(`internal/app`, `internal/streams`, `internal/rtsp`) — including a second RTSP
server, an HTTP API and a WebRTC listener that this project does not want. The
upstream packages copied here have **zero** dependency on go2rtc's `internal/`
packages, which is what makes a clean subset possible.

## What was copied

Only packages reachable from the two entry points this project uses
(`tuya.Dial` for the producer, `rtsp.NewServer` for the local endpoint), minus
test files. The upstream file layout is preserved verbatim so future upstream
diffs stay tractable.

```
aac/  bits/  core/  h264/  h264/annexb/  h265/  mjpeg/  pcm/
rtsp/  shell/  tcp/  tcp/websocket/  tuya/  webrtc/  xnet/  y4m/
```

The only change applied to every file is the import rewrite

```
github.com/AlexxIT/go2rtc/pkg/X  ->  dengan.dev/camera-streamer/internal/go2rtc/X
```

## Local patches

Because the import rewrite is mechanical, the only *semantic* local patches are
these (plus the session rework in `patches/`):

1. `bits.Reader.ReadByte` / `bits.Writer.WriteByte` renamed to
   `ReadUint8` / `WriteUint8`. They have a non-standard signature (no `error`),
   which `go vet` rejects as a stdlib-interface mismatch; the call sites in
   `h264/sps.go` were renamed with them. Behaviour is unchanged.
2. `webrtc/api.go`: the four `webrtc.RTCPFeedback` literals use keyed fields.
   Same values, only the composite literal style changed (fixes `go vet`'s
   unkeyed-fields check).
3. `webrtc/conn.go`: removed the unreachable `return nil, nil` after
   `panic(core.Caller())` in `getMediaCodec`.

No upstream logic, protocol handling or codec code was altered.

## Dependency note (not vendored)

The vendored packages are *not* dependency-free: they use `github.com/pion/*`
(WebRTC, RTP, SDP, ICE, DTLS, SRTP, STUN, TURN), `github.com/eclipse/paho.mqtt.golang`,
`github.com/google/uuid`, `github.com/gorilla/websocket`, `github.com/sigurn/crc8`,
`github.com/sigurn/crc16` and `golang.org/x/net`. Those are ordinary module
dependencies in `go.mod`, exactly as they are upstream. Only go2rtc's own Go
code is vendored.
