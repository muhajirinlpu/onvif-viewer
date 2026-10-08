# Tuya backlog: verified local mux defect, live attribution pending

## Change

Tuya SD alone now uses `-max_interleave_delta 1000000` (1 second). Previously it used `0`, with a comment incorrectly claiming this disabled buffering. FFmpeg documents zero as unlimited waiting for every stream, regardless of timestamp separation: https://ffmpeg.org/ffmpeg-formats.html (Format Options, max_interleave_delta).

This is a queue escape bound, not a new timestamp source. `-itsscale:v 1.50`, video copy, honest 8 kHz mono source audio, AAC compressor/filter path, timeout and HLS flags stay unchanged. ONVIF and HD arguments stay unchanged. No encoded frame dropping or scheduled restart. The existing elapsed-HLS guard stays auxiliary. Telemetry explicitly says `captureLatencyStatus: unavailable_no_source_clock`.

## Repro and results

Run with `HOME=/home/muhajirin TMPDIR=/home/muhajirin/.hermes/cache/scratch GOTMPDIR=/home/muhajirin/.hermes/cache/scratch GOMAXPROCS=2`:

```
go test -p 1 ./internal/stream -run '^TestTuyaMuxDoesNotAccumulateCaptureBacklog$' -count=1 -v
```

The test substitutes a synthetic `core.Producer`, traverses the real `tuyartsp` listener and FFmpeg argument builder, and emits H264 RTP plus PCMA audio. Known capture ordinals are carried in valid user-data SEI, independent of the media timestamps. 80-frame GOP at scaled 75ms gives actual six-second HLS segments. A 20% audio/video clock disagreement initially accumulates skew; clocks then advance equally without resetting the offset. Replay accelerates logical source time with one packet pair per millisecond; this is a clock-domain reproduction, not a wall-time/camera performance benchmark.

Latest RED (same final harness, changed interleave value back to 0):

- source newest ordinal 14399; HLS tail 12399;
- capture backlog **150.000s**;
- final source advance 180.000s; HLS capture edge advance **180.000s**;
- test FAIL, raw exit **1**.

GREEN with only mux interleave bound changed:

- source newest ordinal 14399; HLS tail 14319;
- capture backlog **6.000s**, exactly one GOP;
- final source and edge both advance **180.000s**;
- H264 tail decodes without error; AAC remains 8000 Hz with continuous 1024-sample spacing.

The test stays live at checkpoints: killing the input before measuring would flush the queue and hide the bug. It waits for the edge to settle so sender/socket queue drain is not miscounted as mux backlog. Temp files are home-backed and automatically removed. Synthetic RTSP uses an ephemeral loopback port, not 7878.

## What is proven / not proven

**Proven:** the exact production mux configuration can queue minutes of video behind a lagging independently clocked audio stream, while published video cadence is normal once their clock rates agree again. A finite limit removes that local accumulation in the root data path, without resets or random frame drops.

**Not proven:** that the live camera's three incidents were caused by this mismatch rather than already-stale upstream delivery. No new Tuya/P2P camera consumer, resets, live instrumentation, production session reads, deployment or recording activation was used in this investigation. Fixed video scaling remains an independent mismatch risk; it is not a capture clock. The finite bound cannot recover footage already stale when received from Tuya, and cannot repair genuine source A/V capture skew. It preserves sample order/timebases; audio can be displaced by up to roughly the one-second interleave budget at segment boundaries (42–47 AAC packets observed in the last six-second segment).

Ranked next boundaries if the live symptom persists:

1. FFmpeg interleave (experimentally reproduced here). For live attribution, compare existing stream video/audio RTP progress and FFmpeg output PTS at the fault, without opening another camera session.
2. Already-stale Tuya/WebRTC delivery. Packet arrival timestamps alone cannot establish capture age. Need a trusted sender clock mapping or independently verified overlay sample, not OCR as an automatic production guard.
3. go2rtc sender / socket backpressure. Video sender has a bounded 4096 RTP-packet channel, audio 128 packets, drop-new behavior. Queue age is not currently exposed. RTSP writes can block five seconds and ignore write errors; probe queue residence/blocked writes on the existing connection only, with parent approval.
4. Lifecycle pre-PLAY media. `tuyartsp.wire` starts the producer during DESCRIBE despite comments promising after PLAY. The new active-media harness exposes vendor `state`/`playOK` races. No vendored correction was made.

## Verification / blocker

- `go test -p 1 ./...`: PASS, exit 0 after fixture correction.
- `go vet -p 1 ./...`: PASS, exit 0.
- native `go build -p 1 -o onvif-viewer-backlog-candidate .`: PASS, exit 0.
- `git diff --check`: PASS.
- `go test -race -p 1 ./...`: FAIL, exit 1. New active-media harness exposes existing go2rtc RTSP `Accept` writes (`server.go:170`, `:207`) versus `packetWriter` reads (`consumer.go:96`, `:141`) of state/playOK. No suppression, test skipping, or vendor modifications. Race failure is an open review gate, not a clean verification claim.

## Safe parent review / live acceptance

Review the small Tuya-only argument change and telemetry addition first. Race repair requires separate approval: either minimally correct the bridge's pre-PLAY producer start where possible, or propose a properly synchronized vendor patch with provenance; do not silence the race detector or edit vendor silently.

After approved parent-controlled cutover, confirm the actual running Tuya FFmpeg command carries `-max_interleave_delta 1000000`, recording remains OFF and ONVIF is unaffected. Compare newest backend capture against the current vendor app at baseline and over longer than the prior four-hour recurrence window; separately check HLS cadence, intra-segment 75ms grid, audio continuity/content, and browser playback. A one-second timestamp queue budget is not a global end-to-end latency guarantee. If delay recurs, preserve the segment and source/output timing evidence before targeted recovery and use the smallest approved existing-session probe above. No additional real-camera session.
