# Camera stall: root cause and viewer fixes

**Camera:** 10.2.56.194:5543 (Happytime onvif server V9.1)
**Date:** 2026-09-18
**Status:** cause identified, fixes deployed and verified

## Root cause: the camera serves only 2 concurrent RTSP sessions

Measured directly with a raw RTSP client:

```
session 1: SETUP=200 PLAY=200   (held)
session 2: SETUP=200 PLAY=200   (held)
session 3: DESCRIBE=200 PLAY=454  <- RTSP 454 "Session Not Found"
```

**The critical detail:** while the session table is full, `DESCRIBE` still
returns **200**. The TCP connection succeeds and the handshake looks healthy —
only `PLAY` fails. That is why the symptom reads as *"ping and connection are
okay, but no frame received"*, and why a port-reachability diagnosis reports a
healthy camera during a total outage.

## Why it lasts about an hour

1. The camera can stop delivering media mid-session while holding the socket
   open; the viewer's watchdog then kills ffmpeg
2. Sessions orphaned this way are only reaped by the camera's own expiry,
   roughly an hour
3. `onvif-viewer` retried every 5 s up to 30 times. Retries do not consume
   slots (verified), so the table stayed wedged and every reconnect failed
   until the camera aged the orphans out
4. The old diagnosis only did a TCP dial, so it reported "camera host
   reachable" throughout, and the `exit status 255` in the logs gave no hint

## Reproducing and measuring

| Tool | Purpose |
|---|---|
| `camera-direct/tools/rtsp-probe.py` | raw RTSP (`trace`/`ramp N`/`leak N`/`count`); no ffmpeg |
| `camera-direct/tools/leak-test.py` | fills the table, fires failing retries, releases, re-tests |
| `camera-direct/tools/rtsp-stall-test.sh` | 180 s sustained pulls, 4 stream/transport combos |
| `camera-direct/tools/analyze-progress.py` | frame-delivery timeline; finds zero-frame windows |

Sustained-pull results (180 s each, single client):

| Combination | Media time reached | fps | Stalls |
|---|---|---|---|
| main / TCP | 179.3 s | 19.97 | 0 |
| sub / TCP | 177.3 s | 20.13 | 0 |
| main / UDP | 124.1 s | 19.90 | stream stopped early |
| sub / UDP | 177.6 s | 20.13 | 0 |

Also found: the camera emits **non-monotonic DTS** (duplicate/backwards
timestamps), 12-33 occurrences per 180 s pull.

## Fixes applied to onvif-viewer

1. **New `internal/stream/rtsp_probe.go`** — full RTSP negotiation
   (OPTIONS/DESCRIBE/SETUP/PLAY/collect RTP/TEARDOWN) that classifies the
   failure instead of only dialling a TCP port:
   - `SessionTableFull()` — status 454 at PLAY/DESCRIBE/SETUP
   - `Stalled()` — PLAY accepted but no RTP arrived
   - `MediaFlowing()` — healthy, with packet count
   It always sends TEARDOWN so probing never leaks a slot on a 2-slot camera.
2. **Reconnect backs off 2 minutes on 454** and does not burn reconnect
   attempts — a full table is a camera resource limit, not a failing stream.
3. **`hlsStallTimeout` 90 s to 30 s** — backstop for stall detection.
4. **`-fflags +genpts+igndts`** — discards the camera's bad DTS.
5. **`-max_interleave_delta 0`** — no buffering to re-order; lower latency.

### ffmpeg pitfall

`-rw_timeout` is **not** a valid ffmpeg CLI option. It appears in
`ffmpeg -h full` because that lists AVIO-level options, but passing it fails
with `Option rw_timeout not found` and the process cannot open the input.
The RTSP demuxer's `-timeout` (microseconds, socket I/O) is the correct knob
and was already present at 5 s. Always validate a new flag set against the real
camera before restarting a running service.

## Rollback

The previous binary is kept alongside:

```bash
cd ~/onvif-viewer
ls onvif-viewer.bak-*            # timestamped backup
pkill -f './onvif-viewer$'
cp onvif-viewer.bak-<stamp> onvif-viewer
```

The viewer is started manually (no systemd unit, no boot autostart).

## Deployment verification (2026-09-18 02:15)

- new binary running, listening on 7878, HTTP 200
- ffmpeg launched with the new arg set
- HLS playlist advancing, 7 segments, `#EXTINF:2.00` entries
- survived a deliberate session-exhaustion test (2 slots filled) still running
- `go test ./internal/stream/` passes

## Still open

- Whether the camera stops media because of a session-count interaction or an
  independent firmware timer. The new probe will say which on the next stall:
  a `454` log means the table filled; `"session granted, stream silent"` means
  the camera stopped feeding a valid session.
- `-c:v copy` is still used into HLS; `+igndts` mitigates the bad timestamps
  but a re-encode would be more robust if segment timing issues persist.
