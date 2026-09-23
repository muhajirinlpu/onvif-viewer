# Tuya frame pacing: root cause, fix, and the measurements

**Defect:** the Tuya SD leg ran at 76% of realtime (segments declaring 4.0s
arriving every 5.3s) while ONVIF through the identical pipeline ran at 103%.
The user saw the picture stutter every ~5 seconds.

**Status:** root cause identified with a decisive measurement; fix implemented
and measured; all existing tests pass unmodified.

---

## 1. Where the time goes — camera, not bridge

Measured with `cmd/tuyapace`: ONE camera WebRTC session, the production
`tuyartsp.Server` with its production `tuya.Dial`, instrumented at BOTH ends of
the bridge at once. A second session would have contaminated the result, because
the camera accepts very few concurrent WebRTC sessions.

| point | what it measures | result |
| --- | --- | --- |
| A | the vendored WebRTC read loop (upstream of every line of our code) | 13.02 fps |
| B | a real RTSP client on the loopback endpoint (what ffmpeg receives) | 13.02 fps |
| | **B/A ratio** | **1.000** |

- **Our `internal/tuyartsp` RTP pump is NOT the throttle.** It delivered
  indistinguishable from 100% of what the producer handed it, in every sample.
  `server.go` has no sleep, no pacing ticker, no small blocking channel on this
  path; this measurement rules the whole layer in-or-out rather than reasoning
  about it.
- **We lose nothing:** sequence gaps **0**, out-of-order **0**. We receive every
  packet the camera sends.
- **The camera is not merely slow — it is slow against its own clock.** The
  inter-frame RTP spacing is *exactly* 4500 ticks at the 90kHz H.264 clock,
  median AND mean, histogram `{4500: 480}` / `{4500: 608}` across samples. That
  is a perfect 1/20s stamp grid. Yet only ~13 frames/s arrive.

So the camera stamps a flawless 20fps timeline and delivers ~68% of it. The
media clock therefore advances ~1.18x faster than wall time.

## 2. Why that becomes a stutter

`-c:v copy` into MPEG-TS hands the muxer two things that disagree:

- the timeline says 4.0s of media (80 frames at the stamped 20fps), and
- delivery says those 80 frames took 5.3s to arrive.

The muxer writes a segment declaring 4.0s that appears every 5.3s, so a player
consumes media ~21% faster than the camera produces it and its buffer underruns
every few seconds — exactly the reported ~5s stutter. Nothing is broken in the
HLS layer, the muxer or the browser; the input time base is simply wrong.

## 3. The fix

`-use_wallclock_as_timestamps 1` on the Tuya SD input only, i.e. time the input
by arrival instead of by the camera's clock. Implemented as a third output path,
`OutputTuyaSDWallclock`, selected by a provider-keyed chooser so the ONVIF/SD
argument list (pinned literally by `TestSDArgumentsAreUnchangedFromHEAD`) cannot
acquire a Tuya-only flag.

Measured candidates, same engine, same camera, real ffmpeg muxer:

| variant | result |
| --- | --- |
| baseline (`-c:v copy`) | ffmpeg `speed=0.488x`; playlist advanced at 0.49x |
| `-use_wallclock_as_timestamps 1` | ffmpeg `speed=1.017x`; **playlist 99.4%–100.1% of realtime** |
| `+ -fps_mode vfr` | 0 playlist advances in 70s |
| `-fps_mode passthrough` | no playlist at all |
| `-framerate 20` (input) | no playlist |
| `-setts 1` | no playlist |

## 4. Acceptance

Sampled CONCURRENTLY for 120s (both are Tuya cameras behind the same cloud, so a
sequential comparison would have attributed the camera's own session flakiness
to the change):

| | NEW args (dev :7996) | OLD args (live :7878) |
| --- | --- | --- |
| advances | 22 | 22 |
| gap mean / min / max | 5.596 / 5.419 / 5.633s | 5.575 / 5.022 / 5.823s |
| declared segment | 5.602s | **4.000s** |
| **% of realtime** | **100.1%** | **71.7%** |

ONVIF control unchanged: 2.007s declared / 1.976s gap = **101.5%** (was 102.3%).
Real decoded frames, `image2`, never `-f null`: **40/40** from the new HLS,
H.264 Main, 640x360, 20fps; newest segment 80 frames / 5.674s; no drop/dup
errors on decode. Same from the old live HLS (80 frames / 4.0s).

## 5. What is NOT proved

- A single run reached only ~90% of the requested window before the **camera
  closed the WebRTC session at ~70s** (`webrtc: closed`, ffmpeg respawned by the
  supervisor, segments stitched across restarts). This is the camera's own
  session flakiness, and no cadence claim here relies on that run.
- The Tuya camera delivers 13–14 of 20 fps *on this installation and network*.
  That is a property of this camera's P2P path, not of the fix.
- Measuring the engine concurrently with the live stream was avoided by design;
  the engine-rate samples came from my own single-session harness only.

## 6. A hazard worth remembering

The first end-to-end harness run looked like it had proved the fix and had proved
the opposite: it wired `tuyaengine.Bridge.StartStream`, which calls the
TWO-argument `StreamStarter`, and `stream.Manager.StartStream` defaults the
provider to ONVIF. Production supplies `main.providerStarter`, which is what tags
the stream `tuya`. A harness that skips that seam exercises the ONVIF output path
for a Tuya camera and faithfully reproduces the pre-fix stutter.
`cmd/pacedev` now mirrors the production seam.

## 7. UPDATE — `-use_wallclock_as_timestamps` was only half the fix (superseded)

Section 3 above is correct as far as it goes: wallclock did cure the **declared
segment duration vs wall arrival** mismatch (71.7% -> 100.1%), and that mismatch
was real. But it is NOT sufficient, and on its own it *introduces* the visible
blipping. Measured later, same engine, same camera, interleaved repeats:

| mode | p50 gap | p99 gap | max gap | near-duplicate | freeze-scale |
| --- | --- | --- | --- | --- | --- |
| baseline (`copy`, camera clock) | 0.0500 | 0.0500 | 0.0500 | 0% | 0% |
| `-use_wallclock_as_timestamps 1` | 0.0526 | 0.2457 | **0.5439** | **10.0%** | 0.9% |
| same, second run | 0.0680 | 0.3943 | **0.6317** | 4.4% | **2.1%** |
| **`-itsscale 1.50`** (shipped) | **0.0750** | **0.0750** | **0.0750** | **0%** | **0%** |
| same, second run | 0.0750 | 0.0750 | 0.0750 | 0% | 0% |
| wallclock, simultaneous 3rd run | 0.0526 | 0.1153 | 0.3215 | **26.7%** | **1.8%** |
| wallclock, simultaneous 4th run | 0.0637 | 0.1229 | 0.4149 | 6.4% | **1.9%** |

Why: `-use_wallclock_as_timestamps 1` timestamps every frame by ARRIVAL. The P2P
path delivers frames in bursts, so arrival spacing — not the camera's 20fps grid —
becomes the timestamp spacing. Frames land duplicated (`gap 0.0004s`, 10% of them)
and then stall (`gap 0.54s`, 2%). A player handed a 0.54s hole in a `-c:v copy`
stream has nothing to interpolate with, so it visibly freezes, and the accumulated
drift is never corrected because `copy` cannot retime frames. That is the
"blipping every few seconds" report, and it is a *consequence of the wallclock fix*,
not a camera fault.

`-itsscale 1.50` instead rescales the camera's existing timestamps to match observed
arrival (`20fps stamped / ~14.3fps delivered` = 1.399) and leaves them untouched
otherwise, so the inter-frame grid stays perfectly uniform at 1/14.29fps.

Factor selection. The camera's delivered rate is NOT constant: MEASURED 13.109
fps over a 184s capture (2292 frames / 174.84s -> implied factor 1.526) but ~14.3
fps over short samples (-> 1.40). No single factor is exactly right, so 1.50 is
chosen and biased HIGH deliberately. Over-declaring (factor too high) makes the
declared timeline slower than reality: the player buffers more, latency grows —
smooth but stale. Under-declaring makes the timeline faster than reality: the
player drains its buffer and STUTTERS. MEASURED drift, second half of a 100s arm
vs the first: **-14.3% at 1.40** and **-3.3% at 1.46** (both draining the buffer
toward the stutter), **~0 at 1.5**. Being wrong high costs latency; being wrong
low costs the picture.

Accepted cost: live latency settles at ~20s (vs the old stream's ~8s when it was
healthy, and 0-205s when it was not). That is inherent to 5.6s segments with
`hls_list_size 5` plus hls.js's `liveSyncDurationCount 3`; it can only be reduced
by shortening segments, which needs a re-encode this host cannot afford.

CONFIRMED ON THE LIVE DEPLOYMENT after shipping (headless Chromium, 240s per
stream, sampling `video.currentTime` / `buffered` / hls.js `latency`):

| | before (wallclock) | after (itsscale 1.50) |
| --- | --- | --- |
| Tuya playback | 23.2% - 106.6%, wild swings | **100.0%** |
| Tuya latency | **0 -> 205s** | **19.5 - 25.8s, stable** |
| Tuya blips | froze at t=44.6s and never recovered | startup transient only |
| ONVIF control | 99.9% | 99.9% |

Rejected alternatives: `-c:v libx264 -r 20` (CFR transcode, perfect 0.05s grid but
**0.74x realtime**, not viable); `-fps_mode vfr` / `-fps_mode passthrough` /
`-framerate 20` / `-setts 1` (no usable playlist).
