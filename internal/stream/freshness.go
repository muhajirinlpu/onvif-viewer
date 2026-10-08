package stream

import (
	"bufio"
	"bytes"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"dengan.dev/camera-streamer/internal/models"
)

const (
	freshnessThreshold   = 120 * time.Second
	freshnessWarmup      = 3 * time.Minute
	freshnessCooldown    = 10 * time.Minute
	freshnessConsecutive = 3
)

// hlsFreshness compares elapsed playlist media duration with elapsed wall time.
// It does not infer capture time or viewer latency from segment names or mtimes.
// It belongs to one ffmpeg run and must not be shared across reconnects.
type hlsFreshness struct {
	lastSequence                      int64
	lastDurations                     map[int64]time.Duration
	lastWall, baseline, cooldownUntil time.Time
	mediaElapsed                      time.Duration
	high                              int
}

type freshnessSample struct {
	updated                                 bool
	valid                                   bool
	wallSeconds, mediaSeconds, driftSeconds float64
	recover                                 bool
}

func (f *hlsFreshness) resetRun(now time.Time) {
	f.lastDurations = nil
	f.lastWall = time.Time{}
	f.baseline = time.Time{}
	f.mediaElapsed = 0
	f.high = 0
	f.cooldownUntil = now.Add(freshnessCooldown)
}

// parseHLSClock accepts only a bounded, complete HLS window. An explicit
// discontinuity or missing duration makes this sample unsuitable for rate math.
func parseHLSClock(dir string) (int64, map[int64]time.Duration, bool) {
	file, err := os.Open(filepath.Join(dir, "stream.m3u8"))
	if err != nil {
		return 0, nil, false
	}
	defer file.Close()
	buf, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	if err != nil || len(buf) > 64*1024 || len(buf) == 0 || buf[len(buf)-1] != '\n' || !bytes.HasPrefix(buf, []byte("#EXTM3U\n")) {
		return 0, nil, false
	}
	scan := bufio.NewScanner(bytes.NewReader(buf))
	seq := int64(-1)
	durations := map[int64]time.Duration{}
	pending := time.Duration(0)
	var segmentNames = map[int64]string{}
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		switch {
		case line == "#EXT-X-DISCONTINUITY" || strings.HasPrefix(line, "#EXT-X-DISCONTINUITY-SEQUENCE:"):
			return 0, nil, false
		case strings.HasPrefix(line, "#EXT-X-PROGRAM-DATE-TIME:"):
			// Muxer metadata is not a trusted camera capture timestamp.
		case strings.HasPrefix(line, "#EXT-X-MEDIA-SEQUENCE:"):
			seq, err = strconv.ParseInt(strings.TrimPrefix(line, "#EXT-X-MEDIA-SEQUENCE:"), 10, 64)
			if err != nil || seq < 0 {
				return 0, nil, false
			}
		case strings.HasPrefix(line, "#EXTINF:"):
			raw := strings.SplitN(strings.TrimPrefix(line, "#EXTINF:"), ",", 2)[0]
			seconds, e := strconv.ParseFloat(raw, 64)
			if e != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds <= 0 || seconds > 60 {
				return 0, nil, false
			}
			pending = time.Duration(seconds * float64(time.Second))
		case line != "" && !strings.HasPrefix(line, "#"):
			if seq < 0 || pending == 0 || len(durations) >= 100 {
				return 0, nil, false
			}
			index := seq + int64(len(durations))
			durations[index] = pending
			segmentNames[index] = line
			pending = 0
		}
	}
	if scan.Err() != nil || pending != 0 || len(durations) == 0 {
		return 0, nil, false
	}
	// A segment is only delivered when the playlist URI resolves to a regular
	// local file. Never infer a filename from the media sequence.
	for _, name := range segmentNames {
		if filepath.Base(name) != name || !strings.HasSuffix(name, ".ts") {
			return 0, nil, false
		}
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || !info.Mode().IsRegular() {
			return 0, nil, false
		}
	}
	return seq, durations, true
}

func (f *hlsFreshness) observe(dir string, now time.Time, provider models.ProviderKind) freshnessSample {
	seq, durations, ok := parseHLSClock(dir)
	if !ok {
		f.lastDurations = nil
		f.high = 0
		return freshnessSample{updated: true}
	}
	return f.observeWindow(seq, durations, now, provider)
}

func (f *hlsFreshness) observeWindow(seq int64, durations map[int64]time.Duration, now time.Time, provider models.ProviderKind) freshnessSample {
	if f.lastDurations != nil && seq == f.lastSequence {
		if !now.After(f.lastWall) {
			return freshnessSample{}
		}
		for i, d := range f.lastDurations {
			if next, exists := durations[i]; exists && next != d {
				f.lastDurations = nil
				f.high = 0
				return freshnessSample{updated: true}
			}
		}
		if len(durations) < len(f.lastDurations) {
			f.lastDurations = nil
			f.high = 0
			return freshnessSample{updated: true}
		}
		if len(durations) > len(f.lastDurations) {
			// A newly appended tail at the same sequence is real advancement.
			// Account for each newly completed media duration once.
			var advance time.Duration
			for i := f.lastSequence + int64(len(f.lastDurations)); i < f.lastSequence+int64(len(durations)); i++ {
				advance += durations[i]
			}
			if now.Sub(f.lastWall) > advance*3+30*time.Second {
				f.lastDurations = nil
				f.high = 0
				return freshnessSample{updated: true}
			}
			f.mediaElapsed += advance
			f.lastDurations = durations
			f.lastWall = now
			return f.elapsedSample(now, provider)
		}
		// An unchanged playlist has no new elapsed media.
		return freshnessSample{}
	}
	if f.lastDurations == nil {
		f.lastSequence = seq
		f.lastDurations = durations
		f.lastWall = now
		f.baseline = now
		f.mediaElapsed = 0
		return freshnessSample{updated: true}
	}
	delta := seq - f.lastSequence
	if delta == 0 {
		return freshnessSample{}
	}
	if delta < 0 || delta > int64(len(f.lastDurations)) || !now.After(f.lastWall) {
		// Missing an entire HLS window means no continuous media clock evidence.
		f.lastDurations = nil
		f.high = 0
		return freshnessSample{updated: true}
	}
	var advance time.Duration
	for i := f.lastSequence; i < seq; i++ {
		d, exists := f.lastDurations[i]
		if !exists {
			f.lastDurations = nil
			f.high = 0
			return freshnessSample{updated: true}
		}
		advance += d
	}
	// If HLS windows overlap, their completed durations must agree. A full
	// non-overlapping rotation is also continuous when every prior segment was
	// accounted for; a larger gap is invalidated above.
	overlap := 0
	for i, d := range f.lastDurations {
		if next, exists := durations[i]; exists {
			overlap++
			if next != d {
				f.lastDurations = nil
				f.high = 0
				return freshnessSample{updated: true}
			}
		}
	}
	if overlap == 0 && delta != int64(len(f.lastDurations)) {
		f.lastDurations = nil
		f.high = 0
		return freshnessSample{updated: true}
	}
	// A long source interruption cannot be diagnosed as clock skew. Re-anchor.
	if now.Sub(f.lastWall) > advance*3+30*time.Second {
		f.lastDurations = nil
		f.high = 0
		return freshnessSample{updated: true}
	}
	f.mediaElapsed += advance
	f.lastSequence = seq
	f.lastDurations = durations
	f.lastWall = now
	return f.elapsedSample(now, provider)
}

func (f *hlsFreshness) elapsedSample(now time.Time, provider models.ProviderKind) freshnessSample {
	wall := now.Sub(f.baseline)
	drift := f.mediaElapsed - wall
	s := freshnessSample{updated: true, valid: true, wallSeconds: wall.Seconds(), mediaSeconds: f.mediaElapsed.Seconds(), driftSeconds: drift.Seconds()}
	if provider == models.ProviderTuya && wall >= freshnessWarmup && drift >= freshnessThreshold && !now.Before(f.cooldownUntil) {
		f.high++
	} else {
		f.high = 0
	}
	if f.high >= freshnessConsecutive {
		s.recover = true
		f.high = 0
		f.cooldownUntil = now.Add(freshnessCooldown)
	}
	return s
}
