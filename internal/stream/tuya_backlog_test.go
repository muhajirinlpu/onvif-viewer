package stream

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dengan.dev/camera-streamer/internal/go2rtc/core"
	"dengan.dev/camera-streamer/internal/tuyartsp"
	"github.com/pion/rtp"
)

// Synthetic source: video capture ordinals live in a user-data SEI, not in
// arrival times or muxer timestamps. No camera or application DB is opened.
// The clocks are deliberately inconsistent: video stamps the existing 20fps
// grid; 1.50 video-only scaling yields 75ms/frame, while audio advances 60ms.
// This compresses hours of small real-world skew into seconds of packet replay.
type backlogProducer struct {
	medias     []*core.Media
	tracks     []*core.Receiver
	nal        []byte
	pnals      [][]byte
	once       sync.Once
	stop       chan struct{}
	done       chan struct{}
	frames     int
	latest     atomic.Int64
	emitted    chan struct{}
	checkpoint chan struct{}
	resume     chan struct{}
}

func (p *backlogProducer) GetMedias() []*core.Media { return p.medias }
func (p *backlogProducer) GetTrack(m *core.Media, c *core.Codec) (*core.Receiver, error) {
	for i, media := range p.medias {
		if m == media {
			return p.tracks[i], nil
		}
	}
	return nil, core.ErrCantGetTrack
}
func (p *backlogProducer) Stop() error { p.once.Do(func() { close(p.stop) }); return nil }
func (p *backlogProducer) Start() error {
	defer close(p.done)
	var seq uint16
	var audioTimestamp uint32
	for i := 0; i < p.frames; i++ {
		select {
		case <-p.stop:
			return nil
		default:
		}
		// Zero-free ASCII marker survives AnnexB escaping and copy muxing.
		marker := []byte(fmt.Sprintf("capture-%08d", i))
		sei := append([]byte{6, 5, byte(16 + len(marker))}, []byte("synthetic-clock!")...)
		sei = append(sei, marker...)
		sei = append(sei, 0x80)
		p.tracks[0].WriteRTP(&rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 96, Timestamp: uint32(i * 4500), SequenceNumber: seq, SSRC: 1}, Payload: sei})
		seq++
		frame := p.nal
		if i%80 == 0 {
			frame = p.nal
		} else {
			frame = p.pnals[i%80-1]
		}
		p.tracks[0].WriteRTP(&rtp.Packet{Header: rtp.Header{Version: 2, Marker: true, PayloadType: 96, Timestamp: uint32(i * 4500), SequenceNumber: seq, SSRC: 1}, Payload: frame})
		seq++
		// Build 144 seconds of skew, then resume equal rates without resetting
		// the clocks. In the final phase HLS cadence is normal but footage is old.
		samples := 600
		if i < 9600 {
			samples = 480
		}
		p.tracks[1].WriteRTP(&rtp.Packet{Header: rtp.Header{Version: 2, Marker: true, PayloadType: 97, Timestamp: audioTimestamp, SequenceNumber: uint16(i), SSRC: 2}, Payload: bytes.Repeat([]byte{0xd5}, samples)})
		audioTimestamp += uint32(samples)
		p.latest.Store(int64(i))
		if i == 11999 {
			close(p.checkpoint)
			select {
			case <-p.resume:
			case <-p.stop:
				return nil
			}
		}
		// A bounded serial replay: don't overflow go2rtc's packet queues.
		time.Sleep(time.Millisecond)
	}
	close(p.emitted)
	// Stay open so EOF cannot flush the muxer's queue and conceal the backlog.
	<-p.stop
	return nil
}

func TestTuyaMuxDoesNotAccumulateCaptureBacklog(t *testing.T) {
	if testing.Short() {
		t.Skip("synthetic FFmpeg replay")
	}
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("ffmpeg unavailable")
	}
	dir := t.TempDir()
	fixture := filepath.Join(dir, "fixture.h264")
	cmd := exec.Command("ffmpeg", "-v", "error", "-threads", "1", "-f", "lavfi", "-i", "color=size=16x16:rate=20", "-frames:v", "81", "-c:v", "libx264", "-threads", "1", "-preset", "ultrafast", "-tune", "zerolatency", "-x264-params", "keyint=80:min-keyint=80:scenecut=0:repeat-headers=1", "-f", "h264", fixture)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fixture: %v %s", err, out)
	}
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	nalus := splitBacklogNALs(data)
	var idr, sps, pps []byte
	var pnals [][]byte
	for _, n := range nalus {
		switch n[0] & 31 {
		case 5:
			idr = n
		case 7:
			sps = n
		case 8:
			pps = n
		case 1:
			pnals = append(pnals, n)
		}
	}
	if len(idr) == 0 || len(sps) == 0 || len(pps) == 0 || len(pnals) != 79 {
		t.Fatal("missing fixture NALs")
	}
	// Preserve the real SD keyframe cadence: 80 frames at the scaled 75ms grid
	// makes 6s HLS segments. No random encoded-frame drops.
	stap := []byte{24}
	for _, n := range [][]byte{sps, pps, idr} {
		stap = binary.BigEndian.AppendUint16(stap, uint16(len(n)))
		stap = append(stap, n...)
	}
	vc := &core.Codec{Name: core.CodecH264, ClockRate: 90000, PayloadType: 96}
	ac := &core.Codec{Name: core.CodecPCMA, ClockRate: 8000, Channels: 1, PayloadType: 97}
	vm := &core.Media{Kind: core.KindVideo, Direction: core.DirectionRecvonly, Codecs: []*core.Codec{vc}}
	am := &core.Media{Kind: core.KindAudio, Direction: core.DirectionRecvonly, Codecs: []*core.Codec{ac}}
	p := &backlogProducer{medias: []*core.Media{vm, am}, tracks: []*core.Receiver{core.NewReceiver(vm, vc), core.NewReceiver(am, ac)}, nal: stap, pnals: pnals, stop: make(chan struct{}), done: make(chan struct{}), frames: 14400, emitted: make(chan struct{}), checkpoint: make(chan struct{}), resume: make(chan struct{})}
	server := tuyartsp.New()
	server.SetDialer(func(string) (core.Producer, error) { return p, nil })
	if err := server.AddStream("synthetic", "tuya://synthetic"); err != nil {
		t.Fatal(err)
	}
	if err := server.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	outDir := filepath.Join(dir, "hls")
	if err := os.Mkdir(outDir, 0700); err != nil {
		t.Fatal(err)
	}
	m := &Manager{}
	args := m.ffmpegArgsFor(fmt.Sprintf("rtsp://127.0.0.1:%d/synthetic", server.Port()), outDir, OutputTuyaSDRetimed)
	// Production timing/mux args remain unchanged. Constrain audio codec/filter
	// threads on the shared host.
	args = append([]string{"-v", "error", "-threads", "1", "-filter_threads", "1"}, args...)
	encoder := exec.Command("ffmpeg", args...)
	var logs bytes.Buffer
	encoder.Stderr = &logs
	if err := encoder.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = encoder.Process.Kill(); _ = encoder.Wait() }()
	select {
	case <-p.checkpoint:
	case <-time.After(40 * time.Second):
		t.Fatal("checkpoint timeout")
	}
	first := settledBacklogTail(t, outDir)
	close(p.resume)
	// Read the tail while live; terminating FFmpeg would flush and conceal it.
	select {
	case <-p.emitted:
	case <-time.After(40 * time.Second):
		t.Fatalf("synthetic source incomplete: newest=%d", p.latest.Load())
	}
	latest := settledBacklogTail(t, outDir)
	advance := float64(latest-first) * .075
	t.Logf("equal-clock phase: capture edge advance=%.3fs for 180.000s source advance; first=%d latest=%d", advance, first, latest)
	age := float64(p.frames-1-latest) * .075
	t.Logf("source newest=%d tail capture=%d capture backlog=%.3fs", p.frames-1, latest, age)
	if advance < 174 || advance > 186 {
		t.Fatalf("tail cadence differs: %.3fs", advance)
	}
	if age > 10 {
		t.Fatalf("normal advancing HLS retains %.3fs of capture backlog (want <=10s): latest=%d", age, latest)
	}
	playlist, err := os.ReadFile(filepath.Join(outDir, "stream.m3u8"))
	if err != nil {
		t.Fatal(err)
	}
	var last string
	for _, line := range strings.Split(string(playlist), "\n") {
		if strings.HasSuffix(line, ".ts") {
			last = line
		}
	}
	probe := exec.Command("ffmpeg", "-v", "error", "-threads", "1", "-i", filepath.Join(outDir, last), "-map", "0:v", "-f", "null", "-")
	if output, err := probe.CombinedOutput(); err != nil || len(output) > 0 {
		t.Fatalf("tail decode: %v %s", err, output)
	}
	audioProbe := exec.Command("ffprobe", "-v", "error", "-select_streams", "a", "-show_entries", "stream=codec_name,sample_rate:packet=pts_time", "-of", "json", filepath.Join(outDir, last))
	output, err := audioProbe.CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	var audio struct {
		Streams []struct {
			CodecName  string `json:"codec_name"`
			SampleRate string `json:"sample_rate"`
		} `json:"streams"`
		Packets []struct {
			PTS string `json:"pts_time"`
		} `json:"packets"`
	}
	if err := json.Unmarshal(output, &audio); err != nil {
		t.Fatal(err)
	}
	if len(audio.Streams) == 0 || audio.Streams[0].CodecName != "aac" || audio.Streams[0].SampleRate != "8000" || len(audio.Packets) == 0 {
		t.Fatalf("missing honest-rate audio: %s", output)
	}
	firstPTS, err := strconv.ParseFloat(audio.Packets[0].PTS, 64)
	if err != nil {
		t.Fatal(err)
	}
	lastPTS, err := strconv.ParseFloat(audio.Packets[len(audio.Packets)-1].PTS, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("tail audio: %d AAC packets, PTS %.3f..%.3f", len(audio.Packets), firstPTS, lastPTS)
	// A 1s interleave budget permits up to 1s of AAC packets to arrive in the
	// following segment. Check continuous 1024/8000 packet spacing independently
	// of that boundary displacement; do not pretend this repairs clock skew.
	for i := 1; i < len(audio.Packets); i++ {
		previous, e := strconv.ParseFloat(audio.Packets[i-1].PTS, 64)
		if e != nil {
			t.Fatal(e)
		}
		next, e := strconv.ParseFloat(audio.Packets[i].PTS, 64)
		if e != nil {
			t.Fatal(e)
		}
		if next-previous < .1279 || next-previous > .1281 {
			t.Fatalf("AAC sample continuity lost: %.6f", next-previous)
		}
	}
	if len(audio.Packets) < 40 || len(audio.Packets) > 52 {
		t.Fatalf("audio content not segment-sized: %d packets", len(audio.Packets))
	}
}

func settledBacklogTail(t *testing.T, outDir string) int {
	t.Helper()
	// Allow the intentionally bounded producer/consumer queues to drain before
	// comparing clock-domain checkpoints. Require a stable live edge, not EOF.
	time.Sleep(time.Second)
	previous := backlogTail(t, outDir)
	stable := 0
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		next := backlogTail(t, outDir)
		if next == previous {
			stable++
		} else {
			stable = 0
		}
		if stable >= 10 {
			return next
		}
		previous = next
	}
	t.Fatal("synthetic edge did not settle")
	return -1
}

func backlogTail(t *testing.T, outDir string) int {
	t.Helper()
	playlist, err := os.ReadFile(filepath.Join(outDir, "stream.m3u8"))
	if err != nil {
		t.Fatalf("playlist: %v", err)
	}
	var segments []string
	for _, line := range strings.Split(string(playlist), "\n") {
		if strings.HasSuffix(line, ".ts") {
			segments = append(segments, line)
		}
	}
	if len(segments) < 3 {
		t.Fatalf("insufficient steady segments: %s", playlist)
	}
	last := segments[len(segments)-1]
	segment, err := os.ReadFile(filepath.Join(outDir, last))
	if err != nil {
		t.Fatal(err)
	}
	latest := -1
	for at := 0; at < len(segment); {
		j := bytes.Index(segment[at:], []byte("capture-"))
		if j < 0 {
			break
		}
		at += j
		if at+16 <= len(segment) {
			var n int
			if _, e := fmt.Sscanf(string(segment[at:at+16]), "capture-%08d", &n); e == nil && n > latest {
				latest = n
			}
		}
		at += 8
	}
	if latest < 0 {
		t.Fatalf("no capture SEI in %s", last)
	}
	if !strings.Contains(string(playlist), "#EXTINF:6.000000,") {
		t.Fatalf("not real 6s SD cadence: %s", playlist)
	}
	return latest
}

func splitBacklogNALs(b []byte) [][]byte {
	var out [][]byte
	start := -1
	for i := 0; i+3 < len(b); i++ {
		n := 0
		if b[i] == 0 && b[i+1] == 0 {
			if b[i+2] == 1 {
				n = 3
			} else if b[i+2] == 0 && b[i+3] == 1 {
				n = 4
			}
		}
		if n == 0 {
			continue
		}
		if start >= 0 && i > start {
			out = append(out, b[start:i])
		}
		start = i + n
		i += n - 1
	}
	if start >= 0 && start < len(b) {
		out = append(out, b[start:])
	}
	return out
}
