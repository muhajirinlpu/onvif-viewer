package tuyartsp

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"dengan.dev/camera-streamer/internal/go2rtc/core"
)

// fakeProducer is a core.Producer that hands out one video track, so the RTSP
// handshake can be exercised without a camera and without any external binary.
type fakeProducer struct {
	codec   *core.Codec
	medias  []*core.Media
	track   *core.Receiver
	started chan struct{}
	stopped chan struct{}
}

func newFakeProducer() *fakeProducer {
	codec := &core.Codec{Name: core.CodecH264, ClockRate: 90000, PayloadType: 96}
	media := &core.Media{Kind: core.KindVideo, Direction: core.DirectionRecvonly, Codecs: []*core.Codec{codec}}
	return &fakeProducer{
		codec:   codec,
		medias:  []*core.Media{media},
		started: make(chan struct{}),
		stopped: make(chan struct{}),
	}
}

func (f *fakeProducer) GetMedias() []*core.Media { return f.medias }

func (f *fakeProducer) GetTrack(media *core.Media, codec *core.Codec) (*core.Receiver, error) {
	if f.track == nil {
		f.track = core.NewReceiver(media, codec)
	}
	return f.track, nil
}

func (f *fakeProducer) Start() error { close(f.started); return nil }
func (f *fakeProducer) Stop() error  { close(f.stopped); return nil }

// rtspExchange performs a raw RTSP exchange and returns the status line, the
// headers and the body, so the test reads exactly what ffmpeg would read.
func rtspExchange(t *testing.T, conn net.Conn, method, url string, seq int, extra map[string]string) (string, map[string]string, string) {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s RTSP/1.0\r\nCSeq: %d\r\n", method, url, seq)
	for k, v := range extra {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("\r\n")
	if _, err := conn.Write([]byte(b.String())); err != nil {
		t.Fatalf("write %s: %v", method, err)
	}

	reader := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read %s status: %v", method, err)
	}
	status = strings.TrimRight(status, "\r\n")
	headers := map[string]string{}
	contentLength := 0
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read %s headers: %v", method, err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		headers[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
		if strings.EqualFold(strings.TrimSpace(key), "content-length") {
			fmt.Sscanf(strings.TrimSpace(value), "%d", &contentLength)
		}
	}
	body := ""
	if contentLength > 0 {
		buf := make([]byte, contentLength)
		if _, err := readFull(reader, buf); err != nil {
			t.Fatalf("read %s body: %v", method, err)
		}
		body = string(buf)
	}
	return status, headers, body
}

func readFull(reader *bufio.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := reader.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// TestServerServesDescribeSetupPlay is the protocol-level proof that the
// in-process server is a working RTSP endpoint: OPTIONS answers, DESCRIBE
// returns an SDP with the producer's real codec, SETUP allocates interleaved
// channels and PLAY starts the producer.
func TestServerServesDescribeSetupPlay(t *testing.T) {
	producer := newFakeProducer()
	server := New()
	server.SetDialer(func(source string) (core.Producer, error) {
		if !strings.HasPrefix(source, "tuya://") {
			t.Fatalf("dialer got %q, want a tuya:// source", source)
		}
		return producer, nil
	})
	if err := server.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	if err := server.AddStream("tuya_cam1", "tuya://host?device_id=cam1"); err != nil {
		t.Fatalf("AddStream: %v", err)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", server.Port())
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	url := "rtsp://" + addr + "/tuya_cam1"
	if status, _, _ := rtspExchange(t, conn, "OPTIONS", url, 1, nil); !strings.Contains(status, "200") {
		t.Fatalf("OPTIONS status = %q", status)
	}

	status, headers, sdp := rtspExchange(t, conn, "DESCRIBE", url, 2, map[string]string{"Accept": "application/sdp"})
	if !strings.Contains(status, "200") {
		t.Fatalf("DESCRIBE status = %q", status)
	}
	if !strings.Contains(sdp, "m=video") || !strings.Contains(sdp, "H264/90000") {
		t.Fatalf("SDP does not describe the producer video track:\n%s", sdp)
	}
	if !strings.Contains(headers["content-type"], "application/sdp") {
		t.Fatalf("DESCRIBE content-type = %q", headers["content-type"])
	}

	status, headers, _ = rtspExchange(t, conn, "SETUP", url+"/trackID=0", 3,
		map[string]string{"Transport": "RTP/AVP/TCP;unicast;interleaved=0-1"})
	if !strings.Contains(status, "200") {
		t.Fatalf("SETUP status = %q", status)
	}
	if !strings.Contains(headers["transport"], "interleaved=0-1") {
		t.Fatalf("SETUP transport = %q", headers["transport"])
	}

	status, _, _ = rtspExchange(t, conn, "PLAY", url, 4, nil)
	if !strings.Contains(status, "200") {
		t.Fatalf("PLAY status = %q", status)
	}

	// PLAY must start the producer: that is what makes ffmpeg receive frames.
	select {
	case <-producer.started:
	case <-time.After(3 * time.Second):
		t.Fatal("producer was never started after PLAY")
	}
}

// TestServerRejectsUnknownStream proves an unknown name fails the handshake
// rather than hanging or silently serving another camera.
func TestServerRejectsUnknownStream(t *testing.T) {
	server := New()
	server.SetDialer(func(string) (core.Producer, error) {
		t.Fatal("dialer must not be called for an unknown stream")
		return nil, nil
	})
	if err := server.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	addr := fmt.Sprintf("127.0.0.1:%d", server.Port())
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	status, _, _ := rtspExchange(t, conn, "DESCRIBE", "rtsp://"+addr+"/nope", 1, nil)
	if !strings.Contains(status, "404") {
		t.Fatalf("DESCRIBE unknown stream status = %q, want 404", status)
	}
}

// TestServerCloseStopsProducerAndReleasesPort proves Close is safe with a live
// connection and that the listener is actually released.
func TestServerCloseStopsProducerAndReleasesPort(t *testing.T) {
	producer := newFakeProducer()
	server := New()
	server.SetDialer(func(string) (core.Producer, error) { return producer, nil })
	if err := server.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if err := server.AddStream("tuya_cam1", "tuya://host?device_id=cam1"); err != nil {
		t.Fatalf("AddStream: %v", err)
	}
	port := server.Port()

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	url := "rtsp://" + addr + "/tuya_cam1"
	rtspExchange(t, conn, "DESCRIBE", url, 1, nil)

	if err := server.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	select {
	case <-producer.stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("producer was not stopped by Close")
	}

	// The port must be bindable again, otherwise every restart would leak one.
	deadline := time.Now().Add(3 * time.Second)
	for {
		listener, err := net.Listen("tcp", addr)
		if err == nil {
			_ = listener.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("port %d not released after Close: %v", port, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestServerAddRemoveStreamIsLive proves a stream can be added and removed while
// the server is running, which is what lets a new camera appear without a
// restart.
func TestServerAddRemoveStreamIsLive(t *testing.T) {
	server := New()
	server.SetDialer(func(string) (core.Producer, error) { return newFakeProducer(), nil })
	if err := server.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	if err := server.AddStream("tuya_a", "tuya://host?device_id=a"); err != nil {
		t.Fatalf("AddStream: %v", err)
	}
	if names := server.Streams(); len(names) != 1 || names[0] != "tuya_a" {
		t.Fatalf("Streams() = %v", names)
	}
	server.RemoveStream("tuya_a")
	if names := server.Streams(); len(names) != 0 {
		t.Fatalf("Streams() after remove = %v", names)
	}
}

// TestServerListenRejectsBadAddress makes sure a bind failure is reported rather
// than swallowed: the engine must be able to tell the caller the endpoint is
// unusable.
func TestServerListenRejectsBadAddress(t *testing.T) {
	server := New()
	if err := server.Listen("127.0.0.1:1"); err == nil {
		_ = server.Close()
		t.Skip("binding port 1 succeeded (running as root); cannot assert failure")
	}
	// A second Listen on an already-bound server is a programming error.
	good := New()
	if err := good.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = good.Close() })
	if err := good.Listen("127.0.0.1:0"); err == nil {
		t.Fatal("second Listen was accepted")
	}
}

var _ = context.Background
