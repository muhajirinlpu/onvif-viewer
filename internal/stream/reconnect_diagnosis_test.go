package stream

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"dengan.dev/camera-streamer/internal/logger"
	"dengan.dev/camera-streamer/internal/models"
)

// A fake RTSP endpoint records actual DESCRIBE exchanges, not a test-only
// observer in the manager. DESCRIBE is the step that starts another Tuya media
// producer; a TCP reachability check alone must remain permissible.
func reconnectRTSPServer(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var describes atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				r := bufio.NewReader(conn)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					method := strings.Fields(line)
					cseq := "1"
					for {
						h, err := r.ReadString('\n')
						if err != nil {
							return
						}
						if strings.TrimSpace(h) == "" {
							break
						}
						if strings.HasPrefix(strings.ToLower(h), "cseq:") {
							cseq = strings.TrimSpace(h[5:])
						}
					}
					if len(method) == 0 {
						return
					}
					code := "200 OK"
					if method[0] == "DESCRIBE" {
						describes.Add(1)
						code = "404 Not Found"
					}
					if _, err := fmt.Fprintf(conn, "RTSP/1.0 %s\r\nCSeq: %s\r\nContent-Length: 0\r\n\r\n", code, cseq); err != nil {
						return
					}
				}
			}()
		}
	}()
	return "rtsp://" + ln.Addr().String() + "/tuya_test", &describes
}

func reconnectTestManager(t *testing.T) *Manager {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "ffmpeg-exits")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	l, err := logger.NewLogger(filepath.Join(dir, "logs.db"))
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(filepath.Join(dir, "hls"), l)
	m.ffmpegBin = bin
	t.Cleanup(func() { m.Shutdown(); l.Close() })
	return m
}

func waitForReconnectLog(t *testing.T, m *Manager, id string) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		logs, err := m.logger.GetStreamLogs(id, 20)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range logs {
			if strings.Contains(entry.Message, "Reconnection attempt 1/") {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("reconnect decision not logged within 4s")
}

func TestTuyaReconnectSkipsDuplicateMediaDial(t *testing.T) {
	rtspURL, describes := reconnectRTSPServer(t)
	m := reconnectTestManager(t)
	info, err := m.StartStreamForProvider("tuya:test", rtspURL, models.ProviderTuya)
	if err != nil {
		t.Fatal(err)
	}
	waitForReconnectLog(t, m, info.ID)
	if got := describes.Load(); got != 0 {
		t.Fatalf("Tuya reconnect made %d redundant RTSP DESCRIBE(s), want none", got)
	}
}

func TestONVIFReconnectStillProbesMediaOnLoopback(t *testing.T) {
	rtspURL, describes := reconnectRTSPServer(t)
	m := reconnectTestManager(t)
	info, err := m.StartStreamForProvider("onvif-test", rtspURL, models.ProviderONVIF)
	if err != nil {
		t.Fatal(err)
	}
	waitForReconnectLog(t, m, info.ID)
	if got := describes.Load(); got != 1 {
		t.Fatalf("ONVIF reconnect made %d RTSP DESCRIBE(s), want one even on loopback", got)
	}
}

func TestReconnectMediaProbeOnlySkippedForTuyaLoopbackEngine(t *testing.T) {
	for _, tc := range []struct {
		name     string
		provider models.ProviderKind
		url      string
		want     bool
	}{
		{"tuya IPv4", models.ProviderTuya, "rtsp://127.0.0.1:1234/media", true},
		{"tuya IPv6", models.ProviderTuya, "rtsp://[::1]:1234/media", true},
		{"tuya localhost", models.ProviderTuya, "rtsp://localhost:1234/media", true},
		{"onvif loopback", models.ProviderONVIF, "rtsp://127.0.0.1:1234/media", false},
		{"legacy provider loopback", "", "rtsp://127.0.0.1:1234/media", false},
		{"tuya LAN", models.ProviderTuya, "rtsp://192.0.2.5:1234/media", false},
		{"tuya malformed", models.ProviderTuya, "rtsp://%", false},
		{"tuya no port", models.ProviderTuya, "rtsp://localhost/media", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTuyaLoopbackSource(tc.provider, tc.url); got != tc.want {
				t.Errorf("isTuyaLoopbackSource(%q, %q) = %v, want %v", tc.provider, tc.url, got, tc.want)
			}
		})
	}
}
