package tuyaengine

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// rtspStatus is the parsed outcome of a single RTSP exchange.
type rtspStatus struct {
	Code   int
	Reason string
	Body   string
}

// probeRTSP opens one RTSP connection to rawURL and performs the requested
// methods in order, returning the status of the last one. A transport failure is
// returned as an error; an RTSP-level failure is returned as a status code.
func probeRTSP(ctx context.Context, rawURL string, timeout time.Duration, methods ...string) (rtspStatus, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rtspStatus{}, fmt.Errorf("tuyaengine: parse rtsp url: %w", err)
	}
	host := parsed.Hostname()
	port := parsed.Port()
	if host == "" {
		return rtspStatus{}, fmt.Errorf("tuyaengine: rtsp url %q has no host", rawURL)
	}
	if port == "" {
		port = "554"
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	if parsed.RawQuery != "" {
		path += "?" + parsed.RawQuery
	}

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return rtspStatus{}, err
	}
	defer conn.Close()
	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)
	reader := bufio.NewReader(conn)

	var last rtspStatus
	for i, method := range methods {
		request := fmt.Sprintf("%s %s RTSP/1.0\r\nCSeq: %d\r\nUser-Agent: onvif-viewer-tuyaengine\r\nAccept: application/sdp\r\n\r\n",
			method, path, i+1)
		if _, err := io.WriteString(conn, request); err != nil {
			return rtspStatus{}, err
		}
		status, err := readRTSPResponse(reader)
		if err != nil {
			return rtspStatus{}, err
		}
		last = status
		if status.Code != 200 {
			return status, nil
		}
	}
	return last, nil
}

// readRTSPResponse reads one RTSP response including its Content-Length body.
func readRTSPResponse(reader *bufio.Reader) (rtspStatus, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return rtspStatus{}, err
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "RTSP/") {
		return rtspStatus{}, fmt.Errorf("tuyaengine: unexpected RTSP response line %q", line)
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return rtspStatus{}, fmt.Errorf("tuyaengine: malformed RTSP status line %q", line)
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return rtspStatus{}, fmt.Errorf("tuyaengine: malformed RTSP status code in %q", line)
	}
	status := rtspStatus{Code: code}
	if len(parts) == 3 {
		status.Reason = parts[2]
	}
	contentLength := 0
	for {
		header, err := reader.ReadString('\n')
		if err != nil {
			return status, err
		}
		header = strings.TrimRight(header, "\r\n")
		if header == "" {
			break
		}
		if key, value, ok := strings.Cut(header, ":"); ok && strings.EqualFold(strings.TrimSpace(key), "content-length") {
			if n, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && n > 0 {
				contentLength = n
			}
		}
	}
	if contentLength > 0 {
		body := make([]byte, contentLength)
		if _, err := io.ReadFull(reader, body); err != nil {
			return status, err
		}
		status.Body = string(body)
	}
	return status, nil
}

// RTSPDescribe returns the RTSP status code and SDP body for a stream URL. A
// non-200 code is reported as code, not as a Go error, so callers can tell
// "engine refuses this stream" from "engine not listening".
func RTSPDescribe(ctx context.Context, rawURL string, timeout time.Duration) (int, string, error) {
	status, err := probeRTSP(ctx, rawURL, timeout, "OPTIONS", "DESCRIBE")
	if err != nil {
		return 0, "", err
	}
	return status.Code, status.Body, nil
}

// rtspReachable reports whether the RTSP endpoint answers OPTIONS with 200.
func rtspReachable(ctx context.Context, rawURL string, timeout time.Duration) bool {
	status, err := probeRTSP(ctx, rawURL, timeout, "OPTIONS")
	if err != nil {
		return false
	}
	return status.Code == 200
}

// allocatedPorts holds ports already handed out by this process, so concurrent
// engines in one process cannot be allocated the same "free" port.
var (
	portMu         sync.Mutex
	allocatedPorts = map[int]bool{}
)

// ReserveFreePort asks the kernel for an unused loopback TCP port. The port is
// remembered for the lifetime of the process so two engines started in the same
// process never collide on a port the kernel would happily hand out twice.
func ReserveFreePort() (int, error) {
	for attempt := 0; attempt < 32; attempt++ {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return 0, fmt.Errorf("tuyaengine: allocate port: %w", err)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		_ = listener.Close()
		portMu.Lock()
		if allocatedPorts[port] {
			portMu.Unlock()
			continue
		}
		allocatedPorts[port] = true
		portMu.Unlock()
		return port, nil
	}
	return 0, fmt.Errorf("tuyaengine: could not allocate a free loopback port")
}

// ReleaseFreePort returns a port previously reserved by ReserveFreePort.
func ReleaseFreePort(port int) {
	portMu.Lock()
	delete(allocatedPorts, port)
	portMu.Unlock()
}

// Note on port pinning: ports are allocated once per engine and reused for every
// spawn, because the RTSP URL is handed to ffmpeg and persisted in
// stream_configs (see Engine.ensurePorts). A port stays reserved for the engine's
// lifetime, so ReserveFreePort/ReleaseFreePort — not PortInUse — are the
// authority on which ports this process may hand out.

// PortInUse reports whether a loopback TCP port is currently bound by anyone.
func PortInUse(port int) bool {
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return true
	}
	_ = listener.Close()
	return false
}

// CanBind reports whether this process can bind the loopback port right now.
func CanBind(port int) bool { return !PortInUse(port) }

// WaitPortFree blocks until the loopback port can be bound or the timeout
// elapses, and reports whether it is free.
func WaitPortFree(port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if CanBind(port) {
			return true
		}
		time.Sleep(25 * time.Millisecond)
	}
	return CanBind(port)
}
