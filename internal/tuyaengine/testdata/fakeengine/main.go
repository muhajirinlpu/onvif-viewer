package main

// Fake Tuya->RTSP engine used by internal/tuyaengine tests.
//
// It implements just enough of the real engine's contract to exercise
// supervision without a camera and without the real binary:
//
//	-c <path>       config file (must exist; the RTSP/API ports are read from it)
//	-crash-after N  exit(1) after N seconds of uptime (simulates an unexpected death)
//	-crash-now      exit(1) immediately after binding ports
//	-fail-start     exit(1) before binding anything (simulates a broken binary)
//
// Flags after -c are accepted too, because the engine only ever receives
// `-c <path>`; tests add their own flags by wrapping this binary in a script.
import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const rtspMethods = "OPTIONS, SETUP, TEARDOWN, DESCRIBE, PLAY, PAUSE, ANNOUNCE, RECORD"

func main() {
	configPath := flag.String("c", "", "config file")
	config := flag.String("config", "", "config file")
	crashAfter := flag.Float64("crash-after", 0, "exit after N seconds")
	crashNow := flag.Bool("crash-now", false, "exit immediately after binding")
	failStart := flag.Bool("fail-start", false, "exit before binding")
	flag.Parse()

	if *failStart {
		os.Exit(1)
	}
	path := *configPath
	if path == "" {
		path = *config
	}
	if path == "" {
		fmt.Fprintln(os.Stderr, "fake-engine: -c is required")
		os.Exit(2)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake-engine: read config:", err)
		os.Exit(2)
	}
	text := string(data)
	rtspAddr := listenValue(text, "rtsp")
	apiAddr := listenValue(text, "api")
	if rtspAddr == "" {
		fmt.Fprintln(os.Stderr, "fake-engine: config has no rtsp.listen")
		os.Exit(2)
	}
	if apiAddr == "" {
		apiAddr = "127.0.0.1:1984"
	}

	rtspListener, err := net.Listen("tcp", rtspAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake-engine: listen rtsp:", err)
		os.Exit(2)
	}
	defer rtspListener.Close()
	fmt.Printf("fake-engine listening rtsp=%s\n", rtspListener.Addr())

	if *crashNow {
		os.Exit(1)
	}
	go serveRTSP(rtspListener)

	apiListener, err := net.Listen("tcp", apiAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake-engine: listen api:", err)
		os.Exit(2)
	}
	defer apiListener.Close()
	go serveAPI(apiListener)

	if *crashAfter > 0 {
		time.AfterFunc(time.Duration(*crashAfter*float64(time.Second)), func() {
			fmt.Fprintln(os.Stderr, "fake-engine: simulated crash")
			os.Exit(1)
		})
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	<-signals
	fmt.Println("fake-engine: shutting down")
}

// listenValue extracts `listen: "host:port"` from the named YAML section.
func listenValue(text, section string) string {
	lines := strings.Split(text, "\n")
	inSection := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasSuffix(trimmed, ":") && !strings.HasPrefix(trimmed, "-") {
			inSection = strings.TrimSuffix(trimmed, ":") == section
			continue
		}
		if !inSection {
			continue
		}
		if value, ok := strings.CutPrefix(trimmed, "listen:"); ok {
			return strings.Trim(strings.TrimSpace(value), `"`)
		}
	}
	return ""
}

// serveRTSP answers DESCRIBE/OPTIONS with 200 only for a path that is present in
// an `exec:` stream; everything else 404s, matching the real engine closely
// enough for readiness checks.
func serveRTSP(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()
			buffer := make([]byte, 1024)
			for {
				_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
				n, err := conn.Read(buffer)
				if err != nil {
					return
				}
				request := string(buffer[:n])
				method := strings.Fields(request)
				if len(method) < 2 {
					return
				}
				body := "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fake-engine\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\n" +
					"m=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=control:trackID=0\r\n"
				_, _ = fmt.Fprintf(conn, "RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: %s\r\nContent-Length: %d\r\n\r\n%s",
					rtspMethods, len(body), body)
			}
		}(conn)
	}
}

func serveAPI(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()
			buffer := make([]byte, 4096)
			_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := conn.Read(buffer)
			if err != nil {
				return
			}
			request := string(buffer[:n])
			if !strings.HasPrefix(request, "GET") && !strings.HasPrefix(request, "PUT") && !strings.HasPrefix(request, "DELETE") {
				_, _ = conn.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n"))
				return
			}
			payload := `{"fake_stream":{"producers":[{"url":"tuya://fake"}],"consumers":null}}`
			_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(payload), payload)
		}(conn)
	}
}
