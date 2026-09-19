// Package tuyartsp serves a Tuya camera as a local RTSP endpoint inside the
// viewer process.
//
// It is the in-process replacement for the external go2rtc child process: the
// RTSP protocol layer comes from the vendored go2rtc code in
// internal/go2rtc/rtsp, and the Tuya source comes from internal/go2rtc/tuya.
// Nothing is executed: the only external process left in the pipeline is the
// ffmpeg that internal/stream already runs.
//
// # Design
//
// One Server owns one loopback RTSP listener and a registry of
// stream name -> tuya:// source URL. For every RTSP client connection the
// server speaks the normal RTSP handshake (OPTIONS/DESCRIBE/SETUP/PLAY):
//
//   - DESCRIBE dials the Tuya source in-process (transport/WebRTC/Tuya cloud
//     handshake) and wires the resulting producer tracks into the connection's
//     RTSP sender list, so the SDP handed back describes the real codecs the
//     camera is about to send.
//   - SETUP allocates the interleaved RTP channels.
//   - PLAY starts the producer; RTP then flows camera -> WebRTC -> track ->
//     RTSP interleaved framing -> ffmpeg.
//
// The producer is owned by the connection and stopped when the client
// disconnects, matching go2rtc's own rule that a producer lives no longer than
// the consumers reading it.
//
// # Why one producer per connection
//
// Tuya cameras accept very few concurrent WebRTC sessions, so a producer is
// deliberately never shared between connections. The HLS pipeline keeps exactly
// one ffmpeg (and therefore one RTSP client) per profile token, so the steady
// state is one Tuya session per camera regardless. Caching a producer across
// reconnects would hold a camera session open while the viewer had no reader,
// which is the failure mode the previous supervised-engine design had.
package tuyartsp

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sync"

	"dengan.dev/camera-streamer/internal/go2rtc/core"
	"dengan.dev/camera-streamer/internal/go2rtc/rtsp"
	"dengan.dev/camera-streamer/internal/go2rtc/tuya"
)

// DialFunc dials a source URL and returns the go2rtc producer behind it. It is
// a field so tests can substitute a fake producer; production always uses
// tuya.Dial.
type DialFunc func(source string) (core.Producer, error)

// Server is an in-process RTSP endpoint for Tuya streams.
type Server struct {
	dial DialFunc

	mu       sync.Mutex
	sources  map[string]string
	listener net.Listener
	port     int
	closed   bool
	conns    map[*rtsp.Conn]struct{}
	wg       sync.WaitGroup
}

// ErrNoStream is returned when an RTSP client asks for a name that was never
// registered (or has been removed).
var ErrNoStream = errors.New("tuyartsp: no such stream")

// New creates a Server that dials Tuya sources with tuya.Dial. It does not
// listen until Listen is called.
func New() *Server {
	return &Server{
		dial:    func(source string) (core.Producer, error) { return tuya.Dial(source) },
		sources: map[string]string{},
		conns:   map[*rtsp.Conn]struct{}{},
	}
}

// SetDialer overrides the producer dialer. It exists for tests.
func (s *Server) SetDialer(dial DialFunc) {
	s.mu.Lock()
	s.dial = dial
	s.mu.Unlock()
}

// AddStream registers (or replaces) a stream name and its tuya:// source URL.
// It is safe to call while clients are connected; new clients see the change
// immediately.
func (s *Server) AddStream(name, source string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("tuyartsp: server is closed")
	}
	s.sources[name] = source
	return nil
}

// RemoveStream drops a stream. Connections already serving it keep running
// until their client disconnects.
func (s *Server) RemoveStream(name string) {
	s.mu.Lock()
	delete(s.sources, name)
	s.mu.Unlock()
}

// Streams returns the registered stream names.
func (s *Server) Streams() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	names := make([]string, 0, len(s.sources))
	for name := range s.sources {
		names = append(names, name)
	}
	return names
}

// Listen binds the loopback RTSP listener. address may be "127.0.0.1:0" to let
// the kernel pick a free port, which Port then reports.
func (s *Server) Listen(address string) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("tuyartsp: server is closed")
	}
	if s.listener != nil {
		s.mu.Unlock()
		return errors.New("tuyartsp: already listening")
	}
	s.mu.Unlock()

	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("tuyartsp: listen %s: %w", address, err)
	}

	s.mu.Lock()
	s.listener = listener
	s.port = listener.Addr().(*net.TCPAddr).Port
	s.mu.Unlock()

	s.wg.Add(1)
	go s.acceptLoop(listener)
	return nil
}

// Port reports the bound port, or 0 before Listen.
func (s *Server) Port() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.port
}

// Close stops the listener and closes every live connection. It is idempotent.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	listener := s.listener
	conns := make([]*rtsp.Conn, 0, len(s.conns))
	for conn := range s.conns {
		conns = append(conns, conn)
	}
	s.mu.Unlock()

	if listener != nil {
		_ = listener.Close()
	}
	// Closing each RTSP connection unblocks its Handle loop, which stops the
	// producer and removes the connection from the registry.
	for _, conn := range conns {
		_ = conn.Close()
	}
	s.wg.Wait()
	return nil
}

func (s *Server) acceptLoop(listener net.Listener) {
	defer s.wg.Done()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			_ = conn.Close()
			return
		}
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serve(conn)
		}()
	}
}

// serve runs one RTSP client session.
func (s *Server) serve(netConn net.Conn) {
	c := rtsp.NewServer(netConn)

	var producer core.Producer
	var once sync.Once
	stopProducer := func() {
		once.Do(func() {
			if producer != nil {
				_ = producer.Stop()
			}
		})
	}

	s.mu.Lock()
	s.conns[c] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.conns, c)
		s.mu.Unlock()
		stopProducer()
		_ = c.Close()
	}()

	// The DESCRIBE handler runs synchronously inside c.Accept(), before the
	// response is written, so the SDP describes tracks that already exist.
	c.Listen(func(msg any) {
		method, ok := msg.(string)
		if !ok || method != rtsp.MethodDescribe {
			return
		}
		prod, err := s.wire(c)
		if err != nil {
			log.Printf("tuyartsp: %s: %v", c.URL, err)
			return
		}
		producer = prod
	})

	if err := c.Accept(); err != nil {
		return
	}
	// Accept returns after PLAY (or on failure). Only start pumping RTP when a
	// producer was actually wired, otherwise Handle would spin on a dead
	// connection.
	if producer == nil {
		return
	}
	if err := c.Handle(); err != nil {
		return
	}
}

// wire dials the requested stream and attaches its tracks to the RTSP
// connection. It returns the producer the caller must stop.
//
// Errors are returned so the caller can log them; the RTSP connection answers
// 404 because no sender was added, which is exactly what ffmpeg needs to see to
// retry.
func (s *Server) wire(c *rtsp.Conn) (core.Producer, error) {
	if c.URL == nil {
		return nil, errors.New("tuyartsp: DESCRIBE without URL")
	}
	name := c.URL.Path
	if len(name) > 0 && name[0] == '/' {
		name = name[1:]
	}
	if name == "" {
		return nil, errors.New("tuyartsp: DESCRIBE with empty stream name")
	}

	s.mu.Lock()
	source, ok := s.sources[name]
	dial := s.dial
	s.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNoStream, name)
	}

	producer, err := dial(source)
	if err != nil {
		return nil, fmt.Errorf("tuyartsp: dial %s: %w", name, err)
	}

	// Ask for one video and one audio track with "ANY" codec: the camera
	// decides the concrete codec (H264 on the SD stream, HEVC on HD) and the
	// answer SDP carries the real payload type and fmtp parameters.
	consumerMedias := []*core.Media{
		{Kind: core.KindVideo, Direction: core.DirectionSendonly, Codecs: []*core.Codec{{Name: core.CodecAny}}},
		{Kind: core.KindAudio, Direction: core.DirectionSendonly, Codecs: []*core.Codec{{Name: core.CodecAny}}},
	}

	c.SessionName = "onvif-viewer"
	matched := 0
	for _, consMedia := range consumerMedias {
		// Bound the codec even for a stream with no media of a kind (SD stream
		// with the camera's audio disabled, HD stream while probing), because a
		// producer with no track must not leave a half-built SDP behind.
		found := false
		for _, prodMedia := range producer.GetMedias() {
			if prodMedia.Direction != core.DirectionRecvonly {
				continue
			}
			prodCodec, consCodec := prodMedia.MatchMedia(consMedia)
			if prodCodec == nil {
				continue
			}
			track, err := producer.GetTrack(prodMedia, prodCodec)
			if err != nil {
				log.Printf("tuyartsp: %s: get %s track: %v", name, prodMedia.Kind, err)
				continue
			}
			if err := c.AddTrack(consMedia, consCodec, track); err != nil {
				log.Printf("tuyartsp: %s: add %s track: %v", name, prodMedia.Kind, err)
				continue
			}
			found = true
			matched++
			break
		}
		if !found {
			log.Printf("tuyartsp: %s: no %s track in source", name, consMedia.Kind)
		}
	}

	if matched == 0 {
		_ = producer.Stop()
		return nil, fmt.Errorf("tuyartsp: %s: source produced no usable tracks", name)
	}

	// Start the producer only once the client has PLAYed: c.Handle() below
	// drives the RTP path, and a producer that runs with no reader wastes a
	// camera session.
	go func() {
		if err := producer.Start(); err != nil {
			log.Printf("tuyartsp: %s: producer stopped: %v", name, err)
		}
	}()

	return producer, nil
}
