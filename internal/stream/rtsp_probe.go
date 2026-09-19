package stream

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// RTSP 454 is the camera's "Session Not Found" response. The Happytimesoft V9.1
// firmware serves exactly 2 concurrent RTSP sessions; the third SETUP or PLAY
// fails with 454 while DESCRIBE still returns 200. That combination - reachable
// socket, successful handshake, no media - is what makes a normal TCP/port
// diagnosis report "healthy" during a stall.
const rtspStatusSessionNotFound = 454

var rtspControlRe = regexp.MustCompile(`a=control:(\S+)`)

// RTSPProbeResult summarises one full RTSP negotiation attempt.
type RTSPProbeResult struct {
	OptionsCode  int
	DescribeCode int
	SetupCodes   []int
	PlayCode     int
	SessionID    string
	RTPPackets   int
	Err          error
}

// MediaFlowing reports whether the session actually delivered RTP.
func (r RTSPProbeResult) MediaFlowing() bool { return r.RTPPackets > 0 }

// Accepted reports whether the camera granted a playable session.
func (r RTSPProbeResult) Accepted() bool { return r.PlayCode == 200 }

// SessionTableFull reports the exhausted-session-table condition.
func (r RTSPProbeResult) SessionTableFull() bool {
	return r.PlayCode == rtspStatusSessionNotFound ||
		r.DescribeCode == rtspStatusSessionNotFound ||
		containsCode(r.SetupCodes, rtspStatusSessionNotFound)
}

// Stalled reports a session the camera accepted but never fed.
func (r RTSPProbeResult) Stalled() bool { return r.Accepted() && !r.MediaFlowing() }

func containsCode(codes []int, want int) bool {
	for _, c := range codes {
		if c == want {
			return true
		}
	}
	return false
}

type rtspProbeConn struct {
	conn    net.Conn
	rd      *bufio.Reader
	cseq    int
	session string
	rtpPkts int
}

// rtspProbe performs a complete RTSP handshake against rawURL and reports each
// step. When collect > 0 it also measures whether RTP actually arrives, which
// distinguishes "camera says yes but stays silent" from "camera refused".
func rtspProbe(rawURL string, timeout, collect time.Duration) RTSPProbeResult {
	var res RTSPProbeResult

	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		res.Err = fmt.Errorf("invalid RTSP URL")
		return res
	}
	host := parsed.Host
	if parsed.Port() == "" {
		host = net.JoinHostPort(parsed.Hostname(), "554")
	}

	conn, err := net.DialTimeout("tcp", host, timeout)
	if err != nil {
		res.Err = err
		return res
	}
	defer conn.Close()

	pc := &rtspProbeConn{conn: conn, rd: bufio.NewReader(conn)}
	sessionURL := parsed.String()

	code, _, _, err := pc.request("OPTIONS", sessionURL, nil, timeout)
	res.OptionsCode = code
	if err != nil {
		res.Err = err
		return res
	}

	code, _, body, err := pc.request("DESCRIBE", sessionURL,
		map[string]string{"Accept": "application/sdp"}, timeout)
	res.DescribeCode = code
	if err != nil {
		res.Err = err
		return res
	}
	if code != 200 {
		return res
	}

	tracks := rtspControlRe.FindAllStringSubmatch(body, -1)

	for i, m := range tracks {
		ctrl := m[1]
		trackURL := ctrl
		if !strings.HasPrefix(ctrl, "rtsp://") {
			trackURL = strings.TrimSuffix(sessionURL, "/") + "/" + strings.TrimPrefix(ctrl, "/")
		}
		headers := map[string]string{
			"Transport": fmt.Sprintf("RTP/AVP/TCP;unicast;interleaved=%d-%d", i*2, i*2+1),
		}
		if pc.session != "" {
			headers["Session"] = pc.session
		}
		code, hdrs, _, err := pc.request("SETUP", trackURL, headers, timeout)
		res.SetupCodes = append(res.SetupCodes, code)
		if err != nil {
			res.Err = err
			return res
		}
		if sid, ok := hdrs["session"]; ok && pc.session == "" {
			pc.session = strings.TrimSpace(strings.Split(sid, ";")[0])
			res.SessionID = pc.session
		}
	}

	playHeaders := map[string]string{"Range": "npt=0.000-"}
	if pc.session != "" {
		playHeaders["Session"] = pc.session
	}
	code, _, _, err = pc.request("PLAY", sessionURL, playHeaders, timeout)
	res.PlayCode = code
	if err != nil {
		res.Err = err
		return res
	}
	if code != 200 {
		return res
	}

	if collect > 0 {
		res.RTPPackets = pc.collectRTP(collect)
	}

	// Always release the session: this is the whole point of the probe.
	if pc.session != "" {
		_, _, _, _ = pc.request("TEARDOWN", sessionURL,
			map[string]string{"Session": pc.session}, timeout)
	}
	return res
}

func (c *rtspProbeConn) request(method, uri string, headers map[string]string, timeout time.Duration) (int, map[string]string, string, error) {
	c.cseq++
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s RTSP/1.0\r\n", method, uri)
	fmt.Fprintf(&b, "CSeq: %d\r\n", c.cseq)
	for k, v := range headers {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("User-Agent: onvif-viewer\r\n\r\n")

	_ = c.conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := c.conn.Write([]byte(b.String())); err != nil {
		return 0, nil, "", err
	}
	return c.readResponse(timeout)
}

// readResponse reads one RTSP response, transparently skipping the interleaved
// RTP frames the camera may inject between messages.
func (c *rtspProbeConn) readResponse(timeout time.Duration) (int, map[string]string, string, error) {
	_ = c.conn.SetReadDeadline(time.Now().Add(timeout))

	buf := make([]byte, 0, 2048)
	for {
		b, err := c.rd.ReadByte()
		if err != nil {
			return 0, nil, "", err
		}
		if b == '$' {
			// interleaved frame: 1 byte channel, 2 bytes length, then payload
			_, err := c.rd.ReadByte()
			if err != nil {
				return 0, nil, "", err
			}
			lenBytes := make([]byte, 2)
			if _, err := io.ReadFull(c.rd, lenBytes); err != nil {
				return 0, nil, "", err
			}
			n := int(lenBytes[0])<<8 | int(lenBytes[1])
			c.rtpPkts++
			if n > 0 {
				if _, err := io.CopyN(io.Discard, c.rd, int64(n)); err != nil {
					return 0, nil, "", err
				}
			}
			buf = buf[:0] // nothing valid accumulated yet
			continue
		}
		buf = append(buf, b)
		if len(buf) >= 4 && string(buf[len(buf)-4:]) == "\r\n\r\n" {
			break
		}
		if len(buf) > 64*1024 {
			return 0, nil, "", fmt.Errorf("RTSP response header too large")
		}
	}

	text := string(buf)
	lines := strings.Split(text, "\r\n")
	code := 0
	if len(lines) > 0 {
		fields := strings.Fields(lines[0])
		if len(fields) >= 2 {
			if n, err := strconv.Atoi(fields[1]); err == nil {
				code = n
			}
		}
	}
	hdrs := map[string]string{}
	for _, ln := range lines[1:] {
		if idx := strings.Index(ln, ":"); idx > 0 {
			hdrs[strings.ToLower(strings.TrimSpace(ln[:idx]))] = strings.TrimSpace(ln[idx+1:])
		}
	}

	body := ""
	if cl := hdrs["content-length"]; cl != "" {
		if n, err := strconv.Atoi(cl); err == nil && n > 0 {
			bodyBytes := make([]byte, n)
			if _, err := io.ReadFull(c.rd, bodyBytes); err == nil {
				body = string(bodyBytes)
			}
		}
	}
	return code, hdrs, body, nil
}

// collectRTP counts interleaved RTP packets seen during the window.
func (c *rtspProbeConn) collectRTP(window time.Duration) int {
	deadline := time.Now().Add(window)
	start := c.rtpPkts
	for time.Now().Before(deadline) {
		_ = c.conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		b, err := c.rd.ReadByte()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			break
		}
		if b != '$' {
			continue
		}
		if _, err := c.rd.ReadByte(); err != nil {
			break
		}
		lenBytes := make([]byte, 2)
		if _, err := io.ReadFull(c.rd, lenBytes); err != nil {
			break
		}
		n := int(lenBytes[0])<<8 | int(lenBytes[1])
		c.rtpPkts++
		if n > 0 {
			if _, err := io.CopyN(io.Discard, c.rd, int64(n)); err != nil {
				break
			}
		}
	}
	return c.rtpPkts - start
}

// probeSessionState runs a short RTSP probe and turns the result into a
// human-readable state, so reconnection decisions can distinguish an
// exhausted session table from a genuinely unreachable camera.
func probeSessionState(rtspURL string, timeout, collect time.Duration) (RTSPProbeResult, string) {
	res := rtspProbe(rtspURL, timeout, collect)

	switch {
	case res.Err != nil:
		return res, fmt.Sprintf("RTSP probe failed: %v", res.Err)
	case res.SessionTableFull():
		return res, fmt.Sprintf(
			"camera RTSP session table is FULL (HTTP-style status %d at PLAY); "+
				"the camera allows only 2 concurrent sessions and all are held",
			rtspStatusSessionNotFound)
	case res.Stalled():
		return res, "camera accepted the session but sent no media (session granted, stream silent)"
	case res.MediaFlowing():
		return res, fmt.Sprintf("RTSP session healthy: %d RTP packets received", res.RTPPackets)
	case res.Accepted():
		return res, "camera accepted the session (no RTP sampled)"
	default:
		return res, fmt.Sprintf("RTSP negotiation incomplete: DESCRIBE=%d PLAY=%d",
			res.DescribeCode, res.PlayCode)
	}
}
