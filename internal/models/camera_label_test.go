package models

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// --- M12: the display label names the CAMERA and carries no credential -------
//
// The card title used to be the internal stream id, which is unreadable with
// several cameras on screen. The replacement had to be a field the browser can
// actually receive, and models.StreamInfo.RtspURL is `json:"-"` precisely
// because an RTSP URL can be `rtsp://user:pass@host/...`. So the label is a
// SEPARATE, display-only field - and these tests exist because "we remembered
// to strip the userinfo" is not a guarantee.

// TestCameraLabelFromRTSPURLStripsUserinfo is the security assertion: an RTSP
// URL WITH credentials must yield the host ALONE.
func TestCameraLabelFromRTSPURLStripsUserinfo(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want string
	}{
		{"credentials and port", "rtsp://user:pass@host:554/live", "host"},
		{"credentials, no port", "rtsp://admin:hunter2@10.0.0.4/live", "10.0.0.4"},
		{"the live camera URL", "rtsp://10.2.56.194:5543/19efe2cb88c09c4db24478f5f39db29d/live/channel0", "10.2.56.194"},
		{"username only", "rtsp://operator@camera.local:8554/s1", "camera.local"},
		{"password contains an at", "rtsp://user:p@ss@host/live", "host"},
		{"password contains a colon", "rtsp://user:pa:ss@10.1.2.3:554/live", "10.1.2.3"},
		{"same URL, no userinfo", "rtsp://host:554/live", "host"},
		{"ipv6 literal", "rtsp://[fd00::1]:554/live", "fd00::1"},
		{"ipv6 literal with creds", "rtsp://u:p@[fd00::1]:554/live", "fd00::1"},
		{"query string", "rtsp://user:pass@host/live?channel=0", "host"},
		{"scheme case", "RTSP://user:pass@HOST:554/live", "HOST"},
		{"trailing space", "  rtsp://user:pass@host:554/live  ", "host"},
		{"empty", "", ""},
		{"not a url", "Security Camera", ""},
		{"scheme only", "rtsp://", ""},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := CameraLabelFromRTSPURL(tt.url)
			if got != tt.want {
				t.Fatalf("CameraLabelFromRTSPURL(%q) = %q, want %q", tt.url, got, tt.want)
			}
			// The property, not just the example: whatever comes back can never
			// contain the userinfo separators that carry a credential.
			for _, leaked := range []string{"user", "pass", "admin", "hunter2", "operator", "p@ss", "pa:ss"} {
				if strings.Contains(got, leaked) {
					t.Errorf("label %q leaked %q from the URL", got, leaked)
				}
			}
			if strings.Contains(got, "@") {
				t.Errorf("label %q still contains a userinfo separator", got)
			}
		})
	}
}

// TestCameraLabelOrLabelReducesAnythingURLShaped is the last-line defence used
// on every value that becomes a card title.
func TestCameraLabelOrLabelReducesAnythingURLShaped(t *testing.T) {
	cases := []struct{ in, want string }{
		// A real camera NAME must survive untouched.
		{"Security Camera", "Security Camera"},
		{"Front door", "Front door"},
		// Anything URL-shaped is reduced to its host.
		{"rtsp://user:pass@host:554/live", "host"},
		{"rtsp://user:pass@10.2.56.194:5543/live/channel0", "10.2.56.194"},
		// Scheme-less userinfo is stripped at the LAST "@", and only when the
		// part before it really is userinfo (it contains a colon).
		{"user:pass@10.0.0.7", "10.0.0.7"},
		// A name that merely contains an "@" is NOT userinfo and survives.
		{"cam@home", "cam@home"},
		{"", ""},
	}
	for _, tt := range cases {
		if got := CameraLabelOrLabel(tt.in); got != tt.want {
			t.Errorf("CameraLabelOrLabel(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestStreamInfoStillHidesTheRTSPURLAndPublishesTheLabel pins the two halves of
// the contract AT THE SERIALISATION BOUNDARY: the URL stays json:"-", and the
// label is what a browser actually receives.
func TestStreamInfoStillHidesTheRTSPURLAndPublishesTheLabel(t *testing.T) {
	info := StreamInfo{
		ID:          "stream_1",
		RtspURL:     "rtsp://admin:secret@10.0.0.4:554/live",
		StreamLabel: CameraLabelFromRTSPURL("rtsp://admin:secret@10.0.0.4:554/live"),
	}
	encoded, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	body := string(encoded)
	// The URL and the credential must be absent, whatever else changes.
	for _, forbidden := range []string{"rtsp", "RtspURL", "rtspUrl", "admin", "secret", "user:pass"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("API JSON exposed %q: %s", forbidden, body)
		}
	}
	var got map[string]any
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if got["streamLabel"] != "10.0.0.4" {
		t.Fatalf("streamLabel = %#v, want the bare host", got["streamLabel"])
	}
	// The struct tag is the contract, so assert it directly as well: a future
	// edit that "helpfully" exposes the URL fails here, not in production.
	if tag := streamInfoJSONTag(t, "RtspURL"); tag != "-" {
		t.Fatalf("StreamInfo.RtspURL json tag = %q, want %q: the RTSP URL can carry credentials and must never be sent to the browser", tag, "-")
	}
	if tag := streamInfoJSONTag(t, "StreamLabel"); tag != "streamLabel,omitempty" {
		t.Fatalf("StreamInfo.StreamLabel json tag = %q, want %q", tag, "streamLabel,omitempty")
	}
}

// streamInfoJSONTag reads the json tag of a named StreamInfo field.
func streamInfoJSONTag(t *testing.T, field string) string {
	t.Helper()
	f, ok := reflect.TypeOf(StreamInfo{}).FieldByName(field)
	if !ok {
		t.Fatalf("StreamInfo has no field %q", field)
	}
	return f.Tag.Get("json")
}

// TestShortStreamIDKeepsTheDistinguishingTail documents the fallback: a card
// whose camera could not be named must show a SHORT id, and two ids that differ
// only in their last digits must stay distinguishable.
func TestShortStreamIDKeepsTheDistinguishingTail(t *testing.T) {
	long := "stream_1789961119825723855"
	short := ShortStreamID(long)
	if len([]rune(short)) > 9 {
		t.Fatalf("ShortStreamID(%q) = %q, still too long for a card title", long, short)
	}
	if !strings.HasSuffix(short, "5723855") {
		t.Fatalf("ShortStreamID(%q) = %q, want the distinguishing TAIL", long, short)
	}
	if ShortStreamID("stream_1789961119825723855") == ShortStreamID("stream_1789961119825723856") {
		t.Error("two different streams shortened to the same label; the tail must be long enough to tell siblings apart")
	}
	if got := ShortStreamID("tuya:eb9f1d6e677b1b39f222ag"); got != "…39f222ag" {
		t.Errorf("ShortStreamID(tuya token) = %q, want the device id tail", got)
	}
	if got := ShortStreamID("abc"); got != "abc" {
		t.Errorf("ShortStreamID(short value) = %q, want it unchanged", got)
	}
	if got := ShortStreamID(""); got != "" {
		t.Errorf("ShortStreamID(\"\") = %q, want \"\"", got)
	}
}
