package main

import (
	"strings"
	"testing"
)

// The recorded-footage panel is deliberately secondary to live view: it lives
// INSIDE the app root and is collapsed by default. Adding a timeline and a
// storage surface must not change either fact.
func TestRecordedFootagePanelStaysInsideAppRootAndCollapsed(t *testing.T) {
	html := readIndexHTML(t)
	app := strings.Index(html, `id="app"`)
	if app < 0 {
		t.Fatal("the app root is gone")
	}
	panel := strings.Index(html, `id="recording-playback"`)
	if panel < 0 {
		t.Fatal("the recorded footage panel is gone")
	}
	if panel < app {
		t.Fatal("the recorded footage panel must stay inside the app root")
	}
	// It must remain INSIDE #app and not be moved outside the closing element.
	appClose := strings.Index(html[app:], "<!-- Footer -->")
	if appClose < 0 {
		t.Fatal("the footer marker is gone")
	}
	if panel > app+appClose {
		t.Fatal("the recorded footage panel must stay inside the app root, above the footer")
	}
	for _, token := range []string{
		`const recordingCollapsed = ref(true)`, // collapsed by default
		`v-show="!recordingCollapsed"`,
		`aria-controls="recording-playback-body"`,
	} {
		if !strings.Contains(html, token) {
			t.Errorf("missing collapse contract token %q", token)
		}
	}
}

func TestRecordingTimelineAndStorageUIExists(t *testing.T) {
	html := readIndexHTML(t)
	for _, token := range []string{
		// Timeline: coverage strip, zoom, meta and honest truncation wording.
		`id="recording-strip"`,
		`id="recording-strip-recorded"`,
		`id="recording-strip-meta"`,
		`id="recording-truncation"`,
		`id="recording-zoom-in"`,
		`id="recording-zoom-out"`,
		`id="recording-zoom-reset"`,
		`No gap recorded in this window`,
		`recording-gap-mark`,
		// The summary is fetched from the bounded endpoint.
		`/api/recordings/summary?`,
		// Storage/configuration surface.
		`id="recording-config"`,
		`id="recording-config-driver"`,
		`id="recording-config-location"`,
		`id="recording-config-quota"`,
		`id="recording-config-used"`,
		`id="recording-config-free"`,
		`id="recording-config-paused"`,
		`id="recording-config-uploads"`,
		`id="recording-config-oldest"`,
		`id="recording-config-retention"`,
		`id="recording-config-quota-input"`,
		`id="recording-config-reserve-input"`,
		`id="recording-config-save"`,
		`id="recording-camera-list"`,
		`/api/recordings/status`,
		`/api/recordings/settings`,
		// WIB display with UTC transport.
		`Asia/Jakarta`,
		// Honest driver-switch guard copy.
		`migration is required`,
	} {
		if !strings.Contains(html, token) {
			t.Errorf("missing recording UI token %q", token)
		}
	}
}

// The recorded-footage panel lives INSIDE the Vue app and Vue REPLACES those
// nodes when it mounts, so a listener attached to an element during parse sits
// on a detached node and never fires. MEASURED: with per-element listeners the
// whole panel was inert. The wiring is therefore one DELEGATED document
// listener keyed by element id, and every action must appear exactly once.
func TestRecordingUIActionsAreDelegatedExactlyOnce(t *testing.T) {
	html := readIndexHTML(t)
	mapStart := strings.Index(html, "const RECORDING_ACTIONS=")
	if mapStart < 0 {
		t.Fatal("the delegated action map is missing")
	}
	mapEnd := strings.Index(html[mapStart:], "};")
	if mapEnd < 0 {
		t.Fatal("the delegated action map is unterminated")
	}
	actions := html[mapStart : mapStart+mapEnd]
	for _, id := range []string{
		"recording-load", "recording-live", "recording-zoom-in", "recording-zoom-out",
		"recording-zoom-reset", "recording-config-refresh", "recording-config-save",
	} {
		if got := strings.Count(actions, "'"+id+"':"); got != 1 {
			t.Errorf("%s must appear exactly once in the delegated action map, found %d", id, got)
		}
	}
	if !strings.Contains(html, "document.addEventListener('click'") {
		t.Error("the delegated click listener is missing: the panel would be inert after the Vue mount")
	}
	// No recording control may still be bound per-element: those bindings are
	// exactly the ones Vue's mount discards.
	for _, id := range []string{"recording-load", "recording-live", "recording-zoom-in", "recording-zoom-out", "recording-zoom-reset", "recording-config-refresh", "recording-config-save"} {
		if strings.Contains(html, "$('"+id+"').addEventListener") {
			t.Errorf("%s is still bound per-element, which Vue's mount discards", id)
		}
	}
	// Exactly one summary fetch site, and it must be the bounded endpoint.
	if got := strings.Count(html, `/api/recordings/summary?`); got != 1 {
		t.Errorf("expected exactly one summary request, found %d", got)
	}
}

func TestRecordingUIHasNoCredentialSurface(t *testing.T) {
	html := readIndexHTML(t)
	for _, forbidden := range []string{
		`s3_secret_cipher`,
		`s3_session_cipher`,
		`SecretKey`,
		`SessionToken`,
		`Segment.Spool`,
	} {
		if strings.Contains(html, forbidden) {
			t.Errorf("the UI references %q, which must never reach the client", forbidden)
		}
	}
}
