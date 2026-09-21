package main

import (
	"strings"
	"testing"
)

// --- M12: the card names its CAMERA, and leads with its video -----------------
//
// ADDITIVE, as every earlier block was. Nothing above these lines was changed:
// the 16 assertions in ui_structure_test.go, the 3 in ui_structure_m8_test.go
// and the 6 in ui_structure_m10_test.go all guard the same tokens they always
// did, and they still pass UNMODIFIED.
//
// The contract this block adds is the M12 one, and it is the direct answer to
// the measured complaint that a wall of cameras was unreadable:
//
//  1. the card's title is the CAMERA - the Tuya device name or the ONVIF host -
//     taken from the server's non-secret `streamLabel`, and the internal
//     `stream.id` is DEMOTED into the collapsed panel instead of deleted;
//  2. the metadata that used to push the video down (Started, detail, reconnect,
//     last segment, the M7 resolution/cost lines and the HD warning) is INSIDE
//     that panel, and the always-visible strip is one line: status + resolution
//     + provider badge + Hide/Show;
//  3. the M6 re-login card is an ACTION, so it stays OUTSIDE the panel;
//  4. the video is the first substantial element of the card, on desktop and on
//     a phone;
//  5. a wide monitor gets bigger cameras (the 1560px cap is what made 2560px
//     render identically to 1920px) and every card in a row is the same height.

// m12PhoneBlock returns the body of the max-width:767px media block, so an
// assertion about the phone order cannot be satisfied by a lookalike rule in a
// different breakpoint.
func m12PhoneBlock(t *testing.T, style string) string {
	t.Helper()
	return m12MediaBlock(t, style, "@media (max-width: 767px) {")
}

// m12MediaBlock returns the balanced body of one at-rule, without its opening
// line. Brace counting is what makes it the WHOLE block: a naive slice to the
// next "}" would stop at the first nested rule and silently pass.
func m12MediaBlock(t *testing.T, style, opener string) string {
	t.Helper()
	start := strings.Index(style, opener)
	if start < 0 {
		t.Fatalf("the %q block is missing from the stylesheet", opener)
	}
	body := style[start+len(opener):]
	depth := 1
	for i, r := range body {
		switch r {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return body[:i]
			}
		}
	}
	t.Fatalf("the %q block is not closed", opener)
	return ""
}

// m12Cards returns the per-card template (the M10 helper trims the empty-state
// branch and the Logs Panel, so every count below is card-scoped).
func m12Cards(t *testing.T, html string) string {
	t.Helper()
	return cardTemplate(t, html)
}

// TestFrontendTitlesEachCardWithItsCameraNotAnInternalStreamId is the headline
// defect: `<h3>{{ stream.id }}</h3>` rendered "stream_1789961119825723855",
// which tells you nothing when several cameras are on screen.
func TestFrontendTitlesEachCardWithItsCameraNotAnInternalStreamId(t *testing.T) {
	html := readIndexHTML(t)
	card := m12Cards(t, html)

	// The title is a real element with the server's label in it.
	if !strings.Contains(card, `class="stream-camera-name"`) {
		t.Error("the card must have a dedicated camera-name title element")
	}
	if !strings.Contains(card, "{{ streamLabel(stream) }}") {
		t.Error("the card title must render the server's camera label")
	}
	// The label is the SERVER's field, read straight off the stream, and the
	// helper falls back to a SHORT id - never the full internal id again.
	if !strings.Contains(html, "stream.streamLabel") {
		t.Error("the title must come from the server's streamLabel field")
	}
	if !strings.Contains(html, "const streamLabel = (stream) => {") {
		t.Error("the UI must resolve the card title through one streamLabel helper")
	}
	if !strings.Contains(html, "'…' + value.slice(-8)") {
		t.Error("a card the server could not name must fall back to a SHORT id, not the full stream_... string")
	}

	// The internal id is DEMOTED, not deleted: it must appear INSIDE the
	// collapsed panel, and it must NOT appear anywhere on the card face.
	panelAt := strings.Index(card, `class="stream-actions"`)
	if panelAt < 0 {
		t.Fatal("the collapsed control panel is missing from the card")
	}
	visible := card[:panelAt]
	panel := card[panelAt:]
	if strings.Contains(visible, "{{ stream.id }}") {
		t.Error("the internal stream id is still rendered on the card face; it must be demoted into the collapsed details")
	}
	if !strings.Contains(panel, "stream-metadata-id-value") || !strings.Contains(panel, "{{ stream.id }}") {
		t.Error("the internal stream id must remain readable inside the collapsed details")
	}
	if !strings.Contains(panel, "Stream id:") {
		t.Error("the demoted id must be labelled, or it is just an opaque string in the panel")
	}

	// SECURITY: the title is a non-secret display field, so the page must never
	// reach for the RTSP URL to build it. RtspUrl is json:"-" on the server
	// precisely so it cannot arrive; touching it here would render an empty
	// title forever and invite someone to "fix" it by exposing the URL.
	for _, forbidden := range []string{"stream.rtspUrl", "stream.rtspURL", "stream.RtspUrl"} {
		if strings.Contains(html, forbidden) {
			t.Errorf("the page must never read %s: the RTSP URL is deliberately not sent to the browser", forbidden)
		}
	}
}

// TestFrontendFoldsTheCardMetadataIntoTheControlsPanel is the second half of
// the complaint: six lines of prose sat between the title and the video.
func TestFrontendFoldsTheCardMetadataIntoTheControlsPanel(t *testing.T) {
	html := readIndexHTML(t)
	card := m12Cards(t, html)

	panelAt := strings.Index(card, `class="stream-actions"`)
	if panelAt < 0 {
		t.Fatal("the collapsed control panel is missing from the card")
	}
	visible := card[:panelAt]
	panel := card[panelAt:]

	// Every metadata line moved INSIDE the panel...
	for _, token := range []string{
		"Started: {{ new Date(stream.startedAt).toLocaleString() }}",
		"{{ stream.detail }}",
		"Reconnect attempt {{ stream.reconnectCount }}",
		"Last video segment: {{ new Date(stream.lastHlsAdvance).toLocaleString() }}",
		"stream-resolution-value",
		"stream-resolution-cost",
		"stream-resolution-warning",
	} {
		if !strings.Contains(panel, token) {
			t.Errorf("metadata %q must live INSIDE the collapsed panel", token)
		}
		if strings.Contains(visible, token) {
			t.Errorf("metadata %q is still rendered on the card face, so it still pushes the video down", token)
		}
	}
	// ...and it is grouped, so the panel reads as prose followed by actions
	// rather than one long run of buttons.
	if !strings.Contains(panel, `class="stream-metadata"`) {
		t.Error("the moved metadata must be grouped in its own .stream-metadata block")
	}

	// The always-visible strip is ONE line and still answers "what is this card
	// doing?": the status word AND the resolution the server reports, read from
	// the server's own state rather than from the last thing the user clicked.
	if !strings.Contains(visible, "{{ stream.status }}") {
		t.Error("the always-visible status line must keep the status word")
	}
	if !strings.Contains(visible, `class="stream-status-resolution`) {
		t.Error("the status line must carry a one-line resolution summary")
	}
	if !strings.Contains(visible, "String(stream.resolution).toUpperCase()") {
		t.Error("the status-line resolution must come from the server's reported resolution")
	}
	// It is a summary, not a second copy of the panel: the resolution LINE (with
	// its cost and warning) belongs to the panel only.
	if strings.Contains(visible, "streamResolutionLabel(stream)") {
		t.Error("the status line must not also render the full resolution line that the panel now owns")
	}
}

// TestFrontendKeepsTheReloginActionOutsideTheCollapsedPanel guards the one thing
// the user said must NOT be folded away: a camera whose Tuya session died.
//
// It is an ACTION, not metadata. If it were hidden behind the disclosure, a dead
// camera would render as a card with no video and no visible reason.
func TestFrontendKeepsTheReloginActionOutsideTheCollapsedPanel(t *testing.T) {
	html := readIndexHTML(t)
	card := m12Cards(t, html)

	panelAt := strings.Index(card, `class="stream-actions"`)
	if panelAt < 0 {
		t.Fatal("the collapsed control panel is missing from the card")
	}
	visible := card[:panelAt]
	panel := card[panelAt:]

	if !strings.Contains(visible, `class="tuya-card-relogin`) {
		t.Error("the re-login card must stay on the card face, outside the collapsed panel")
	}
	if !strings.Contains(visible, "Sign in again and resume this camera") {
		t.Error("the re-login action must stay reachable without expanding anything")
	}
	if !strings.Contains(visible, "beginTuyaRelogin") {
		t.Error("the re-login handler must stay wired on the always-visible card")
	}
	if strings.Contains(panel, "tuya-card-relogin") {
		t.Error("the re-login action must NOT be inside the collapsed panel")
	}
	// The status the card keys off must still be the server's own state.
	if !strings.Contains(html, "stream.suspended || stream.status === 'needs_relogin'") {
		t.Error("the re-login card must still be driven by the server-reported state")
	}
}

// TestFrontendMakesTheVideoTheFirstSubstantialCardElement is the ordering half:
// the card is title -> video -> one-line status -> disclosure.
func TestFrontendMakesTheVideoTheFirstSubstantialCardElement(t *testing.T) {
	html := readIndexHTML(t)
	card := m12Cards(t, html)
	style := styleBlock(t, html)

	titleAt := strings.Index(card, `class="stream-card-title"`)
	// The M10 contract pins this exact binding, so it is the video's landmark.
	videoAt := strings.Index(card, `:class="['video-container', stream.isFullscreen ? 'is-fullscreen' : '']"`)
	statusAt := strings.Index(card, `class="stream-status-line"`)
	panelAt := strings.Index(card, `class="stream-actions"`)
	if titleAt < 0 || videoAt < 0 || statusAt < 0 || panelAt < 0 {
		t.Fatalf("card landmarks missing: title=%d video=%d status=%d panel=%d", titleAt, videoAt, statusAt, panelAt)
	}
	if !(titleAt < videoAt) {
		t.Error("the card must lead with its camera name, above the video")
	}
	if !(videoAt < statusAt && statusAt < panelAt) {
		t.Errorf("the card order must be title(%d) < video(%d) < status(%d) < controls(%d)", titleAt, videoAt, statusAt, panelAt)
	}

	// The title must be ONE line: a two-line name would move the video down and
	// break the uniform grid rhythm the next test guards.
	titleOpen := strings.Index(style, ".stream-camera-name {")
	if titleOpen < 0 {
		t.Fatal(".stream-camera-name has no CSS rule")
	}
	titleRule := style[titleOpen:]
	titleRule = titleRule[:strings.Index(titleRule, "}")]
	for _, want := range []string{"white-space:nowrap", "text-overflow:ellipsis"} {
		if !strings.Contains(titleRule, want) {
			t.Errorf(".stream-camera-name must stay on one line: missing %q", want)
		}
	}

	// On a phone the video comes BEFORE the status/identity block and the
	// controls, and the title precedes everything that carries a flex `order`.
	phone := m12PhoneBlock(t, style)
	if !strings.Contains(phone, ".video-container { order:1; margin-top:12px; }") {
		t.Error("the phone block must still put the video first")
	}
	if !strings.Contains(phone, ".stream-controls { order:3; }") {
		t.Error("the phone block must still put the controls last")
	}
	if strings.Contains(phone, ".stream-card-title { order:") {
		t.Error("the phone block must not give the title an explicit order: an unset order is 0, which puts it before the ordered children and keeps the picture first")
	}
	// The video must not be separated from the title by a spacer.
	if !strings.Contains(style, ".stream-card-title + .video-container { margin-top:0; }") {
		t.Error("the video must start directly under the camera name, with no spacer between them")
	}
}

// TestFrontendRaisesThePageCapSoAWideMonitorGetsBiggerCameras guards the MEASURED
// defect that a 2560px monitor rendered IDENTICALLY to a 1920px one (card width
// 369px at both) because the page stopped growing at 1560px.
func TestFrontendRaisesThePageCapSoAWideMonitorGetsBiggerCameras(t *testing.T) {
	html := readIndexHTML(t)
	style := styleBlock(t, html)

	// The cap that made 2560 == 1920 must no longer be the widest one.
	narrow := strings.Index(style, ".page-container { width:min(100%,1560px); }")
	wide := strings.Index(style, "@media (min-width: 1920px) { .page-container { width:min(100%,1980px); } }")
	wider := strings.Index(style, "@media (min-width: 2200px) { .page-container { width:min(100%,2440px); } }")
	if wide < 0 {
		t.Fatal("a >=1920px rule must widen the page past the old 1560px cap, or a big monitor keeps 1920px-sized cameras")
	}
	if wider < 0 {
		t.Fatal("a >=2200px rule must widen the page again, or a 2560px monitor renders like a 1920px one")
	}
	if !(narrow < wide && wide < wider) {
		t.Error("the widened caps must come AFTER the narrow one, or the narrow rule still wins and the page never grows")
	}
	// The base cap grows too: 1440px is where two cameras per row actually get
	// room, and it is what a 1440px monitor now fills exactly.
	if !strings.Contains(style, ".page-container { width:min(100%,1440px); margin-inline:auto; }") {
		t.Error("the base page width must be raised to 1440px")
	}
	// The diagnostics gutter must still be reserved wherever the streams are
	// wide: widening the page must not let the gutter overlap the grid.
	if !strings.Contains(style, ".dashboard-grid { grid-template-columns:minmax(0,1fr) 360px; }") {
		t.Error("the wide-desktop gutter pairing must survive the wider page container")
	}
}

// TestFrontendKeepsCardHeightsUniformInARow guards the MEASURED 551px next to
// 591px inside one row: with `align-items:start` each tile ended wherever its own
// optional lines happened to end.
func TestFrontendKeepsCardHeightsUniformInARow(t *testing.T) {
	html := readIndexHTML(t)
	style := styleBlock(t, html)

	base := strings.Index(style, ".stream-grid { display:grid; grid-template-columns:1fr; gap:16px; align-items:start; }")
	if base < 0 {
		t.Fatal("the stream grid's base rule is missing")
	}
	// The LAST declaration of align-items on .stream-grid is the one that wins,
	// so it must be the stretch - wherever the M10 base rule sits.
	stretch := strings.LastIndex(style, ".stream-grid { align-items:stretch; }")
	if stretch < 0 {
		t.Fatal("the grid must stretch its items, or a row of cards keeps ragged heights")
	}
	if stretch < base {
		t.Error("the stretch must be declared AFTER the grid's base rule, or the earlier align-items:start wins")
	}
	// Every card is a full-height column whose last block is pinned to the
	// bottom, so a row of cameras is a row of equal rectangles.
	if !strings.Contains(style, ".stream-card > .stream-controls { margin-top:auto; }") {
		t.Error("the card's trailing block must be pushed to the bottom so the cards in a row line up")
	}
	if !strings.Contains(style, ".stream-card { position:relative; display:flex; flex-direction:column; overflow:hidden;") {
		t.Error("the card must stay a column flex container, which is what the stretch has to fill")
	}
	// The phone breakpoint must not undo it.
	if !strings.Contains(m12PhoneBlock(t, style), ".stream-grid { grid-template-columns:1fr; gap:12px; }") {
		t.Error("the phone block must keep its single-column stream grid")
	}
}
