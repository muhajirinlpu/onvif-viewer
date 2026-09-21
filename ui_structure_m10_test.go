package main

import (
	"regexp"
	"strings"
	"testing"
)

// --- M10: multi-camera layout and control density -----------------------------
//
// ADDITIVE, as every earlier block was. Nothing above these lines was changed:
// the M4 unified-grid assertion on `class="stream-card"`, the M7 resolution/HD
// cost lines, the M8 session-store honesty lines and the M6 re-login card all
// guard the same tokens they always did, and they still pass unmodified.
//
// The contract this block adds is the M10 one:
//
//  1. the video is CONTAINER-driven - there is no per-size max-height cap left,
//     because that cap is what kept a tile from ever filling its own card;
//  2. every card control except Hide/Show is behind ONE disclosure that is
//     collapsed by default;
//  3. Hide/Show lives in the status indicator line and is compact;
//  4. the fullscreen control is actually reachable (its wrapper had
//     `group-hover:opacity-100` with no ancestor carrying `group`);
//  5. the grid's track count per breakpoint is explicit rather than `auto-fill`
//     over a grid squeezed by a fixed 360px diagnostics column.

// cardTemplate returns the markup of the per-stream card template: from the
// `v-for` that renders the grid to the end of the Logs Panel. Every card-scoped
// assertion below is anchored to it, so a control that drifted OUT of the card
// fails rather than passing on a same-named token elsewhere in the file.
func cardTemplate(t *testing.T, html string) string {
	t.Helper()
	loop := strings.Index(html, "v-for=\"stream in streams\" :key=\"stream.id\"")
	if loop < 0 {
		t.Fatal("the stream card loop is missing")
	}
	end := strings.Index(html[loop:], "<!-- Logs Panel -->")
	if end < 0 {
		t.Fatal("could not find the end of the card grid")
	}
	card := html[loop : loop+end]
	// Trim the "no active streams" v-else branch, which renders after the card
	// template but before the Logs Panel. Without this the slice would include
	// the Configure Camera button and every card-scoped count would be wrong.
	if vElse := strings.Index(card, `<div v-else class="panel-body text-center`); vElse >= 0 {
		card = card[:vElse]
	}
	return card
}

// styleBlock returns everything inside the single <style> element, so a CSS
// assertion cannot be satisfied by a lookalike rule in the inline Tailwind
// config or in the JS.
func styleBlock(t *testing.T, html string) string {
	t.Helper()
	open := strings.Index(html, "<style>")
	close := strings.Index(html, "</style>")
	if open < 0 || close < 0 || close < open {
		t.Fatal("the <style> block is missing")
	}
	return html[open:close]
}

// TestFrontendDrivesTheVideoFromItsContainerNotAPerSizeCap guards the actual
// desktop defect: the wrapper capped height per S/M/L, so the picture could
// never fill the card it sat in.
func TestFrontendDrivesTheVideoFromItsContainerNotAPerSizeCap(t *testing.T) {
	html := readIndexHTML(t)
	card := cardTemplate(t, html)

	// The per-size height caps must be gone. These are the exact Tailwind
	// classes the old binding chose between.
	for _, forbidden := range []string{"max-h-[400px]", "max-h-[600px]", "max-h-[800px]"} {
		if strings.Contains(html, forbidden) {
			t.Errorf("the per-size video height cap %q is still present; the video cannot fill its card while it is", forbidden)
		}
	}
	// The old ternary binding must be gone as a whole, not merely neutralised.
	if strings.Contains(html, "stream.videoSize === 'small' ? 'aspect-video") {
		t.Error("the video wrapper still binds its aspect/height to stream.videoSize")
	}

	// The card's own video wrapper must exist and be driven by CSS.
	if !strings.Contains(card, `:class="['video-container', stream.isFullscreen ? 'is-fullscreen' : '']"`) {
		t.Error("the video wrapper must be a plain .video-container with an is-fullscreen modifier, with no per-size height cap")
	}
	style := styleBlock(t, html)
	if !strings.Contains(style, "aspect-ratio:16 / 9") {
		t.Error(".video-container must take its size from the container (a CSS aspect-ratio), not from a JS-selected height cap")
	}
	// The video must fill that container rather than keep its intrinsic size.
	if !strings.Contains(style, ".video-container video { width:100%; height:100%") {
		t.Error("the video element must fill its container, otherwise a wide card still shows a small picture")
	}
}

// TestFrontendCollapsesEveryCardControlExceptHideBehindOneDisclosure is the
// central M10 contract: ONE disclosure, collapsed by default, owning every
// control except Hide/Show - which is not in it.
func TestFrontendCollapsesEveryCardControlExceptHideBehindOneDisclosure(t *testing.T) {
	html := readIndexHTML(t)
	card := cardTemplate(t, html)

	// There is exactly one disclosure control per card.
	if n := strings.Count(card, `class="stream-actions-toggle"`); n != 1 {
		t.Errorf("a card must have exactly ONE disclosure control, found %d", n)
	}
	// It is a real, state-bearing disclosure: aria-expanded is bound to state
	// and aria-controls names the panel it owns.
	if !strings.Contains(card, `:aria-expanded="streamActionsOpen(stream) ? 'true' : 'false'"`) {
		t.Error("the disclosure must report its expanded state")
	}
	if !strings.Contains(card, `:aria-controls="'stream-actions-' + stream.id"`) {
		t.Error("the disclosure must point at the panel it controls")
	}
	// The panel is bound with v-show (a visibility change) and carries the id
	// the disclosure names. v-if would destroy the controls; v-show keeps them
	// in the DOM and merely hides them.
	if !strings.Contains(card, `v-show="streamActionsOpen(stream)" :id="'stream-actions-' + stream.id" class="stream-actions"`) {
		t.Error("the control panel must be hidden with v-show on streamActionsOpen, keyed to the disclosure's aria-controls id")
	}
	// Collapsed by DEFAULT: the reactive field must not be initialised true
	// anywhere, and a freshly loaded stream falls back to the stored value,
	// which is false unless the user opened it themselves.
	if strings.Contains(html, "actionsOpen: true") || strings.Contains(html, "actionsOpen:true") {
		t.Error("the control panel must be collapsed by default")
	}
	if !strings.Contains(html, "actionsOpen: existingStream?.actionsOpen ?? storedActionsOpen(stream.id)") {
		t.Error("a loaded stream must carry an explicit actionsOpen state that defaults to collapsed")
	}
	if !strings.Contains(html, "const streamActionsOpen = (stream) => stream.actionsOpen === true;") {
		t.Error("streamActionsOpen must be false for an unset state, so the panel starts collapsed")
	}

	// Every control that is NOT Hide/Show must be inside the panel, and must
	// have moved OUT of the status line. Collapsing is a visibility change, so
	// the handlers must be untouched.
	panelAt := strings.Index(card, `class="stream-actions"`)
	if panelAt < 0 {
		t.Fatal("the collapsed control panel is missing from the card")
	}
	statusLine := strings.Index(card, `class="stream-status-line"`)
	hideAt := strings.Index(card, `class="stream-hide-toggle"`)
	if statusLine < 0 || hideAt < 0 || hideAt < statusLine {
		t.Fatal("the Hide/Show control must live inside the status indicator line")
	}
	panel := card[panelAt:]
	for _, control := range []string{
		`class="size-selector`,
		`@click="setVideoSize(stream, 'small')"`,
		`@click="setVideoSize(stream, 'medium')"`,
		`@click="setVideoSize(stream, 'large')"`,
		`@click="synchronizeStream(stream)"`,
		`@click="diagnoseStream(stream)"`,
		`@click="reconnectStream(stream)"`,
		`@click="stopStream(stream.id)"`,
	} {
		if !strings.Contains(panel, control) {
			t.Errorf("control %q must remain reachable INSIDE the collapsed panel", control)
		}
	}
	// Nothing that lives in the panel may ALSO be rendered above it: a control
	// that is both collapsed and always visible would defeat the disclosure.
	visible := card[:panelAt]
	for _, leaked := range []string{
		`@click="setVideoSize(stream,`,
		`@click="synchronizeStream(stream)"`,
		`@click="diagnoseStream(stream)"`,
		`@click="reconnectStream(stream)"`,
		`@click="stopStream(stream.id)"`,
	} {
		if strings.Contains(visible, leaked) {
			t.Errorf("control %q is still rendered OUTSIDE the collapsed panel", leaked)
		}
	}
	// Exactly four buttons exist outside the panel - the disclosure, the
	// status-line Hide/Show, the fullscreen overlay button and the M6 re-login
	// action - so no seventh control has appeared on the card face.
	if n := strings.Count(visible, "<button"); n != 4 {
		t.Errorf("exactly 4 buttons may render when the panel is collapsed (disclosure, Hide/Show, fullscreen, re-login); found %d", n)
	}
	// And inside the panel: the four ONVIF-path actions, with Sync gated so a
	// Tuya card renders three.
	if n := strings.Count(panel, "<button"); n != 4 {
		t.Errorf("the panel must contain the 4 recovery/stop actions, found %d", n)
	}
	// Hide/Show must NOT be inside the collapsible panel.
	if strings.Contains(panel, `class="stream-hide-toggle"`) {
		t.Error("Hide/Show must stay visible, not be folded into the collapsed panel")
	}
}

// TestFrontendKeepsHideShowCompactInTheStatusLine covers the second half of the
// user's request: the Hide/Show control moves into the indicator row and shrinks,
// while keeping an accessible name because it must work on touch.
func TestFrontendKeepsHideShowCompactInTheStatusLine(t *testing.T) {
	html := readIndexHTML(t)
	card := cardTemplate(t, html)

	// It sits in the status line, next to the dot/status word/provider badge.
	line := card[strings.Index(card, `class="stream-status-line"`):strings.Index(card, `class="stream-hide-toggle"`)]
	for _, neighbour := range []string{"rounded-full", "provider-badge", "{{ stream.status }}"} {
		if !strings.Contains(line, neighbour) {
			t.Errorf("the status indicator line must still contain %q", neighbour)
		}
	}
	// It is a compact, icon-first control: the icon IS the label, and the
	// accessible name is supplied by aria-label + title.
	hide := card[strings.Index(card, `class="stream-hide-toggle"`):]
	hide = hide[:strings.Index(hide, "</button>")]
	for _, token := range []string{
		`:aria-label="stream.showVideo ? 'Hide video for ' + stream.id : 'Show video for ' + stream.id"`,
		`:title="stream.showVideo ? 'Hide video' : 'Show video'"`,
		`:aria-pressed="stream.showVideo ? 'true' : 'false'"`,
		`stream.showVideo ? 'fas fa-eye-slash' : 'fas fa-eye'`,
	} {
		if !strings.Contains(hide, token) {
			t.Errorf("the compact Hide/Show control is missing %q", token)
		}
	}
	// It must not use the global 44px button floor: that floor is what made six
	// controls own the phone viewport.
	style := styleBlock(t, html)
	rule := regexp.MustCompile(`\.stream-hide-toggle\s*\{[^}]*\}`).FindString(style)
	if rule == "" {
		t.Fatal(".stream-hide-toggle has no CSS rule")
	}
	if !strings.Contains(rule, "min-height:0") {
		t.Error("the compact Hide/Show control must opt out of the 44px global button floor")
	}
	if !strings.Contains(rule, "width:28px; height:28px") {
		t.Error("the Hide/Show control must be a small fixed square, not a full-width button")
	}
	// The old full-width full-colour Hide/View button must be gone from the
	// actions row.
	if strings.Contains(card, "{{ stream.showVideo ? 'Hide' : 'View' }}") {
		t.Error("the old full-size Hide/View button is still rendered")
	}
	// The global floor itself is untouched - every OTHER button keeps it.
	if !strings.Contains(style, "button,input,select { min-height:44px; }") {
		t.Error("the 44px touch-target floor must remain for every other control")
	}
	// And the S/M/L items, which are divs and so are not covered by that floor,
	// must get an equivalent touch target of their own: folding them into the
	// collapsed panel must not also shrink them.
	if !strings.Contains(style, ".size-selector>div { display:flex; align-items:center; justify-content:center; min-width:44px; min-height:44px; }") {
		t.Error("the S/M/L items must keep a 44px touch target even though they are divs")
	}
	for _, pressed := range []string{
		`:aria-pressed="stream.videoSize === 'small' ? 'true' : 'false'"`,
		`:aria-pressed="stream.videoSize === 'medium' ? 'true' : 'false'"`,
		`:aria-pressed="stream.videoSize === 'large' ? 'true' : 'false'"`,
	} {
		if !strings.Contains(card, pressed) {
			t.Errorf("the S/M/L items must report their selected state: missing %q", pressed)
		}
	}
	// They must be keyboard operable, not click-only divs.
	if n := strings.Count(card, `role="button" tabindex="0"`); n != 3 {
		t.Errorf("all three S/M/L items must be focusable role=button controls, found %d", n)
	}
}

// TestFrontendMakesTheFullscreenControlReachable is the third defect: the
// overlay wrapper used `group-hover:opacity-100` but no ancestor carried the
// Tailwind `group` class, so the button was invisible on hover and unreachable
// on touch.
func TestFrontendMakesTheFullscreenControlReachable(t *testing.T) {
	html := readIndexHTML(t)
	card := cardTemplate(t, html)

	// The card must carry the `group` marker the wrapper's group-hover depends
	// on. It comes from the static class attribute the card template already
	// had, so the `class="stream-card"` literal the M4 assertion guards stays
	// byte-for-byte intact.
	if !regexp.MustCompile(`class="stream-card group"|class="stream-card"[\s\S]{0,200}:class=`).MatchString(card) {
		t.Error("the stream card must carry the `group` class the overlay's group-hover rule requires")
	}
	// And a hover/focus rule must actually exist in CSS, independent of whether
	// Tailwind's JIT emits the variant.
	style := styleBlock(t, html)
	if !strings.Contains(style, ".stream-card:hover .video-overlay-controls") {
		t.Error("the overlay must be revealed by a real CSS rule on card hover")
	}
	// Touch and keyboard: focus-within reveals it, and a coarse pointer gets it
	// permanently visible because hover does not exist there.
	if !strings.Contains(style, ".stream-card:focus-within .video-overlay-controls") {
		t.Error("the overlay must be revealed when the fullscreen button itself receives focus, so keyboard users can reach it")
	}
	if !strings.Contains(style, "@media (hover:none), (pointer:coarse), (max-width:767px) { .video-overlay-controls { opacity:1; } }") {
		t.Error("the overlay must be permanently visible on touch devices, where there is no hover")
	}
	// The button keeps its accessible name.
	if !strings.Contains(card, `:aria-label="stream.isFullscreen ? 'Exit fullscreen' : 'Enter fullscreen'"`) {
		t.Error("the fullscreen control must keep its accessible name")
	}
	// The fullscreen state class must still take the container over the screen.
	if !strings.Contains(style, ".video-container.is-fullscreen { position:fixed") {
		t.Error("fullscreen must still promote the video container to the viewport")
	}
}

// TestFrontendDeclaresExplicitGridColumnsPerBreakpoint replaces `auto-fill`
// over a grid squeezed by a fixed diagnostics gutter with a stated track count
// per breakpoint, which is what makes "several cameras at once" watchable.
func TestFrontendDeclaresExplicitGridColumnsPerBreakpoint(t *testing.T) {
	html := readIndexHTML(t)
	style := styleBlock(t, html)

	// One explicit base column, and an explicit count at each step up.
	for _, rule := range []string{
		".stream-grid { display:grid; grid-template-columns:1fr; gap:16px; align-items:start; }",
		"@media (min-width: 768px) { .stream-grid { grid-template-columns:repeat(2,minmax(0,1fr)); } }",
		"@media (min-width: 1920px) { .stream-grid { grid-template-columns:repeat(3,minmax(0,1fr)); } }",
	} {
		if !strings.Contains(style, rule) {
			t.Errorf("the grid's column count must be stated explicitly: missing %q", rule)
		}
	}
	// auto-fill must be gone: it is what produced tiles sized by whatever width
	// the fixed 360px diagnostics column had left over.
	if strings.Contains(style, "grid-template-columns:repeat(auto-fill,minmax(340px,1fr))") {
		t.Error("the stream grid must not size its tracks with auto-fill over a squeezed grid")
	}
	// Below 1600px the diagnostics gutter must stop stealing the grid's width:
	// at 1440 it was taking a quarter of the page and forcing every tile small.
	if !strings.Contains(style, "@media (max-width: 1599px) {\n      .dashboard-grid { grid-template-columns:minmax(0,1fr); }") {
		t.Error("below 1600px the diagnostics column must move below the streams rather than squeeze them")
	}
	if !strings.Contains(style, "@media (min-width: 1600px) {\n      .page-container { width:min(100%,1560px); }") {
		t.Error("a wide desktop must widen the page container so the diagnostics gutter and the streams can coexist")
	}
	// The S/M/L control still EXISTS (nothing removed) but now claims grid
	// tracks instead of capping a height, and S - one track per camera - is the
	// default, which is what "watch several at once" means.
	for _, rule := range []string{`.stream-card[data-size="medium"] { grid-column:span 2; }`, `.stream-card[data-size="large"] { grid-column:span 2; }`} {
		if !strings.Contains(style, rule) {
			t.Errorf("the size selector must now claim grid tracks: missing %q", rule)
		}
	}
	if !strings.Contains(html, `const savedVideoSize = localStorage.getItem(`+ "`videoSize_${stream.id}`" + `) || 'small';`) {
		t.Error("one grid track per camera must be the default size, or a fresh grid stacks its cameras one per row")
	}
	if !strings.Contains(cardTemplate(t, html), `:data-size="stream.videoSize || 'small'"`) {
		t.Error("the card must declare which grid span the size selector selected")
	}
}

// TestFrontendPutsVideoBeforeControlsOnAPhone is the mobile half of the defect:
// the card's buttons used to own the viewport and push the video below the fold.
func TestFrontendPutsVideoBeforeControlsOnAPhone(t *testing.T) {
	html := readIndexHTML(t)
	style := styleBlock(t, html)

	// The phone block must define the card as one explicit column, and must
	// order video, then the identity/status block, then the controls.
	if !strings.Contains(style, "@media (max-width: 767px) {") {
		t.Fatal("the phone breakpoint block is missing")
	}
	for _, rule := range []string{
		".stream-grid { grid-template-columns:1fr; gap:12px; }",
		".video-container { order:1; margin-top:12px; }",
		".stream-card-header { order:2; margin-top:12px; flex-direction:column; align-items:stretch; }",
		".stream-controls { order:3; }",
	} {
		if !strings.Contains(style, rule) {
			t.Errorf("the phone layout must put video first and controls last: missing %q", rule)
		}
	}
	// The old "every control becomes full width" rule must be gone.
	if strings.Contains(style, ".stream-actions>button { flex:1; }") {
		t.Error("the phone block must not stretch every control to full width")
	}
	// The narrow-phone panel is a single column, not the old 2x2 button block.
	if strings.Contains(style, ".stream-actions { display:grid; grid-template-columns:1fr 1fr; }") {
		t.Error("the <=420px block must not render a 2x2 block of always-visible buttons")
	}
	if !strings.Contains(style, ".stream-actions { display:grid; grid-template-columns:1fr; }") {
		t.Error("the <=420px panel must stack its controls in one full-width column")
	}
	// The card must be a column flex container, or `order` on its children is
	// inert and the video would not actually come first.
	if !strings.Contains(style, ".stream-card { position:relative; display:flex; flex-direction:column;") {
		t.Error("the stream card must be a column flex container for the phone ordering to take effect")
	}
}
