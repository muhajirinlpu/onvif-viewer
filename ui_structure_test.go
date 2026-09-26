package main

import (
	"os"
	"strings"
	"testing"
)

// readIndexHTML loads the single-file UI under test.
func readIndexHTML(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestFrontendResponsiveStructure(t *testing.T) {
	html := readIndexHTML(t)
	required := []string{
		"class=\"app-shell\"",
		"class=\"topbar",
		"class=\"dashboard-grid\"",
		"class=\"modal-shell\"",
		"class=\"modal-body ",
		"class=\"modal-footer\"",
		"@media (max-width: 767px)",
		"min-height:44px",
	}
	for _, token := range required {
		if !strings.Contains(html, token) {
			t.Errorf("missing responsive UI token %q", token)
		}
	}
	streams := strings.Index(html, "<!-- Active Streams -->")
	logs := strings.Index(html, "<!-- Logs Panel -->")
	if streams < 0 || logs < 0 || streams > logs {
		t.Error("active streams must appear before diagnostic logs")
	}
}

func TestFrontendModalLocksBodyScroll(t *testing.T) {
	data, err := os.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)
	if !strings.Contains(html, "document.body.classList.toggle('modal-open'") {
		t.Error("camera setup modal must lock background scrolling")
	}
}

func TestFrontendRecoversFatalHLSFailures(t *testing.T) {
	data, err := os.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)
	// A transport blip is still answered in place: ask for the data again and
	// make sure the element is playing (without the play() a paused element
	// stays paused after a 502/404 and looks disconnected).
	for _, token := range []string{"Hls.ErrorTypes.NETWORK_ERROR", "hls.startLoad()"} {
		if !strings.Contains(html, token) {
			t.Errorf("missing HLS recovery behavior %q", token)
		}
	}
	// Everything else is NOT recoverable in place on a live stream. This used to
	// assert hls.recoverMediaError(), but a blip surfaces as
	// mediaError/bufferAppendError (and mediaSourceRequiresReset), and
	// recoverMediaError() cannot fix an unplayable buffer -- it loops forever,
	// which is the frozen picture users reported. Measured: 49 fatal errors and
	// no recovery at all with the old handler, versus full recovery once the
	// player is rebuilt. The assertion is therefore inverted: in-place media
	// recovery must NOT be relied on, a rebuild must be reachable, and the
	// recovery must not give up permanently.
	if strings.Contains(html, "hls.recoverMediaError()") {
		t.Error("in-place media recovery cannot fix a live-stream blip; rebuild the player instead")
	}
	for _, token := range []string{"resetPlayer", "hls.liveSyncPosition", "recoveryWatchdog"} {
		if !strings.Contains(html, token) {
			t.Errorf("missing live-stream player recovery %q", token)
		}
	}
}

func TestFrontendProvidesManualStreamRecoveryControls(t *testing.T) {
	data, err := os.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)
	for _, token := range []string{
		`@click="synchronizeStream(stream)"`,
		`@click="diagnoseStream(stream)"`,
		`@click="reconnectStream(stream)"`,
		`fetch('/api/stream/synchronize'`,
		"fetch(`/api/stream/diagnose?id=${encodeURIComponent(stream.id)}`",
		"fetch(`/api/stream/reconnect?id=${encodeURIComponent(stream.id)}`",
	} {
		if !strings.Contains(html, token) {
			t.Errorf("missing manual recovery control %q", token)
		}
	}
}

func TestFrontendDisplaysStreamHealthDiagnostics(t *testing.T) {
	data, err := os.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)
	for _, token := range []string{"stream.status", "stream.detail", "stream.reconnectCount", "stream.lastHlsAdvance"} {
		if !strings.Contains(html, token) {
			t.Errorf("missing visible stream health field %q", token)
		}
	}
}

// --- M4: multi-provider additions -------------------------------------------
//
// The assertions below are ADDITIVE. Nothing above this line was changed: every
// earlier assertion still guards the same token, so a regression in the ONVIF
// contract still fails the suite.

func TestFrontendStartsWithAProviderChooser(t *testing.T) {
	html := readIndexHTML(t)
	for _, token := range []string{
		`class="provider-chooser"`,
		`class="provider-chooser-options"`,
		"role=\"group\" aria-label=\"Camera provider\"",
		`@click="selectProvider('onvif')"`,
		`@click="selectProvider('tuya')"`,
		"'provider-option-active': providerChoice === 'onvif'",
		"'provider-option-active': providerChoice === 'tuya'",
		// The chooser must precede the ONVIF form inside the modal.
		"<!-- Provider Chooser: adding a camera starts here -->",
	} {
		if !strings.Contains(html, token) {
			t.Errorf("missing provider chooser token %q", token)
		}
	}
	chooser := strings.Index(html, "<!-- Provider Chooser: adding a camera starts here -->")
	form := strings.Index(html, "<!-- Config Form -->")
	connection := strings.Index(html, "<!-- Connection Settings -->")
	if chooser < 0 || form < 0 || connection < 0 || chooser < form || chooser > connection {
		t.Error("the provider chooser must sit at the top of the camera setup form, before the ONVIF fields")
	}
}

func TestFrontendKeepsTheONVIFFormInsideItsOwnPanel(t *testing.T) {
	html := readIndexHTML(t)
	// The original form landmarks must still exist AND be gated behind the
	// ONVIF choice, so the existing fields are untouched but no longer shown
	// for Tuya.
	for _, token := range []string{
		"<!-- ONVIF Panel: the original form, untouched -->",
		"<template v-if=\"providerChoice === 'onvif'\">",
		"<!-- Connection Settings -->",
		"<!-- Authentication -->",
		"<!-- Advanced Options -->",
	} {
		if !strings.Contains(html, token) {
			t.Errorf("missing ONVIF panel token %q", token)
		}
	}
	if !strings.Contains(html, "v-if=\"providerChoice === 'onvif'\" @click=\"fetchStreamUri\"") {
		t.Error("the Start Stream action must stay on the ONVIF panel")
	}
}

func TestFrontendProvidesTuyaQRSignInWithACountdown(t *testing.T) {
	html := readIndexHTML(t)
	for _, token := range []string{
		"<!-- Tuya Panel: QR sign-in -> device list -> pick -->",
		`<template v-if="providerChoice === 'tuya'">`,
		`class="tuya-qr-frame"`,
		`:src="tuyaQr"`,
		"alt=\"Tuya login QR code\"",
		`class="tuya-countdown"`,
		"{{ tuyaCountdownLabel }}",
		`@click="beginTuyaLogin"`,
		`fetch('/api/tuya/login/begin'`,
		"`/api/tuya/login/poll?token=${encodeURIComponent(tuyaToken.value)}`",
		`fetch('/api/tuya/session')`,
		`fetch('/api/providers/cameras?provider=tuya')`,
		// The countdown must be alive, not decorative.
		"setInterval(() => {",
		"tuyaQrExpiresAt.value",
	} {
		if !strings.Contains(html, token) {
			t.Errorf("missing Tuya sign-in token %q", token)
		}
	}
}

func TestFrontendOffersARefreshActionWhenTheQRExpires(t *testing.T) {
	html := readIndexHTML(t)
	// The main UX failure mode is a stale QR that silently fails. An expired
	// token must both say so and offer a way out.
	for _, token := range []string{
		"tuyaQrExpired",
		`v-if="tuyaQrExpired"`,
		"This QR code has expired and can no longer be scanned. Request a fresh one.",
		"'Refresh QR code'",
		"'Get QR code'",
		"resp.status === 410",
		"growTuyaExpired",
	} {
		if !strings.Contains(html, token) {
			t.Errorf("missing expired-QR recovery token %q", token)
		}
	}
}

func TestFrontendRendersBothProvidersInOneCardGrid(t *testing.T) {
	html := readIndexHTML(t)
	for _, token := range []string{
		`class="stream-grid"`,
		"<!-- ONE grid for every provider",
		`class="provider-badge"`,
		"provider-badge-tuya",
		"provider-badge-onvif",
		"streamProvider(stream)",
		"stream.provider",
	} {
		if !strings.Contains(html, token) {
			t.Errorf("missing unified-grid token %q", token)
		}
	}
	// The single collapsible square card must still be the card template.
	if !strings.Contains(html, "v-for=\"stream in streams\" :key=\"stream.id\"") ||
		!strings.Contains(html, "class=\"stream-card\"") {
		t.Error("the unified grid must keep rendering the existing stream-card template")
	}
	// The provider badge must be rendered per card, i.e. inside the loop.
	loop := strings.Index(html, "v-for=\"stream in streams\" :key=\"stream.id\"")
	if loop < 0 {
		t.Fatal("the stream card loop is missing")
	}
	gridEnd := strings.Index(html[loop:], "<!-- Logs Panel -->")
	if gridEnd < 0 {
		t.Fatal("could not find the end of the card grid")
	}
	card := html[loop : loop+gridEnd]
	if !strings.Contains(card, `class="provider-badge"`) || !strings.Contains(card, "streamProvider(stream)") {
		t.Error("the provider badge must live inside the per-stream card")
	}
}

func TestFrontendOmitsONVIFOnlyControlsForTuyaCards(t *testing.T) {
	html := readIndexHTML(t)
	// Sync is a SOAP call with no Tuya equivalent: it must be gated rather than
	// rendered as a dead button.
	if !strings.Contains(html, "v-if=\"streamProvider(stream) === 'onvif'\"") {
		t.Error("ONVIF-only controls must be hidden for Tuya cards")
	}
	if !strings.Contains(html, "<!-- Sync is an ONVIF-only SOAP call") {
		t.Error("the ONVIF-only gating must be explained where it happens")
	}
	// The Siya path must still call the same start endpoint with a provider.
	if !strings.Contains(html, "body: JSON.stringify({ provider: 'tuya', deviceId: camera.id })") {
		t.Error("the Tuya device picker must start the stream through /api/stream/start")
	}
}

// --- M6: session lifecycle --------------------------------------------------
//
// Again ADDITIVE. Every assertion above this line still guards the same token.

func TestFrontendShowsExpiryOnlyWhenTheCloudStatedIt(t *testing.T) {
	html := readIndexHTML(t)
	for _, token := range []string{
		// The three axes must be surfaced separately, because the whole point of
		// M6 is that "a file exists" is not "the cloud accepted it".
		"tuyaSession.filePresent",
		"tuyaSession.cloudVerified",
		"tuyaSession.expiryKnown",
		"tuyaExpiryLabel",
		"tuya-expiry-known",
		"tuya-expiry-unknown",
		"tuyaSession.expirySource",
		// The honest absence of a number.
		"Expiry unknown",
		"no countdown can be shown",
	} {
		if !strings.Contains(html, token) {
			t.Errorf("missing honest-expiry token %q", token)
		}
	}
	// The countdown must be gated on expiryKnown, never rendered unconditionally.
	if !strings.Contains(html, `v-if="tuyaSession.expiryKnown"`) {
		t.Error("the expiry countdown must be gated on tuyaSession.expiryKnown")
	}
	if !strings.Contains(html, `v-else`) {
		t.Error("expiryKnown=false must have its own honest branch")
	}
	// The label must never be derived from the file's age or a hardcoded TTL.
	for _, forbidden := range []string{"SESSION_TTL", "sessionTtl", "LAST_REFRESH_TTL"} {
		if strings.Contains(html, forbidden) {
			t.Errorf("a fabricated client-side TTL appeared in the UI: %q", forbidden)
		}
	}
}

func TestFrontendOffersReLoginOnAffectedCards(t *testing.T) {
	html := readIndexHTML(t)
	for _, token := range []string{
		"tuya-card-relogin",
		"tuya-card-relogin-action",
		"beginTuyaRelogin",
		"Re-login required",
		"Sign in again and resume this camera",
		// The card must key off the suspended/needs_relogin state the server
		// reports, not off a local guess.
		"stream.suspended || stream.status === 'needs_relogin'",
	} {
		if !strings.Contains(html, token) {
			t.Errorf("missing re-login token %q", token)
		}
	}
	// The server-reported status string must match the Go constant exactly.
	if !strings.Contains(html, "'needs_relogin'") {
		t.Error("the card must recognise the needs_relogin status the server emits")
	}
	// The re-login action must live INSIDE the per-stream card.
	loop := strings.Index(html, "v-for=\"stream in streams\" :key=\"stream.id\"")
	if loop < 0 {
		t.Fatal("the stream card loop is missing")
	}
	gridEnd := strings.Index(html[loop:], "<!-- Logs Panel -->")
	if gridEnd < 0 {
		t.Fatal("could not find the end of the card grid")
	}
	card := html[loop : loop+gridEnd]
	if !strings.Contains(card, "beginTuyaRelogin") {
		t.Error("the one-click re-login action must be inside the per-stream card")
	}
}

func TestFrontendExplainsThatLogoutIsLocalOnly(t *testing.T) {
	html := readIndexHTML(t)
	for _, token := range []string{
		"fetch('/api/tuya/logout'",
		"Sign out on this device",
		// The honesty note: no server-side logout exists.
		"Tuya has no server-side logout",
	} {
		if !strings.Contains(html, token) {
			t.Errorf("missing logout token %q", token)
		}
	}
	// Signing out must NOT be described as revoking the account.
	if strings.Contains(html, "Use a different Tuya account") &&
		!strings.Contains(html, "emoves the stored session from this device only") {
		t.Error("sign-out must be described as local credential removal, not as an account switch")
	}
}

func TestFrontendResumesCamerasAfterAScanWithoutReselecting(t *testing.T) {
	html := readIndexHTML(t)
	for _, token := range []string{
		// The server reports how many streams came back; the UI must say so.
		"data.resumedStreams",
		"resumed — no device needed re-adding",
		// The grid must be refreshed so a stream that could NOT be resumed is
		// not left as a stale card.
		"await loadStreams()",
	} {
		if !strings.Contains(html, token) {
			t.Errorf("missing resume-after-scan token %q", token)
		}
	}
}

func TestFrontendDoesNotRenderADeadVideoElementForADeadSession(t *testing.T) {
	html := readIndexHTML(t)
	// The re-login banner must be paired with the card, and the video element
	// must not be the only thing shown.
	loop := strings.Index(html, "v-for=\"stream in streams\" :key=\"stream.id\"")
	if loop < 0 {
		t.Fatal("the stream card loop is missing")
	}
	gridEnd := strings.Index(html[loop:], "<!-- Logs Panel -->")
	if gridEnd < 0 {
		t.Fatal("could not find the end of the card grid")
	}
	card := html[loop : loop+gridEnd]
	if !strings.Contains(card, "Re-login required") {
		t.Error("an affected card must say why it is not playing")
	}
	if !strings.Contains(card, "stopped cleanly") {
		t.Error("an affected card must say the stream was stopped deliberately, not that it failed")
	}
}
