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
	for _, token := range []string{"Hls.ErrorTypes.NETWORK_ERROR", "hls.startLoad()", "Hls.ErrorTypes.MEDIA_ERROR", "hls.recoverMediaError()"} {
		if !strings.Contains(html, token) {
			t.Errorf("missing HLS recovery behavior %q", token)
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

