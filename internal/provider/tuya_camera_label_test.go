package provider

import (
	"context"
	"strings"
	"testing"
)

// --- M12: the Tuya provider names the CAMERA on the stream it starts ---------
//
// A Tuya stream's RTSP URL is a loopback address on this process's own engine,
// so nothing about it names the camera. The card would therefore fall back to an
// internal id - the exact defect this milestone fixes - unless the provider hands
// the NAME it already knows (from the cloud device listing) to the stream
// manager at start time.

// recordingLabeller stands in for *stream.Manager: it records what the provider
// registered against a profile token.
type recordingLabeller struct {
	tokens []string
	labels []string
}

func (r *recordingLabeller) SetPendingStreamLabel(profileToken, label string) {
	r.tokens = append(r.tokens, profileToken)
	r.labels = append(r.labels, label)
}

// TestTuyaStartStreamRegistersTheCameraNameForTheCard is the assertion: the
// device name from the device listing reaches the stream's label, keyed to the
// namespaced profile token the manager will create the stream under.
func TestTuyaStartStreamRegistersTheCameraNameForTheCard(t *testing.T) {
	labeller := &recordingLabeller{}
	lister := &fakeLister{devices: measuredAccount()}
	p := NewTuya("/tmp/session.json",
		WithTuyaBridge(&fakeBridge{}),
		WithTuyaCameraLabeller(labeller),
		withTuyaLister(lister, testSession()),
	)

	// One discovery listing populates the NAME cache; this is exactly what the
	// UI's own camera fetch does before a start.
	cams, err := p.Cameras(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(cams) != 1 || cams[0].Name != "Security Camera" {
		t.Fatalf("cams = %#v, want the one camera named Security Camera", cams)
	}

	info, err := p.StartStream("eb9f1d6e677b1b39f222ag")
	if err != nil {
		t.Fatal(err)
	}
	if len(labeller.labels) != 1 {
		t.Fatalf("the provider registered %d labels, want exactly 1", len(labeller.labels))
	}
	if labeller.tokens[0] != "tuya:eb9f1d6e677b1b39f222ag" {
		t.Errorf("registered token = %q, want the namespaced profile token", labeller.tokens[0])
	}
	if labeller.labels[0] != "Security Camera" {
		t.Errorf("registered label = %q, want the cloud device NAME", labeller.labels[0])
	}
	// The provider also echoes it onto the returned info, so a caller that does
	// not go through the manager still gets a card title that names the camera.
	if info == nil || info.StreamLabel != "Security Camera" {
		t.Fatalf("info.StreamLabel = %#v, want the camera name", info)
	}
}

// TestTuyaStartStreamWithoutANameCachesNothingAndRegistersNothing is the honest
// degradation: with no discovery listing in this process there is no name to
// register, and the provider must not invent one (the manager then falls back to
// a short device id).
func TestTuyaStartStreamWithoutANameCachesNothingAndRegistersNothing(t *testing.T) {
	labeller := &recordingLabeller{}
	p := NewTuya("/tmp/session.json",
		WithTuyaBridge(&fakeBridge{}),
		WithTuyaCameraLabeller(labeller),
		withTuyaLister(&fakeLister{}, testSession()),
	)

	if _, err := p.StartStream("eb9f1d6e677b1b39f222ag"); err != nil {
		t.Fatal(err)
	}
	if len(labeller.labels) != 0 {
		t.Fatalf("the provider registered %v with no device name to offer", labeller.labels)
	}
	if got := p.CameraLabelForProfile("tuya:eb9f1d6e677b1b39f222ag"); got != "" {
		t.Fatalf("CameraLabelForProfile = %q, want \"\" when nothing is cached", got)
	}
}

// TestTuyaCameraLabelForProfileIsNameOnly covers the RESTORE-time lookup: a
// stored row carries a profile token, so this is how the camera name is
// recovered. It must answer only for Tuya tokens, and it must be a cache read
// (no cloud call), or a restart would be able to hang on labelling.
func TestTuyaCameraLabelForProfileIsNameOnly(t *testing.T) {
	lister := &fakeLister{devices: measuredAccount()}
	p := NewTuya("/tmp/session.json", withTuyaLister(lister, testSession()))
	if _, err := p.Cameras(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := p.CameraLabelForProfile("tuya:eb9f1d6e677b1b39f222ag"); got != "Security Camera" {
		t.Fatalf("CameraLabelForProfile = %q, want the cached device name", got)
	}
	// An ONVIF token must never be answered with a Tuya device name.
	for _, token := range []string{"Profile_1", "", "tuya:", "tuya:not a device id"} {
		if got := p.CameraLabelForProfile(token); got != "" {
			t.Errorf("CameraLabelForProfile(%q) = %q, want \"\"", token, got)
		}
	}
	// ...and the cache is names only: no credential material may be reachable
	// through it.
	if strings.Contains(p.CameraLabelForProfile("tuya:eb9f1d6e677b1b39f222ag"), "secret") {
		t.Error("the name cache exposed credential material")
	}
}
