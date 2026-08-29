package main

import "testing"

func TestListenAddressDefaultsToAllInterfaces(t *testing.T) {
	t.Setenv("ONVIF_VIEWER_LISTEN_ADDR", "")
	if got, want := listenAddress(), ":7878"; got != want {
		t.Fatalf("listenAddress() = %q, want %q", got, want)
	}
}

func TestListenAddressUsesConfiguredAddress(t *testing.T) {
	t.Setenv("ONVIF_VIEWER_LISTEN_ADDR", "127.0.0.1:7879")
	if got, want := listenAddress(), "127.0.0.1:7879"; got != want {
		t.Fatalf("listenAddress() = %q, want %q", got, want)
	}
}
