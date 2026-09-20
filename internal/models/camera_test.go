package models

import (
	"encoding/json"
	"testing"
)

// A stream created before the provider column existed, or by a code path that
// never set it, must still advertise a concrete provider in API JSON.
func TestStreamInfoReportsONVIFWhenProviderUnset(t *testing.T) {
	encoded, err := json.Marshal(StreamInfo{ID: "s1"})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if got["provider"] != "onvif" {
		t.Fatalf("provider = %#v, want \"onvif\" (encoded: %s)", got["provider"], encoded)
	}
}

func TestStreamInfoReportsTuyaProvider(t *testing.T) {
	encoded, err := json.Marshal(StreamInfo{ID: "s1", Provider: ProviderTuya})
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(encoded) || string(encoded) == "" {
		t.Fatalf("invalid JSON: %s", encoded)
	}
	var got map[string]any
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if got["provider"] != "tuya" {
		t.Fatalf("provider = %#v, want \"tuya\"", got["provider"])
	}
}

func TestProviderKindOrDefault(t *testing.T) {
	if got := ProviderKind("").OrDefault(); got != ProviderONVIF {
		t.Errorf("OrDefault(\"\") = %q, want %q", got, ProviderONVIF)
	}
	if got := ProviderTuya.OrDefault(); got != ProviderTuya {
		t.Errorf("OrDefault(tuya) = %q, want %q", got, ProviderTuya)
	}
}
