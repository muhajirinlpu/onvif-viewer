package logger

import (
	"path/filepath"
	"testing"
)

func TestStreamConfigurationsRoundTripAndDelete(t *testing.T) {
	l, err := NewLogger(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := l.UpsertStreamConfig("profile-a", "rtsp://user:pass@camera/live"); err != nil {
		t.Fatal(err)
	}
	configs, err := l.ListStreamConfigs()
	if err != nil {
		t.Fatal(err)
	}
	if len(configs) != 1 || configs[0].ProfileToken != "profile-a" || configs[0].RTSPURL != "rtsp://user:pass@camera/live" {
		t.Fatalf("unexpected configs: %#v", configs)
	}
	if err := l.DeleteStreamConfig("profile-a"); err != nil {
		t.Fatal(err)
	}
	configs, err = l.ListStreamConfigs()
	if err != nil || len(configs) != 0 {
		t.Fatalf("after delete: %#v, %v", configs, err)
	}
}
