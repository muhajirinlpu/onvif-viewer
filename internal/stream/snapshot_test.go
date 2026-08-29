package stream

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestSnapshotArgsExtractOneJPEGFrame(t *testing.T) {
	input := filepath.Join("/tmp", "onvif-hls123", "stream_42", "stream.m3u8")
	output := filepath.Join("/tmp", "snapshot.jpg")

	want := []string{
		"-hide_banner", "-loglevel", "error", "-y",
		"-i", input,
		"-frames:v", "1",
		"-f", "image2", output,
	}
	if got := snapshotArgs(input, output); !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshotArgs() = %#v, want %#v", got, want)
	}
}

func TestSnapshotInputPathUsesManagedHLSDirectory(t *testing.T) {
	manager := &Manager{hlsBaseDir: "/var/tmp/onvif-hls"}
	if got, want := manager.snapshotInputPath("stream_42"), "/var/tmp/onvif-hls/stream_42/stream.m3u8"; got != want {
		t.Fatalf("snapshotInputPath() = %q, want %q", got, want)
	}
}

func TestSnapshotInputPathRejectsTraversal(t *testing.T) {
	manager := &Manager{hlsBaseDir: "/var/tmp/onvif-hls"}
	if got := manager.snapshotInputPath("../other-stream"); got != "" {
		t.Fatalf("snapshotInputPath() = %q, want empty path for traversal", got)
	}
}

func TestNewManagerAllowsOnlyOneConcurrentSnapshot(t *testing.T) {
	manager := NewManager(t.TempDir(), nil)
	manager.snapshotSem <- struct{}{}
	select {
	case manager.snapshotSem <- struct{}{}:
		t.Fatal("snapshot semaphore permitted a second concurrent extraction")
	default:
	}
	<-manager.snapshotSem
}
