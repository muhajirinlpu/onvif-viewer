// recording_fixture imports synthetic HLS segments into a disposable app database.
// Usage: recording_fixture DB_PATH RECORDING_DIR HLS_DIR CAMERA_KEY
package main

import (
	"context"
	"dengan.dev/camera-streamer/internal/logger"
	"dengan.dev/camera-streamer/internal/recording"
	"dengan.dev/camera-streamer/internal/recording/storage/local"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func main() {
	if len(os.Args) != 5 {
		panic("usage: recording_fixture DB_PATH RECORDING_DIR HLS_DIR CAMERA_KEY")
	}
	db, e := logger.NewLogger(os.Args[1])
	if e != nil {
		panic(e)
	}
	defer db.Close()
	store, e := local.New(filepath.Join(os.Args[2], "objects"))
	if e != nil {
		panic(e)
	}
	rec, e := recording.New(db.DB(), filepath.Join(os.Args[2], "spool"), store, recording.Config{QuotaBytes: 50 << 20, RetentionDays: 1})
	if e != nil {
		panic(e)
	}
	if e = rec.SetEnabled(os.Args[4], true); e != nil {
		panic(e)
	}
	if e = rec.IngestPlaylist(os.Args[4], "synthetic-run", os.Args[3], time.Now().UTC()); e != nil {
		panic(e)
	}
	if e = rec.Process(context.Background()); e != nil {
		panic(e)
	}
	segments, e := rec.Coverage(os.Args[4], time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if e != nil {
		panic(e)
	}
	fmt.Printf("imported=%d camera=%s\n", len(segments), os.Args[4])
}
