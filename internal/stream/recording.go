package stream

import (
	"os"
	"path/filepath"
	"time"
)

// observeRecordedPlaylist does no network work. Slow storage never blocks ffmpeg
// or the live watchdog; each run has one bounded observer that exits with ffmpeg.
func (sm *Manager) observeRecordedPlaylist(camera, run, dir string, done <-chan struct{}) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	var last time.Time
	visit := func() {
		fi, err := os.Stat(filepath.Join(dir, "stream.m3u8"))
		if err != nil || !fi.ModTime().After(last) {
			return
		}
		last = fi.ModTime()
		sm.recordingObserver(camera, run, dir, time.Now().UTC())
	}
	for {
		select {
		case <-ticker.C:
			visit()
		case <-done:
			visit()
			return
		}
	}
}
