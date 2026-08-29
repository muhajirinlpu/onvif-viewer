package stream

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const snapshotTimeout = 15 * time.Second

// snapshotArgs returns the FFmpeg arguments used to extract one JPEG frame from HLS.
func snapshotArgs(inputPath, outputPath string) []string {
	return []string{
		"-hide_banner", "-loglevel", "error", "-y",
		"-i", inputPath,
		"-frames:v", "1",
		"-f", "image2", outputPath,
	}
}

// snapshotInputPath returns the managed playlist path for a stream ID. It rejects
// any value that could escape the HLS directory.
func (sm *Manager) snapshotInputPath(streamID string) string {
	if streamID == "" || filepath.Base(streamID) != streamID || strings.Contains(streamID, string(filepath.Separator)) {
		return ""
	}
	return filepath.Join(sm.hlsBaseDir, streamID, "stream.m3u8")
}

// Snapshot extracts the newest available video frame from an active stream.
func (sm *Manager) Snapshot(streamID string) ([]byte, error) {
	select {
	case sm.snapshotSem <- struct{}{}:
		defer func() { <-sm.snapshotSem }()
	default:
		return nil, fmt.Errorf("snapshot already in progress")
	}

	sm.mutex.RLock()
	process, ok := sm.streams[streamID]
	sm.mutex.RUnlock()
	if !ok {
		return nil, fmt.Errorf("stream %q not found", streamID)
	}

	process.mutex.RLock()
	status := process.Info.Status
	process.mutex.RUnlock()
	if status != "running" && status != "reconnecting" {
		return nil, fmt.Errorf("stream %q is not active", streamID)
	}

	inputPath := sm.snapshotInputPath(streamID)
	if inputPath == "" {
		return nil, fmt.Errorf("invalid stream ID")
	}
	if _, err := os.Stat(inputPath); err != nil {
		return nil, fmt.Errorf("stream playlist is unavailable: %w", err)
	}

	output, err := os.CreateTemp("", "onvif-snapshot-*.jpg")
	if err != nil {
		return nil, fmt.Errorf("create snapshot file: %w", err)
	}
	outputPath := output.Name()
	if err := output.Close(); err != nil {
		_ = os.Remove(outputPath)
		return nil, fmt.Errorf("close snapshot file: %w", err)
	}
	defer os.Remove(outputPath)

	ctx, cancel := context.WithTimeout(context.Background(), snapshotTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ffmpeg", snapshotArgs(inputPath, outputPath)...)
	if commandOutput, err := cmd.CombinedOutput(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("snapshot timed out: %w", ctx.Err())
		}
		return nil, fmt.Errorf("extract snapshot: %w: %s", err, strings.TrimSpace(string(commandOutput)))
	}

	jpeg, err := os.ReadFile(outputPath)
	if err != nil {
		return nil, fmt.Errorf("read snapshot: %w", err)
	}
	if len(jpeg) == 0 {
		return nil, fmt.Errorf("snapshot is empty")
	}
	return jpeg, nil
}
