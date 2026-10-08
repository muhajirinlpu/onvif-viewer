package stream

import (
	"os/exec"
	"syscall"
	"time"

	"dengan.dev/camera-streamer/internal/models"
)

// canRecoverFreshness requires the exact command and monitor run still own
// this stream. A resumed, suspended, stopped or ONVIF stream is never eligible.
func (p *Process) canRecoverFreshness(cmd *exec.Cmd, runID uint64) bool {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.runID == runID && p.Command == cmd && cmd != nil && cmd.Process != nil && p.pgid > 0 && p.pgid == cmd.Process.Pid && p.shouldReconnect && !p.suspended && p.Info.Provider == models.ProviderTuya &&
		(p.lastFreshnessRecovery.IsZero() || time.Since(p.lastFreshnessRecovery) >= freshnessCooldown)
}

func (p *Process) recoverFreshness(cmd *exec.Cmd, runID uint64, now time.Time) bool {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if p.runID != runID || p.Command != cmd || cmd == nil || cmd.Process == nil || p.pgid <= 0 || p.pgid != cmd.Process.Pid || !p.shouldReconnect || p.suspended || p.Info.Provider != models.ProviderTuya ||
		(!p.lastFreshnessRecovery.IsZero() && now.Sub(p.lastFreshnessRecovery) < freshnessCooldown) {
		return false
	}
	// Only signal an owned child, while the ownership lock is held. The monitor
	// handles Wait/backoff; no second RTSP producer is created here.
	if err := syscall.Kill(-p.pgid, syscall.SIGTERM); err != nil {
		return false
	}
	p.lastFreshnessRecovery = now
	return true
}

func (p *Process) publishFreshness(s freshnessSample, now time.Time, runID uint64) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if p.runID != runID || !s.updated {
		return
	}
	if !s.valid {
		p.Info.Freshness = nil
		return
	}
	p.Info.Freshness = &models.HLSFreshness{Kind: "hls_elapsed_drift", MeasuredAt: now, WallElapsedSeconds: s.wallSeconds, MediaElapsedSeconds: s.mediaSeconds, DriftSeconds: s.driftSeconds}
}
