package stream

import (
	"encoding/json"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"dengan.dev/camera-streamer/internal/models"
)

func TestFreshnessRecoveryRequiresCurrentTuyaProcess(t *testing.T) {
	cmd := exec.Command("sleep", "60")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	p := &Process{Info: models.StreamInfo{Provider: models.ProviderTuya, Status: "running"}, Command: cmd, pgid: cmd.Process.Pid, runID: 1, shouldReconnect: true}
	if !p.canRecoverFreshness(cmd, 1) {
		t.Fatal("active Tuya run should be eligible")
	}
	for _, mutate := range []func(){func() { p.runID = 2 }, func() { p.runID = 1; p.Command = exec.Command("true") }, func() { p.Command = cmd; p.suspended = true }, func() { p.suspended = false; p.shouldReconnect = false }, func() { p.shouldReconnect = true; p.Info.Provider = models.ProviderONVIF }} {
		mutate()
		if p.canRecoverFreshness(cmd, 1) {
			t.Fatal("stale, suspended, stopped or ONVIF process must not be terminated")
		}
	}
	p.Info.Provider = models.ProviderTuya
	p.lastFreshnessRecovery = time.Now()
	if p.canRecoverFreshness(cmd, 1) {
		t.Fatal("cooldown must survive run restart")
	}
}

func TestFreshnessRecoverySignalsOnlyOwnedSyntheticProcess(t *testing.T) {
	cmd := exec.Command("sleep", "60")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	p := &Process{Info: models.StreamInfo{Provider: models.ProviderTuya, Status: "running"}, Command: cmd, pgid: cmd.Process.Pid, runID: 7, shouldReconnect: true}
	now := time.Now()
	if p.recoverFreshness(cmd, 6, now) {
		t.Fatal("wrong run killed child")
	}
	if err := syscall.Kill(cmd.Process.Pid, 0); err != nil {
		t.Fatalf("wrong run terminated child: %v", err)
	}
	if !p.recoverFreshness(cmd, 7, now) {
		t.Fatal("owned child was not signalled")
	}
	if p.recoverFreshness(cmd, 7, now.Add(time.Second)) {
		t.Fatal("repeated signal inside cooldown")
	}
	if p.lastFreshnessRecovery != now {
		t.Fatal("recovery timestamp not retained")
	}
}

func TestFreshnessInvalidPlaylistDoesNotTriggerRecovery(t *testing.T) {
	base := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	var f hlsFreshness
	freshnessPlaylist(t, dir, 1, 6, false)
	f.observe(dir, base, models.ProviderTuya)
	freshnessPlaylist(t, dir, 2, 900, false)
	s := f.observe(dir, base.Add(6*time.Second), models.ProviderTuya)
	if s.valid || s.recover {
		t.Fatalf("impossible duration accepted: %+v", s)
	}
	freshnessPlaylist(t, dir, 3, 6, false)
	s = f.observe(dir, base.Add(12*time.Second), models.ProviderTuya)
	if s.valid || s.recover {
		t.Fatalf("invalid playlist must invalidate baseline: %+v", s)
	}
}

func TestFreshnessCooldownAfterAutomaticRecovery(t *testing.T) {
	base := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	var f hlsFreshness
	f.cooldownUntil = base.Add(14 * time.Minute)
	for i := 0; i <= 145; i++ {
		freshnessPlaylist(t, dir, i, 7, false)
		s := f.observe(dir, base.Add(time.Duration(i)*6*time.Second), models.ProviderTuya)
		if i < 122 && s.recover {
			t.Fatalf("recovered before consecutive threshold at %d", i)
		}
		if i == 122 && s.recover {
			t.Fatal("cooldown must suppress otherwise eligible drift")
		}
		if i == 142 && !s.recover {
			t.Fatalf("recovery did not resume after cooldown: %+v", s)
		}
	}
}

func TestTelemetryIncludesElapsedWallMediaNotCaptureTimestamp(t *testing.T) {
	p := &Process{Info: models.StreamInfo{Provider: models.ProviderTuya}, runID: 1}
	now := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	p.publishFreshness(freshnessSample{updated: true, valid: true, wallSeconds: 600, mediaSeconds: 660, driftSeconds: 60}, now, 1)
	got := p.Info.Freshness
	wire, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(wire, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["captureLatencyStatus"] != "unavailable_no_source_clock" {
		t.Fatalf("must explicitly report unavailable capture latency: %s", wire)
	}
	if got == nil || got.WallElapsedSeconds != 600 || got.MediaElapsedSeconds != 660 || got.DriftSeconds != 60 || got.MeasuredAt != now || got.Kind != "hls_elapsed_drift" {
		t.Fatalf("honest drift snapshot: %+v", got)
	}
	p.publishFreshness(freshnessSample{}, now.Add(time.Second), 1)
	if p.Info.Freshness == nil || p.Info.Freshness.MeasuredAt != now {
		t.Fatal("unchanged playlist must preserve last measured sample")
	}
	p.publishFreshness(freshnessSample{updated: true}, now.Add(2*time.Second), 1)
	if p.Info.Freshness != nil {
		t.Fatal("invalid data must remove, not retain, telemetry")
	}
	p.publishFreshness(freshnessSample{updated: true, valid: true, wallSeconds: 6}, now.Add(3*time.Second), 1)
	p.runID = 2
	p.publishFreshness(freshnessSample{updated: true, valid: true, wallSeconds: 10000}, now.Add(4*time.Second), 1)
	if p.Info.Freshness == nil || p.Info.Freshness.WallElapsedSeconds != 6 {
		t.Fatal("superseded run overwrote current telemetry")
	}
}
