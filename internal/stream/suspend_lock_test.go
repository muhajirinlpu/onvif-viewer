package stream

import (
	"sync"
	"testing"
	"time"

	"dengan.dev/camera-streamer/internal/models"
)

// These are the regression tests for the reproduced M11 crash
//
//	fatal error: sync: unlock of unlocked mutex
//
// The crash was a lock-discipline defect, not a slow test. It lived in the
// interaction between three things:
//
//  1. `monitorStreamWithReconnect` protected its own `close(done)` with
//     `process.closed.Do(...)`, a sync.Once stored ON THE PROCESS.
//  2. `resumeSuspendedProcess` replaced that Process value with a zero one,
//     `process.closed = sync.Once{}`, to give the resumed run a fresh flag.
//  3. Nothing waited for a returning run to finish. `SuspendStreamForSessionLoss`
//     waits only for `process.Exited`, which the monitor closes as a `defer` —
//     so the wait can be satisfied while the run is still unwinding, and any
//     `cmd.Start()` it had already committed is not waited for at all.
//
// When a returning run and the run that replaced it shared one Once variable,
// whichever of them called it SECOND took the slow path against a Once whose
// `done` was already set. A sync.Once that finds itself unlocked-but-marked-done
// is impossible in Go's own implementation; the state can only arise from a
// reset that raced a live call, and it makes `doSlow`'s `defer o.m.Unlock()`
// release a mutex it no longer holds. That is the fatal.
//
// The fix keys the flag on a per-run identity (`Process.runID` +
// `Process.runsClosed`), allocated under the process lock, so a run only ever
// shares its Once with itself. The tests below pin both halves of that: the
// structural guarantee, and the higher-level property (a done-close after a
// resume must be a no-op) that the fix makes hold outright.

// TestAMonitorRunClosingDoneCannotResetTheNextRunsOnce pins the structural
// guarantee: the Done-close for a run that has been SUPERSEDED is an outright
// no-op, not a call into a flag the next run owns.
//
// It is written white-box because the defect IS the flag's ownership. A
// black-box version cannot distinguish "the old run correctly did nothing" from
// "the old run called the new run's Once and got away with it", which is
// exactly the distinction the crash turned on.
func TestAMonitorRunClosingDoneCannotResetTheNextRunsOnce(t *testing.T) {
	m := newSuspendTestManager(t)
	info := startTuyaStream(t, m, "eb9f1d6e677b1b39f222ag")
	waitForStatus(t, m, info.ID, "running", 5*time.Second)

	m.mutex.RLock()
	process := m.streams[info.ID]
	m.mutex.RUnlock()
	if process == nil {
		t.Fatal("no process registered for the running stream")
	}

	process.mutex.RLock()
	oldDone := process.Done
	oldRunID := process.runID
	process.mutex.RUnlock()
	if oldRunID == 0 {
		t.Fatal("a started stream has runID 0; the run identity was never allocated")
	}

	// A resume hands the stream a NEW run identity and fresh channels. This is
	// the exact state in which the old code let two runs share one Once.
	if err := m.SuspendStreamForSessionLoss(info.ID, "session expired"); err != nil {
		t.Fatalf("SuspendStreamForSessionLoss: %v", err)
	}
	if _, err := m.ResumeSuspended(info.ID, "rtsp://127.0.0.1:43625/tuya_eb9f1d6e677b1b39f222ag", providerOf(t, m, info.ID)); err != nil {
		t.Fatalf("ResumeSuspended: %v", err)
	}
	waitForStatus(t, m, info.ID, "running", 5*time.Second)

	process.mutex.RLock()
	newRunID := process.runID
	newDone := process.Done
	process.mutex.RUnlock()
	if newRunID == oldRunID {
		t.Fatalf("resume reused runID %d; a new run must get a fresh identity or its Once is shared", oldRunID)
	}
	if newDone == oldDone {
		t.Fatal("resume reused the Done channel; the runs would share their close flag")
	}

	// The old run is gone from the manager's view of the world: closing its own
	// Done must not touch the new run's flag at all. If this reaches the new
	// run's sync.Once, the next close of newDone panics with the M11 fatal.
	process.closeDoneForRun(oldRunID, oldDone)

	// The new run's flag is still pristine: its first call still closes, and a
	// second call is still a no-op. A panicking or already-spent Once fails here.
	closed := make(chan struct{})
	go func() {
		process.closeDoneForRun(newRunID, newDone)
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("closeDoneForRun on the live run never returned; the flag was left locked")
	}
	// Idempotence: a second call for the SAME run must be a no-op, not a
	// second close of the channel (which would panic).
	process.closeDoneForRun(newRunID, newDone)
	if n := countStubProcs(t, m, streamRTSPURL(t, m, info.ID)); n != 1 {
		t.Fatalf("owned ffmpeg processes = %d, want 1; the stream did not survive the flag juggling", n)
	}
}

// TestClosingDoneIsSafeUnderConcurrentRunReplacement drives the flag mechanics
// directly, with no process spawning and no sleeps, so it is deterministic on a
// loaded host. It reproduces the M11 hazard in miniature: a run that is being
// superseded calls its done-close at the same time as the run that replaces it,
// which is the interleaving that made the two share one sync.Once.
//
// The old discipline -- one Once on the Process, zeroed by the resume -- is
// unsafe under exactly this interleaving. The fixed discipline must complete
// with no panic, no double close, and no lock left held.
func TestClosingDoneIsSafeUnderConcurrentRunReplacement(t *testing.T) {
	process := &Process{
		Done:       make(chan bool),
		Exited:     make(chan struct{}),
		runsClosed: make(map[uint64]*sync.Once),
	}

	// A "resume" replaces the run identity and the channel under the lock,
	// exactly as resumeSuspendedProcess does.
	process.runID = nextRunID()

	const supersessions = 200
	for i := 0; i < supersessions; i++ {
		process.mutex.RLock()
		oldRunID, oldDone := process.runID, process.Done
		process.mutex.RUnlock()

		// The superseding run allocates its own identity and channel, and the
		// path performing the supersession (suspend/resume) closes the OLD
		// run's Done under the OLD identity -- that close is the cancellation
		// signal the old run's backoff select is waiting on. It happens BEFORE
		// the identity is swapped, exactly as suspend/stop do it.
		process.closeDoneForRun(oldRunID, oldDone)

		process.mutex.Lock()
		process.Done = make(chan bool)
		process.runsClosed = make(map[uint64]*sync.Once)
		process.runID = nextRunID()
		process.mutex.Unlock()

		// Both the superseded run's own deferred close and the new run's close
		// now run concurrently, several times each (a monitor's deferred close
		// and a stop path can each reach it). The superseded run's calls must
		// be no-ops against the new run's flag.
		var wg sync.WaitGroup
		for j := 0; j < 4; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				process.closeDoneForRun(oldRunID, oldDone)
			}()
		}
		process.mutex.RLock()
		newRunID, newDone := process.runID, process.Done
		process.mutex.RUnlock()
		for j := 0; j < 4; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				process.closeDoneForRun(newRunID, newDone)
			}()
		}
		wg.Wait()

		// The superseded run must have left the new run's channel alone: it is
		// closed by the new run's own close, and a double close would have
		// panicked above. A channel that never closed means a lost wakeup.
		select {
		case <-newDone:
		case <-time.After(2 * time.Second):
			t.Fatalf("round %d: the live run's Done was never closed", i)
		}
	}

	// The flag map is bounded: at the live run's entry plus at most one entry a
	// just-superseded run can resurrect with its own deferred close. Pruning
	// happens at the supersession, so nothing accumulates over the life of the
	// process however many resumes it sees.
	process.mutex.RLock()
	remaining := len(process.runsClosed)
	process.mutex.RUnlock()
	if remaining > 2 {
		t.Fatalf("runsClosed holds %d entries after %d supersessions, want at most 2 (live run + one resurrected)", remaining, supersessions)
	}
}

// providerOf reports the provider a registered stream is running under, so a
// resume can be asked for the provider the stream actually has instead of a
// hard-coded one.
func providerOf(t *testing.T, m *Manager, streamID string) models.ProviderKind {
	t.Helper()
	for _, s := range m.ListStreams() {
		if s.ID == streamID {
			return s.Provider
		}
	}
	t.Fatalf("stream %s not found", streamID)
	return models.ProviderONVIF
}
