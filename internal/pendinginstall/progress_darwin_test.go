//go:build darwin

package pendinginstall

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// The bar has to be measuring real work, not elapsed time.
//
// This is the whole claim the feature makes. A bar driven by a timer looks
// identical for the first few seconds and then lies for the rest of the
// copy — and the moment it sits at 90% for a minute, nobody believes any
// bar this product draws again.
func TestProgressCountsBytesThatHaveActuallyBeenWritten(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	write(t, filepath.Join(src, "a.bin"), 600)
	write(t, filepath.Join(src, "b.bin"), 400)

	// Guarded: the sink is called from the watcher's goroutine and read
	// from this one. Without the lock the test races, which `go test -race`
	// reports as a failure of the test rather than of the code.
	var (
		mu      sync.Mutex
		reports []Progress
	)
	snapshot := func() []Progress {
		mu.Lock()
		defer mu.Unlock()
		return append([]Progress(nil), reports...)
	}
	SetProgressSink(func(p Progress) {
		mu.Lock()
		reports = append(reports, p)
		mu.Unlock()
	})
	t.Cleanup(func() { SetProgressSink(nil) })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { watchCopy(ctx, src, dst, "Copying"); close(done) }()

	// The first report is the total, before anything has been copied.
	waitFor(t, func() bool { return len(snapshot()) > 0 })
	if got := snapshot()[0]; got.Total != 1000 || got.Done != 0 {
		t.Fatalf("opening report is %d/%d, want 0/1000", got.Done, got.Total)
	}

	// Half the work appears in the destination.
	write(t, filepath.Join(dst, "a.bin"), 600)
	waitFor(t, func() bool { return latest(snapshot()).Done == 600 })

	cancel()
	<-done

	last := latest(snapshot())
	if last.Done != 600 || last.Total != 1000 {
		t.Fatalf("after copying 600 of 1000 bytes the report is %d/%d",
			last.Done, last.Total)
	}
	if last.Phase != "Copying" {
		t.Errorf("phase = %q", last.Phase)
	}
}

// A tree being written to by another process is the NORMAL case here, not a
// failure: files appear and vanish between the walk deciding to visit one
// and getting there, and a half-copied bundle has directories that cannot
// be read yet. Stopping at the first of those would break the measurement
// exactly when it is working.
func TestMeasuringCarriesOnPastWhatItCannotRead(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "real.bin"), 100)

	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })

	// Named deliberately: the file AFTER the unreadable directory is the
	// one that would be lost if the walk gave up at the first error.
	write(t, filepath.Join(dir, "zz-after.bin"), 50)

	if got := treeSize(dir); got != 150 {
		t.Errorf("size = %d, want 150 — the walk stopped at a directory it "+
			"could not read, so everything after it went uncounted", got)
	}
}

// Symlinks are counted by their OWN size, because the walk lstats rather
// than following them — a bundle is full of them (Frameworks/Versions/
// Current and friends) and following them would count the same payload
// several times over, or walk out of the bundle entirely.
//
// Both sides are measured the same way, so the ratio the bar draws stays
// honest; what matters is only that this does not change under somebody.
func TestSymlinksAreCountedWithoutBeingFollowed(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "payload.bin"), 1000)
	if err := os.Symlink("payload.bin", filepath.Join(dir, "Current")); err != nil {
		t.Fatal(err)
	}

	got := treeSize(dir)
	if got >= 2000 {
		t.Errorf("size = %d — the link was followed and its target counted twice", got)
	}
	if got < 1000 {
		t.Errorf("size = %d, want the payload at least", got)
	}
}

func TestMeasuringAnAbsentTreeIsZeroNotAPanic(t *testing.T) {
	if got := treeSize(filepath.Join(t.TempDir(), "nothing-here")); got != 0 {
		t.Errorf("size = %d, want 0", got)
	}
}

func write(t *testing.T, path string, n int) {
	t.Helper()
	if err := os.WriteFile(path, make([]byte, n), 0o600); err != nil {
		t.Fatal(err)
	}
}

func latest(reports []Progress) Progress {
	if len(reports) == 0 {
		return Progress{}
	}
	return reports[len(reports)-1]
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for a progress report")
}
