package agentstatus

import (
	"path/filepath"
	"testing"
	"time"
)

func useTempPath(t *testing.T) {
	t.Helper()
	pathOverride = filepath.Join(t.TempDir(), "status.json")
	t.Cleanup(func() { pathOverride = "" })
}

// Write stamps the time, so a reader can tell a current answer from one the
// agent left behind before it died. A caller must not have to remember.
func TestWriteStampsTheTime(t *testing.T) {
	useTempPath(t)

	if err := Write(Status{Connected: true, Machine: "macbook"}); err != nil {
		t.Fatal(err)
	}

	got, ok := Read()
	if !ok {
		t.Fatal("nothing could be read back")
	}
	if got.UpdatedAt.IsZero() {
		t.Error("no timestamp was recorded, so the reader cannot tell a live status from a stale one")
	}
	if got.Stale(time.Minute) {
		t.Error("a status written just now reads as stale")
	}
	if !got.Connected || got.Machine != "macbook" {
		t.Errorf("the fields did not survive the round trip: %+v", got)
	}
}

// A stopped agent leaves its last status behind. Believing it would show a
// green tick for a process that is not running — the one thing this icon must
// never do.
func TestAnOldStatusIsStale(t *testing.T) {
	useTempPath(t)

	old := Status{Connected: true}
	old.UpdatedAt = time.Now().Add(-5 * time.Minute)
	if !old.Stale(50 * time.Second) {
		t.Error("a five-minute-old status was treated as current")
	}
}

// Nothing written yet is not an error: it is the state of a machine where the
// agent has never run, which the menu bar has to show.
func TestReadingNothingIsNotAnError(t *testing.T) {
	useTempPath(t)

	if _, ok := Read(); ok {
		t.Error("a status was read from a file that was never written")
	}
}

// The file is replaced by rename, so a reader never catches it half-written.
// Without that, a poll landing mid-write shows "unknown" at random.
func TestRepeatedWritesAlwaysReadBackWhole(t *testing.T) {
	useTempPath(t)

	for i := 0; i < 50; i++ {
		if err := Write(Status{Connected: i%2 == 0, AgentID: "abc"}); err != nil {
			t.Fatal(err)
		}
		got, ok := Read()
		if !ok {
			t.Fatalf("write %d could not be read back", i)
		}
		if got.AgentID != "abc" {
			t.Fatalf("write %d read back incomplete: %+v", i, got)
		}
	}
}
