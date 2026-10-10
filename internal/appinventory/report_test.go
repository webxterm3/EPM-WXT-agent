package appinventory

import (
	"encoding/json"
	"testing"
	"time"
)

func snapshotOf(n int) Snapshot {
	apps := make([]Application, n)
	for i := range apps {
		apps[i] = Application{ID: "id-" + itoa(i), Name: "App " + itoa(i)}
	}
	return Snapshot{CollectedAt: time.Now().UTC(), OS: "darwin", Apps: apps}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func TestChunkCoversEveryApplicationExactlyOnce(t *testing.T) {
	snap := snapshotOf(603)
	reports := snap.Chunk("snap-1", 250)

	if len(reports) != 3 {
		t.Fatalf("got %d chunks for 603 apps at 250 each, want 3", len(reports))
	}

	seen := map[string]int{}
	for i, r := range reports {
		if r.Chunk != i {
			t.Errorf("chunk %d reports index %d", i, r.Chunk)
		}
		if r.Chunks != 3 {
			t.Errorf("chunk %d reports a total of %d", i, r.Chunks)
		}
		if r.SnapshotID != "snap-1" {
			t.Errorf("chunk %d has snapshot id %q", i, r.SnapshotID)
		}
		for _, app := range r.Apps {
			seen[app.ID]++
		}
	}

	if len(seen) != 603 {
		t.Errorf("chunks covered %d distinct applications, want 603", len(seen))
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("%s appeared in %d chunks", id, n)
		}
	}
}

// Only the last chunk may trigger the backend's removal sweep. If an earlier
// one claimed to be final, a machine's whole inventory would be marked removed
// while the rest of the scan was still arriving.
func TestOnlyTheLastChunkIsFinal(t *testing.T) {
	reports := snapshotOf(500).Chunk("s", 200)
	if len(reports) != 3 {
		t.Fatalf("got %d chunks", len(reports))
	}
	for i, r := range reports {
		want := i == len(reports)-1
		if r.Final() != want {
			t.Errorf("chunk %d Final() = %v, want %v", i, r.Final(), want)
		}
	}
}

// "This machine has no software" and "this machine has never reported" are
// different answers. Sending nothing would make them indistinguishable.
func TestEmptySnapshotStillReportsOnce(t *testing.T) {
	reports := Snapshot{OS: "windows"}.Chunk("s", 250)

	if len(reports) != 1 {
		t.Fatalf("got %d reports for an empty snapshot, want 1", len(reports))
	}
	if !reports[0].Final() {
		t.Error("the only report of an empty snapshot is not marked final")
	}
	if len(reports[0].Apps) != 0 {
		t.Errorf("got %d apps", len(reports[0].Apps))
	}
}

func TestSnapshotSmallerThanOneChunkIsASingleReport(t *testing.T) {
	reports := snapshotOf(7).Chunk("s", 250)
	if len(reports) != 1 || len(reports[0].Apps) != 7 || !reports[0].Final() {
		t.Fatalf("got %d reports, first has %d apps, final=%v", len(reports), len(reports[0].Apps), reports[0].Final())
	}
}

func TestExactMultipleDoesNotProduceAnEmptyTrailingChunk(t *testing.T) {
	reports := snapshotOf(500).Chunk("s", 250)
	if len(reports) != 2 {
		t.Fatalf("got %d chunks for an exact multiple, want 2", len(reports))
	}
	for i, r := range reports {
		if len(r.Apps) == 0 {
			t.Errorf("chunk %d is empty", i)
		}
	}
}

// Each scan must be distinguishable, or two scans' chunks interleave and the
// removal sweep acts on a mixture of both.
func TestSnapshotIDsAreUnique(t *testing.T) {
	seen := make(map[string]bool, 500)
	for i := 0; i < 500; i++ {
		id := NewSnapshotID()
		if id == "" {
			t.Fatal("empty snapshot id")
		}
		if seen[id] {
			t.Fatalf("snapshot id %q repeated", id)
		}
		seen[id] = true
	}
}

// The report is what crosses to the backend, so the fields the backend
// reconciles on have to survive the trip.
func TestReportRoundTripsThroughJSON(t *testing.T) {
	original := Report{
		SnapshotID: "abc123", Chunk: 1, Chunks: 2,
		CollectedAt: time.Date(2026, 10, 6, 10, 0, 0, 0, time.UTC),
		OS:          "windows", AgentVersion: "1.2.3",
		Apps: []Application{{
			ID: "registry:user:corp\\yesveer:chrome", Name: "Google Chrome",
			Version: "120.0", Publisher: "Google LLC",
			ExePath: `C:\Users\yesveer\AppData\Local\Chrome\chrome.exe`,
			Scope:   ScopeUser, OSUser: `CORP\yesveer`, Source: "registry",
		}},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Report
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if back.SnapshotID != original.SnapshotID || back.Chunk != 1 || back.Chunks != 2 {
		t.Errorf("envelope did not survive: %+v", back)
	}
	if len(back.Apps) != 1 {
		t.Fatalf("got %d apps", len(back.Apps))
	}
	got, want := back.Apps[0], original.Apps[0]
	if got.ID != want.ID {
		t.Errorf("ID = %q, want %q — the identity is what reconciliation keys on", got.ID, want.ID)
	}
	if got.ExePath != want.ExePath || got.Scope != want.Scope || got.OSUser != want.OSUser {
		t.Errorf("app fields did not survive: %+v", got)
	}
}
