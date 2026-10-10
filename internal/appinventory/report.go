package appinventory

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// ReportDiscriminator is the StatusUpdate tag the backend routes on. It is
// mirrored by a constant in the backend and pinned by a cross-repo drift test,
// because a mismatch here is not a compile error — the reports simply stop
// arriving and the fleet silently shows no software.
const ReportDiscriminator = "__app_inventory__"

// DefaultChunkSize is how many applications ride in one report.
//
// A typical machine fits in a single chunk. Chunking exists for the ones that
// do not — a developer workstation with a thousand packages and long paths is
// an ordinary machine, not a hypothetical — and it is here from the start
// because adding it after agents are deployed means supporting both envelopes
// forever.
const DefaultChunkSize = 250

// Report is one chunk of one snapshot.
//
// The backend reconciles per snapshot: it updates what each chunk contains and
// only marks absent software as removed once the final chunk has arrived. That
// is why SnapshotID and the chunk counters are part of the envelope rather
// than implied — a report that stops halfway must leave the previous inventory
// intact, not look like the machine was wiped.
type Report struct {
	SnapshotID string `json:"snapshot_id"`

	// Chunk is this report's index, and Chunks the total in the snapshot. The
	// backend's removal sweep runs only on the last one.
	Chunk  int `json:"chunk"`
	Chunks int `json:"chunks"`

	CollectedAt  time.Time `json:"collected_at"`
	OS           string    `json:"os"`
	AgentVersion string    `json:"agent_version"`

	// CollectError records a collector that failed or was cut short. The
	// backend uses it to refuse the removal sweep: a partial scan must never
	// be mistaken for "this software is gone".
	CollectError string `json:"collect_error,omitempty"`

	Apps []Application `json:"apps"`
}

// Final reports whether this is the last chunk of its snapshot.
func (r Report) Final() bool { return r.Chunk == r.Chunks-1 }

// Chunk splits a snapshot into reports of at most size applications.
//
// A snapshot with no applications still produces one report. That is
// deliberate: "this machine has no software" and "this machine has never
// reported" are different answers, and sending nothing would make them
// indistinguishable.
func (s Snapshot) Chunk(snapshotID string, size int) []Report {
	if size <= 0 {
		size = DefaultChunkSize
	}

	total := (len(s.Apps) + size - 1) / size
	if total == 0 {
		total = 1
	}

	reports := make([]Report, 0, total)
	for i := 0; i < total; i++ {
		start := i * size
		end := start + size
		if end > len(s.Apps) {
			end = len(s.Apps)
		}

		reports = append(reports, Report{
			SnapshotID:  snapshotID,
			Chunk:       i,
			Chunks:      total,
			CollectedAt: s.CollectedAt,
			OS:          s.OS,
			Apps:        s.Apps[start:end],
		})
	}
	return reports
}

// NewSnapshotID returns a random identifier for one scan.
//
// It groups a snapshot's chunks together on the backend. Randomness rather
// than a timestamp because two scans could otherwise collide within a second
// and have their chunks interleaved, which would make the removal sweep act on
// a mixture of two scans.
func NewSnapshotID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// A scan with no usable id cannot be reconciled safely, so fall back
		// to something unique-enough rather than an empty string the backend
		// would have to reject.
		return hex.EncodeToString([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(buf[:])
}
