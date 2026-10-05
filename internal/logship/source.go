// Package logship collects the machine's own system logs and ships them off
// the endpoint.
//
// This is deliberately separate from the agent's operational logging. The
// agent logs what the AGENT did; this collects what the MACHINE recorded —
// Windows Event Log, the macOS unified log, DNS lookups — so an operator can
// answer "what happened on this laptop" after the fact.
//
// Two properties shape the whole design:
//
// Volume. A single machine can produce hundreds of megabytes of system log a
// day, nearly all of it system internals nobody will ever read. Everything
// here is therefore built around bounding that: channel selection, per-batch
// caps and a hard daily budget, all reported so the cost is visible rather
// than discovered on an invoice.
//
// Ordering and loss. Logs are read from a position that survives restarts, so
// nothing is shipped twice and nothing is skipped when the agent is stopped —
// the two failures that make a log archive untrustworthy for the one question
// it exists to answer.
package logship

import (
	"context"
	"time"
)

// Record is one log line, normalised across platforms so the backend and any
// downstream SIEM see a single shape regardless of where it came from.
type Record struct {
	// Timestamp is when the event occurred on the machine, not when it was
	// collected.
	Timestamp time.Time `json:"ts"`

	// Source names the collector: "windows-eventlog", "macos-unified", "dns".
	Source string `json:"source"`

	// Channel is the subdivision within the source — an Event Log channel, a
	// unified-log subsystem.
	Channel string `json:"channel,omitempty"`

	// Level is the severity as the OS reported it, lowercased:
	// "critical", "error", "warning", "info", "debug".
	Level string `json:"level,omitempty"`

	// EventID is the numeric identifier where the platform has one (Windows).
	EventID int `json:"event_id,omitempty"`

	// Process is the program that emitted the record, where known.
	Process string `json:"process,omitempty"`

	// User is the OS account the record is attributed to, where known.
	User string `json:"user,omitempty"`

	// Message is the human-readable text.
	Message string `json:"message"`

	// Raw carries the platform's own structured form for anything the fields
	// above do not capture. It is what makes this useful for forensics later,
	// when the question being asked is not one these fields anticipated.
	Raw string `json:"raw,omitempty"`
}

// Source is one collector. Implementations are platform-specific.
type Source interface {
	// Name identifies the source in Record.Source and in bookmarks.
	Name() string

	// Read returns records newer than the source's stored position, up to
	// limit. It returns the position to persist alongside them; the caller
	// saves that only after the batch is safely handed over, so a crash
	// mid-flight re-reads rather than loses.
	Read(ctx context.Context, from Position, limit int) ([]Record, Position, error)

	// Close releases anything the source holds.
	Close() error
}

// Position is a source's opaque read cursor.
//
// Its meaning is the source's own: a Windows EventRecordID per channel, a
// timestamp for the macOS unified log. Keeping it opaque means a source can
// change how it tracks progress without the shipper or the on-disk format
// having to know.
type Position struct {
	// Cursor is the source-defined position, persisted verbatim.
	Cursor map[string]string `json:"cursor,omitempty"`

	// Since bounds the first read after a fresh install, so a machine with
	// months of history does not ship all of it the moment the agent starts.
	Since time.Time `json:"since,omitempty"`
}

// NewPosition returns an empty position starting from t.
func NewPosition(t time.Time) Position {
	return Position{Cursor: map[string]string{}, Since: t}
}

// Get reads a cursor value, returning "" when absent.
func (p Position) Get(key string) string {
	if p.Cursor == nil {
		return ""
	}
	return p.Cursor[key]
}

// Set records a cursor value, returning the updated position. It copies rather
// than mutating so a caller holding the previous position — to retry a failed
// batch — is not affected.
func (p Position) Set(key, value string) Position {
	next := Position{Cursor: make(map[string]string, len(p.Cursor)+1), Since: p.Since}
	for k, v := range p.Cursor {
		next.Cursor[k] = v
	}
	next.Cursor[key] = value
	return next
}
