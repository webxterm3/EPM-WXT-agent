// Package agentstatus is how the agent tells the rest of the machine how it is
// doing.
//
// A file rather than a socket or an IPC channel, because the reader is a menu
// bar item running as the logged-in user while the agent is a root daemon.
// Anything connection-based between those two needs a listener, an
// authentication story and a reconnect loop, to deliver three fields that
// change every few seconds. A file the daemon writes and the user reads is the
// whole mechanism.
//
// It is written atomically and read best-effort: a reader that catches a
// half-written file shows "unknown" for one tick, not a crash.
package agentstatus

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Status is what the agent publishes about itself.
type Status struct {
	// Connected is the single fact the menu bar exists to show.
	Connected bool `json:"connected"`

	AgentID  string `json:"agent_id,omitempty"`
	Machine  string `json:"machine,omitempty"`
	Server   string `json:"server,omitempty"`
	Version  string `json:"version,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`

	// UpdatedAt is when this was last written.
	//
	// The reader needs it to tell "the agent says it is disconnected" from
	// "the agent stopped writing ten minutes ago", which look identical
	// without a timestamp and mean very different things.
	UpdatedAt time.Time `json:"updated_at"`

	// LastError is the most recent reason the agent could not connect, if any.
	LastError string `json:"last_error,omitempty"`

	// PermissionsOK is whether macOS currently grants remote control what it
	// needs, as last observed by the agent.
	//
	// It is published here rather than discovered by whoever wants to know,
	// because ASKING macOS creates a privacy row attributed to whichever
	// program is at the head of the chain that asked — so a menu bar item that
	// checked for itself would put its own name in System Settings, granting
	// nothing to anybody. Only the agent asks, and everybody else reads the
	// answer from here.
	PermissionsOK bool `json:"permissions_ok,omitempty"`

	// PermissionNote is the human-readable reason when PermissionsOK is false.
	PermissionNote string `json:"permission_note,omitempty"`
}

// Stale reports whether this status is too old to believe.
//
// The agent republishes on a short interval, so anything much older than that
// means the agent is not running at all — which the menu bar shows as
// disconnected rather than as whatever the file last said.
func (s Status) Stale(maxAge time.Duration) bool {
	return time.Since(s.UpdatedAt) > maxAge
}

// pathOverride redirects the status file. Set only by tests in this package:
// the real path is root-owned and world-readable by design, and making it
// settable at runtime would turn a cosmetic file into a way to show the person
// a status that is not true.
var pathOverride string

// Path is where the status file lives on this platform.
func Path() string {
	if pathOverride != "" {
		return pathOverride
	}
	return platformPath()
}

// Write publishes the status.
//
// Atomic: written to a temporary file in the same directory and renamed over
// the real one, so a reader never sees a half-written document. Same
// directory because rename is only atomic within a filesystem.
func Write(s Status) error {
	s.UpdatedAt = time.Now()

	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}

	path := Path()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { // #nosec G301
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".status-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once the rename succeeds

	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// World-readable on purpose: the reader is the logged-in user and this
	// file is written by root. It carries no secret — an agent id, a server
	// name and a boolean.
	if err := os.Chmod(tmpName, 0o644); err != nil { // #nosec G302
		return err
	}
	return os.Rename(tmpName, path)
}

// Read returns the published status. A missing file is not an error: it means
// the agent has never run, which is a state the reader has to show.
func Read() (Status, bool) {
	raw, err := os.ReadFile(Path()) // #nosec G304 -- a path this program chose
	if err != nil {
		return Status{}, false
	}
	var s Status
	if err := json.Unmarshal(raw, &s); err != nil {
		return Status{}, false
	}
	return s, true
}
