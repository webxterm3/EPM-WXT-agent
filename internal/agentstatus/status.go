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

// PendingInstall is one downloaded installer and what will happen to it.
//
// A flattened copy of the agent's own decision rather than a reference to it:
// this crosses a file, is read by a different program running as a different
// user, and anything it has to look up elsewhere is something that can be
// missing by the time it looks.
type PendingInstall struct {
	// Path identifies it, and is what the menu bar sends back to ask for an
	// install. Shown too, because two downloads of the same thing are
	// otherwise indistinguishable.
	Path string `json:"path"`
	// User is whose downloads it is in. The menu bar shows only its own
	// user's, since offering to install from somebody else's folder is a
	// surprising thing to put in front of a person.
	User string `json:"user,omitempty"`

	Label  string `json:"label"`
	Format string `json:"format"`
	// Publisher is who the operating system says signed it, empty when
	// nothing vouches for it.
	Publisher string `json:"publisher,omitempty"`
	SizeBytes int64  `json:"size_bytes,omitempty"`
	// Closed reports that the agent has ejected the image this was in.
	//
	// The menu bar needs to know, because the two situations call for
	// different words: software that is sitting there refusing to install is
	// not the same as software whose image is no longer open, and telling
	// somebody to drag across something that is not on screen any more reads
	// as a fault.
	Closed bool `json:"closed,omitempty"`
	// Requested reports that the agent has already asked for approval and
	// the ask left the machine.
	//
	// The menu bar needs it so it can stop offering to do what has been
	// done. Raised automatically when the image is opened, because opening
	// an installer IS the decision — waiting for somebody to find a button
	// means they have already been refused once for no reason they can see.
	Requested bool `json:"requested,omitempty"`
	// CanDrag reports that the window onto /Applications is actually open
	// for this person right now.
	//
	// It is not a given. The window is an access-control entry, and a
	// managed Mac refuses to write one even to root — so on many machines
	// dragging an approved application across meets the administrator
	// password sheet. The menu bar needs to know which it is, because
	// telling somebody to drag something that cannot be dragged is worse
	// than not telling them anything.
	CanDrag bool `json:"can_drag,omitempty"`
	// Installed marks a row that is an application already on the machine
	// rather than one sitting in a mounted disk image.
	Installed bool `json:"installed,omitempty"`
	// Removable reports that policy allows this person to remove it. When
	// it does not, the row offers to ask instead.
	Removable bool `json:"removable,omitempty"`
	// Updates reports that a version of this application is already
	// installed, so acting on this row replaces it rather than adding one.
	Updates bool `json:"updates,omitempty"`
	// Version is what the mounted image carries, InstalledVersion what is
	// already on the machine. Shown together so somebody can see whether
	// they are moving forwards.
	Version          string `json:"version,omitempty"`
	InstalledVersion string `json:"installed_version,omitempty"`

	// Outcome is one of installable, blocked, unverified, unsupported,
	// no-policy. Reason is the sentence to show.
	Outcome string `json:"outcome"`
	Reason  string `json:"reason"`
	Rule    string `json:"rule,omitempty"`
	Policy  string `json:"policy,omitempty"`

	// Installing and LastError describe an attempt in progress or just
	// finished, so a person who pressed the button sees something happen.
	Installing bool   `json:"installing,omitempty"`
	LastError  string `json:"last_error,omitempty"`
}

// Status is what the agent publishes about itself.
type Status struct {
	// DragUnavailable reports that macOS refuses the access-control entry
	// that would let somebody drag applications into Applications or to the
	// Trash.
	//
	// Published at the top level, not per row, because it is a fact about
	// the Mac rather than about one application — and because somebody who
	// has just met Finder's password prompt needs to be told where the
	// working route is, before they go looking for a row.
	DragUnavailable bool `json:"drag_unavailable,omitempty"`

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

	// ConnectedSince is when the CURRENT connection was established.
	//
	// Not when the agent started, and not the last time it refreshed this
	// file: a reader showing "connected for 3 days" when the stream dropped
	// and re-established four times overnight reports the opposite of what
	// somebody asking that question wants to know. Zero while disconnected,
	// and reset every time a connection is made.
	ConnectedSince time.Time `json:"connected_since,omitempty"`

	// PolicySyncedAt is when application policy last arrived from the portal.
	//
	// Separate from UpdatedAt because they answer different questions. This
	// file is rewritten every few seconds; policy arrives when somebody saves
	// one, which may be days apart. "Last synced a few seconds ago" on a
	// machine whose policy is a week old would be a lie by omission.
	PolicySyncedAt time.Time `json:"policy_synced_at,omitempty"`

	// PolicyRules and PolicyMode describe the policy currently held, so a
	// reader can say what arrived rather than only when.
	PolicyRules int    `json:"policy_rules,omitempty"`
	PolicyMode  string `json:"policy_mode,omitempty"`

	// PendingInstalls are installers sitting in people's download folders,
	// with what policy says about each.
	//
	// Published here rather than discovered by the menu bar, for the same
	// reason the permission state is: the menu bar runs as the logged-in user
	// and cannot read another account's downloads, check a package signature
	// against the system's trust store, or see the policy at all. One side
	// decides; the other shows.
	PendingInstalls []PendingInstall `json:"pending_installs,omitempty"`

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
