package agentstatus

import (
	"errors"
	"os"
	"path/filepath"
	"time"
)

// A "sync now" request, from the menu bar item to the agent.
//
// The two cannot talk directly: the menu bar runs as the logged-in user with a
// desktop, the agent runs as root or SYSTEM with neither. A socket between
// them needs a listener, an authentication story and a reconnect loop to carry
// one bit that is pressed by hand a few times a year.
//
// # Why the file is pre-created rather than written on demand
//
// The obvious shape — the menu bar creates a file, the agent removes it — does
// not work, and failed in exactly the way this directory is set up to prevent.
// /var/log/vsay is owned by root because the agent's log lives there, so an
// unprivileged process cannot create or unlink anything inside it:
//
//	open /var/log/vsay/sync-request: permission denied
//
// Loosening the directory would make the agent's own log writable by every
// user on the machine, to deliver a button.
//
// So the AGENT creates the file, once, world-writable; the menu bar only ever
// writes INTO it, which needs permission on the file and not on the directory;
// and the agent empties it. Nothing but the agent may create or remove
// anything in that directory, and the surface a user gains is one file whose
// contents are never read.
//
// The request carries NO instruction — only "the user asked". What a sync does
// is decided by the agent and the backend, so writing this gains nobody
// anything they could not have by waiting.

// syncRequestPath sits beside the status file, in the directory the agent owns.
func syncRequestPath() string {
	// Path(), not platformPath(): the request has to follow the status file
	// wherever it goes, including the redirect tests use.
	return filepath.Join(filepath.Dir(Path()), "sync-request")
}

// ErrSyncUnavailable means the agent has not prepared the request file, so
// there is nothing to ask.
//
// Distinct from a permission error on purpose: "the agent is not running" and
// "you may not do this" send somebody to completely different places.
var ErrSyncUnavailable = errors.New("the agent has not prepared a sync request file")

// PrepareSyncRequest creates the file the menu bar writes into. Called by the
// agent, as root, at startup.
//
// Mode 0666 because the person at the keyboard is the one who presses the
// button, and the agent does not know who that will be. The file holds a
// timestamp nobody parses; its CONTENTS are never used for anything, so a
// user who can write it can say "I asked" and nothing else.
func PrepareSyncRequest() error {
	path := syncRequestPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { // #nosec G301
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o666) // #nosec G302,G304
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// O_CREATE respects the umask, which for a daemon is usually 022 — that
	// would leave this 0644 and the button would fail for exactly the user it
	// exists for. Set explicitly.
	return os.Chmod(path, 0o666) // #nosec G302
}

// RequestSync asks the agent to fetch policy now. Called by the menu bar, as
// the logged-in user.
//
// Writes into the existing file rather than creating one, because creating
// requires permission on a directory that belongs to root.
func RequestSync() error {
	f, err := os.OpenFile(syncRequestPath(), os.O_WRONLY|os.O_TRUNC, 0) // #nosec G304
	if err != nil {
		if os.IsNotExist(err) {
			return ErrSyncUnavailable
		}
		return err
	}
	defer f.Close()

	// A timestamp so somebody looking at the directory can see when it was
	// asked for. Nothing reads it; a non-empty file IS the request.
	_, err = f.WriteString(time.Now().UTC().Format(time.RFC3339) + "\n")
	return err
}

// TakeSyncRequest reports whether a sync was asked for, and consumes it.
//
// Consuming is a TRUNCATE, not a remove: removing needs permission on the
// directory, and emptying the file leaves it in place for the next press. The
// agent is the only reader, so the window between seeing content and clearing
// it belongs to one process.
func TakeSyncRequest() bool {
	fi, err := os.Stat(syncRequestPath())
	if err != nil || fi.Size() == 0 {
		return false
	}
	// Failing to clear it would re-fire the same press on every tick, which
	// is a sync a second until somebody noticed.
	if err := os.Truncate(syncRequestPath(), 0); err != nil {
		return false
	}
	return true
}

// ClearSyncRequest drops a pending request without acting on it, for shutdown.
// A request left behind would fire on the next start, long after whoever
// pressed it stopped caring.
func ClearSyncRequest() { _ = os.Truncate(syncRequestPath(), 0) }
