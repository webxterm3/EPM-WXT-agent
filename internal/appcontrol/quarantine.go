package appcontrol

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Quarantining moves a blocked application out of the way entirely.
//
// Withholding the execute bit (macOS) or setting an Image File Execution
// Options entry (Windows) stops an application launching, but it is still
// sitting in the Applications folder looking installed — and on macOS the
// execute-bit lock needs the App Management permission, which not every
// machine grants. Quarantine is the stronger answer: the application is moved
// into a directory only the agent writes to, so it disappears from where the
// user looks for it and nothing can start it.
//
// It is a MOVE, never a delete.
//
// That distinction is the whole safety story. A policy aimed at the wrong
// application, a rule that matched more than its author expected, an operator
// who changes their mind — all of those are recoverable from a move and none
// of them are recoverable from a delete. The original location is recorded, a
// policy that stops blocking puts the application back, and uninstalling the
// agent restores everything it holds.

// quarantineDirName is the folder inside the agent's state directory where
// blocked applications are kept.
const quarantineDirName = "quarantine"

// quarantinePath is where a given application is kept while blocked.
//
// Named from the original path rather than from the application's name:
// two applications can share a name, and the path is what has to be restored.
func quarantinePath(root, original string) string {
	clean := strings.TrimPrefix(filepath.ToSlash(original), "/")
	clean = strings.ReplaceAll(clean, ":", "")
	return filepath.Join(root, quarantineDirName, filepath.FromSlash(clean))
}

// quarantine moves an application aside. It is idempotent: an application
// already put away is left where it is.
func quarantine(root string, t Target) (string, error) {
	if root == "" {
		return "", fmt.Errorf("no state directory, so nothing could be restored later")
	}
	src := t.Path
	if src == "" {
		return "", fmt.Errorf("no path to quarantine for %q", t.Name)
	}
	if isProtectedPath(src) || isOwnBinary(src) {
		// Belt and braces. The callers check too, but this one is about
		// moving an operating system out of its own way, so it checks again.
		return "", fmt.Errorf("refusing to quarantine a protected path: %s", src)
	}

	dst := quarantinePath(root, src)
	if _, err := os.Stat(dst); err == nil {
		// Already held. If the original is somehow back as well, the newer
		// copy wins and the old one is left where it is rather than silently
		// overwritten — losing a user's data here is the one unrecoverable
		// outcome.
		if _, err := os.Stat(src); err != nil {
			return dst, nil
		}
		return "", fmt.Errorf("%s is already quarantined and has reappeared; not overwriting", src)
	}

	if _, err := os.Stat(src); err != nil {
		if os.IsNotExist(err) {
			return "", nil // nothing installed to move
		}
		return "", err
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return "", err
	}
	if err := os.Rename(src, dst); err != nil {
		// Rename fails across filesystems. An application on another volume is
		// left alone and reported rather than copied-then-deleted, because a
		// copy that fails half way through is the delete this design exists to
		// avoid.
		return "", fmt.Errorf("could not move %s aside: %w", src, err)
	}
	return dst, nil
}

// release puts a quarantined application back where it was.
func release(root string, original string) error {
	if root == "" || original == "" {
		return nil
	}
	held := quarantinePath(root, original)
	if _, err := os.Stat(held); err != nil {
		if os.IsNotExist(err) {
			return nil // nothing of ours is holding it
		}
		return err
	}

	if _, err := os.Stat(original); err == nil {
		// Something is back at the original path — a reinstall, most likely.
		// The user's copy wins; ours is dropped rather than put back over it.
		return os.RemoveAll(held)
	}

	if err := os.MkdirAll(filepath.Dir(original), 0o755); err != nil { // #nosec G301 -- restoring an application directory
		return err
	}
	return os.Rename(held, original)
}
