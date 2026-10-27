//go:build darwin

package pendinginstall

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Removing an application on somebody's behalf.
//
// Dragging an application to the Trash means deleting a directory out of
// /Applications, which a standard user cannot do — so Finder asks for an
// administrator password, which is the prompt this product exists to remove.
// The per-application access-control entry that would let them do it is the
// same mechanism macOS refuses to write on a managed Mac.
//
// So the agent does it, as root, when asked. Exactly as it does the install.

// usersDir is where home directories live. A var so a test can put the
// Trash somewhere it is allowed to write; nothing changes it at runtime.
var usersDir = "/Users"

// RemoveBundle moves an installed application to the console user's Trash.
//
// To the Trash, NEVER deleted. Somebody who removes the wrong thing has a
// way back that they already know, and an uninstall that cannot be undone is
// a much larger promise than the one being made. It is also what Finder
// itself would have done.
func RemoveBundle(bundle, user string) error {
	if !strings.HasSuffix(bundle, ".app") {
		return fmt.Errorf("not an application bundle: %s", bundle)
	}
	if filepath.Dir(bundle) != applicationsDir {
		// Only out of /Applications. The menu can only name what the agent
		// published, but the request file is writable by any account on the
		// machine by design, so a path from anywhere else is refused rather
		// than acted on.
		return fmt.Errorf("%s is not in %s", bundle, applicationsDir)
	}
	if isOwnInstallPath(bundle) {
		return fmt.Errorf("the agent cannot remove itself")
	}
	if user == "" {
		return fmt.Errorf("nobody is logged in at the screen")
	}

	trash := filepath.Join(usersDir, user, ".Trash")
	if err := os.MkdirAll(trash, 0o700); err != nil {
		return fmt.Errorf("preparing the Trash: %w", err)
	}

	dst := filepath.Join(trash, filepath.Base(bundle))
	if _, err := os.Stat(dst); err == nil {
		// Something of the same name is already in the Trash — a previous
		// removal, or the person's own. Numbered rather than overwritten,
		// the way Finder does it, so neither copy is lost.
		dst = nextFreeTrashPath(dst)
	}

	if err := os.Rename(bundle, dst); err != nil {
		return fmt.Errorf("moving %s to the Trash: %w", filepath.Base(bundle), err)
	}

	// Owned by the person whose Trash it is, so they can empty it.
	_ = chownTree(dst, user)
	return nil
}

// nextFreeTrashPath numbers a name that is already taken.
func nextFreeTrashPath(path string) string {
	base := strings.TrimSuffix(path, ".app")
	for i := 2; i < 100; i++ {
		candidate := base + " " + strconv.Itoa(i) + ".app"
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate
		}
	}
	return base + " " + strconv.FormatInt(time.Now().Unix(), 10) + ".app"
}

// chownTree hands the moved application to the person whose Trash it is.
//
// It was moved by root, so without this it sits in their Trash owned by
// somebody else and emptying it asks for a password — which is the prompt
// the removal was done to avoid, just one step later.
var chownTree = func(path, user string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "/usr/sbin/chown", "-R", user, path).Run()
}
