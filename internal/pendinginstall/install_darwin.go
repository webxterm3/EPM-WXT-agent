//go:build darwin

package pendinginstall

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Installing it, rather than asking macOS for permission to let somebody
// else install it.
//
// The original design opened a window: an access-control entry on
// /Applications letting the person at the screen drag an approved
// application across. On a real managed Mac that write is refused —
// `chmod: Failed to set ACL on file '/Applications': Operation not
// permitted`, as root, every time. Writing INTO /Applications works (the
// agent replaces its own bundle there on every self-update); setting the
// directory's ACL does not.
//
// So the window could not be opened, Finder fell back to the administrator
// password sheet, and it did so even for software an approver had just
// approved — the one case the feature exists to make painless.
//
// The agent is root and can simply do the copy. That needs no privacy grant,
// no configuration profile and no standing permission on /Applications,
// which also removes the write grant that previously had to be cleaned up
// after a crash.

// copyTree is ditto, behind a seam.
//
// ditto, not cp. It is the tool that preserves the extended attributes,
// resource forks and ACLs an application bundle carries; cp -R drops some of
// them, and an application whose signature no longer verifies because its
// metadata was lost will not launch.
//
// A seam because the thing worth testing is what happens when a copy fails
// HALF WAY — which is the case the staging directory exists for, and which
// cannot be produced by pointing ditto at a missing file.
var copyTree = func(ctx context.Context, src, dst string) error {
	out, err := exec.CommandContext(ctx, "/usr/bin/ditto", src, dst).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// InstallBundle copies an application from a mounted image into
// /Applications, replacing any earlier copy.
//
// Staged beside the destination and then swapped, so a failure part way
// through cannot leave half an application where a working one was. Both
// paths are on the same filesystem, which is what makes the rename atomic.
func InstallBundle(src string) error {
	name := filepath.Base(src)
	if !strings.HasSuffix(name, ".app") {
		return fmt.Errorf("not an application bundle: %s", src)
	}
	dst := filepath.Join(applicationsDir, name)
	if isOwnInstallPath(dst) {
		// The agent updates itself through its own update path, which knows
		// how to stop and restart the service around the swap. Copying over
		// a running agent from here would replace the binary underneath the
		// process doing the copying.
		return fmt.Errorf("the agent installs itself through its own update")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	staging := dst + ".installing"
	_ = os.RemoveAll(staging)
	defer os.RemoveAll(staging)

	if err := copyTree(ctx, src, staging); err != nil {
		return fmt.Errorf("copying %s: %w", name, err)
	}

	// The old copy goes out of the way first, and is only deleted once the
	// new one is in place — so a failed rename leaves the old application
	// working rather than leaving nothing at all.
	previous := ""
	if _, err := os.Stat(dst); err == nil {
		previous = dst + ".replacing"
		_ = os.RemoveAll(previous)
		if err := os.Rename(dst, previous); err != nil {
			return fmt.Errorf("moving the installed %s aside: %w", name, err)
		}
	}

	if err := os.Rename(staging, dst); err != nil {
		if previous != "" {
			_ = os.Rename(previous, dst)
		}
		return fmt.Errorf("putting %s into place: %w", name, err)
	}
	if previous != "" {
		_ = os.RemoveAll(previous)
	}
	return nil
}
