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

	// Watched while it runs, so somebody can see it moving.
	//
	// The staging directory is what is measured, not the destination: the
	// destination does not exist until the rename at the end, so a bar
	// watching it would sit at zero for the whole copy and then jump to
	// done — which is exactly the shape of a hang.
	watchCtx, stopWatching := context.WithCancel(ctx)
	go watchCopy(watchCtx, src, staging, "Copying "+strings.TrimSuffix(name, ".app"))

	err := copyTree(ctx, src, staging)
	stopWatching()
	if err != nil {
		return fmt.Errorf("copying %s: %w", name, err)
	}

	// The last word is the full size, not whatever the final tick caught.
	//
	// Without it the bar stops wherever the 200ms sampling happened to land
	// — 94%, 98% — and stays there while the rename and the cleanup run.
	// Finishing at a number below 100 reads as an install that gave up.
	full := treeSize(src)
	report(Progress{Phase: "Finishing", Done: full, Total: full})

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

// InstallMounted installs whatever is in a mounted image, by what it is.
//
// One entry point rather than two, because the choice between copying a
// bundle and running a package is not a decision the caller should be making
// — it is a property of the thing that was found, decided when the image was
// read. A caller that got it wrong would run `installer` against a folder, or
// copy a package into /Applications as though it were an application.
func InstallMounted(app MountedApp) error {
	if app.Kind != KindPackage {
		return InstallBundle(app.BundlePath)
	}

	// Checked again here, with the file in hand.
	//
	// DecideMounted already refuses an unsigned package — it has no
	// publisher, so it comes out unverified, which is not even requestable.
	// This is not that check repeated out of habit: the decision was made
	// when the image was mounted, and what is on disk at the moment the
	// installer runs is a different fact. The image is writable in principle
	// and the decision is minutes old; between the two, this is the one
	// instant that matters, because what follows runs as root.
	if verifiedPackageSigner(app.BundlePath) == "" {
		//nolint:lll // the sentence reads better whole
		return fmt.Errorf("%s is not signed by anyone this Mac trusts, "+
			"and an installer package runs with full privilege",
			filepath.Base(app.BundlePath))
	}
	return installPackage(app.BundlePath)
}
