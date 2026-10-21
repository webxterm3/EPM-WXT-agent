//go:build darwin

package agent

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
)

// macAppBundlePath is the installed application, which is what launchd starts.
const macAppBundlePath = "/Applications/wxt-agent.app"

// macAgentCLI is the command-line copy, kept in step with the bundle so that
// `wxt-agent` in a terminal is never an older build than the daemon.
const macAgentCLI = "/usr/local/bin/wxt-agent"

// swapMacOSBundle replaces the whole application bundle with the one in the
// update package.
//
// On macOS the unit of update is the bundle, not a loose binary — every Mac
// application works this way, and for good reason: a bundle is sealed by one
// code signature covering everything inside it. Writing a new binary into an
// existing bundle breaks that seal, and the operating system then refuses to
// open the application at all, telling the user it "is damaged" and offering
// to move it to the Trash. Replacing the bundle wholesale keeps the signature
// that came with it.
//
// Returns done=false when this is not a macOS bundle update, so the caller can
// fall back to the ordinary binary swap.
func (a *Agent) swapMacOSBundle(pkgPath, workDir string) (done bool, err error) {
	// Asked FIRST, because it decides whether anything below may be forgiven.
	//
	// With no bundle installed this is a CLI-only machine, and a package that
	// turns out to carry no bundle is a perfectly good update for it. With a
	// bundle installed, the bundle IS what launchd runs, so failing to get a
	// new one is a failed update — never a reason to quietly try something
	// else.
	bundleInstalled := false
	if _, statErr := os.Stat(macAppBundlePath); statErr == nil {
		bundleInstalled = true
	}

	newApp, err := extractAppBundle(pkgPath, workDir)
	switch {
	case err != nil && bundleInstalled:
		// Reported, not swallowed. This exact fallthrough hid a real failure
		// once already: the downloaded package was saved to a temp file with
		// no extension, the extractor could not tell what it was, and the
		// update died several steps later complaining about something else
		// entirely.
		return true, fmt.Errorf("reading the update package: %w", err)
	case err != nil:
		return false, nil
	case newApp == "" && bundleInstalled:
		return true, fmt.Errorf(
			"this machine runs the agent from %s, but the update package contains no "+
				"application bundle to replace it with", macAppBundlePath)
	case newApp == "":
		// A bare binary for a CLI-only install. The ordinary swap is right.
		return false, nil
	case !bundleInstalled:
		// A bundle was offered and there is nowhere to put it.
		return false, nil
	}

	// Moved aside rather than deleted, and only removed once the new one is
	// in place. A failure half way through must leave a working agent, not a
	// machine with no bundle at all.
	previous := macAppBundlePath + ".replacing"
	_ = os.RemoveAll(previous)
	if err := os.Rename(macAppBundlePath, previous); err != nil {
		return true, fmt.Errorf("moving the old bundle aside: %w", err)
	}

	if err := os.Rename(newApp, macAppBundlePath); err != nil {
		// Put the old one back. An agent that failed to update still works;
		// one whose bundle vanished does not.
		if restoreErr := os.Rename(previous, macAppBundlePath); restoreErr != nil {
			return true, fmt.Errorf("installing the new bundle failed (%w) AND the old one could not be restored (%v)", err, restoreErr)
		}
		return true, fmt.Errorf("installing the new bundle: %w", err)
	}
	_ = os.RemoveAll(previous)

	// A download carries the quarantine attribute, and it is inherited by
	// everything copied out of the package. Left in place it is the
	// "unidentified developer" refusal on the next launch.
	_ = exec.Command("/usr/bin/xattr", "-dr", "com.apple.quarantine", macAppBundlePath).Run()

	a.refreshAgentCLI()
	a.logger.Info("Self-update: replaced the application bundle",
		zap.String("path", macAppBundlePath))
	return true, nil
}

// refreshAgentCLI copies the new agent out of the bundle to /usr/local/bin.
//
// Best effort: the daemon runs from the bundle, so a stale CLI copy is a
// confusing `wxt-agent version` rather than a broken install.
func (a *Agent) refreshAgentCLI() {
	src := filepath.Join(macAppBundlePath, "Contents", "MacOS", "wxt-agent")
	data, err := os.ReadFile(src) // #nosec G304 -- a path this agent owns
	if err != nil {
		a.logger.Warn("Self-update: could not refresh the command-line copy", zap.Error(err))
		return
	}
	// Written through a temporary file and renamed: the running process may be
	// executing this very path on a CLI-only install.
	tmp := macAgentCLI + ".new"
	if err := os.WriteFile(tmp, data, 0o755); err != nil { // #nosec G306 -- it must be executable
		a.logger.Warn("Self-update: could not refresh the command-line copy", zap.Error(err))
		return
	}
	if err := os.Rename(tmp, macAgentCLI); err != nil {
		_ = os.Remove(tmp)
		a.logger.Warn("Self-update: could not refresh the command-line copy", zap.Error(err))
	}
}

// extractAppBundle finds a .app inside an already-downloaded package.
//
// Returns "" when the package carries no bundle, which is not an error: a
// tarball of a bare binary is still a valid update for an install that has no
// application bundle.
func extractAppBundle(pkgPath, workDir string) (string, error) {
	lower := strings.ToLower(pkgPath)
	switch {
	case strings.HasSuffix(lower, ".dmg"):
		return extractAppFromDmg(pkgPath, workDir)
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		return extractAppFromTarGz(pkgPath, workDir)
	}
	return "", nil
}

// extractAppFromDmg mounts the image and copies the bundle out of it.
func extractAppFromDmg(pkgPath, workDir string) (string, error) {
	mount := filepath.Join(workDir, "mnt")
	if err := os.MkdirAll(mount, 0o755); err != nil { // #nosec G301
		return "", err
	}
	// -nobrowse so the image does not appear in the Finder of whoever happens
	// to be logged in while an update runs.
	out, err := exec.Command("/usr/bin/hdiutil", "attach", "-nobrowse", "-quiet",
		pkgPath, "-mountpoint", mount).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("mounting the update image: %w: %s", err, strings.TrimSpace(string(out)))
	}
	defer func() { _ = exec.Command("/usr/bin/hdiutil", "detach", mount, "-quiet").Run() }()

	src := filepath.Join(mount, "wxt-agent.app")
	if _, err := os.Stat(src); err != nil {
		return "", nil // no bundle in this image
	}

	dst := filepath.Join(workDir, "wxt-agent.app")
	// cp -R rather than a Go walk: it preserves the symlinks, modes and
	// extended attributes a signed bundle depends on, and a bundle copied any
	// other way can fail its own signature check.
	if out, err := exec.Command("/bin/cp", "-R", src, dst).CombinedOutput(); err != nil {
		return "", fmt.Errorf("copying the bundle out of the image: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return dst, nil
}

// extractAppFromTarGz unpacks the archive and looks for a bundle in it.
func extractAppFromTarGz(pkgPath, workDir string) (string, error) {
	dir := filepath.Join(workDir, "tar")
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301
		return "", err
	}
	// tar preserves the bundle's symlinks and permissions; re-creating them by
	// hand is how a copied bundle stops satisfying its own signature.
	if out, err := exec.Command("/usr/bin/tar", "-xzf", pkgPath, "-C", dir).CombinedOutput(); err != nil {
		return "", fmt.Errorf("unpacking the update: %w: %s", err, strings.TrimSpace(string(out)))
	}

	app := filepath.Join(dir, "wxt-agent.app")
	if _, err := os.Stat(app); err != nil {
		return "", nil
	}
	return app, nil
}

// insideAppBundlePath reports whether a path sits inside a macOS .app.
func insideAppBundlePath(path string) bool {
	for dir := filepath.Clean(path); dir != "/" && dir != "." && dir != ""; dir = filepath.Dir(dir) {
		if strings.EqualFold(filepath.Ext(dir), ".app") {
			return true
		}
	}
	return false
}
