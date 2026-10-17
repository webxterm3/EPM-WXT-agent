//go:build darwin

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// macBundleMacOS is where the application bundle keeps its executables.
//
// Everything the product runs on a Mac lives here and nowhere else. That is
// not tidiness: macOS records a privacy grant against the responsible process
// — the topmost launchd-started ancestor of whoever calls the API, which
// launchctl asuser does not reset — so a daemon started from /usr/local/bin
// and a daemon started from inside the bundle produce two DIFFERENT rows in
// System Settings for the same product, and granting one does nothing for the
// other. Running everything from one place is what makes one grant enough.
const macBundleMacOS = macAppBundle + "/Contents/MacOS"

// bundleBinary returns the bundle's copy of name, or "" when it is not usable.
//
// Checked rather than assumed. An agent enrolled from the command line has no
// bundle at all, and pointing launchd at a path that does not exist would stop
// the agent working entirely rather than merely costing an extra row.
func bundleBinary(name string) string {
	path := filepath.Join(macBundleMacOS, name)
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() || fi.Mode()&0o111 == 0 {
		return ""
	}
	return path
}

// runtimeAgentPath is the agent binary launchd should start.
//
// The bundle copy when there is one, so that every session helper it spawns is
// attributed to the bundle. Falls back to /usr/local/bin for a command-line
// install, which still works — it just shows its own row.
func runtimeAgentPath() string {
	if p := bundleBinary("wxt-agent"); p != "" {
		return p
	}
	return filepath.Join(macInstallDir, "wxt-agent")
}

// runtimeMenuBarPath is the menu bar binary the LaunchAgent should start.
func runtimeMenuBarPath() string {
	if p := bundleBinary("wxt-agent-menubar"); p != "" {
		return p
	}
	return macMenuBarBinary
}

// removeLooseCopy deletes a binary that should not exist beside the bundle.
//
// A second copy of the same program at a second path is a second TCC client:
// macOS lists it separately, under a blank icon, and nothing the product ships
// can remove that row afterwards. Both installers already delete these; this
// stops configure putting them back.
func removeLooseCopy(path string) {
	if _, err := os.Stat(path); err != nil {
		return
	}
	if err := os.Remove(path); err == nil {
		fmt.Printf("✓ Removed a duplicate copy at %s (it would have appeared separately in System Settings)\n", path)
	}
}
