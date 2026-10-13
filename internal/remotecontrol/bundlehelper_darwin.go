//go:build darwin

package remotecontrol

import (
	"os"
	"path/filepath"
)

// macAppHelperDir is where the application bundle keeps its copy of the
// session helper.
const macAppHelperDir = "/Applications/wxt-agent.app/Contents/MacOS"

// bundleHelperDir returns that directory when a usable helper is in it.
//
// Checked rather than assumed: an agent installed from the command line has no
// bundle, and pointing at a path that does not exist would stop remote control
// working at all rather than merely showing a second row in System Settings.
func bundleHelperDir() string {
	path := filepath.Join(macAppHelperDir, "wxt-agent-session")
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() || fi.Mode()&0o111 == 0 {
		return ""
	}
	return macAppHelperDir
}
