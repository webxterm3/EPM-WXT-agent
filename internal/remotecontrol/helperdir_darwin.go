//go:build darwin

package remotecontrol

// fallbackHelperDir is where a helper is installed when the bundle has none.
//
// The same directory the installers use for the agent command, which is
// outside any application bundle and therefore safe to write to.
const fallbackHelperDir = "/usr/local/bin"
