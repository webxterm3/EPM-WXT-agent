//go:build !darwin

package pendinginstall

// IsOwnPackage is macOS-only.
//
// The drag-to-Applications install exists on macOS; on Windows the agent is
// installed by an .exe that is run, not dragged, and nothing here refuses it.
func IsOwnPackage(MountedApp) bool { return false }
