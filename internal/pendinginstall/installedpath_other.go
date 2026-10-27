//go:build !darwin

package pendinginstall

// InstalledPathFor is macOS-only; application bundles are.
func InstalledPathFor(string) string { return "" }

// IsInstalledPath is macOS-only too.
func IsInstalledPath(string) bool { return false }

// IsOwnInstallPath is macOS-only too.
func IsOwnInstallPath(string) bool { return false }
