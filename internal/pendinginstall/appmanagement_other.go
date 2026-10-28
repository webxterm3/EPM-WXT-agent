//go:build !darwin

package pendinginstall

// AppManagementHeld is macOS-only; the permission is.
func AppManagementHeld(string) bool { return false }
