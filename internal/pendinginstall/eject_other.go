//go:build !darwin

package pendinginstall

// Eject is macOS-only; disk images are.
func Eject(string) error { return nil }
