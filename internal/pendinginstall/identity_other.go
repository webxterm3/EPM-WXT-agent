//go:build !darwin

package pendinginstall

// ConsoleUserEmail is macOS-only; the drag-to-Applications install is.
func ConsoleUserEmail() string { return "" }
