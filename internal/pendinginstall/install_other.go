//go:build !darwin

package pendinginstall

import "errors"

// InstallBundle is macOS-only; application bundles are.
func InstallBundle(string) error { return errors.New("not supported on this platform") }
