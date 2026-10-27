//go:build !darwin

package pendinginstall

import "errors"

// RemoveBundle is macOS-only; application bundles are.
func RemoveBundle(string, string) error { return errors.New("not supported on this platform") }
