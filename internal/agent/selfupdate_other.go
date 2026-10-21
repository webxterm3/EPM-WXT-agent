//go:build !darwin

package agent

// Application bundles are a macOS idea. Everywhere else the unit of update is
// the binary, which the ordinary swap handles.

func (a *Agent) swapMacOSBundle(string, string) (bool, error) { return false, nil }

func insideAppBundlePath(string) bool { return false }
