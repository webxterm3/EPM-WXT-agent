//go:build !darwin

package remotecontrol

// bundleHelperDir is a macOS concern: only there does living inside an
// application bundle change which name a privacy grant is recorded under.
func bundleHelperDir() string { return "" }
