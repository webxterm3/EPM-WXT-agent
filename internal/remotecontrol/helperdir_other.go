//go:build !darwin

package remotecontrol

// fallbackHelperDir is unused off macOS — no other platform has application
// bundles — but it has to exist for the shared code to compile.
const fallbackHelperDir = "."
