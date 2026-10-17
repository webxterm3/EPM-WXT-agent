//go:build !darwin

package remotecontrol

// Application bundles are a macOS idea, and so is keying a permission to the
// binary that asks for it. On every other platform there is no bundle to
// prefer, so the helper simply lives beside the agent.

func bundleHelperDir() string { return "" }

// BundleHelperPath is the helper inside the application bundle, or "".
//
// Exported for the installer, which needs to know whether the bundle is the
// canonical home before deciding whether to write a second copy elsewhere.
func BundleHelperPath() string { return "" }
