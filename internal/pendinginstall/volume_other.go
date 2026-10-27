//go:build !darwin

package pendinginstall

// Mounting a disk image to drag an application out of it is a macOS idea.

type MountedApp struct {
	Volume, BundlePath, Name, BundleID, Version, Publisher string
}

func MountedApps() []MountedApp { return nil }
func ConsoleUser() string       { return "" }

// VolumeNames is macOS-only; disk images are.
func VolumeNames() []string { return nil }
