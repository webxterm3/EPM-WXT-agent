//go:build !darwin

package capture

// ScreenRecordingPermitted is a macOS question; elsewhere capture needs no
// grant, so reporting "denied" would be a false alarm.
func ScreenRecordingPermitted() bool { return true }

// RequestScreenRecording is a macOS prompt; elsewhere there is nothing to ask
// for and nothing to register.
func RequestScreenRecording() bool { return true }
