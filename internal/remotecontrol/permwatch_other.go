//go:build !darwin

package remotecontrol

// watchForPermissions is a macOS concern: only there does an operating-system
// permission stand between the agent and remote control.
func (c *Controller) watchForPermissions() {}
