//go:build darwin

package pendinginstall

// Whether this Mac will let the agent arrange what people need.
//
// Everything the agent does FOR somebody — installing, updating, removing —
// works without this. What needs it is the part only they can do: dragging
// an application into Applications or to the Trash, and an application's own
// "check for updates", which writes where they cannot.
//
// macOS refuses the access-control entry those need unless the agent holds
// App Management, and it refuses it SILENTLY: no prompt, no row in System
// Settings, just EPERM. A background service never asks, so nobody is ever
// told there is a switch. This is how the product finds out and says so.

// AppManagementHeld reports whether macOS will let the agent write an
// access-control entry where it needs to.
//
// Measured, not assumed: the entry is written and immediately taken away
// again. Asking any other way would be asking about a permission rather than
// about the thing the permission is for, and those have come apart before.
func AppManagementHeld(user string) bool {
	if user == "" {
		return false
	}
	if err := applyACL(applicationsDir, user, true); err != nil {
		return false
	}
	// Taken away again at once. The real grant is made when an approved
	// image is actually mounted, and a window left open by a probe is a
	// standing permission nobody asked for.
	_ = applyACL(applicationsDir, user, false)
	return true
}
